// Minimal ARM64 Android injector that calls dlopen() in a target process.
//
// Usage:
//   ./dlopen64 <pid|process-name> /full/path/lib.so

#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#if !defined(__aarch64__)
# error "ARM64 only"
#endif

#define LOGE(...) do { fprintf(stdout, "[E] " __VA_ARGS__); fputc('\n', stdout); } while (0)
#define LOGI(...) do { fprintf(stdout, "[*] " __VA_ARGS__); fputc('\n', stdout); } while (0)

#include <sys/user.h>
#include <linux/elf.h>

static int get_regs(pid_t pid, struct user_pt_regs* regs) {
  struct iovec io { regs, sizeof(*regs) };
  return ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &io);
}
static int set_regs(pid_t pid, const struct user_pt_regs* regs) {
  struct iovec io { (void*)regs, sizeof(*regs) };
  return ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &io);
}

static int wait_stopped(pid_t pid) {
  int status = 0;
  if (waitpid(pid, &status, 0) < 0) return -1;
  return WIFSTOPPED(status) ? 0 : -1;
}

static pid_t find_pid_by_name(const char* name) {
  DIR* d = opendir("/proc");
  if (!d) return -1;
  struct dirent* de;
  while ((de = readdir(d))) {
    if (de->d_type != DT_DIR) continue;
    pid_t pid = atoi(de->d_name);
    if (pid <= 0) continue;
    char p[64]; snprintf(p, sizeof p, "/proc/%d/cmdline", pid);
    int fd = open(p, O_RDONLY);
    if (fd < 0) continue;
    char buf[256] = {0};
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n > 0 && strstr(buf, name)) { closedir(d); return pid; }
  }
  closedir(d);
  return -1;
}

static uintptr_t get_module_base(pid_t pid, const char* needle) {
  char maps[64];
  snprintf(maps, sizeof maps, "/proc/%d/maps", pid);
  FILE* f = fopen(maps, "re");
  if (!f) return 0;
  char line[1024];
  uintptr_t best = 0;
  while (fgets(line, sizeof line, f)) {
    if (!strstr(line, needle)) continue;
    unsigned long start=0; char perms[5]={0};
    if (sscanf(line, "%lx-%*lx %4s", &start, perms) == 2) {
      if (strchr(perms, 'x')) { best = start; break; }
      if (!best) best = start;
    }
  }
  fclose(f);
  return best;
}

static uintptr_t local_module_base(const char* needle) {
  return get_module_base(getpid(), needle);
}

static uintptr_t remote_addr_from_local(pid_t pid, const char* module_name, void* local_fn) {
  uintptr_t l_base = local_module_base(module_name);
  uintptr_t r_base = get_module_base(pid, module_name);
  if (!l_base || !r_base) return 0;
  uintptr_t off = (uintptr_t)local_fn - l_base;
  return r_base + off;
}

static int write_remote(pid_t pid, uintptr_t remote, const void* buf, size_t len) {
  // Try process_vm_writev first
  struct iovec liov{ (void*)buf, len };
  struct iovec riov{ (void*)remote, len };
  ssize_t n = process_vm_writev(pid, &liov, 1, &riov, 1, 0);
  if (n == (ssize_t)len) return 0;

  // Fallback: ptrace POKEDATA (slow)
  const uint8_t* p = (const uint8_t*)buf;
  size_t off = 0;
  while (off < len) {
    long word = 0;
    size_t chunk = (len - off >= sizeof(long)) ? sizeof(long) : (len - off);
    memcpy(&word, p + off, chunk);
    if (ptrace(PTRACE_POKEDATA, pid, (void*)(remote + off), (void*)word) < 0) return -1;
    off += chunk;
  }
  return 0;
}

// --- tiny call stub (ARM64) ---
static const uint32_t LDR_X16_LITERAL = 0x58000090; // ldr x16, #8
static const uint32_t BLR_X16         = 0xD63F0200; // blr x16
static const uint32_t BRK_0           = 0xD4200000; // brk #0
static const uint32_t NOP             = 0xD503201F; // nop

struct RemoteSession {
  pid_t pid;
  bool attached{false};
  bool have_saved{false};
  struct user_pt_regs saved{};

  explicit RemoteSession(pid_t p) : pid(p) {
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == 0 && wait_stopped(pid) == 0) {
      attached = true;
      if (get_regs(pid, &saved) == 0) have_saved = true;
    }
  }
  ~RemoteSession() {
    if (attached) {
      if (have_saved) set_regs(pid, &saved);
      ptrace(PTRACE_DETACH, pid, 0, 0);
    }
  }

  bool ok() const { return attached && have_saved; }

  // Call remote function (fn_addr) with up to 4 args using a small stub placed at 'scratch'.
  // Returns x0, or -1 on failure.
  long call_with_stub(uintptr_t scratch, uintptr_t fn_addr,
                      uintptr_t x0=0, uintptr_t x1=0,
                      uintptr_t x2=0, uintptr_t x3=0) {
    if (!ok()) return -1;

    // write stub
    uint8_t stub[0x18]{0};
    *(uint32_t*)(stub + 0x00) = LDR_X16_LITERAL;
    *(uint32_t*)(stub + 0x04) = BLR_X16;
    *(uint32_t*)(stub + 0x08) = BRK_0;
    *(uint32_t*)(stub + 0x0C) = NOP;
    *(uint64_t*)(stub + 0x10) = (uint64_t)fn_addr;
    if (write_remote(pid, scratch, stub, sizeof stub) != 0) {
      LOGE("write stub failed");
      return -1;
    }

    // set args & run
    struct user_pt_regs regs = saved;
    regs.regs[0] = x0; regs.regs[1] = x1; regs.regs[2] = x2; regs.regs[3] = x3;
    regs.pc = scratch; regs.regs[30] = 0;
    if (set_regs(pid, &regs) != 0) { LOGE("SETREGS(call)"); return -1; }
    if (ptrace(PTRACE_CONT, pid, 0, 0) != 0) { LOGE("CONT(call): %s", strerror(errno)); return -1; }
    if (wait_stopped(pid) != 0) { LOGE("wait(call)"); return -1; }
    if (get_regs(pid, &regs) != 0) { LOGE("GETREGS(ret)"); return -1; }

    long ret = (long)regs.regs[0];
    // restore registers after each call
    if (set_regs(pid, &saved) != 0) { LOGE("restore regs failed"); return -1; }
    return ret;
  }

  // Allocate RWX memory via remote mmap and return its address (or 0 on failure).
  uintptr_t remote_mmap(size_t size, uintptr_t r_mmap) {
    if (!ok() || !r_mmap) return 0;
    struct user_pt_regs regs = saved;
    regs.regs[0] = 0;               // addr
    regs.regs[1] = (uintptr_t)size; // len
    regs.regs[2] = PROT_READ | PROT_WRITE | PROT_EXEC;
    regs.regs[3] = MAP_PRIVATE | MAP_ANONYMOUS;
    regs.regs[4] = (uintptr_t)-1;   // fd
    regs.regs[5] = 0;               // off
    regs.pc = r_mmap; regs.regs[30] = 0;
    if (set_regs(pid, &regs) != 0) { LOGE("SETREGS(mmap)"); return 0; }
    if (ptrace(PTRACE_CONT, pid, 0, 0) != 0) { LOGE("CONT(mmap): %s", strerror(errno)); return 0; }
    if (wait_stopped(pid) != 0) { LOGE("wait(mmap)"); return 0; }
    if (get_regs(pid, &regs) != 0) { LOGE("GETREGS(mmap ret)"); return 0; }
    uintptr_t addr = regs.regs[0];
    // restore after syscall
    if (set_regs(pid, &saved) != 0) { LOGE("restore regs after mmap failed"); return 0; }
    if ((long)addr < 0x1000) { LOGE("mmap failed: x0=0x%lx", (unsigned long)addr); return 0; }
    return addr;
  }
};

int main(int argc, char** argv) {
  if (argc != 3) {
    fprintf(stderr, "Usage: %s <pid|process-name> /full/path/lib.so\n", argv[0]);
    return 1;
  }

  // resolve target pid
  pid_t pid = 0;
  if (strspn(argv[1], "0123456789") == strlen(argv[1])) pid = (pid_t)atoi(argv[1]);
  else pid = find_pid_by_name(argv[1]);
  if (pid <= 0) { LOGE("bad pid/process: %s", argv[1]); return 2; }

  // check lib path
  const char* libpath = argv[2];
  struct stat st{};
  if (stat(libpath, &st) != 0) { LOGE("cannot stat %s", libpath); return 3; }

  // find remote dlopen
  void* local_dlopen = dlsym(RTLD_NEXT, "dlopen");
  uintptr_t r_dlopen = 0;
  const char* cand[] = {
    "libdl.so",
    "bionic/libdl.so",
    "linker64",
    "/apex/com.android.runtime/lib64/bionic/libdl.so"
  };
  for (const char* m : cand) {
    r_dlopen = remote_addr_from_local(pid, m, local_dlopen);
    if (r_dlopen) { LOGI("remote dlopen in %s @ 0x%lx", m, (unsigned long)r_dlopen); break; }
  }
  if (!r_dlopen) { LOGE("failed to locate remote dlopen()"); return 4; }

  // find remote mmap
  void* local_mmap = dlsym(RTLD_NEXT, "mmap");
  uintptr_t r_mmap = 0;
  const char* libcand[] = {
    "libc.so",
    "bionic/libc.so",
    "/apex/com.android.runtime/lib64/bionic/libc.so"
  };
  for (const char* m : libcand) {
    r_mmap = remote_addr_from_local(pid, m, local_mmap);
    if (r_mmap) { LOGI("remote mmap in %s @ 0x%lx", m, (unsigned long)r_mmap); break; }
  }
  if (!r_mmap) { LOGE("failed to locate remote mmap"); return 5; }

  // attach
  RemoteSession S(pid);
  if (!S.ok()) { LOGE("ptrace attach / save-regs failed"); return 6; }

  // scratch page
  uintptr_t scratch = S.remote_mmap(0x2000, r_mmap);
  if (!scratch) return 7;
  LOGI("remote scratch @ 0x%lx", (unsigned long)scratch);

  // write library path at scratch+0x100
  uintptr_t remote_path = scratch + 0x100;
  if (write_remote(pid, remote_path, libpath, strlen(libpath) + 1) != 0) {
    LOGE("write path failed");
    return 8;
  }

  // call dlopen(lib, RTLD_NOW|RTLD_GLOBAL)
  long h = S.call_with_stub(scratch, r_dlopen,
                            remote_path,
                            RTLD_NOW | RTLD_GLOBAL,
                            0, 0);
  if (h == -1) { LOGE("dlopen call failed"); return 9; }

  LOGI("dlopen returned 0x%lx", (unsigned long)h);
  return 0;
}
