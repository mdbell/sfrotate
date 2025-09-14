// src/sf_rotate_and64.cpp
// Build as: libsfrotate.so (arm64)
// Hooks surfaceflinger to force non-primary display orientation = ROT_270.
//
// Requires: And64InlineHook (A64HookFunction)
#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <vector>
#include <stdint.h>

extern "C" {
#include "And64InlineHook.hpp"
}

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  "sfrotate", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "sfrotate", __VA_ARGS__)

// ---------- configuration ----------
static const char* kExePath = "/system/bin/surfaceflinger";

// Enum matches aidl::android::hardware::graphics::common::Transform
static const int32_t ROT_0   = 0;
static const int32_t ROT_90  = 1;
static const int32_t ROT_180 = 2;
static const int32_t ROT_270 = 3;

// Treat displayId == 1 as primary on this device (adjust if needed)
static inline bool isPrimary(uint64_t id) { return id == 1; }

// Mangled targets we’ll try to hook (some may be absent on a given build)
static const char* kSym_getPhys_Aidl =
  "_ZN7android4Hwc212AidlComposer29getPhysicalDisplayOrientationEmPN4aidl7android8hardware8graphics6common9TransformE";
static const char* kSym_getPhys_Hidl =
  "_ZN7android4Hwc212HidlComposer29getPhysicalDisplayOrientationEmPN4aidl7android8hardware8graphics6common9TransformE";
static const char* kSym_isSup_Aidl =
  "_ZNK7android4Hwc212AidlComposer11isSupportedENS0_8Composer15OptionalFeatureE";
static const char* kSym_isSup_Hidl =
  "_ZNK7android4Hwc212HidlComposer11isSupportedENS0_8Composer15OptionalFeatureE";

// ---- tiny helpers: get module base (surfaceflinger) ----
static uintptr_t findSurfaceFlingerBase() {
  FILE* f = fopen("/proc/self/maps", "re");
  if (!f) return 0;
  char line[1024];
  uintptr_t base = 0;
  while (fgets(line, sizeof(line), f)) {
    // find r-xp mapping for /system/bin/surfaceflinger
    // format: start-end perms offset dev inode path
    uintptr_t start=0, end=0;
    char perms[8]={0}, path[512]={0};
    if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %511[^\n]", &start, &end, perms, path) == 4) {
      if (strstr(perms, "r-x") && strstr(path, "surfaceflinger")) {
        base = start;
        break;
      }
    }
  }
  fclose(f);
  return base;
}

// ---- tiny ELF symbol lookup on-disk ----
struct SymHit { std::string name; uint64_t value; uint64_t size; };

static bool loadFile(const char* path, std::vector<uint8_t>& buf) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;
  struct stat st{};
  if (fstat(fd, &st) != 0 || st.st_size <= 0) { close(fd); return false; }
  buf.resize(st.st_size);
  ssize_t n = read(fd, buf.data(), buf.size());
  close(fd);
  return n == (ssize_t)buf.size();
}

static bool collectSymbols(const std::vector<uint8_t>& img, std::vector<SymHit>& out) {
  if (img.size() < sizeof(Elf64_Ehdr)) return false;
  auto* eh = (const Elf64_Ehdr*)img.data();
  if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 || eh->e_ident[EI_CLASS] != ELFCLASS64) return false;

  auto shoff = eh->e_shoff;
  auto shnum = eh->e_shnum;
  if (shoff == 0 || shnum == 0) return false;

  const Elf64_Shdr* sh = (const Elf64_Shdr*)(img.data() + shoff);
  // We’ll look at both SYMTAB and DYNSYM
  for (int pass = 0; pass < 2; ++pass) {
    for (uint16_t i = 0; i < shnum; ++i) {
      if (sh[i].sh_type != (pass == 0 ? SHT_SYMTAB : SHT_DYNSYM)) continue;

      const Elf64_Shdr& symsh = sh[i];
      const Elf64_Shdr& strsh = sh[symsh.sh_link];
      if (symsh.sh_offset + symsh.sh_size > img.size()) continue;
      if (strsh.sh_offset + strsh.sh_size > img.size()) continue;

      auto* syms   = (const Elf64_Sym*)(img.data() + symsh.sh_offset);
      size_t count = symsh.sh_size / sizeof(Elf64_Sym);
      const char* strtab = (const char*)(img.data() + strsh.sh_offset);
      size_t strsz = strsh.sh_size;

      for (size_t si = 0; si < count; ++si) {
        const Elf64_Sym& s = syms[si];
        if (s.st_name == 0) continue;
        if (ELF64_ST_TYPE(s.st_info) != STT_FUNC) continue;
        const char* nm = (s.st_name < strsz) ? (strtab + s.st_name) : nullptr;
        if (!nm || !*nm) continue;
        // For PIE, st_value is offset from base load address.
        out.push_back({nm, (uint64_t)s.st_value, (uint64_t)s.st_size});
      }
    }
  }
  return !out.empty();
}

static void* resolveSymbolRuntime(const char* wanted) {
  std::vector<uint8_t> img;
  if (!loadFile(kExePath, img)) {
    LOGE("read %s failed", kExePath);
    return nullptr;
  }
  std::vector<SymHit> syms;
  if (!collectSymbols(img, syms)) {
    LOGE("no symbols found in %s (stripped?)", kExePath);
    return nullptr;
  }
  uintptr_t base = findSurfaceFlingerBase();
  if (!base) {
    LOGE("cannot find surfaceflinger base");
    return nullptr;
  }
  for (auto& s : syms) {
    if (s.name == wanted) {
      void* addr = (void*)(base + s.value);
      LOGI("resolved %s -> %p (base=%p,+0x%llx)", wanted, addr, (void*)base, (unsigned long long)s.value);
      return addr;
    }
  }
  LOGE("symbol not found: %s", wanted);
  return nullptr;
}

// ---------- Hook typedefs ----------
using get_phys_t = int(*)(void* self, uint64_t displayId, int32_t* outTransform);
using is_sup_t   = bool(*)(void* self, int feature);

static get_phys_t  orig_getPhys_aidl = nullptr;
static get_phys_t  orig_getPhys_hidl = nullptr;
static is_sup_t    orig_isSup_aidl   = nullptr;
static is_sup_t    orig_isSup_hidl   = nullptr;

// ---------- Replacements ----------
static int repl_getPhys_common(const char* which, get_phys_t orig,
                               void* self, uint64_t displayId, int32_t* out) {
  if (!out) return orig ? orig(self, displayId, out) : -1;
  if (isPrimary(displayId)) {
    int r = orig ? orig(self, displayId, out) : 0;
    LOGI("[%s] primary id=0x%llx -> pass-through (%d)", which,
         (unsigned long long)displayId, r);
    return r;
  } else {
    *out = ROT_270;
    LOGI("[%s] non-primary id=0x%llx -> FORCED ROT_270", which,
         (unsigned long long)displayId);
    return 0; // STATUS_OK
  }
}

static int repl_getPhys_aidl(void* self, uint64_t id, int32_t* out) {
  return repl_getPhys_common("AIDL", orig_getPhys_aidl, self, id, out);
}
static int repl_getPhys_hidl(void* self, uint64_t id, int32_t* out) {
  return repl_getPhys_common("HIDL", orig_getPhys_hidl, self, id, out);
}

static bool repl_isSup_common(const char* which, is_sup_t orig, void* self, int feat) {
  // HWC2 OptionalFeature::PhysicalDisplayOrientation == 4 on your build.
  if (feat == 4) {
    // Claim support so SF will call into getPhysicalDisplayOrientation()
    LOGI("[%s] isSupported(%d) -> SUPPORTED (forced)", which, feat);
    return true;
  }
  bool r = orig ? orig(self, feat) : false;
  // minimal log to avoid spam
  return r;
}
static bool repl_isSup_aidl(void* self, int feat) { return repl_isSup_common("AIDL", orig_isSup_aidl, self, feat); }
static bool repl_isSup_hidl(void* self, int feat) { return repl_isSup_common("HIDL", orig_isSup_hidl, self, feat); }

// ---------- Install ----------
static void try_hook(const char* name, void** orig, void* repl) {
  void* addr = resolveSymbolRuntime(name);
  if (!addr) return;
  if (A64HookFunction(addr, repl, orig), *orig) {
    LOGI("hooked %s @ %p", name, addr);
  } else {
    LOGE("hook failed for %s", name);
  }
}

__attribute__((constructor))
static void init_sfrotate() {
  LOGI("sfrotate init");

  // getPhysicalDisplayOrientation (both variants)
  try_hook(kSym_getPhys_Aidl, (void**)&orig_getPhys_aidl, (void*)repl_getPhys_aidl);
  try_hook(kSym_getPhys_Hidl, (void**)&orig_getPhys_hidl, (void*)repl_getPhys_hidl);

  // isSupported (both variants) – so calls won’t be short-circuited
  try_hook(kSym_isSup_Aidl,   (void**)&orig_isSup_aidl,   (void*)repl_isSup_aidl);
  try_hook(kSym_isSup_Hidl,   (void**)&orig_isSup_hidl,   (void*)repl_isSup_hidl);

  LOGI("sfrotate ready");
}
