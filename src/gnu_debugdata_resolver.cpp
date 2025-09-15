#include <elf.h>
#include <vector>
#include <string>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "log.h"

extern "C" {
// xz-embedded API headers
#include "xz.h"
}


static bool read_file(const char* path, std::vector<uint8_t>& out) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;
  struct stat st{};
  if (fstat(fd, &st) != 0 || st.st_size <= 0) { close(fd); return false; }
  out.resize((size_t)st.st_size);
  ssize_t n = read(fd, out.data(), out.size());
  close(fd);
  return n == (ssize_t)out.size();
}

static const Elf64_Ehdr* as_ehdr(const std::vector<uint8_t>& b) {
  if (b.size() < sizeof(Elf64_Ehdr)) return nullptr;
  auto* eh = (const Elf64_Ehdr*)b.data();
  if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return nullptr;
  if (eh->e_ident[EI_CLASS] != ELFCLASS64) return nullptr;
  return eh;
}

static const Elf64_Shdr* shdr(const std::vector<uint8_t>& b, const Elf64_Ehdr* eh, size_t i) {
  const auto shoff = eh->e_shoff;
  const auto entsz = eh->e_shentsize;
  if (shoff == 0 || entsz < sizeof(Elf64_Shdr)) return nullptr;
  const uint8_t* base = b.data() + shoff + i * entsz;
  if (base + sizeof(Elf64_Shdr) > b.data() + b.size()) return nullptr;
  return (const Elf64_Shdr*)base;
}

static const char* shstr(const std::vector<uint8_t>& b, const Elf64_Ehdr* eh, uint32_t name_off) {
  const auto* shstr = shdr(b, eh, eh->e_shstrndx);
  if (!shstr) return nullptr;
  const char* s = (const char*)(b.data() + shstr->sh_offset);
  if ((size_t)name_off >= shstr->sh_size) return nullptr;
  return s + name_off;
}

static bool decompress_xz(const uint8_t* in, size_t in_len, std::vector<uint8_t>& out) {
  // Allocate a reasonable output buffer and grow if needed.
  out.clear(); out.reserve(in_len * 6); // rough guess; will grow if necessary

  xz_crc32_init();
  xz_crc64_init();

  struct xz_dec* s = xz_dec_init(XZ_DYNALLOC, 1 << 26); // up to 64 MB dict
  if (!s) return false;

  xz_buf b{};
  std::vector<uint8_t> tmp(1 << 20); // 1MB chunk writer
  b.in = in; b.in_pos = 0; b.in_size = in_len;

  xz_ret ret = XZ_OK;
  do {
    size_t old_size = out.size();
    out.resize(old_size + tmp.size());
    b.out = out.data();
    b.out_pos = old_size;
    b.out_size = out.size();

    ret = xz_dec_run(s, &b);
    out.resize(b.out_pos); // shrink to written

    if (ret == XZ_OK && b.out_pos == old_size) {
      // Output full but decoder not finished: grow buffer and continue
      out.reserve(out.size() + tmp.size());
    }
    LOGV("xz_dec_run: ret=%d  in_pos=%zu/%zu  out_pos=%zu/%zu",
         ret, b.in_pos, b.in_size, b.out_pos, b.out_size);
  } while (ret == XZ_OK);

  if(ret != XZ_OK) {
    LOGI("Input data (first 64 bytes or less):");
    size_t dump_len = (in_len < 64) ? in_len : 64;
    for (size_t i = 0; i < dump_len; i++) {
      LOGI("%02x ", in[i]);
    }
  }

  xz_dec_end(s);
  return ret == XZ_STREAM_END;
}

// ---------- public API ----------
struct GnuDebugSym {
  std::string name;
  uint64_t    value;   // st_value (VMA)
  uint64_t    size;    // st_size
  unsigned    type;    // STT_*
};

bool load_gnu_debugdata(const char* exe_path,
                               std::vector<GnuDebugSym>& out_syms) {
  out_syms.clear();

  // 1) Read the main ELF (surfaceflinger file on disk)
  std::vector<uint8_t> main_bin;
  if (!read_file(exe_path, main_bin)) return false;
  const auto* eh = as_ehdr(main_bin);
  if (!eh) return false;

  LOGV("main ELF read: %s  size=0x%lx", exe_path, (unsigned long)main_bin.size());

  // 2) Locate .gnu_debugdata
  const Elf64_Shdr* sec = nullptr;
  for (uint16_t i = 0; i < eh->e_shnum; i++) {
    const auto* sh = shdr(main_bin, eh, i);
    if (!sh) continue;
    const char* nm = shstr(main_bin, eh, sh->sh_name);
    if (nm && strcmp(nm, ".gnu_debugdata") == 0) { sec = sh; break; }
  }
  if (!sec || sec->sh_size == 0) return false;

  LOGV(".gnu_debugdata found: offset=0x%lx size=0x%lx",
       (unsigned long)sec->sh_offset, (unsigned long)sec->sh_size);

  const uint8_t* cdat = main_bin.data() + sec->sh_offset;
  size_t clen = (size_t)sec->sh_size;

  // 3) Decompress (XZ/LZMA2) -> mini ELF with .symtab
  std::vector<uint8_t> dbg_elf;
  if (!decompress_xz(cdat, clen, dbg_elf)) return false;

  LOGV(".gnu_debugdata decompressed: size=0x%lx", (unsigned long)dbg_elf.size());

  const auto* deh = as_ehdr(dbg_elf);
  if (!deh) return false;

  // 4) Find .symtab and its .strtab
  const Elf64_Shdr *symtab = nullptr, *strtab = nullptr;
  for (uint16_t i = 0; i < deh->e_shnum; i++) {
    const auto* sh = shdr(dbg_elf, deh, i);
    if (!sh) continue;
    const char* nm = shstr(dbg_elf, deh, sh->sh_name);
    if (!nm) continue;
    if (!symtab && sh->sh_type == SHT_SYMTAB) symtab = sh;
    if (!strtab && strcmp(nm, ".strtab") == 0) strtab = sh;
  }
  if (!symtab || !strtab){
    LOGE(".symtab or .strtab not found in .gnu_debugdata");
    LOGE("symtab=%p strtab=%p", (void*)symtab, (void*)strtab);
    return false;
  }

  LOGV(".symtab found: offset=0x%lx size=0x%lx  .strtab offset=0x%lx size=0x%lx",
       (unsigned long)symtab->sh_offset, (unsigned long)symtab->sh_size,
       (unsigned long)strtab->sh_offset, (unsigned long)strtab->sh_size);

  const char* str = (const char*)(dbg_elf.data() + strtab->sh_offset);
  const auto* sym = (const Elf64_Sym*)(dbg_elf.data() + symtab->sh_offset);
  size_t count    = symtab->sh_size / sizeof(Elf64_Sym);

  LOGV("symbol count: %zu", count);

  // 5) Collect defined function symbols
  for (size_t i = 0; i < count; i++) {
    if (sym[i].st_name == 0) continue;
    const char* nm = str + sym[i].st_name;
    if (!nm || !*nm) continue;

    unsigned type = ELF64_ST_TYPE(sym[i].st_info);
    if (type != STT_FUNC) continue;
    if (sym[i].st_shndx == SHN_UNDEF) continue;

    GnuDebugSym s;
    s.name  = nm;
    s.value = sym[i].st_value; // VMA
    s.size  = sym[i].st_size;
    s.type  = type;
    out_syms.push_back(std::move(s));

    LOGV("  [%04zu] %s  type=%u  value=0x%lx size=0x%lx",
         i, nm, type, (unsigned long)sym[i].st_value, (unsigned long)sym[i].st_size);
  }
  return !out_syms.empty();
}

// Find address of a mangled name. Return 0 on failure.
// runtime_base is the in-memory base (offset 0 mapping) from /proc/self/maps.
uintptr_t resolve_addr_from_gnu_debugdata(const char* exe_path,
                                                 const char* mangled_name,
                                                 uintptr_t runtime_base) {
  std::vector<GnuDebugSym> syms;
  if (!load_gnu_debugdata(exe_path, syms)) return 0;
  for (auto& s : syms) {
    if (s.name == mangled_name) {
      // PIE: st_value is relative to load base
      return runtime_base + (uintptr_t)s.value;
    }
  }
  return 0;
}
