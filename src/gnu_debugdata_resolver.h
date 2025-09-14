#pragma once
#include <stdint.h>

uintptr_t resolve_addr_from_gnu_debugdata(const char* exe_path,
                                          const char* mangled_name,
                                          uintptr_t runtime_base);
uintptr_t get_sf_runtime_base();
