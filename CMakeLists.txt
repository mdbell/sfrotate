cmake_minimum_required(VERSION 3.22)
project(sfrotate)


set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_ANDROID_ARCH_ABI arm64-v8a)
set(CMAKE_ANDROID_NDK $ENV{ANDROID_NDK})
set(CMAKE_ANDROID_STL c++_static)
set(CMAKE_ANDROID_API 29)

# (Optional) If C++ standard wasn’t set:
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(SFROTATE_DEBUG "Enable sfrotate verbose logging" OFF)

add_library(xzdec STATIC
  third_party/xz/xz_crc32.c
  third_party/xz/xz_crc64.c
  third_party/xz/xz_dec_lzma2.c
  third_party/xz/xz_dec_stream.c
)

target_include_directories(xzdec PUBLIC third_party/xz)

# Hook library
add_library(sf_rotate SHARED
    src/And64InlineHook.cpp
    src/sf_rotate.cpp
    src/gnu_debugdata_resolver.cpp
)

target_compile_options(sf_rotate PRIVATE -mbranch-protection=standard)
target_link_libraries(sf_rotate PRIVATE xzdec log dl)

target_compile_definitions(sf_rotate PRIVATE XZ_DEC_ANY_CHECK XZ_USE_CRC64)

# injector

add_executable(dlopen64 src/dlopen64.cpp)
target_link_libraries(dlopen64 PRIVATE dl)

if (SFROTATE_DEBUG)
  target_compile_definitions(sf_rotate PRIVATE SFROTATE_DEBUG=1)
endif()
