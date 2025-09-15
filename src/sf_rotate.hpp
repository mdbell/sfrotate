#pragma once

#include <sys/system_properties.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "log.h"
#include "gnu_debugdata_resolver.h"
#include "And64InlineHook.hpp"

#if defined(__aarch64__)
    #define SF_BRPROT __attribute__((target("branch-protection=standard")))
#else
    #define SF_BRPROT
#endif

#define SURFACEFLINGER_BIN "/system/bin/surfaceflinger"

// Hwc2::Composer::OptionalFeature::PhysicalDisplayOrientation
enum OptionalFeature {
  PhysicalDisplayOrientation = 4,
};

// transformations - xored to get combined transforms

#define TF_NONE 0
#define TF_FLIP_H 1
#define TF_FLIP_V 2
#define TF_ROT_90 4

enum Transform {
  ROT_0 = TF_NONE,
  ROT_90 = TF_ROT_90,
  ROT_180 = TF_FLIP_H | TF_FLIP_V,
  ROT_270 = TF_ROT_90 | TF_FLIP_H | TF_FLIP_V
};

// symbols to hook - may vary between Android versions

static const char* SYM_IMPL =
  "_ZNK7android4impl10HWComposer29getPhysicalDisplayOrientationENS_17PhysicalDisplayIdE";

static const char* SYM_HIDL_IS_SUPPORTED =
  "_ZNK7android4Hwc212HidlComposer11isSupportedENS0_8Composer15OptionalFeatureE";

// (legacy, unused) - offsets
static const uintptr_t OFF_AIDL_IS_SUPPORTED = 0x10f204; // _ZNK7android4Hwc212AidlComposer11isSupportedENS0_8Composer15OptionalFeatureE

// hook function prototypes

using IsSupportedFn = bool(*)(void* self, OptionalFeature feature);
using GetPhysOriFn  = Transform (*)(void* self, unsigned long long displayId);

// utilities

static inline Transform get_transform_for_degree(int degree) {
  LOGV("get_transform_for_degree(%d)", degree);
  switch (degree) {
    case 0: return Transform::ROT_0;
    case 90: return Transform::ROT_90;
    case 180: return Transform::ROT_180;
    case 270: return Transform::ROT_270;
    default: return Transform::ROT_0; // should not happen
  }
}