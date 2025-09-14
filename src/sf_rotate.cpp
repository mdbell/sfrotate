#include <sys/system_properties.h>
#include <stdlib.h>
#include <android/log.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#if defined(__aarch64__)
#  define SF_BRPROT __attribute__((target("branch-protection=standard")))
#else
#  define SF_BRPROT
#endif


#ifdef SFROTATE_DEBUG
  #define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  "sfrotate", __VA_ARGS__)
  #define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "sfrotate", __VA_ARGS__)
#else
  #define LOGI(...) ((void)0)
  #define LOGE(...) ((void)0)
#endif

#define FEATURE_ROTATION 4

#define TF_NONE 0
#define TF_FLIP_H 1
#define TF_FLIP_V 2
#define TF_ROT_90 4

#define ROT_270 (TF_ROT_90 | TF_FLIP_H | TF_FLIP_V)
#define ROT_180 (TF_FLIP_H | TF_FLIP_V)
#define ROT_90  TF_ROT_90
#define ROT_0   TF_NONE

//TODO: resolve these symbols ourselves instead of hardcoding offsets
//      till then we can get offsets via offsets.js script and run it via frida
static const uintptr_t OFF_HIDL_IS_SUPPORTED = 0x139e2c; // _ZNK7android4Hwc212HidlComposer11isSupportedENS0_8Composer15OptionalFeatureE

// when using this hook it causes surfaceflinger to crash - so it's presently unused.
static const uintptr_t OFF_AIDL_IS_SUPPORTED = 0x10f204; // _ZNK7android4Hwc212AidlComposer11isSupportedENS0_8Composer15OptionalFeatureE

static const uintptr_t OFF_IMPL = 0x159ed0; // _ZNK7android4impl10HWComposer29getPhysicalDisplayOrientationENS_17PhysicalDisplayIdE

static int rotation_degree = 270; // desired rotation for external display

extern "C" void A64HookFunction(void *symbol, void *replace, void **result); // And64InlineHook

// prototypes that match the targets
using IsSupportedFn = bool(*)(void* self, int feature);
using GetPhysOriFn  = int (*)(void* self, unsigned long long displayId, int* outTransform);

using GetPhysOriReturning  = int (*)(void* self, unsigned long long displayId);

static IsSupportedFn origHidlIsSupported = nullptr;
static IsSupportedFn origAidlIsSupported = nullptr;
static GetPhysOriReturning  origImpl = nullptr;


static bool prop_enabled() {
  char v[PROP_VALUE_MAX] = {0};
  if (__system_property_get("persist.sfrotate.enable", v) > 0) return strcmp(v, "0") != 0;
  return true; // default on
}
static int prop_degree() {
  char v[PROP_VALUE_MAX] = {0};
  if (__system_property_get("persist.panel.rds.orientation", v) > 0) {
    int d = atoi(v);
    if (d==0 || d==90 || d==180 || d==270) return d;
  }
  return rotation_degree;
}

static int get_transform_for_degree(int degree) {
  LOGI("get_transform_for_degree(%d)", degree);
  switch (degree) {
    case 0: return ROT_0;
    case 90: return ROT_90;
    case 180: return ROT_180;
    case 270: return ROT_270;
    default: return ROT_0; // should not happen
  }
}

static uintptr_t get_sf_base() {
  FILE* f = fopen("/proc/self/maps", "r");
  if (!f) return 0;

  char line[512];
  uintptr_t base_with_off0 = 0;
  uintptr_t base_min_any   = (uintptr_t)-1;

  while (fgets(line, sizeof line, f)) {
    if (strstr(line, "/system/bin/surfaceflinger") == nullptr) continue;

    // format: start-end perms offset dev inode pathname
    unsigned long start = 0, off = 0;
    if (sscanf(line, "%lx-%*lx %*4s %lx", &start, &off) != 2) continue;

    if (off == 0 && base_with_off0 == 0) base_with_off0 = (uintptr_t) start;
    if ((uintptr_t) start < base_min_any) base_min_any = (uintptr_t) start;
  }
  fclose(f);

  // Prefer the ELF base (offset 0). Fallback to lowest mapping for the file.
  if (base_with_off0) return base_with_off0;
  if (base_min_any != (uintptr_t)-1) return base_min_any;
  return 0;
}

SF_BRPROT static bool isSupportedHIDLHook(void* self, int feature) {
  if(!prop_enabled()){
    return origHidlIsSupported ? origHidlIsSupported(self, feature) : false;
  }
  if (feature == FEATURE_ROTATION){
    LOGI("isSupportedHIDL(4) -> true (forced)");
    return true;
  }
  LOGI("isSupportedHIDL(%d)", feature);
  return origHidlIsSupported ? origHidlIsSupported(self, feature) : false;
}

SF_BRPROT static bool isSupportedAIDLHook(void* self, int feature) {

  if(!prop_enabled()){
    return origAidlIsSupported ? origAidlIsSupported(self, feature) : false;
  }

  if (feature == FEATURE_ROTATION){
    LOGI("isSupportedAIDL(4) -> true");
    return true;
  }
  LOGI("isSupportedAIDL(%d)", feature);
  return origAidlIsSupported ? origAidlIsSupported(self, feature) : false;
}

SF_BRPROT static int getPhysicalDisplayOrientationHook(void* self, unsigned long long id) {

  if (!prop_enabled()) {
    return origImpl ? origImpl(self, id) : ROT_0;
  }

  const bool isPrimary = (id == 1ULL);
  if(isPrimary) {
    auto result = origImpl ? origImpl(self, id) : ROT_0;
    LOGI("getPhysicalDisplayOrientation(%" PRIu64 ") -> %d", id, result); 
    return result;
  }
  auto rotation = prop_degree();
  LOGI("getPhysicalDisplayOrientation(%" PRIu64 ") -> %d degrees (forced)", id, rotation);
  return get_transform_for_degree(rotation);
}

SF_BRPROT __attribute__((constructor))
static void init_sfrotate() {
  LOGI("sfrotate init");
  const uintptr_t base = get_sf_base();
  if (!base) { LOGE("could not find surfaceflinger base"); return; }

  void* hidlIsSupported = (void*)(base + OFF_HIDL_IS_SUPPORTED);
  void* aidlIsSupported = (void*)(base + OFF_AIDL_IS_SUPPORTED);
  void* impl = (void*)(base + OFF_IMPL);

LOGI("base=0x%lx  off_impl=0x%lx  abs=0x%lx",
     (unsigned long)base,
     (unsigned long)OFF_IMPL,
     (unsigned long)(base + OFF_IMPL));

  // install hooks (best-effort, some symbols may not exist on your build)
  auto hook = [&](void* sym, void* rep, void** orig, const char* name){
    // crude probe: avoid crashing if offset is bogus
    if (((uintptr_t)sym & 0xfff) == 0) { LOGE("skip %s: looks nullish", name); return; }
    A64HookFunction(sym, rep, orig);
    LOGI("hooked %s @ %p", name, sym);
  };

  hook(hidlIsSupported, (void*)isSupportedHIDLHook, (void**)&origHidlIsSupported, "_ZNK7android4Hwc212HidlComposer11isSupportedENS0_8Composer15OptionalFeatureE");
  //hooking the aidl func causes surfaceflinger to crash - so let it be for now
  //hook(aidlIsSupported, (void*)isSupportedAIDLHook, (void**)&origAidlIsSupported, "_ZNK7android4Hwc212AidlComposer11isSupportedENS0_8Composer15OptionalFeatureE");
  hook(impl, (void*)getPhysicalDisplayOrientationHook,    (void**)&origImpl, "_ZNK7android4impl10HWComposer29getPhysicalDisplayOrientationENS_17PhysicalDisplayIdE");

  LOGI("sfrotate ready");
}
