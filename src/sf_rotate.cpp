#include "sf_rotate.hpp"

// default rotation (can be overridden by prop)
// 0, 90, 180, 270
// 270 = portrait
static int rotation_degree = 270;

static IsSupportedFn origHidlIsSupported = nullptr;
static IsSupportedFn origAidlIsSupported = nullptr;
static GetPhysOriFn  origGetPhysicalDisplayOrientation = nullptr;

static bool prop_enabled() {
  char v[PROP_VALUE_MAX] = {0};
  if (__system_property_get("persist.sfrotate.enable", v) > 0){
    return strcmp(v, "0") != 0;
  }
  return true; // default on
}

static int prop_degree() {
  char v[PROP_VALUE_MAX] = {0};
  if (__system_property_get("persist.panel.rds.orientation", v) > 0) {
    int d = atoi(v);
    if (d==0 || d==90 || d==180 || d==270){
      return d;
    }
  }
  return rotation_degree;
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

SF_BRPROT static bool isSupportedHIDLHook(void* self, OptionalFeature feature) {
  if(!prop_enabled()){
    return origHidlIsSupported ? origHidlIsSupported(self, feature) : false;
  }
  if (feature == OptionalFeature::PhysicalDisplayOrientation){
    LOGV("isSupportedHIDL(PhysicalDisplayOrientation) -> true (forced)");
    return true;
  }
  LOGV("isSupportedHIDL(%d)", feature);
  return origHidlIsSupported ? origHidlIsSupported(self, feature) : false;
}

SF_BRPROT static bool isSupportedAIDLHook(void* self, OptionalFeature feature) {

  if(!prop_enabled()){
    return origAidlIsSupported ? origAidlIsSupported(self, feature) : false;
  }

  if (feature == OptionalFeature::PhysicalDisplayOrientation){
    LOGV("isSupportedAIDL(PhysicalDisplayOrientation) -> true (forced)");
    return true;
  }
  LOGV("isSupportedAIDL(%d)", feature);
  return origAidlIsSupported ? origAidlIsSupported(self, feature) : false;
}

SF_BRPROT static Transform getPhysicalDisplayOrientationHook(void* self, uint64_t id) {

  if (!prop_enabled()) {
    return origGetPhysicalDisplayOrientation ? origGetPhysicalDisplayOrientation(self, id) : Transform::ROT_0;
  }

  const bool isPrimary = (id == 1ULL);
  if(isPrimary) {
    auto result = origGetPhysicalDisplayOrientation ? origGetPhysicalDisplayOrientation(self, id) : Transform::ROT_0;
    LOGV("getPhysicalDisplayOrientation(%" PRIu64 ") -> %d", id, result); 
    return result;
  }
  auto rotation = prop_degree();
  LOGV("getPhysicalDisplayOrientation(%" PRIu64 ") -> %d degrees (forced)", id, rotation);
  return get_transform_for_degree(rotation);
}

SF_BRPROT __attribute__((constructor))
static void init_sfrotate() {
  LOGI("sfrotate init");
  const uintptr_t base = get_sf_base();
  if (!base) {
    LOGE("could not find surfaceflinger base");
    return;
  }

  void* hidlIsSupported = (void*)resolve_addr_from_gnu_debugdata(SURFACEFLINGER_BIN,
                                                        SYM_HIDL_IS_SUPPORTED, base);
  //void* aidlIsSupported = (void*)(base + OFF_AIDL_IS_SUPPORTED);
  void* getPhysicalDisplayOrientation = (void*)resolve_addr_from_gnu_debugdata(SURFACEFLINGER_BIN,
                                                        SYM_IMPL, base);

  if(!hidlIsSupported) {
    LOGE("hidlIsSupported symbol not found via .gnu_debugdata");
    return;
  }

  if (!getPhysicalDisplayOrientation) {
    LOGE("getPhysicalDisplayOrientation symbol not found via .gnu_debugdata");
    return;
  }

  LOGV("surfaceflinger base @ 0x%lx", (unsigned long)base);
  LOGV("hidlIsSupported @ %p", hidlIsSupported);
  LOGV("getPhysicalDisplayOrientation @ %p", getPhysicalDisplayOrientation);

  // install hooks (best-effort, some symbols may not exist)
  auto hook = [&](void* sym, void* rep, void** orig, const char* name){
    // crude probe: avoid crashing if offset is bogus
    if (((uintptr_t)sym & 0xfff) == 0) {
      LOGE("skip %s: looks nullish", name);
      return;
    }
    A64HookFunction(sym, rep, orig);
    LOGI("hooked %s @ %p", name, sym);
  };

  hook(hidlIsSupported, (void*)isSupportedHIDLHook, (void**)&origHidlIsSupported, SYM_HIDL_IS_SUPPORTED);
  hook(getPhysicalDisplayOrientation, (void*)getPhysicalDisplayOrientationHook,    (void**)&origGetPhysicalDisplayOrientation, SYM_IMPL);

  LOGI("sfrotate ready");
}
