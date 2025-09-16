'use strict';

// ---- Tunables --------------------------------------------------------------
const FORCE_DEGREES   = 270;          // 0, 90, 180, 270
const PRIMARY_ID_HEX  = '0x1';       // adjust after you learn the real primary id
const FORCE_ALL_IDS   = false;       // set true briefly to verify it visually
const QUIET_LOG       = true;
// ---------------------------------------------------------------------------

// HWC/AIDL transform bit flags:
const TF_NONE   = 0;
const TF_FLIP_H = 1;
const TF_FLIP_V = 2;
const TF_ROT90  = 4;

function transformForDegrees(d) {
    switch (d) {
        case 0:   return TF_NONE;
        case 90:  return TF_ROT90;
        case 180: return TF_FLIP_H | TF_FLIP_V;              // 3
        case 270: return TF_ROT90 | TF_FLIP_H | TF_FLIP_V;   // 7
        default:  return TF_NONE;
    }
}

const FORCED_TF = transformForDegrees(FORCE_DEGREES);

function log(s){ if (!QUIET_LOG) console.log(s); }

// Normalize 64-bit ids Frida hands us
function toU64(x){
    if (typeof x === 'bigint') return x;
    if (typeof x === 'number') return BigInt(x >>> 0);
    return BigInt('0x' + x.toString(16));
}
const PRIMARY_ID = BigInt(PRIMARY_ID_HEX);

let seenIds = new Set();
function classify(displayIdU64){
    const id = toU64(displayIdU64);
    seenIds.add(id.toString());
    if (FORCE_ALL_IDS) return { id, isPrimary:false };
    return { id, isPrimary:(id === PRIMARY_ID) };
}

function findOne(mod, needle){
    const hits = mod.enumerateSymbols().filter(s => s.name.indexOf(needle) !== -1);
    return hits.length ? (hits.find(h => h.name === needle) || hits[0]).address : null;
}

function hookIsSupported(addr, tag){
    if (!addr) return false;
    console.log(`[+] hook isSupported ${tag} @ ${addr}`);
    const orig = new NativeFunction(addr, 'bool', ['pointer', 'int']);
    Interceptor.replace(addr, new NativeCallback(function (self, feature) {
        // 4 == PhysicalDisplayOrientation on this build
        if (feature === 4) { log(`[isSupported ${tag}] feature=4 -> SUPPORTED (forced)`); return 1; }
        return Number(orig(self, feature));
    }, 'bool', ['pointer', 'int']));
    return true;
}

function replaceGetPhys_outparam(addr, tag){
    if (!addr) return false;
    console.log(`[+] replace getPhysicalDisplayOrientation (out*) ${tag} @ ${addr}`);
    // (this*, uint64 displayId, Transform* out) -> status_t(int)
    Interceptor.replace(addr, new NativeCallback(function (self, displayId, outPtr) {
        const { id, isPrimary } = classify(displayId);
        const tf = isPrimary ? TF_NONE : FORCED_TF;
        outPtr.writeS32(tf);               // write **Transform bitflags**, NOT ui::Rotation
        log(`[getPhys ${tag}] id=0x${id.toString(16)} -> tf=${tf} ${isPrimary ? '(primary)' : '(non-primary)'}`);
        return 0; // STATUS_OK
    }, 'int', ['pointer', 'uint64', 'pointer']));
    return true;
}

function replaceGetPhys_returning(addr, tag){
    if (!addr) return false;
    console.log(`[+] replace HWComposer::getPhysicalDisplayOrientation (ret) ${tag} @ ${addr}`);
    // (this*, PhysicalDisplayId(u64)) -> Transform(int)
    Interceptor.replace(addr, new NativeCallback(function (self, displayId) {
        const { id, isPrimary } = classify(displayId);
        const tf = isPrimary ? TF_NONE : FORCED_TF;
        log(`[getPhys ${tag}] id=0x${id.toString(16)} -> tf=${tf} ${isPrimary ? '(primary)' : '(non-primary)'}`);
        return tf; // return **Transform bitflags**
    }, 'int', ['pointer', 'uint64']));
    return true;
}

const m = Process.getModuleByName('surfaceflinger');
console.log(`[*] Using module: ${m.name} ${m.base} size ${m.size}`);

// HIDL path
hookIsSupported(findOne(m,
                        '_ZNK7android4Hwc212HidlComposer11isSupportedENS0_8Composer15OptionalFeatureE'), 'HIDL');

replaceGetPhys_outparam(findOne(m,
                                '_ZN7android4Hwc212HidlComposer29getPhysicalDisplayOrientationEmPN4aidl7android8hardware8graphics6common9TransformE'), 'HIDL');

// AIDL path
hookIsSupported(findOne(m,
                        '_ZNK7android4Hwc212AidlComposer11isSupportedENS0_8Composer15OptionalFeatureE'), 'AIDL');

replaceGetPhys_outparam(findOne(m,
                                '_ZN7android4Hwc212AidlComposer29getPhysicalDisplayOrientationEmPN4aidl7android8hardware8graphics6common9TransformE'), 'AIDL');

// SF impl path (most reliable)
replaceGetPhys_returning(findOne(m,
                                 '_ZNK7android4impl10HWComposer29getPhysicalDisplayOrientationENS_17PhysicalDisplayIdE'), 'impl');

console.log('[+] Installed: correct Transform bitflags; primary=0°, non-primary=forced');
