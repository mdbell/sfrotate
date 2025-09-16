const m = Process.getModuleByName('surfaceflinger');
function off(nameSubstr, tag='') {
  const s = m.enumerateSymbols().find(x => x.name.indexOf(nameSubstr) !== -1);
  if (!s) throw new Error('no match for ' + nameSubstr);
  const rel = ptr(s.address).sub(m.base);
  console.log(nameSubstr, `${tag ? `[${tag}] `: ''}addr=`, s.address, 'base=', m.base, 'off=0x' + rel.toString(16));
}
off('_ZNK7android4Hwc212HidlComposer11isSupportedENS0_8Composer15OptionalFeatureE', 'HIDL-isSupported');
off('_ZNK7android4Hwc212AidlComposer11isSupportedENS0_8Composer15OptionalFeatureE', 'AIDL-isSupported');
off('_ZNK7android4impl10HWComposer29getPhysicalDisplayOrientationENS_17PhysicalDisplayIdE', 'impl');