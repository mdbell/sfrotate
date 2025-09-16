cp /sdcard/sfrotate/* /data/local/tmp/ || true
cp /storage/self/primary/sfrotate/* /data/local/tmp/ || true
cp /storage/[A-F0-9-]*/sfrotate/* /data/local/tmp/ || true
chmod 755 /data/local/tmp/dlopen64
chmod 755 /data/local/tmp/libsf_rotate.so
/data/local/tmp/dlopen64 surfaceflinger /data/local/tmp/libsf_rotate.so