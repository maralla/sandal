#!/bin/sh
# sandal-export — export overlay filesystem diff as a .layer file.
# Usage: sandal-export [ignored]

# The output path is NEVER sent from the guest: the VMM names the layer
# itself (the default content-addressed name) and logs the path — the
# old dedicated virtio-console port whose whole stream was the path is
# gone, and with it the only guest→host path delivery there was. The
# operator renames from the log line.

# Find the overlay upper directory.
UPPER=""
if [ -d /mnt/root{MNT_DISK}/upper ]; then
    UPPER=/mnt/root{MNT_DISK}/upper
elif [ -d /mnt/root{MNT_TMP}/upper ]; then
    UPPER=/mnt/root{MNT_TMP}/upper
else
    echo "sandal-export: cannot find overlay upper directory" >&2
    exit 1
fi

# Check if there's anything to export.
if [ -z "$(ls -A "$UPPER" 2>/dev/null)" ]; then
    echo "sandal-export: overlay upper directory is empty, nothing to export" >&2
    exit 1
fi

# If {DATA_DEV} is mounted as ext2 (disk mode), the VMM can read it directly.
if mount | grep -q '{DATA_DEV}.*ext2'; then
    # Flush dirty pages so the VMM's in-memory image has all upper/ writes.
    sync
    /usr/sbin/sandal-export-done 2>/dev/null
    echo "Layer exported (disk mode)."
    exit 0
fi

# tmpfs mode: resize {DATA_DEV}, write tar, signal done.
/usr/sbin/sandal-export-resize 2>/dev/null

# Wait for kernel to process the config-change and resize {DATA_DEV}.
N=0
while [ "$N" -lt 10 ]; do
    VDB_SECTORS=$(cat /sys/block/{DATA_DEV_NAME}/size 2>/dev/null || echo 0)
    # 4096 sectors = 2MB, larger than the initial 1MB stub
    [ "$VDB_SECTORS" -gt 4096 ] 2>/dev/null && break
    N=$((N + 1))
done

# Write tar archive to {DATA_DEV} (uncompressed — VMM will zstd-compress it).
# tmp/ rides the overlay upper (it shares the data disk) — it is
# workspace scratch and must NEVER be exported; excluded here and
# filtered again VMM-side (handle_export_done) so no path can leak it.
tar cf - -C "$UPPER" --exclude=./tmp --exclude=tmp . > {DATA_DEV} 2>/dev/null

# Signal VMM that tar data is ready.
/usr/sbin/sandal-export-done 2>/dev/null
echo "Layer exported."
