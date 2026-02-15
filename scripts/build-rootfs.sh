#!/usr/bin/env bash
#
# build-rootfs.sh — Assemble a minimal embedded rootfs from an Alpine rootfs dir.
#
# Usage: build-rootfs.sh <output.ext2.gz> <pack-binary>
#
# Environment variables (set by the Makefile):
#   ROOTFS_FILES     — space-separated list of files to copy (relative to rootfs/)
#   ROOTFS_SYMLINKS  — space-separated target:link-path pairs
#   ROOTFS_DIRS      — space-separated directories to create
#   ROOTFS_TOUCH     — space-separated empty files to create
#   ROOTFS_APK_CONF  — space-separated apk config files to copy (relative to rootfs/)
#   ROOTFS_APK_KEYS  — path to apk signing keys directory (relative to rootfs/)

set -euo pipefail

OUTPUT="$1"
PACK_BIN="$2"
SRCDIR="rootfs"

# Bootstrap: if the pack binary doesn't exist yet (fresh checkout / CI),
# build it with a stub rootfs so we can use `sandal pack`.
if [ ! -x "$PACK_BIN" ]; then
    echo "Bootstrapping: building binary with stub rootfs..."
    touch "$OUTPUT"
    cargo build --release
    if [ -f sandal.entitlements ]; then
        codesign --entitlements sandal.entitlements -s - "$PACK_BIN" --force
    fi
fi

_R=$(mktemp -d)
trap 'rm -rf "$_R"' EXIT

# Create directory structure
for d in $ROOTFS_DIRS; do
    mkdir -p "$_R/$d"
done

# Copy binaries and libraries
for f in $ROOTFS_FILES; do
    cp "$SRCDIR/$f" "$_R/$f"
done

# Create symlinks
for pair in $ROOTFS_SYMLINKS; do
    target="${pair%%:*}"
    link="${pair#*:}"
    ln -s "$target" "$_R/$link"
done

# Create empty placeholder files (apk database)
for f in $ROOTFS_TOUCH; do
    touch "$_R/$f"
done

# Copy apk config files and signing keys
for f in $ROOTFS_APK_CONF; do
    cp "$SRCDIR/$f" "$_R/$f"
done
if [ -n "${ROOTFS_APK_KEYS:-}" ] && [ -d "$SRCDIR/$ROOTFS_APK_KEYS" ]; then
    cp "$SRCDIR/$ROOTFS_APK_KEYS"/* "$_R/$ROOTFS_APK_KEYS/"
fi

# Replicate all busybox symlinks from the source rootfs
for dir in bin sbin usr/bin usr/sbin; do
    [ -d "$SRCDIR/$dir" ] || continue
    for f in "$SRCDIR/$dir"/*; do
        [ -L "$f" ] || continue
        case $(readlink "$f") in *busybox*) ;; *) continue ;; esac
        ln -sf /bin/busybox "$_R/$dir/$(basename "$f")"
    done
done

# Pack into ext2 and compress
"$PACK_BIN" pack "$_R" -o "$_R/minimal.ext2"
gzip -9 -c "$_R/minimal.ext2" > "$OUTPUT"

echo "Built $OUTPUT ($(wc -c < "$OUTPUT" | tr -d ' ') bytes)"
