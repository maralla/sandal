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
#   ROOTFS_BASELAYOUT — space-separated base-layout files to copy (relative to rootfs/)

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
    if [ -f sandal.entitlements ] && [ "$(uname -s)" = "Darwin" ]; then
        codesign --entitlements sandal.entitlements -s - "$PACK_BIN" --force
    fi
fi

_R=$(mktemp -d)
trap 'rm -rf "$_R"' EXIT

# Create directory structure
for d in $ROOTFS_DIRS; do
    mkdir -p "$_R/$d"
done

# Normalize a relative path by collapsing "." and ".." components. Pure
# bash so it works with the system bash 3.2 on macOS (no `readlink -f`).
normalize_rel() {
    local out="" part
    local IFS=/
    for part in $1; do
        case "$part" in
            ""|.) ;;
            ..) case "$out" in */*) out="${out%/*}" ;; *) out="" ;; esac ;;
            *) out="${out:+$out/}$part" ;;
        esac
    done
    printf '%s\n' "$out"
}

# Copy one path from the source tree into the staging tree, preserving
# symlinks: the link is recreated verbatim and its target is copied too
# (recursively). Entries may be listed by their loader-facing name
# (usr/lib/libz.so.1) while the real patch-versioned file is pulled in as the
# link target, so ROOTFS_FILES never pins an Alpine version.
copy_from_rootfs() {
    local rel="$1"
    local depth="${2:-0}"
    local src="$SRCDIR/$rel"

    if [ "$depth" -gt 8 ]; then
        echo "build-rootfs: symlink chain too deep at '$rel'" >&2
        exit 1
    fi

    mkdir -p "$_R/$(dirname "$rel")"

    if [ -L "$src" ]; then
        local target real
        target="$(readlink "$src")"
        ln -sfn "$target" "$_R/$rel"
        case "$target" in
            /*) real="${target#/}" ;;
            *)  real="$(normalize_rel "$(dirname "$rel")/$target")" ;;
        esac
        copy_from_rootfs "$real" $((depth + 1))
    elif [ -f "$src" ]; then
        cp "$src" "$_R/$rel"
    else
        echo "build-rootfs: no file matched ROOTFS_FILES entry: $rel" >&2
        exit 1
    fi
}

# Copy binaries and libraries. Entries may be shell globs (e.g.
# usr/lib/libapk.so.*) so patch-versioned sonames are resolved from the pinned
# Alpine tree instead of being hardcoded in the Makefile.
for f in $ROOTFS_FILES; do
    found=0
    for src in $SRCDIR/$f; do
        [ -e "$src" ] || [ -L "$src" ] || continue
        copy_from_rootfs "${src#"$SRCDIR"/}"
        found=1
    done
    if [ "$found" -eq 0 ]; then
        echo "build-rootfs: no file matched ROOTFS_FILES entry: $f" >&2
        exit 1
    fi
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

# Base-layout files (passwd/group/os-release/...). -p preserves source modes
# (e.g. /etc/shadow is 0640).
if [ -n "${ROOTFS_BASELAYOUT:-}" ]; then
    for f in $ROOTFS_BASELAYOUT; do
        cp -p "$SRCDIR/$f" "$_R/$f"
    done
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

# Pack into ext2 and compress (zstd: ~3x faster to decode than gzip at
# a similar ratio — the VMM decompresses this on every VM start).
"$PACK_BIN" pack "$_R" -o "$_R/minimal.ext2"
zstd -19 -c "$_R/minimal.ext2" > "$OUTPUT"

echo "Built $OUTPUT ($(wc -c < "$OUTPUT" | tr -d ' ') bytes)"
