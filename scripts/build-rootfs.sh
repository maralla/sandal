#!/usr/bin/env bash
#
# build-rootfs.sh — Assemble a minimal embedded rootfs from an Alpine minirootfs.
#
# Usage: build-rootfs.sh <output.ext2.zst> <pack-binary>
#
# Runs on Linux/macOS only (the symlinks need a real OS).
#   ROOTFS_BASELAYOUT — space-separated base-layout files to copy (relative to rootfs/)

set -euo pipefail

OUTPUT="$1"
PACK_BIN="$2"
SRCDIR="rootfs"

# ── The rootfs config (moved here from the Makefile: this script is the
# ── single source of truth, callable from make AND directly from CI).
UNAME_M="$(uname -m)"
case "$UNAME_M" in arm64) ALPINE_ARCH=aarch64 ;; *) ALPINE_ARCH="$UNAME_M" ;; esac
ALPINE_VERSION="3.24.2"
ALPINE_RELEASE="${ALPINE_VERSION%.*}"
ALPINE_MIRROR="https://dl-cdn.alpinelinux.org/alpine"
ALPINE_URL="$ALPINE_MIRROR/v$ALPINE_RELEASE/releases/$ALPINE_ARCH/alpine-minirootfs-$ALPINE_VERSION-$ALPINE_ARCH.tar.gz"

# Binaries and libraries to copy into the minimal rootfs. Entries may be
# shell globs, and symlinks are dereferenced below: name the loader-facing
# soname (usr/lib/libz.so.1) and glob the patch-versioned real file
# (usr/lib/libapk.so.*) instead of pinning per-Alpine-release versions.
ROOTFS_FILES="bin/busybox lib/ld-musl-$ALPINE_ARCH.so.1 sbin/apk usr/bin/ldd \
	usr/bin/ssl_client usr/lib/libapk.so.* usr/lib/libcrypto.so.* \
	usr/lib/libssl.so.* usr/lib/libz.so.1"
ROOTFS_SYMLINKS="ld-musl-$ALPINE_ARCH.so.1:lib/libc.musl-$ALPINE_ARCH.so.1 \
	../usr/lib/os-release:etc/os-release"
ROOTFS_DIRS="bin sbin usr/bin usr/sbin lib/apk/db usr/lib dev proc sys tmp \
	var/cache/apk etc/apk/keys root"
ROOTFS_TOUCH="lib/apk/db/lock lib/apk/db/triggers"
ROOTFS_APK_CONF="etc/apk/repositories etc/apk/arch etc/apk/world lib/apk/db/installed"
ROOTFS_APK_KEYS="etc/apk/keys"
# The alpine-baselayout files: /etc/passwd + /etc/group give `id` a user
# database, /etc/os-release tells distro-sniffing scripts something. A few
# KiB of text (~1 KiB compressed).
ROOTFS_BASELAYOUT="etc/passwd etc/group etc/shadow etc/shells etc/hostname \
	etc/hosts etc/issue etc/nsswitch.conf etc/alpine-release usr/lib/os-release"

# The Alpine tree downloads on first use (a fresh checkout / CI). The
# extraction is strict: any failure is fatal.
if [ ! -f "$SRCDIR/etc/alpine-release" ]; then
    echo "build-rootfs: downloading Alpine $ALPINE_VERSION ($ALPINE_ARCH)..."
    rm -rf "$SRCDIR"
    mkdir -p "$SRCDIR"
    curl -fSL --progress-bar "$ALPINE_URL" | tar xz -C "$SRCDIR"
fi

# Bootstrap: if the pack binary doesn't exist yet (fresh checkout / CI),
# build it so we can use `sandal pack`. The touch is load-bearing: the
# crate embeds this very file (include_bytes!), so it must EXIST — empty
# — before the first compile; the real blob replaces it right after, and
# the caller's cargo step rebuilds with the real content.
if [ ! -x "$PACK_BIN" ]; then
    echo "Bootstrapping: building pack binary..."
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

# Base-layout files (passwd/group/os-release/...). -p preserves source
# modes (e.g. /etc/shadow is 0640). Copied BEFORE the symlinks so their
# staging targets exist.
if [ -n "${ROOTFS_BASELAYOUT:-}" ]; then
    for f in $ROOTFS_BASELAYOUT; do
        cp -p "$SRCDIR/$f" "$_R/$f"
    done
fi

# Create symlinks (real links; the ext2 writer preserves them and the
# layer format round-trips them). The baselayout copy above staged their
# targets first.
for pair in $ROOTFS_SYMLINKS; do
    target="${pair%%:*}"
    link="${pair#*:}"
    mkdir -p "$_R/$(dirname "$link")"
    ln -s "$target" "$_R/$link"
done

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
# a similar ratio — the VMM decompresses this on every VM start). The
# compression rides the sandal binary's own zstd.
"$PACK_BIN" pack "$_R" -o "$_R/minimal.ext2" --zstd
mv "$_R/minimal.ext2" "$OUTPUT"

echo "Built $OUTPUT ($(wc -c < "$OUTPUT" | tr -d ' ') bytes)"
