#!/bin/sh
# sandal installer — downloads the newest release binary from GitHub.
#
#   curl -fsSL https://raw.githubusercontent.com/maralla/sandal/main/install.sh | sh
#
# What this does:
#   1. picks the release build for this system (every supported system:
#      macos-arm64, linux-x86_64, linux-arm64)
#   2. resolves the newest release version (prereleases included —
#      releases/latest skips them, the release list does not)
#   3. downloads, unpacks, installs the binary
#
# Transport is GitHub TLS; the release carries no separate checksums, so
# this protects the download channel, not the artifact chain.
set -eu

repo=maralla/sandal
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# fetch URL [OUTPUT] — curl where available, busybox wget otherwise.
fetch() {
    if command -v curl >/dev/null 2>&1; then
        if [ $# -ge 2 ]; then curl -fsL -o "$2" "$1"; else curl -fsL "$1"; fi
    else
        if [ $# -ge 2 ]; then wget -q -O "$2" "$1"; else wget -qO- "$1"; fi
    fi
}

# ── 1. Pick the release build ────────────────────────────────────────
# Build names follow make dist's DIST_PLATFORM (darwin→macos, aarch64→arm64).
os=$(uname -s)
arch=$(uname -m)
case "$os/$arch" in
    Darwin/arm64)  build=macos-arm64 ;;
    Linux/x86_64)  build=linux-x86_64 ;;
    Linux/aarch64) build=linux-arm64 ;;
    *)
        echo "sandal: unsupported system: $os/$arch" >&2
        echo "        supported: macOS/arm64, Linux/x86_64, Linux/aarch64" >&2
        exit 1
        ;;
esac

# ── 2. Resolve the newest release ────────────────────────────────────
version=$(fetch "https://api.github.com/repos/$repo/releases?per_page=1" |
    sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
[ -n "$version" ] || { echo "sandal: cannot resolve newest release" >&2; exit 1; }

echo "==> sandal $version ($build)"

# ── 3. Download, unpack, install ─────────────────────────────────────
url="https://github.com/$repo/releases/download/$version/sandal-$version-$build.tar.gz"
fetch "$url" "$tmp/sandal.tar.gz" || {
    echo "sandal: $version has no prebuilt binary for $build yet" >&2
    echo "        build from source: make kernel && make dist (docs/kernel.md)" >&2
    exit 1
}
tar xzf "$tmp/sandal.tar.gz" -C "$tmp"

dest=/usr/local/bin
mkdir -p /usr/local/bin 2>/dev/null || true
[ -w /usr/local/bin ] || dest=$HOME/.local/bin
mkdir -p "$dest"
cp "$tmp/sandal" "$dest/sandal"
chmod 755 "$dest/sandal"

echo "==> installed $dest/sandal"
[ "$dest" = /usr/local/bin ] ||
    echo "    note: add $dest to PATH" >&2

# ── 4. What sandal needs to run ─────────────────────────────────────
# No runtime libraries to install (the binary links only libc/libgcc);
# on Linux it cannot run without KVM.
if [ "$os" = Linux ]; then
    if [ ! -e /dev/kvm ]; then
        echo "sandal: warning: /dev/kvm is missing — load the kvm module" >&2
    elif [ ! -w /dev/kvm ]; then
        echo "sandal: warning: no write access to /dev/kvm — join the kvm group" >&2
    fi
fi
