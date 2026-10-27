#!/usr/bin/env bash
#
# fetch-kernel.sh — Fetch the prebuilt sandal guest kernel for one
# architecture from the sandal-assets release.
#
# The kernels are built by the sandal-assets CI (kernel-* tags there) from
# the kernel configs this project used to build locally
# (scripts/build-kernel.sh moved to that repository). This downloads
# `vmlinux-sandal-<arch>` into the project root — the same place a local
# build put it, and where the VMM resolves it (see resolve_data_path).
#
# Usage:
#   scripts/fetch-kernel.sh [ARCH]    # ARCH: x86_64 | aarch64 (default: host arch)
#
# The download is verified against SHA256SUMS from the same release. An
# existing vmlinux-sandal-<arch> is left alone (delete it to re-fetch);
# the partial downloads this script leaves behind on failure are covered
# by the vmlinux-sandal-* gitignore pattern.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

info()  { printf "\033[1;34m==>\033[0m %s\n" "$*"; }
ok()    { printf "\033[1;32m==>\033[0m %s\n" "$*"; }
error() { printf "\033[1;31mERR\033[0m %s\n" "$*" >&2; }

usage() {
    cat <<'EOF'
Usage:
  scripts/fetch-kernel.sh [ARCH]   # ARCH: x86_64 | aarch64 (default: host arch)

Fetches vmlinux-sandal-<arch> from the sandal-assets release into the
project root. Override the release with SANDAL_ASSETS_URL (default:
https://github.com/maralla/sandal-assets/releases).
EOF
}

RELEASES="${SANDAL_ASSETS_URL:-https://github.com/maralla/sandal-assets/releases}"

map_arch() {
    case "$1" in
        x86_64|x86|amd64)   printf 'x86_64' ;;
        aarch64|arm64)      printf 'aarch64' ;;
        *)                  return 1 ;;
    esac
}

# Verify a file against a SHA256SUMS-format line, using sha256sum (Linux)
# or shasum (macOS). The line file is given relative to the project root.
check_sha256() {   # check_sha256 REL_SUMS_FILE
    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$PROJECT_DIR" && sha256sum -c "$1")
    elif command -v shasum >/dev/null 2>&1; then
        (cd "$PROJECT_DIR" && shasum -a 256 -c "$1")
    else
        error "no SHA-256 tool found (sha256sum or shasum)"
        return 1
    fi
}

case "${1:-}" in
    -h|--help) usage; exit 0 ;;
esac
ARCH="$(map_arch "${1:-$(uname -m)}")" || {
    error "unsupported architecture: ${1:-$(uname -m)}"
    usage
    exit 1
}

OUT="$PROJECT_DIR/vmlinux-sandal-$ARCH"

info "Fetching SHA256SUMS from $RELEASES/latest/..."
SUMS="$(curl -fsSL "$RELEASES/latest/download/SHA256SUMS")" || {
    error "could not fetch SHA256SUMS from $RELEASES/latest/"
    echo "A release exists only after a kernel-* tag was pushed in sandal-assets." >&2
    exit 1
}
EXPECTED="$(awk -v f="vmlinux-sandal-$ARCH" '$2 == f { print $1 }' <<<"$SUMS")"
[ -n "$EXPECTED" ] || {
    error "SHA256SUMS has no entry for vmlinux-sandal-$ARCH"
    exit 1
}

# A local kernel is kept only if it matches the latest release's hash: a
# new sandal-assets tag moves the release, and a cached/stale file (CI
# caches the blob by this script's hash) must follow it, not linger.
if [ -e "$OUT" ]; then
    LOCAL="$(sha256sum "$OUT" | cut -d' ' -f1)"
    if [ "$LOCAL" = "$EXPECTED" ]; then
        ok "$(basename "$OUT") already present and current ($(du -h "$OUT" | cut -f1))"
        exit 0
    fi
    info "$(basename "$OUT") differs from the latest release; re-fetching"
fi

info "Fetching vmlinux-sandal-$ARCH..."
PART="$OUT.part"
curl -fSL --progress-bar "$RELEASES/latest/download/vmlinux-sandal-$ARCH" -o "$PART" || {
    rm -f "$PART"
    error "download failed"
    exit 1
}

info "Verifying SHA-256..."
# The sum line names the .part file (relative to the project root), so the
# check runs against what was actually downloaded.
rel_part="vmlinux-sandal-$ARCH.part"
rel_sums="vmlinux-sandal-$ARCH.part.SHA256SUMS"
printf '%s  %s\n' "$EXPECTED" "$rel_part" > "$PROJECT_DIR/$rel_sums"
if check_sha256 "$rel_sums"; then
    rm -f "$PROJECT_DIR/$rel_sums"
    mv "$PART" "$OUT"
    ok "Kernel saved to $(basename "$OUT") ($(du -h "$OUT" | cut -f1 | xargs))"
else
    rm -f "$PART" "$PROJECT_DIR/$rel_sums"
    error "checksum verification failed for vmlinux-sandal-$ARCH"
    exit 1
fi
