BINARY := target/release/sandal
ENTITLEMENTS := sandal.entitlements
BUILTIN_ROOTFS := src/rootfs.ext2.zst

# Alpine minirootfs settings (source for the embedded rootfs). The guest
# architecture matches the host (KVM/HVF are same-arch), so the rootfs is
# built for `uname -m` (aarch64 on Apple Silicon, x86_64 on Linux PCs).
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),arm64)
ALPINE_ARCH := aarch64
else
ALPINE_ARCH := $(UNAME_M)
endif
ALPINE_VERSION := 3.24
ALPINE_MIRROR := https://dl-cdn.alpinelinux.org/alpine
ALPINE_ROOTFS_URL := $(ALPINE_MIRROR)/v$(ALPINE_VERSION)/releases/$(ALPINE_ARCH)/alpine-minirootfs-$(ALPINE_VERSION).0-$(ALPINE_ARCH).tar.gz

# Binaries and libraries to copy into the minimal rootfs (paths relative to rootfs/).
# To add a new component, just append to ROOTFS_FILES.
ROOTFS_FILES := \
	bin/busybox \
	lib/ld-musl-$(ALPINE_ARCH).so.1 \
	sbin/apk \
	usr/bin/ldd \
	usr/bin/ssl_client \
	usr/lib/libapk.so.3.0.0 \
	usr/lib/libcrypto.so.3 \
	usr/lib/libssl.so.3 \
	usr/lib/libz.so.1.3.2

# Symlinks: target:link-path (inside the rootfs tmp dir)
ROOTFS_SYMLINKS := \
	ld-musl-$(ALPINE_ARCH).so.1:lib/libc.musl-$(ALPINE_ARCH).so.1 \
	libz.so.1.3.2:usr/lib/libz.so.1 \
	../usr/lib/os-release:etc/os-release

# Directories to create (beyond what the file copies imply)
ROOTFS_DIRS := \
	bin sbin usr/bin usr/sbin lib/apk/db usr/lib \
	dev proc sys tmp var/cache/apk etc/apk/keys root

# Empty files the apk database needs to exist
ROOTFS_TOUCH := \
	lib/apk/db/lock lib/apk/db/triggers

# Apk config and database to copy verbatim from rootfs/ (keys/ dir is copied recursively)
ROOTFS_APK_CONF := etc/apk/repositories etc/apk/arch etc/apk/world lib/apk/db/installed
ROOTFS_APK_KEYS := etc/apk/keys

# Base-layout files from the alpine-baselayout / alpine-baselayout-data /
# alpine-release packages. The apk database copied above lists those packages
# as installed, and their files are what make the guest look like a normal
# Linux userspace: /etc/passwd + /etc/group give `id`/`login` a user database,
# /etc/os-release + /etc/alpine-release tell installers what distro this is.
# Without them `id`/`id -un` name lookups fail with "unknown ID 0" and scripts
# that sniff the distro see nothing. The files are a few KiB of text
# (~1 KiB compressed).
ROOTFS_BASELAYOUT := \
	etc/passwd \
	etc/group \
	etc/shadow \
	etc/shells \
	etc/hostname \
	etc/hosts \
	etc/issue \
	etc/nsswitch.conf \
	etc/alpine-release \
	usr/lib/os-release

.PHONY: build debug test lint rootfs-minimal dist

UNAME_S := $(shell uname -s)

build: $(BUILTIN_ROOTFS)
	@cargo build --release
ifeq ($(UNAME_S),Darwin)
	@codesign --entitlements $(ENTITLEMENTS) -s - $(BINARY) --force
endif

debug: $(BUILTIN_ROOTFS)
	@cargo build
ifeq ($(UNAME_S),Darwin)
	@codesign --entitlements $(ENTITLEMENTS) -s - target/debug/sandal --force
endif

# Wall-clock cap for the hang gate; from Homebrew coreutils on macOS.
TIMEOUT := $(shell command -v timeout 2>/dev/null || command -v gtimeout 2>/dev/null)

# Python runner for the integration tests: `uv run python` when uv is
# available (as on the macOS dev machines), plain python3 otherwise.
# The tests only use the stdlib, so either works.
ifneq ($(shell command -v uv 2>/dev/null),)
PYTHON := uv run python
else
PYTHON := python3
endif

.PHONY: kernel-x86

# Build the x86_64 guest kernel (Linux hosts only; on macOS the committed
# arm64 `vmlinux-sandal` is used). Produces a stripped ELF vmlinux with the
# PVH entry note, booted directly by the VMM (no firmware).
kernel-x86:
	@bash scripts/build-kernel-x86.sh

ifeq ($(UNAME_S)-$(UNAME_M),Linux-x86_64)
KERNEL_DEP := kernel-x86
else
KERNEL_DEP :=
endif

# Test suites:
#   - cargo unit tests (incl. the ustar layer round-trips and the KVM backend
#     UAPI layout tests)
#   - device/feature test: virtio IDs, block queue geometry, rng (tests/test_devices.py)
#   - multi-segment block I/O integrity (tests/test_blk.py)
#   - export/load integration test (tests/test_export.py)
#   - shared-directory (virtiofs) test (tests/test_share.py)
#   - interactive console input: echo latency, backspace erase, line edit
#     (tests/test_console_input.py)
#   - guest package management over TLS (tests/test_packages.py)
#   - uv + CPython install and the interactive python REPL
#     (tests/test_python_repl.py)
#   - tmux in the guest (devpts / PTY support) (tests/test_tmux.py)
#   - user-space network/curl test (tests/test_curl_hang.sh)
#   - interactive console hang gate (tests/test_interactive_gate.sh)
#
# The guest is a Linux VM (arch matches the host): the integration/gate
# guest, so they require macOS on Apple Silicon (HVF) or Linux on arm64 with
# /dev/kvm. On other hosts (e.g. x86_64) they print SKIP and pass — the unit
# tests above still run everywhere.
test: build $(KERNEL_DEP)
	cargo test --release
	$(PYTHON) tests/test_devices.py
	$(PYTHON) tests/test_blk.py
	$(PYTHON) tests/test_export.py
	$(PYTHON) tests/test_share.py
	$(PYTHON) tests/test_console_input.py
	$(PYTHON) tests/test_packages.py
	$(PYTHON) tests/test_python_repl.py
	$(PYTHON) tests/test_tmux.py
	tests/test_curl_hang.sh 1 128
	$(TIMEOUT) $(if $(TIMEOUT),60,) env REPRO_FAIL_FAST=1 REPRO_FAST_STRESS=1 tests/test_interactive_gate.sh --fail-fast --exit-cycle

lint:
	cargo fmt --all
	cargo clippy --all-targets --all-features -- -D warnings

# Download and extract the Alpine minirootfs. The stamp filename embeds the
# version, so bumping ALPINE_VERSION re-extracts instead of silently reusing
# an older tree (the previous busybox sentinel never noticed version bumps).
ROOTFS_STAMP := rootfs/.alpine-$(ALPINE_VERSION)
$(ROOTFS_STAMP):
	@echo "Downloading Alpine $(ALPINE_VERSION) minirootfs..."
	@rm -rf rootfs
	@mkdir -p rootfs
	@curl -fSL --progress-bar "$(ALPINE_ROOTFS_URL)" | tar xz -C rootfs
	@touch $@
	@echo "Alpine rootfs extracted to rootfs/ ($(ALPINE_VERSION))"
$(addprefix rootfs/,$(ROOTFS_FILES)): $(ROOTFS_STAMP)

# Build a minimal rootfs (busybox + musl + TLS + apk) and compress for embedding.
rootfs-minimal: $(BUILTIN_ROOTFS)
$(BUILTIN_ROOTFS): $(ROOTFS_STAMP) $(addprefix rootfs/,$(ROOTFS_FILES))
	@echo "Building minimal built-in rootfs..."
	@ROOTFS_FILES="$(ROOTFS_FILES)" \
	 ROOTFS_SYMLINKS="$(ROOTFS_SYMLINKS)" \
	 ROOTFS_DIRS="$(ROOTFS_DIRS)" \
	 ROOTFS_TOUCH="$(ROOTFS_TOUCH)" \
	 ROOTFS_APK_CONF="$(ROOTFS_APK_CONF)" \
	 ROOTFS_APK_KEYS="$(ROOTFS_APK_KEYS)" \
	 ROOTFS_BASELAYOUT="$(ROOTFS_BASELAYOUT)" \
	 scripts/build-rootfs.sh $(BUILTIN_ROOTFS) $(BINARY)

# ── Single-file release build ─────────────────────────────────────
# `make dist` embeds the guest kernel (zstd-compressed) into the binary
# so the release artifact is one self-contained file: nothing to ship
# alongside it, and it boots from any directory. Dev builds never set
# SANDAL_EMBED_KERNEL — there the kernel stays a drop-in external file
# next to the binary (see src/vm/x86_64.rs and src/vm/aarch64.rs).

ifeq ($(UNAME_M),arm64)
KERNEL_EMBED_SRC := vmlinux-sandal
KERNEL_EMBED_DST := src/kernel-aarch64.zst
else
KERNEL_EMBED_SRC := vmlinux-sandal-x86
KERNEL_EMBED_DST := src/kernel-x86_64.zst
endif

DIST_PLATFORM := $(shell printf '%s-%s' "$(UNAME_S)" "$(UNAME_M)" | tr '[:upper:]' '[:lower:]' | sed 's/^darwin/macos/;s/aarch64/arm64/')
SANDAL_VERSION := $(shell sed -n 's/^version[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' Cargo.toml | head -1)

dist:
	@test -f $(KERNEL_EMBED_SRC) || { echo "missing $(KERNEL_EMBED_SRC) (x86_64: make kernel-x86; arm64: scripts/build-kernel.sh)" >&2; exit 1; }
	@zstd -19 -T0 -f $(KERNEL_EMBED_SRC) -o $(KERNEL_EMBED_DST)
	SANDAL_EMBED_KERNEL=1 cargo build --release
ifeq ($(UNAME_S),Darwin)
	@codesign --entitlements $(ENTITLEMENTS) -s - $(BINARY) --force
endif
	@rm -rf dist/$(DIST_PLATFORM)
	@mkdir -p dist
	@rm -f dist/sandal-v*.tar.gz
	@_d=$$(mktemp -d); \
		cp $(BINARY) $$_d/sandal; \
		cp LICENSE README.md $$_d/; \
		tar -C $$_d -czf dist/sandal-v$(SANDAL_VERSION)-$(DIST_PLATFORM).tar.gz sandal LICENSE README.md; \
		rm -rf $$_d
	@cd dist && sha256sum sandal-v$(SANDAL_VERSION)-$(DIST_PLATFORM).tar.gz > SHA256SUMS
	@echo "dist/sandal-v$(SANDAL_VERSION)-$(DIST_PLATFORM).tar.gz: single-file release (kernel embedded)"
