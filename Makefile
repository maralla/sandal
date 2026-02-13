BINARY := target/release/sandal
ENTITLEMENTS := sandal.entitlements
BUILTIN_ROOTFS := src/rootfs.ext2.gz

# Alpine minirootfs settings (source for the embedded rootfs)
ALPINE_VERSION := 3.21
ALPINE_ARCH := aarch64
ALPINE_MIRROR := https://dl-cdn.alpinelinux.org/alpine
ALPINE_ROOTFS_URL := $(ALPINE_MIRROR)/v$(ALPINE_VERSION)/releases/$(ALPINE_ARCH)/alpine-minirootfs-$(ALPINE_VERSION).0-$(ALPINE_ARCH).tar.gz

# Binaries and libraries to copy into the minimal rootfs (paths relative to rootfs/).
# To add a new component, just append to ROOTFS_FILES.
ROOTFS_FILES := \
	bin/busybox \
	lib/ld-musl-aarch64.so.1 \
	sbin/apk \
	usr/bin/ssl_client \
	usr/lib/libapk.so.2.14.0 \
	usr/lib/libcrypto.so.3 \
	usr/lib/libssl.so.3 \
	usr/lib/libz.so.1.3.1

# Symlinks: target:link-path (inside the rootfs tmp dir)
ROOTFS_SYMLINKS := \
	ld-musl-aarch64.so.1:lib/libc.musl-aarch64.so.1 \
	libz.so.1.3.1:usr/lib/libz.so.1

# Directories to create (beyond what the file copies imply)
ROOTFS_DIRS := \
	bin sbin usr/bin usr/sbin lib/apk/db usr/lib \
	dev proc sys tmp var/cache/apk etc/apk/keys root

# Empty files the apk database needs to exist
ROOTFS_TOUCH := \
	lib/apk/db/installed lib/apk/db/lock lib/apk/db/triggers etc/apk/world

# Apk config to copy verbatim from rootfs/ (keys/ dir is copied recursively)
ROOTFS_APK_CONF := etc/apk/repositories etc/apk/arch
ROOTFS_APK_KEYS := etc/apk/keys

.PHONY: build debug clippy rootfs-minimal

build: $(BUILTIN_ROOTFS)
	@cargo build --release
	@codesign --entitlements $(ENTITLEMENTS) -s - $(BINARY) --force

debug: $(BUILTIN_ROOTFS)
	@cargo build
	@codesign --entitlements $(ENTITLEMENTS) -s - target/debug/sandal --force

lint:
	cargo fmt --all
	cargo clippy --all-targets --all-features -- -D warnings

# Download and extract Alpine minirootfs if not present.
# Uses bin/busybox as sentinel — all other files come from the same tarball.
rootfs/bin/busybox:
	@echo "Downloading Alpine $(ALPINE_VERSION) minirootfs..."
	@mkdir -p rootfs
	@curl -fSL --progress-bar "$(ALPINE_ROOTFS_URL)" | tar xz -C rootfs
	@echo "Alpine rootfs extracted to rootfs/"
$(filter-out rootfs/bin/busybox,$(addprefix rootfs/,$(ROOTFS_FILES))): rootfs/bin/busybox

# Build a minimal rootfs (busybox + musl + TLS + apk) and compress for embedding.
rootfs-minimal: $(BUILTIN_ROOTFS)
$(BUILTIN_ROOTFS): $(addprefix rootfs/,$(ROOTFS_FILES))
	@echo "Building minimal built-in rootfs..."
	@ROOTFS_FILES="$(ROOTFS_FILES)" \
	 ROOTFS_SYMLINKS="$(ROOTFS_SYMLINKS)" \
	 ROOTFS_DIRS="$(ROOTFS_DIRS)" \
	 ROOTFS_TOUCH="$(ROOTFS_TOUCH)" \
	 ROOTFS_APK_CONF="$(ROOTFS_APK_CONF)" \
	 ROOTFS_APK_KEYS="$(ROOTFS_APK_KEYS)" \
	 scripts/build-rootfs.sh $(BUILTIN_ROOTFS) $(BINARY)
