BINARY := target/release/sandal
ENTITLEMENTS := sandal.entitlements
BUILTIN_ROOTFS := src/rootfs.ext2.gz

.PHONY: build debug clippy rootfs-minimal

build: $(BUILTIN_ROOTFS)
	@cargo build --release
	@codesign --entitlements $(ENTITLEMENTS) -s - $(BINARY) --force

debug: $(BUILTIN_ROOTFS)
	@cargo build
	@codesign --entitlements $(ENTITLEMENTS) -s - target/debug/sandal --force

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

# Build a minimal rootfs (busybox + musl) and compress for embedding.
# Requires rootfs/ to exist (run scripts/setup-image.sh first).
rootfs-minimal: $(BUILTIN_ROOTFS)
$(BUILTIN_ROOTFS): rootfs/bin/busybox rootfs/lib/ld-musl-aarch64.so.1
	@echo "Building minimal built-in rootfs..."
	@TMPDIR=$$(mktemp -d) && \
	mkdir -p "$$TMPDIR"/{bin,sbin,usr/bin,usr/sbin,lib,dev,proc,sys,tmp,etc,root} && \
	cp rootfs/bin/busybox "$$TMPDIR/bin/" && \
	cp rootfs/lib/ld-musl-aarch64.so.1 "$$TMPDIR/lib/" && \
	ln -s ld-musl-aarch64.so.1 "$$TMPDIR/lib/libc.musl-aarch64.so.1" && \
	for cmd in sh ash mount umount ls cat echo date ip stty which insmod uname mkdir poweroff devmem; do \
		ln -s busybox "$$TMPDIR/bin/$$cmd"; \
	done && \
	ln -s ../bin/busybox "$$TMPDIR/sbin/poweroff" && \
	$(BINARY) pack "$$TMPDIR" -o "$$TMPDIR/minimal.ext2" && \
	gzip -9 -c "$$TMPDIR/minimal.ext2" > $(BUILTIN_ROOTFS) && \
	rm -rf "$$TMPDIR" && \
	echo "Built $(BUILTIN_ROOTFS) ($$(wc -c < $(BUILTIN_ROOTFS) | tr -d ' ') bytes)"
