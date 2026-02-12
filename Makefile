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
$(BUILTIN_ROOTFS): rootfs/bin/busybox rootfs/lib/ld-musl-aarch64.so.1 \
		rootfs/usr/bin/ssl_client rootfs/usr/lib/libssl.so.3 rootfs/usr/lib/libcrypto.so.3
	@echo "Building minimal built-in rootfs..."
	@_ROOTFS_TMP=$$(mktemp -d) && \
	mkdir -p "$$_ROOTFS_TMP"/{bin,sbin,usr/bin,usr/sbin,lib,usr/lib,dev,proc,sys,tmp,etc,root} && \
	cp rootfs/bin/busybox "$$_ROOTFS_TMP/bin/" && \
	cp rootfs/lib/ld-musl-aarch64.so.1 "$$_ROOTFS_TMP/lib/" && \
	ln -s ld-musl-aarch64.so.1 "$$_ROOTFS_TMP/lib/libc.musl-aarch64.so.1" && \
	cp rootfs/usr/bin/ssl_client "$$_ROOTFS_TMP/usr/bin/" && \
	cp rootfs/usr/lib/libssl.so.3 "$$_ROOTFS_TMP/usr/lib/" && \
	cp rootfs/usr/lib/libcrypto.so.3 "$$_ROOTFS_TMP/usr/lib/" && \
	for dir in bin sbin usr/bin usr/sbin; do \
		[ -d "rootfs/$$dir" ] || continue; \
		for f in rootfs/$$dir/*; do \
			[ -L "$$f" ] || continue; \
			case $$(readlink "$$f") in *busybox*) ;; *) continue ;; esac; \
			cmd=$$(basename "$$f"); \
			ln -sf /bin/busybox "$$_ROOTFS_TMP/$$dir/$$cmd"; \
		done; \
	done && \
	$(BINARY) pack "$$_ROOTFS_TMP" -o "$$_ROOTFS_TMP/minimal.ext2" && \
	gzip -9 -c "$$_ROOTFS_TMP/minimal.ext2" > $(BUILTIN_ROOTFS) && \
	rm -rf "$$_ROOTFS_TMP" && \
	echo "Built $(BUILTIN_ROOTFS) ($$(wc -c < $(BUILTIN_ROOTFS) | tr -d ' ') bytes)"
