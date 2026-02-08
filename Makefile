BINARY := target/release/sandal
ENTITLEMENTS := sandal.entitlements

.PHONY: build debug clippy

build:
	@cargo build --release
	@codesign --entitlements $(ENTITLEMENTS) -s - $(BINARY) --force

debug:
	@cargo build
	@codesign --entitlements $(ENTITLEMENTS) -s - target/debug/sandal --force

clippy:
	cargo clippy --all-targets --all-features -- -D warnings
