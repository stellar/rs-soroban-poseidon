# Package lists
LIB_CRATE = soroban-poseidon
TEST_CRATES = $(shell cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.name | startswith("test_")) | .name' | tr '\n' ' ')

# MSRV from Cargo.toml - used by CI
MSRV = $(shell cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.name == "$(LIB_CRATE)") | .rust_version')

# Doc args - CI overrides with empty value
CARGO_DOC_ARGS ?= --open

default: test

test: fmt build
	cargo test --workspace

build: fmt build-libs build-test-wasms

build-libs: fmt
	cargo build --release --package $(LIB_CRATE)
	cargo build --release --target wasm32v1-none --package $(LIB_CRATE)

build-test-wasms: fmt
	cargo build --release --target wasm32v1-none $(foreach c,$(TEST_CRATES),--package $(c))
	@cd target/wasm32v1-none/release/ && \
		for i in *.wasm ; do \
			ls -l "$$i"; \
		done

doc: fmt
	cargo doc --no-deps --all-features $(CARGO_DOC_ARGS)

fmt:
	cargo fmt --all

check: fmt
	cargo check --workspace --all-features
	cargo clippy --workspace --all-features -- -D warnings

publish-dry-run:
	cargo publish --dry-run

clean:
	cargo clean

msrv:
	@echo $(MSRV)

.PHONY: default test build build-libs build-test-wasms doc fmt check publish-dry-run clean msrv
