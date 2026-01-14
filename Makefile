TEST_CRATES = $(shell cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.name | startswith("test_")) | .name' | tr '\n' ' ')

default: test

test: fmt build-test-wasms
	cargo test --workspace

build-test-wasms: fmt
	cargo build --release --target wasm32v1-none $(foreach c,$(TEST_CRATES),--package $(c))
	@cd target/wasm32v1-none/release/ && \
		for i in *.wasm ; do \
			ls -l "$$i"; \
		done

fmt:
	cargo fmt --all

clean:
	cargo clean

.PHONY: default test build-test-wasms fmt clean
