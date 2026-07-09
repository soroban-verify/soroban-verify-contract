default: build

all: fmt-check clippy test build

build:
	cargo build --target wasm32v1-none --release

test:
	cargo test

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all --check

clippy:
	cargo clippy --all-targets -- -D warnings

clean:
	cargo clean

.PHONY: default all build test fmt fmt-check clippy clean
