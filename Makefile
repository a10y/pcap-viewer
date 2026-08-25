.PHONY: build dev test check clean

build:
	./scripts/build.sh

dev:
	./scripts/dev.sh

test:
	cargo test

check:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	cargo check --target wasm32-unknown-unknown

clean:
	cargo clean
	rm -rf dist pkg
