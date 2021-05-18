BIN := contracts/ckb-dynamic-loading-rsa/target/riscv64imac-unknown-none-elf/debug/ckb-dynamic-loading-rsa

test: build/debug/ckb-dynamic-loading-rsa
	cargo test

install-tools:
	cargo install --git https://github.com/xxuejie/ckb-binary-patcher.git

contract:
	docker run --rm -v `pwd`:/code jjy0/ckb-capsule-recipe-rust:2020-9-28 bash -c "cd /code/contracts/ckb-dynamic-loading-rsa && cargo build"

fix:
	ckb-binary-patcher -i $(BIN) -o build/debug/ckb-dynamic-loading-rsa
