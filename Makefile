BIN := contracts/ckb-dynamic-loading-rsa/target/riscv64imac-unknown-none-elf/debug/ckb-dynamic-loading-rsa

test: contract fix
	cargo test

install-tools:
	cargo install --git https://github.com/xxuejie/ckb-binary-patcher.git

contract:
	cd contracts/ckb-dynamic-loading-rsa && cargo build

fix:
	ckb-binary-patcher -i $(BIN) -o build/debug/ckb-dynamic-loading-rsa
