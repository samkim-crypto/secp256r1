RUST_TOOLCHAIN_NIGHTLY = nightly-2026-01-22
SOLANA_CLI_VERSION = v4.1.2
SBF_ARCH = v3

nightly = +${RUST_TOOLCHAIN_NIGHTLY}

make-path = $1

rust-toolchain-nightly:
	@echo ${RUST_TOOLCHAIN_NIGHTLY}

solana-cli-version:
	@echo ${SOLANA_CLI_VERSION}

audit:
	cargo audit $(ARGS)

spellcheck:
	cargo spellcheck --code 1 $(ARGS)

clippy-%:
	cargo $(nightly) clippy --manifest-path $(call make-path,$*)/Cargo.toml \
		--all-targets \
		--all-features \
		-- \
		--deny=warnings $(ARGS)

format-check-%:
	cargo $(nightly) fmt --check --manifest-path $(call make-path,$*)/Cargo.toml $(ARGS)

powerset-%:
	cargo $(nightly) hack check \
		--feature-powerset \
		--all-targets \
		--manifest-path $(call make-path,$*)/Cargo.toml \
		$(ARGS)

build-doc-%:
	RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo $(nightly) doc \
		--all-features \
		--no-deps \
		--manifest-path $(call make-path,$*)/Cargo.toml \
		$(ARGS)

build-sbf-%:
	cargo build-sbf --arch $(SBF_ARCH) --manifest-path $(call make-path,$*)/Cargo.toml -- --locked $(ARGS)

test-%:
	SBF_OUT_DIR=$(PWD)/target/deploy cargo test \
		--locked \
		--manifest-path $(call make-path,$*)/Cargo.toml \
		$(ARGS)

cu-program: build-sbf-program
	SBF_OUT_DIR=$(PWD)/target/deploy cargo test \
		--locked \
		--manifest-path program/Cargo.toml \
		--test mollusk \
		-- --nocapture

build-sbf-secp256r1: build-sbf-program
build-doc-secp256r1: build-doc-program
clippy-secp256r1: clippy-program
cu-secp256r1: cu-program
format-check-secp256r1: format-check-program
powerset-secp256r1: powerset-program
test-secp256r1: test-program

generate-clients:
	exit 0

