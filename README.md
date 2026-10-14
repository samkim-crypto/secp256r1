# solana-secp256r1-program

> **Status: not ready for use.** The final elliptic-curve check of the ECDSA
> verification is not implemented yet. It depends on the secp256r1 curve
> syscalls from SIMD-0565, which are not in a released runtime yet. Until then
> the verifier accepts any signature that passes the scalar range and
> malleability checks.

With the deprecation of native precompiles on Solana (as outlined in SIMD-0568),
support for the native `Secp256r1SigVerify1111111111111111111111111` precompile
is being removed.

To support protocols that rely on secp256r1 (NIST P-256) ECDSA signature
verification, such as WebAuthn and passkeys, this repository provides an SBF
alternative. It is split into two components:

1. **`solana-secp256r1-verify`**: a stateless, zero-allocation library for
   in-program verification.
2. **`solana-secp256r1-program`**: a standalone SBF program that verifies a
   signature on-chain.

## Instruction format

The program verifies a single signature and expects no accounts. Instruction
data is:

```text
[0 .. 33]     compressed public key (33 bytes: 0x02 or 0x03, then X)
[33 .. 97]    signature r || s (64 bytes)
[97 ..]       message
```

The message is hashed with SHA-256, and signatures with `s > N/2` are rejected,
the same as the native precompile. Any verification failure is returned as
`ProgramError::InvalidInstructionData`.

The `verify` helper in `solana-secp256r1-verify` builds this layout:

```rust
use solana_secp256r1_verify::{verify, ID};

let instruction = verify(&ID, &public_key, &signature, message);
```

## Library usage

Programs can skip the CPI and verify signatures directly with
`Secp256r1Verifier`:

```rust
use solana_secp256r1_verify::Secp256r1Verifier;

Secp256r1Verifier::default().verify_signature(
    &public_key, // &[u8; 33], compressed
    &signature,  // &[u8; 64], r || s
    message,     // &[u8]
)?;
```

By default the verifier hashes the message with SHA-256 and rejects high-s
signatures. Two options change that:

- `allow_high_s()` accepts both low-s and high-s signatures. Many signers,
  including most WebAuthn authenticators, do not normalize `s`, so protocols that
  are not affected by signature malleability may want this.
- The `RawHasher` type parameter takes a message that has already been hashed to
  exactly 32 bytes, for example
  `Secp256r1Verifier::<RawHasher>::new().verify_signature(...)`.

## Cargo features

| Feature       | Unlocks                                                        | Pulls in                               |
| ------------- | -------------------------------------------------------------- | -------------------------------------- |
| `verify`      | `Secp256r1Verifier`, `Secp256r1VerifyError`, the hashers       | `solana-sha256-hasher`                 |
| `instruction` | `verify()`, `id()`, `ID` (the client-side instruction builder) | `solana-instruction`, `solana-address` |

## Build and test

Stable Rust `1.93.1` is pinned in `rust-toolchain.toml`. Some make targets also
require the nightly Rust toolchain `nightly-2026-01-22`.

```sh
# Library unit tests (host, no SBF toolchain required)
cargo test --manifest-path secp256r1-verify/Cargo.toml

# SBF build via Makefile
make build-sbf-program

# Host unit tests, then SBF integration tests via Mollusk
make test-program

# Print Mollusk compute-unit measurements for the SBF program
make cu-program
```

The Mollusk tests execute `target/deploy/solana_secp256r1_program.so`. They skip
unless `SBF_OUT_DIR` is set. The tests that need the elliptic-curve check are
marked `#[ignore]` until it is implemented.
