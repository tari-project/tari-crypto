# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [0.13.2](https://github.com/tari-project/tari-crypto/compare/v0.13.1...v0.13.2) (2022-06-15)


### Features

* add extended range proofs ([#102](https://github.com/tari-project/tari-crypto/issues/102)) ([b7f7761](https://github.com/tari-project/tari-crypto/commit/b7f77612d9903d70a0770e017a60288149ba6597))

### [0.13.1](https://github.com/tari-project/tari-crypto/compare/v0.13.0...v0.13.1) (2022-06-13)


### Features

* add extended ristretto commitment factory and pedersen generators ([#99](https://github.com/tari-project/tari-crypto/issues/99)) ([9a579f6](https://github.com/tari-project/tari-crypto/commit/9a579f6029c3ef3513887ef69dafe96152d073f3))

## [0.13.0](https://github.com/tari-project/tari-crypto/compare/v0.12.5...v0.13.0) (2022-04-29)


### ⚠ BREAKING CHANGES

* changes method signature of RistrettoComSig::sign to pass in references (#91)

### Bug Fixes

* clippy lints ([#93](https://github.com/tari-project/tari-crypto/issues/93)) ([fa0d728](https://github.com/tari-project/tari-crypto/commit/fa0d7286e941b06038a10de5adead415339d4603))
* adds clippy lints config and fix lints ([#91](https://github.com/tari-project/tari-crypto/issues/91)) ([5de3d45](https://github.com/tari-project/tari-crypto/commit/5de3d45661386d5c6af9ebbc2c5af9fe62fca1ed))

### [0.12.2](https://github.com/tari-project/tari-crypto/compare/v0.12.1...v0.12.2) (2022-03-25)

### Bug Fixes

- lock bulletproof repo to correct version ([4650715](https://github.com/tari-project/tari-crypto/commit/465071528e26f0913f19d4297f3c05b0b4f21e41))

### [0.12.1](https://github.com/tari-project/tari-crypto/compare/v0.12.0...v0.12.1) (2022-03-14)

### Features

- allow custom hash parameters to be specified ([#84](https://github.com/tari-project/tari-crypto/issues/84)) ([5b412d0](https://github.com/tari-project/tari-crypto/commit/5b412d04ebc9a0bb0149a7dbf5ebf3c6116261c3))

### Bug Fixes

- **ci:** fix invalid env syntax ([#79](https://github.com/tari-project/tari-crypto/issues/79)) ([053e64e](https://github.com/tari-project/tari-crypto/commit/053e64ea1eea16c582df8b506d024326e075b876))
- code coverage only works on nightly ([#78](https://github.com/tari-project/tari-crypto/issues/78)) ([a3ceaa9](https://github.com/tari-project/tari-crypto/commit/a3ceaa9a72debf7428cce2618fe6828ad66ff0b9))
- ensure ExecutionStack cannot exceed MAX_STACK_SIZE ([#65](https://github.com/tari-project/tari-crypto/issues/65)) ([1b74d94](https://github.com/tari-project/tari-crypto/commit/1b74d944218587dd0fa60bc75db2eca1d5d7057d))

### [0.11.0](https://github.com/tari-project/tari-crypto/compare/v0.10.0...v0.11.0) (2021-09-06)

### General

- All dependencies to use the digest 0.9 traits and APIs.

Clients of this generally only need to update the `result` method to
`finalize`; and obviously make use of the v0.9 `digest::Digest` trait
where necessary.

As a result, the deprecated k12, sha3 and Blake3 objects have been removed.
Methods and functins that need a hasher are all generic over `Digest`.

We retain the convenience wrapper over `VarBlake2B` to produce 256 bit
hashes and implement the necessary sub-traits to support `digest::Digest`.

### Bug Fixes

- remove extra compress call during pubkey::deserialize ([#56](https://github.com/tari-project/tari-crypto/issues/56)) ([8864b5a2](https://github.com/tari-project/tari-crypto/commit/8864b5a20bd55c8e075be67b132daebe22762e0c))

### [0.10.0](https://github.com/tari-project/tari-crypto/compare/v0.2.0...v0.10.0) (2021-07-05)

- Support stable rust

Updated dependencies such that Rust stable 1.53 is now supported.
The optimised avx_2 option will NOT rust on stable because there's
still an unstable feature on subtle-ng. BUT this feature is actually
for doc generation and has been removed from Rust. As soon as subtle-ng
merges https://github.com/dalek-cryptography/subtle/pull/85, avx2 will
probably be supported on stable as well.

### [0.2.0](https://github.com/tari-project/tari-crypto/compare/v0.2.0) (2020-02-07)

### General

- WASM and crate version now match. Eliminate that confusion.

### WASM module

- Breaking change: `KeyRing.sign` doesn't take a nonce any more. It's not needed, and why risk someone re-using it?
- New method: `key_utils.sign` to sign keys not in the key ring
- New module: Commitments
