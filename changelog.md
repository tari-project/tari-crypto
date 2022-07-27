# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [0.15.1](https://github.com/tari-project/tari-crypto/compare/v0.15.0...v0.15.1) (2022-07-27)


### Features

* add hasher macro ([#121](https://github.com/tari-project/tari-crypto/issues/121)) ([0eacedc](https://github.com/tari-project/tari-crypto/commit/0eacedc2371405b0e7d96bba28fb4993870e5a8b))
* implement Digest for DomainSeparatedHasher ([#119](https://github.com/tari-project/tari-crypto/issues/119)) ([967d0a3](https://github.com/tari-project/tari-crypto/commit/967d0a331772778f0059dd621c281d196971fcc8))
* refactor PublicKey length trait to accomodate specific KEY_LEN const ([#118](https://github.com/tari-project/tari-crypto/issues/118)) ([8fe8075](https://github.com/tari-project/tari-crypto/commit/8fe80756acf10e8a3ed6c257253fbeae0d74d0e6))


### Bug Fixes

* add checking for Blake256 parameters ([#117](https://github.com/tari-project/tari-crypto/issues/117)) ([d23fbbc](https://github.com/tari-project/tari-crypto/commit/d23fbbc0e8a0c47699191f262cd71946841770d8)), closes [#110](https://github.com/tari-project/tari-crypto/issues/110)
* don't print a secret key by default ([#112](https://github.com/tari-project/tari-crypto/issues/112)) ([45c5728](https://github.com/tari-project/tari-crypto/commit/45c57281d94856a2694c6464e01f640c892c982c))
* **hashing:** avoid heap allocations for domain-separated hashing API ([#116](https://github.com/tari-project/tari-crypto/issues/116)) ([77d536e](https://github.com/tari-project/tari-crypto/commit/77d536e3a87f237bb2d301678646bd43920af319)), closes [#113](https://github.com/tari-project/tari-crypto/issues/113) [#113](https://github.com/tari-project/tari-crypto/issues/113)

## [0.15.0](https://github.com/tari-project/tari-crypto/compare/v0.14.0...v0.15.0) (2022-07-04)


### ⚠ BREAKING CHANGES

BREAKING CHANGE: `Blake256` no longer re-exposed under the `common` mod and must be imported as `hash::blake2::Blake256`
BREAKING CHANGE: `avx2` and `simd` features have been removed. Use `simd_backend` instead
BREAKING CHANGE: `macros` mod is now private
BREAKING CHANGE: Various constants have been made private
BREAKING CHANGE: `DalekRangeProofService` moved from `ristretto::dalek_range_proof` to `ristretto`
BREAKING CHANGE: `ristretto_com_sig` and `ristretto_sig` mods have been made private. The structs and methods inside were already re-exposed under `ristretto`

### Features

* hashing api ([#106](https://github.com/tari-project/tari-crypto/issues/106)) ([fcb02af](https://github.com/tari-project/tari-crypto/commit/fcb02af03e68f0eacffd9db78cb786a0985bbc96))


### Bug Fixes

* remove unneeded pub uses ([#94](https://github.com/tari-project/tari-crypto/issues/94)) ([b81f1bb](https://github.com/tari-project/tari-crypto/commit/b81f1bbe72b217be379fcd8250ab403f06af741b))

## [0.14.0](https://github.com/tari-project/tari-crypto/compare/v0.13.2...v0.14.0) (2022-06-24)


### ⚠ BREAKING CHANGES

* - any project based on a specific commitment in `tari_crypto` needs to be updated, as a commitment for the same value and blinding factor will now yield a different commitment. This was a necessary change as as described below.


### Features

* change to nums constants ([#111](https://github.com/tari-project/tari-crypto/issues/111)) ([04d5d1e](https://github.com/tari-project/tari-crypto/commit/04d5d1e739c328f4b4ba2ea5088d217529deeacd))

### [0.13.3](https://github.com/tari-project/tari-crypto/compare/v0.13.2...v0.13.3) (2022-06-23)


### Features

* add bulletproof_plus to wasm ([#107](https://github.com/tari-project/tari-crypto/issues/107)) ([62cb98d](https://github.com/tari-project/tari-crypto/commit/62cb98d7e94e4324bf7077105ee3d517cc3a5254))
* add simple bulletproofs plus interface([#105](https://github.com/tari-project/tari-crypto/issues/105)) ([4f9500c](https://github.com/tari-project/tari-crypto/commit/4f9500c9bd3a346c4d045f79139961b6344c1968))

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
