# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## [0.17.0](https://github.com/tari-project/tari-crypto/compare/v0.16.12...v0.17.0) (2023-06-13)


### ⚠ BREAKING CHANGES

* expose secret key length as a constant (#181)

### Features

* expose secret key length as a constant ([#181](https://github.com/tari-project/tari-crypto/issues/181)) ([90ad63d](https://github.com/tari-project/tari-crypto/commit/90ad63d0517e2513644cfca2df5a93b7e93d6667))

### [0.16.12](https://github.com/tari-project/tari-crypto/compare/v0.16.11...v0.16.12) (2023-04-13)


### Features

* `RistrettoSecretKey` inversion ([#173](https://github.com/tari-project/tari-crypto/issues/173)) ([9b990a3](https://github.com/tari-project/tari-crypto/commit/9b990a32a7195b3410665cc1969d90ca5960dbee))

### [0.16.9](https://github.com/tari-project/tari-crypto/compare/v0.16.8...v0.16.9) (2023-04-03)


### Features

* require secret keys to be zeroized on drop ([#171](https://github.com/tari-project/tari-crypto/issues/171)) ([a8b9479](https://github.com/tari-project/tari-crypto/commit/a8b947986c59b6566a0832a936c1f6573a462384)), closes [#147](https://github.com/tari-project/tari-crypto/issues/147)

### [0.16.8](https://github.com/tari-project/tari-crypto/compare/v0.16.7...v0.16.8) (2023-03-09)


### Features

* add partialeq and eq trait derivation to domain separated hasher ([#169](https://github.com/tari-project/tari-crypto/issues/169)) ([00f5975](https://github.com/tari-project/tari-crypto/commit/00f59758b10d1e618711252dbeae8d6bf1ce40b1))

### [0.16.7](https://github.com/tari-project/tari-crypto/compare/v0.16.6...v0.16.7) (2023-03-08)


### Features

* add missing methods to Commitment signature ([#167](https://github.com/tari-project/tari-crypto/issues/167)) ([e43fb45](https://github.com/tari-project/tari-crypto/commit/e43fb45d7f291f5fa3bc3215926d511875cba44d))
* qual of life improvements for pubkey display ([#164](https://github.com/tari-project/tari-crypto/issues/164)) ([1a71aff](https://github.com/tari-project/tari-crypto/commit/1a71affea781fee5bce45818b19a5e3ea796be43)), closes [#68](https://github.com/tari-project/tari-crypto/issues/68)


### Bug Fixes

* source coverage workflow ([#165](https://github.com/tari-project/tari-crypto/issues/165)) ([b075db3](https://github.com/tari-project/tari-crypto/commit/b075db359eb7294abc089529ad094430fa60d6b2))
* typo in docstring ([#166](https://github.com/tari-project/tari-crypto/issues/166)) ([1998432](https://github.com/tari-project/tari-crypto/commit/19984322e5e9736dc48cd83700be62f7f0e3567e))

### [0.16.6](https://github.com/tari-project/tari-crypto/compare/v0.16.5...v0.16.6) (2023-01-04)


### Features

* deterministic pseudorandom operations ([#140](https://github.com/tari-project/tari-crypto/issues/140)) ([306cf1b](https://github.com/tari-project/tari-crypto/commit/306cf1be8fa12f95cb3ca2d7a8a6c77e47cf3feb))
* use pre-computation tables for extended commitment factory with extension degree = 1 ([#158](https://github.com/tari-project/tari-crypto/issues/158)) ([0d816e4](https://github.com/tari-project/tari-crypto/commit/0d816e4a3522e3b4ea1cae43616fb168e2364000))


### Bug Fixes

* make schnorr sig impls more general ([#155](https://github.com/tari-project/tari-crypto/issues/155)) ([656fe7a](https://github.com/tari-project/tari-crypto/commit/656fe7a3ac77f3b9bf0f8178cc6a1481099336bc))
* use updated range proof API ([#160](https://github.com/tari-project/tari-crypto/issues/160)) ([be0a491](https://github.com/tari-project/tari-crypto/commit/be0a491e719c89ff025fe96673efb480d19452f8))

### [0.16.5](https://github.com/tari-project/tari-crypto/compare/v0.16.4...v0.16.5) (2022-11-24)


### Features

* relax zeroize ([#157](https://github.com/tari-project/tari-crypto/issues/157)) ([270f568](https://github.com/tari-project/tari-crypto/commit/270f5681ee29de303e11ffd5d5c05b1cb1c8407e))

### [0.16.4](https://github.com/tari-project/tari-crypto/compare/v0.16.3...v0.16.4) (2022-11-24)


### Bug Fixes

* serialization of RistrettoSecretKey ([#156](https://github.com/tari-project/tari-crypto/issues/156)) ([a51d55f](https://github.com/tari-project/tari-crypto/commit/a51d55f71651a014dd6cd8a7722a85da6c6b3ae2))

### [0.16.3](https://github.com/tari-project/tari-crypto/compare/v0.16.2...v0.16.3) (2022-11-23)


### Features

* add Borsh ([#150](https://github.com/tari-project/tari-crypto/issues/150)) ([4a4b633](https://github.com/tari-project/tari-crypto/commit/4a4b633699124b17dfb9163c125db7c403d58404))


### Bug Fixes

* remove 2 unnecessary allocations in batch_mul ([#154](https://github.com/tari-project/tari-crypto/issues/154)) ([ea33445](https://github.com/tari-project/tari-crypto/commit/ea3344585b28f5b5449d90b718f1c64929768937))

### [0.16.2](https://github.com/tari-project/tari-crypto/compare/v0.16.1...v0.16.2) (2022-11-21)


### Features

* update tari_utilities and tests ([#152](https://github.com/tari-project/tari-crypto/issues/152)) ([c61cd00](https://github.com/tari-project/tari-crypto/commit/c61cd0049b91505664e79fe0f5db34c0babbec8a))

### [0.16.1](https://github.com/tari-project/tari-crypto/compare/v0.16.0...v0.16.1) (2022-11-17)

## [0.16.0](https://github.com/tari-project/tari-crypto/compare/v0.15.7...v0.16.0) (2022-11-14)


### ⚠ BREAKING CHANGES

* improve signature api  (#145)

### Features

* functionality to work with `Hidden` types ([#148](https://github.com/tari-project/tari-crypto/issues/148)) ([086d164](https://github.com/tari-project/tari-crypto/commit/086d164d792b471bc13b88e1d577fd5c32ed4d45))
* improve signature api  ([#145](https://github.com/tari-project/tari-crypto/issues/145)) ([27a9472](https://github.com/tari-project/tari-crypto/commit/27a947295fbb69db9ac9d04818c122b697ca92da))


### Bug Fixes

* resolve wasm deprecation warnings ([#146](https://github.com/tari-project/tari-crypto/issues/146)) ([b65f1cd](https://github.com/tari-project/tari-crypto/commit/b65f1cda2087f87e883652283b183a2321b12d22))

### [0.15.7](https://github.com/tari-project/tari-crypto/compare/v0.15.6...v0.15.7) (2022-10-27)


### Features

* add `Zeroize` support to key types, and create new shared secret type ([#137](https://github.com/tari-project/tari-crypto/issues/137)) ([532ccc0](https://github.com/tari-project/tari-crypto/commit/532ccc0f583d601d7ba2bb7f98f9b7355f7f5c4f))
* add deepsource config ([c658619](https://github.com/tari-project/tari-crypto/commit/c658619558c6373f9423f80165c522c5e47d3e0c))
* add new commitment signature to use complete representation proof ([#131](https://github.com/tari-project/tari-crypto/issues/131)) ([e02fa0f](https://github.com/tari-project/tari-crypto/commit/e02fa0fbaf08b75332a32e6d326415d6e08478b5))
* use precomputation for default commitments ([#136](https://github.com/tari-project/tari-crypto/issues/136)) ([acdcee6](https://github.com/tari-project/tari-crypto/commit/acdcee6dc493b79277354f73815dd52f24c21def)), closes [#135](https://github.com/tari-project/tari-crypto/issues/135)


### Bug Fixes

* include wasm features only if required ([#134](https://github.com/tari-project/tari-crypto/issues/134)) ([8b77df3](https://github.com/tari-project/tari-crypto/commit/8b77df31060e243c57406ced43dcd711cddd5a0b))

### [0.15.6](https://github.com/tari-project/tari-crypto/compare/v0.15.5...v0.15.6) (2022-10-04)


### Features

* port dalek ([#132](https://github.com/tari-project/tari-crypto/issues/132)) ([0f99276](https://github.com/tari-project/tari-crypto/commit/0f9927634d0b6b8cb05cdb599a996a74cdd49bd4))

### [0.15.5](https://github.com/tari-project/tari-crypto/compare/v0.15.4...v0.15.5) (2022-08-29)


### Features

* **hashing:** eager implement common traits ([#129](https://github.com/tari-project/tari-crypto/issues/129)) ([3f72eb6](https://github.com/tari-project/tari-crypto/commit/3f72eb67bcd9ec2657bb6e2c204ca8ee77c2e1fe))


### Bug Fixes

* zeroize temp fields during serializing ([#126](https://github.com/tari-project/tari-crypto/issues/126)) ([e13c556](https://github.com/tari-project/tari-crypto/commit/e13c556155a7d018dc658d81bbf50d91d11e01c2))

### [0.15.4](https://github.com/tari-project/tari-crypto/compare/v0.15.3...v0.15.4) (2022-08-03)

* Removed trailing dot in domain tag if an empty label is provided to `DomainSeparatedHasher::new_with_label`



### [0.15.3](https://github.com/tari-project/tari-crypto/compare/v0.15.2...v0.15.3) (2022-07-28)


### Features

* synchronize the standard digest `new()` with `domain separated hasher::new()` ([#123](https://github.com/tari-project/tari-crypto/issues/123)) ([2f86219](https://github.com/tari-project/tari-crypto/commit/2f862195d8bf4d25ca30076bd66028461beb8627))

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
