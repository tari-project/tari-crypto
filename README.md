# Tari Crypto

![](https://github.com/tari-project/tari-crypto/workflows/Security%20audit/badge.svg)
![](https://github.com/tari-project/tari-crypto/workflows/Clippy/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/tari-project/tari-crypto/badge.svg?branch=main)](https://coveralls.io/github/tari-project/tari-crypto?branch=main)

This crate is part of the [Tari Cryptocurrency](https://tari.com) project.

Major features of this library include:

- Pedersen commitments
- Schnorr Signatures
- Generic Public and Secret Keys
- no-std support

The `tari_crypto` crate makes heavy use of the excellent [Dalek](https://github.com/dalek-cryptography/curve25519-dalek)
libraries. The default implementation for Tari ECC is the [Ristretto255 curve](https://ristretto.group).

# Feature flags
### bulletproofs_plus
This adds in support for rangeproofs using the tari bulletproof plus library
### serde
This adds serialise and deserialize support for all structs using the serde library 
### borsh
This adds serialise and deserialize support for all structs using the borsh library
### precomputed_tables
This uses optimised precomputed tables for calculations. While this is faster than straight-up calculations, this requires large memory to store which is not ideal for small no_std devices

# WASM and FFI support
TariCrypto has external WASM and FFI wrappers available here
WASM: https://github.com/tari-project/tari-crypto-wasm
FFI: https://github.com/tari-project/tari-crypto-ffi

# Benchmarks

To run the benchmarks:

    $ cargo bench

The benchmarks use Criterion and will produce nice graphs (if you have gnuplot installed)



