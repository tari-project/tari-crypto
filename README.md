# Tari Crypto

![](https://github.com/tari-project/tari-crypto/workflows/Security%20audit/badge.svg)
![](https://github.com/tari-project/tari-crypto/workflows/Clippy/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/tari-project/tari-crypto/badge.svg?branch=main)](https://coveralls.io/github/tari-project/tari-crypto?branch=main)

This crate is part of the [Tari Cryptocurrency](https://tari.com) project.

Major features of this library include:

- Pedersen commitments
- Schnorr Signatures
- Generic Public and Secret Keys

The `tari_crypto` crate makes heavy use of the excellent [Dalek](https://github.com/dalek-cryptography/curve25519-dalek)
libraries. The default implementation for Tari ECC is the [Ristretto255 curve](https://ristretto.group).
# Benchmarks

To run the benchmarks:

    $ cargo bench

The benchmarks use Criterion and will produce nice graphs (if you have gnuplot installed)



