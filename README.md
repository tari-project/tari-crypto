# Tari Crypto

![](https://github.com/tari-project/tari-crypto/workflows/Security%20audit/badge.svg)
![](https://github.com/tari-project/tari-crypto/workflows/Clippy/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/tari-project/tari-crypto/badge.svg?branch=main)](https://coveralls.io/github/tari-project/tari-crypto?branch=main)

This crate is part of the [Tari Cryptocurrency](https://tari.com) project.

Major features of this library include:

* Pedersen commitments
* Schnorr Signatures
* Generic Public and Secret Keys
* [Musig!](https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures/)

The `tari_crypto` crate makes heavy use of the excellent [Dalek](https://github.com/dalek-cryptography/curve25519-dalek)
libraries. The default implementation for Tari ECC is the [Ristretto255 curve](https://ristretto.group).

# Compiling to WebAssembly
To build the WebAssembly module, the `wasm` feature must be enabled:

    $ wasm-pack build . -- --features "wasm"

To generate a module for use in node.js, use this command:

    $ wasm-pack build --target nodejs -d tari_js . -- --features "wasm"

Note: Node v10+ is needed for the WASM 

## Example (Node.js)

```js
const keys = KeyRing.new();

// Create new keypair
keys.new_key("Alice");
keys.new_key("Bob");
console.log(`${keys.len()} keys in ring`); // 2
console.log("kA = ", keys.private_key("Alice"));
console.log("PB = ", keys.public_key("Bob"));
keys.free();
````

# Benchmarks

To run the benchmarks:

    $ cargo bench

The benchmarks use Criterion and will produce nice graphs (if you have gnuplot installed)

To run the benchmarks with SIMD instructions:

    $ cargo bench --features "avx2"

# Change log

## v0.11.0

* All dependencies to use the digest 0.9 traits and APIs.

Clients of this generally only need to update the `result` method to
`finalize`; and obviously make use of the v0.9 `digest::Digest` trait
where necessary.

As a result, the deprecated k12, sha3 and Blake3 objects have been removed.
Methods and functins that need a hasher are all generic over `Digest`.

We retain the convenience wrapper over `VarBlake2B` to produce 256 bit
hashes and implement the necessary sub-traits to support `digest::Digest`.

## v0.10.0

* Support stable rust

Updated dependencies such that Rust stable 1.53 is now supported.
The optimised avx_2 option will NOT rust on stable because there's
still an unstable feature on subtle-ng. BUT this feature is actually
for doc generation and has been removed from Rust. As soon as subtle-ng
merges https://github.com/dalek-cryptography/subtle/pull/85, avx2 will
probably be supported on stable as well.

## v0.2.0

### General
* WASM and crate version now match. Eliminate that confusion.

### WASM module
* Breaking change: `KeyRing.sign` doesn't take a nonce any more. It's not needed, and why risk someone re-using it?
* New method: `key_utils.sign` to sign keys not in the key ring
* New module: Commitments

# Building the C FFI module

To build the C bindings, you can run

    make ffi

To build the release version (recommended):

    make ffi-release

To run the small demo:

    make demo
    ./bin/demo
