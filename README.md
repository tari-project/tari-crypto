# Tari Crypto

![](https://github.com/tari-project/tari-crypto/workflows/Security%20audit/badge.svg)
![](https://github.com/tari-project/tari-crypto/workflows/Clippy/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/tari-project/tari-crypto/badge.svg?branch=main)](https://coveralls.io/github/tari-project/tari-crypto?branch=main)

This crate is part of the [Tari Cryptocurrency](https://tari.com) project.

Major features of this library include:

- Pedersen commitments
- Schnorr Signatures
- Generic Public and Secret Keys
- [Musig!](https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures/) **NOT PRODUCTION READY**

The `tari_crypto` crate makes heavy use of the excellent [Dalek](https://github.com/dalek-cryptography/curve25519-dalek)
libraries. The default implementation for Tari ECC is the [Ristretto255 curve](https://ristretto.group).

# Compiling to WebAssembly

To build the WebAssembly module, the `wasm` feature must be enabled:

    $ wasm-pack build . -- --features "wasm"

To generate a module for use in node.js, use this command:

    $ wasm-pack build --target nodejs -d tari_js . -- --features "wasm"

To run the wasm bindings unit tests, use this command:

    $ wasm-pack test --node --features wasm

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
```

# Benchmarks

To run the benchmarks:

    $ cargo bench

The benchmarks use Criterion and will produce nice graphs (if you have gnuplot installed)

To run the benchmarks with SIMD instructions:

    $ cargo bench --features "avx2"

# Building the C FFI module

To build the C bindings, you can run

    make ffi

To build the release version (recommended):

    make ffi-release

To run the small demo:

    make demo
    ./bin/demo
