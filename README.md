# Tari Crypto

![](https://github.com/tari-project/tari-crypto/workflows/Security%20audit/badge.svg)
![](https://github.com/tari-project/tari-crypto/workflows/Clippy/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/tari-project/tari-crypto/badge.svg?branch=main)](https://coveralls.io/github/tari-project/tari-crypto?branch=main)

This crate is part of the [Tari Cryptocurrency](https://tari.com) project.

Major features of this library include:

- Pedersen commitments
- Schnorr signatures
- Generic public and secret Keys
- [Musig!](https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures/) **NOT PRODUCTION READY**
- Hardware wallet support

The `tari_crypto` crate makes heavy use of the excellent [Dalek](https://github.com/dalek-cryptography/curve25519-dalek)
libraries. The default implementation for Tari ECC is the [Ristretto255 curve](https://ristretto.group).

## Building

### General

Due to the hardware wallet support, general building requires the `--all-features` flag.

To run cargo check:

    $ cargo check --all-targets --all-features

To run cargo clippy:

    $ cargo clippy --all-targets --all-features -- -D warnings

To run cargo lints clippy:

    $ cargo lints clippy --all-targets --all-features

To build the library:

    $ cargo build --release --all-features

To test the library:

    $ cargo test --release --all-features

### Compiling to WebAssembly

To build the WebAssembly module, the `wasm` feature must be enabled:

    $ wasm-pack build . -- --features "wasm"

To generate a module for use in node.js, use this command:

    $ wasm-pack build --target nodejs -d tari_js . -- --features "wasm"

To run the wasm bindings unit tests, use this command:

    $ wasm-pack test --node --features wasm

Note: Node v10+ is needed for the WASM

#### Example (Node.js)

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

### Building the C FFI module

To build the C bindings, you can run

    make ffi

To build the release version (recommended):

    make ffi-release

To run the small demo:

    make demo
    ./bin/demo

## Benchmarks

To run the benchmarks:

    $ cargo bench

The benchmarks use Criterion and will produce nice graphs (if you have gnuplot installed)

## Hardware wallet support

Tari Crypto supports hardware wallets like Ledger Nano S, X and S Plus when included in the project with the "no_std" 
and "borsh_ser" feature flags. Whenever `tari_rypto` is changed, test locally if the proper "no_std" is adhered to by 
running the following commands: 
```
rustup target add --toolchain nightly thumbv8m.main-none-eabi
export PATH="$HOME/.cargo/bin:$PATH"
cargo +nightly rustc --release --crate-type lib --no-default-features --features "no_std" --features "borsh_ser" -Zavoid-dev-deps --target=thumbv8m.main-none-eabi
```

The following project can also be used to test if everything works end-to-end: https://github.com/tari-project/ledger.

## Feature Flags

Some of the utilities can be removed with feature flags. The following feature flags are available:

### no_std

This feature removes the dependency on the Rust standard library. This is useful for embedded systems and hardware.

### borsh_ser

This will include support for borsh serialization.

### wasm

This will include support for WebAssembly.

### ffi

This will include support for the C FFI module.

### zero

This will include support for zeroing memory.

### precomputed_tables

This will include support for precomputed tables for the curve.

### musig

This will include support for MuSig. **NOT PRODUCTION READY**

### serialize

This will include support for Serde serialization.
