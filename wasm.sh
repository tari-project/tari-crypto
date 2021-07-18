#!/bin/bash

set -e

CHOICE="${1:-""}"
shift || true

if ! [ -x "$(command -v wasm-pack)" ]; then
  echo "Please install wasm-pack to run this script. https://rustwasm.github.io/wasm-pack/"
  exit 1
fi

if ! [ -x "$(command -v node)" ]; then
  echo "Please install node to run this script."
  exit 1
fi

case "$CHOICE" in
  test) wasm-pack test --node --features wasm "$@"
    ;;
  build) wasm-pack build --target nodejs --out-dir tari_js/ -- --features wasm "$@"
    ;;
  "")
    echo "USAGE: $0 (test|build)"
  ;;
  *)
    echo "Invalid option '$CHOICE'"
    echo "USAGE: $0 (test|build)"
  ;;
esac

