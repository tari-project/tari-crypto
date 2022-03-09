ifeq ($(shell uname),Darwin)
    LDFLAGS := -Ltarget/release/
else
    LDFLAGS := -Ltarget/release/
endif

SRC = libtari
BIN = bin
PWD = $(shell pwd)

CC=cc

CFLAGS   =

clean:
	rm $(SRC)/tari_crypto.h
	rm $(BIN)/demo

$(LIB)/tari_crypto.h target/release/libtari_crypto.a:
	cargo build --features=ffi --release

target/debug/libtari_crypto.a:
	cargo build --features=ffi

$(BIN)/demo: $(LIB)/tari_crypto.h target/release/libtari_crypto.a
	mkdir -p $(BIN)
	$(CC) $(SRC)/demo.c $(LDFLAGS) -ltari_crypto -o $@

demo: $(BIN)/demo

ffi: target/debug/libtari_crypto.a

ffi-release: target/release/libtari_crypto.a

wasm:
	wasm-pack build . -- --features "wasm"

wasm-node:
	wasm-pack build --target nodejs -d tari_js . -- --features "wasm"
