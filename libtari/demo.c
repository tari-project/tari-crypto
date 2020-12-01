#include "tari_crypto.h"
#include <stdio.h>

void print_key(uint8_t key[]) {
  int i;
  for (i = 0; i < KEY_LENGTH; i++) {
    printf("%02X", key[i]);
  }
  printf("\n");
}

/*
 * This demo generates a key pair, signs a message and then validates the signature.
 * All memory in this FFI is managed by the caller. In this demo, the data is kept on the stack, and so explicit
 * memory management is not done, but in general, you have to allocate and free memory yourself.
 */
int main() {
    const char *ver = version();
    printf("Tari Crypto (v%s)\n", ver);

    uint8_t pub_key[KEY_LENGTH], priv_key[KEY_LENGTH];

    int code = random_keypair(&priv_key, &pub_key);
    if (code) {
        printf("Error code: %d\n", code);
        return code;
    }
    printf("Keys generated\n");
    print_key(priv_key);
    print_key(pub_key);

    // Sign and verify message
    const char msg[] = "Hello world\0";
    const char invalid[] = "Hullo world\0";

    uint8_t r[KEY_LENGTH], sig[KEY_LENGTH];

    code = sign(&priv_key, &msg[0], &r, &sig);
    if (code) {
        printf("Error code: %d\n", code);
        return code;
    }

    // Demonstrate error handling
    char *err_msg = malloc( sizeof(char) * ( 128 + 1 ) );
    lookup_error_message(-1, &err_msg[0], 128);
    printf("The error message for code -1 is \"%s\"\n", err_msg);

    printf("Signed message\n");
    print_key(r);
    print_key(sig);

    printf("Check (invalid) signature..");
    if (verify(&pub_key, &invalid[0], &r, &sig, &code)) {
        printf("Oh no. This should have failed\n");
    } else {
        printf("The signature is invalid, as expected\n");
    }

    printf("Check signature..");
    if (verify(&pub_key, &msg[0], &r, &sig, &code)) {
        printf("SUCCESS\n");
    } else {
        printf("FAILED\n");
    }
    return code;
}

