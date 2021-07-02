#ifndef tari_crypto_h // Include guard, prevents header being included twice, very important
#define tari_crypto_h

#ifdef __cplusplus // Make sure it is interpreted as C in a CPP environment, very important
extern "C" {
#endif

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define MAX_SIGNATURES 32768

#define REWIND_PROOF_MESSAGE_LENGTH 23

#define REWIND_USER_MESSAGE_LENGTH 21

#define OK 0

#define NULL_POINTER -1

#define BUFFER_TOO_SMALL -2

#define INVALID_SECRET_KEY_SER -1000

#define SIGNING_ERROR -1100

#define STR_CONV_ERR -2000

#define KEY_LENGTH 32

#define OP_CHECK_HEIGHT_VERIFY 102

#define OP_CHECK_HEIGHT 103

#define OP_COMPARE_HEIGHT_VERIFY 104

#define OP_COMPARE_HEIGHT 105

#define OP_DROP 112

#define OP_DUP 113

#define OP_REV_ROT 114

#define OP_PUSH_HASH 122

#define OP_PUSH_ZERO 123

#define OP_NOP 115

#define OP_PUSH_ONE 124

#define OP_PUSH_INT 125

#define OP_PUSH_PUBKEY 126

#define OP_EQUAL 128

#define OP_EQUAL_VERIFY 129

#define OP_ADD 147

#define OP_SUB 148

#define OP_GE_ZERO 130

#define OP_GT_ZERO 131

#define OP_LE_ZERO 132

#define OP_LT_ZERO 133

#define OP_OR_VERIFY 100

#define OP_OR 101

#define OP_CHECK_SIG 172

#define OP_CHECK_SIG_VERIFY 173

#define OP_HASH_BLAKE256 176

#define OP_HASH_SHA256 177

#define OP_HASH_SHA3 178

#define OP_RETURN 96

#define OP_IF_THEN 97

#define OP_ELSE 98

#define OP_END_IF 99

#define MAX_STACK_SIZE 256

#define TYPE_NUMBER 1

#define TYPE_HASH 2

#define TYPE_COMMITMENT 3

#define TYPE_PUBKEY 4

#define TYPE_SIG 5

typedef uint8_t KeyArray[KEY_LENGTH];

#define RISTRETTO_PEDERSEN_G RISTRETTO_BASEPOINT_POINT

const char *version(void);

int lookup_error_message(int code, char *buffer, int length);

int random_keypair(KeyArray *priv_key,
                   KeyArray *pub_key);

int sign(const KeyArray *priv_key, const char *msg, KeyArray *nonce, KeyArray *signature);

bool verify(const KeyArray *pub_key,
            const char *msg,
            KeyArray *pub_nonce,
            KeyArray *signature,
            int *err_code);

#ifdef __cplusplus
}
#endif

#endif
