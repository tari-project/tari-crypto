/**
 * Copyright 2021 The Tari Project
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the
 * following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of
 * its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <jni.h>
#include <android/log.h>
#include <string>
#include <cmath>
#include <android/log.h>
#include "jniCommon.cpp"
#include "tari_crypto.h"

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_taricryptoandroid_TariCrypto_jniVersion(JNIEnv *jEnv, jobject jThis) {
    const char *pVersion = version();
    jstring result = jEnv->NewStringUTF(pVersion);
    return result;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_taricryptoandroid_TariCrypto_jniLookupError(JNIEnv *jEnv, jobject jThis,
                                                             jint error_code) {
    char *err_msg = static_cast<char *>(malloc(sizeof(char) * (128 + 1)));
    lookup_error_message(error_code, &err_msg[0], 128);
    jstring result = jEnv->NewStringUTF(err_msg);
    free(err_msg);
    err_msg = nullptr;
    return result;
}

extern "C"
JNIEXPORT jobject JNICALL
Java_com_example_taricryptoandroid_TariCrypto_jniRandomKeyPair(JNIEnv *jEnv, jobject jThis) {
    // Java does not have any unsigned types, would be better to modify the FFI
    // interface to accept and return a char* that can be parsed into a string
    uint8_t pub_key[KEY_LENGTH];
    uint8_t priv_key[KEY_LENGTH];
    random_keypair(&priv_key,&pub_key);
    // Having a method to generate keys separately in the FFI interface
    // will greatly simplify having to do the below
    jbyteArray pub_bytes = jEnv->NewByteArray(KEY_LENGTH);
    jEnv->SetByteArrayRegion(
            pub_bytes, 0, KEY_LENGTH, reinterpret_cast<const jbyte*>(pub_key));
    jbyteArray priv_bytes = jEnv->NewByteArray(KEY_LENGTH);
    jEnv->SetByteArrayRegion(
            priv_bytes, 0, KEY_LENGTH, reinterpret_cast<const jbyte*>(priv_key));
    jclass pairClass = jEnv->FindClass("android/util/Pair");
    jmethodID constructor = jEnv->GetMethodID(pairClass, "<init>","(Ljava/lang/Object;Ljava/lang/Object;)V");
    return jEnv->NewObject(pairClass,constructor,priv_bytes,pub_bytes);
}

extern "C"
JNIEXPORT jobject JNICALL
Java_com_example_taricryptoandroid_TariCrypto_jniSignMessage(JNIEnv *jEnv, jobject jThis,
                                                             jbyteArray secret_key,
                                                             jstring message) {
    uint8_t signature[KEY_LENGTH];
    uint8_t nonce[KEY_LENGTH];
    jbyte* secPtr = jEnv->GetByteArrayElements(secret_key, 0);
    const char *nativeString = jEnv->GetStringUTFChars(message, 0);
    sign(reinterpret_cast<KeyArray const *>((uint8_t *) secPtr), nativeString,
         &nonce, &signature);
    jEnv->ReleaseStringUTFChars(message,nativeString);
    jEnv->ReleaseByteArrayElements(secret_key,secPtr,JNI_ABORT);
    jbyteArray sig_bytes = jEnv->NewByteArray(KEY_LENGTH);
    jEnv->SetByteArrayRegion(
            sig_bytes, 0, KEY_LENGTH, reinterpret_cast<const jbyte*>(signature));
    jbyteArray nonce_bytes = jEnv->NewByteArray(KEY_LENGTH);
    jEnv->SetByteArrayRegion(
            nonce_bytes, 0, KEY_LENGTH, reinterpret_cast<const jbyte*>(nonce));
    jclass pairClass = jEnv->FindClass("android/util/Pair");
    jmethodID constructor = jEnv->GetMethodID(pairClass, "<init>","(Ljava/lang/Object;Ljava/lang/Object;)V");
    return jEnv->NewObject(pairClass,constructor,sig_bytes,nonce_bytes);
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_example_taricryptoandroid_TariCrypto_jniVerifyMessage(JNIEnv *jEnv, jobject jThis,
                                                               jbyteArray public_key,
                                                               jstring message, jbyteArray nonce,
                                                               jbyteArray signature, jint error) {
    jbyte* pubPtr = jEnv->GetByteArrayElements(public_key, 0);
    jbyte* noncePtr = jEnv->GetByteArrayElements(nonce, 0);
    jbyte* sigPtr = jEnv->GetByteArrayElements(signature, 0);
    const char *nativeString = jEnv->GetStringUTFChars(message, 0);
    bool result = verify(reinterpret_cast<KeyArray const *>((uint8_t *) pubPtr), nativeString ,
                         reinterpret_cast<KeyArray *>((uint8_t *) noncePtr),
                         reinterpret_cast<KeyArray *>((uint8_t *) sigPtr), &error);
    jEnv->ReleaseStringUTFChars(message,nativeString);
    jEnv->ReleaseByteArrayElements(public_key,pubPtr,JNI_ABORT);
    jEnv->ReleaseByteArrayElements(nonce,noncePtr,JNI_ABORT);
    jEnv->ReleaseByteArrayElements(signature,sigPtr,JNI_ABORT);
    return result;
}
