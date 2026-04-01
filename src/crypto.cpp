// File: src/crypto.cpp
#include "./headers/crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <cstring>
#include <iostream>

using namespace std;

// Hardcoded shared key for simplicity (16 bytes for AES-128)
const uint8_t SHARED_SECRET_KEY[16] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
};

void generate_iv(uint8_t *iv) {
    if (RAND_bytes(iv, 16) != 1) {
        cerr << "[CRYPTO] Error generating random IV!" << endl;
    }
}

bool aes_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                 const uint8_t *key, const uint8_t *iv,
                 uint8_t *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len;
    int ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool aes_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                 const uint8_t *key, const uint8_t *iv,
                 uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len;
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool generate_hmac(const uint8_t *packet_data, size_t packet_len,
                   const uint8_t *key, uint8_t *hmac_out) {
    unsigned int len = 32;
    uint8_t *result = HMAC(EVP_sha256(), key, 16, packet_data, packet_len, hmac_out, &len);
    return result != NULL;
}

bool verify_hmac(const uint8_t *packet_data, size_t packet_len,
                 const uint8_t *key, const uint8_t *expected_hmac) {
    uint8_t computed_hmac[32];
    if (!generate_hmac(packet_data, packet_len, key, computed_hmac)) {
        return false;
    }
    return CRYPTO_memcmp(computed_hmac, expected_hmac, 32) == 0;
}
