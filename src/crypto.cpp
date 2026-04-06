// File: src/crypto.cpp
#include "./headers/crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <cstring>
#include <iostream>

using namespace std;

// Security keys are now in constants.h
#include "headers/constants.h"
const uint8_t *SHARED_SECRET_KEY = DataBeam::SHARED_SECRET_KEY;
void expand_iv_8_to_16(const uint64_t *iv8, uint8_t iv16[16])
{
    // Copy 8 bytes
    memcpy(iv16, iv8, 8);

    // Fill remaining 8 bytes deterministically (CTR-safe)
    memset(iv16 + 8, 0, 8);
}
void generate_iv(uint64_t *iv)
{
    if (RAND_bytes(reinterpret_cast<unsigned char *>(iv), sizeof(uint64_t)) != 1)
    {
        cerr << "[CRYPTO] Error generating IV!" << endl;
    }
}
bool aes_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                 const uint8_t *key, const uint64_t *iv8,
                 uint8_t *ciphertext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    uint8_t iv16[16];
    expand_iv_8_to_16(iv8, iv16);

    int len;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv16) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;
}
bool aes_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                 const uint8_t *key, const uint64_t *iv8,
                 uint8_t *plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    uint8_t iv16[16];
    expand_iv_8_to_16(iv8, iv16);

    int len;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv16) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;
}
bool generate_hmac(const uint8_t *packet_data, size_t packet_len,
                   const uint8_t *key, uint8_t *hmac_out)
{
    unsigned int len = 32;
    uint8_t full_hmac[32];

    if (!HMAC(EVP_sha256(), key, DataBeam::SHARED_SECRET_KEY_LEN, packet_data, packet_len, full_hmac, &len))
        return false;

    memcpy(hmac_out, full_hmac, DataBeam::HMAC_TAG_LEN); // truncate to 16 bytes
    return true;
}

bool verify_hmac(const uint8_t *packet_data, size_t packet_len,
                 const uint8_t *key, const uint8_t *expected_hmac)
{
    uint8_t computed_hmac[DataBeam::HMAC_TAG_LEN];

    if (!generate_hmac(packet_data, packet_len, key, computed_hmac))
        return false;

    return CRYPTO_memcmp(computed_hmac, expected_hmac, DataBeam::HMAC_TAG_LEN) == 0;
}
