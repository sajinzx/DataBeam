// File: src/headers/crypto.h
#ifndef CRYPTO_H
#define CRYPTO_H

#include <cstdint>
#include <cstddef>
#include "packet.h"

// Hardcoded shared key for HMAC and AES-128
extern const uint8_t SHARED_SECRET_KEY[16];

// Generate 16 bytes of random IV
void generate_iv(uint8_t *iv);

// Encrypt plaintext using AES-128-CTR
// Returns true on success
bool aes_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                 const uint8_t *key, const uint8_t *iv,
                 uint8_t *ciphertext);

// Decrypt ciphertext using AES-128-CTR
// Returns true on success
bool aes_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                 const uint8_t *key, const uint8_t *iv,
                 uint8_t *plaintext);

// Generate HMAC-SHA256 over the provided packet data
bool generate_hmac(const uint8_t *packet_data, size_t packet_len,
                   const uint8_t *key, uint8_t *hmac_out);

// Verify HMAC-SHA256 over the provided packet data
bool verify_hmac(const uint8_t *packet_data, size_t packet_len,
                 const uint8_t *key, const uint8_t *expected_hmac);

#endif // CRYPTO_H
