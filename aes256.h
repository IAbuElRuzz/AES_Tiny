#ifndef AES256_H
#define AES256_H

#include <openssl/evp.h>
#include <stdint.h>

// Define the sizes for key, IV, and tag
#define AES256_KEY_SIZE 32
#define AES256_IV_SIZE 12
#define AES256_TAG_SIZE 16

// Structure to hold the AES context including key and IV
typedef struct {
    uint8_t key[AES256_KEY_SIZE];
    uint8_t iv[AES256_IV_SIZE];
} AES256_CTX;

// Function prototypes for AES-256 GCM encryption and decryption
int aes256_gcm_encrypt(const AES256_CTX *ctx, const uint8_t *plaintext, int plaintext_len,
                       const uint8_t *aad, int aad_len,
                       uint8_t *ciphertext, uint8_t *tag);

int aes256_gcm_decrypt(const AES256_CTX *ctx, const uint8_t *ciphertext, int ciphertext_len,
                       const uint8_t *aad, int aad_len,
                       const uint8_t *tag, uint8_t *plaintext);

// Function prototypes for AES-256 CTR encryption and decryption
int aes256_ctr_encrypt(const AES256_CTX *ctx, const uint8_t *plaintext, int plaintext_len,
                       uint8_t *ciphertext);

int aes256_ctr_decrypt(const AES256_CTX *ctx, const uint8_t *ciphertext, int ciphertext_len,
                       uint8_t *plaintext);

#endif // AES256_H
