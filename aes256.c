#include "aes256.h"
#include <openssl/evp.h>
#include <string.h>

int aes256_gcm_encrypt(const AES256_CTX *ctx, const uint8_t *plaintext, int plaintext_len,
                       const uint8_t *aad, int aad_len,
                       uint8_t *ciphertext, uint8_t *tag) {
    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) return -1;

    int len, ciphertext_len;

    if (1 != EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }

    if (1 != EVP_EncryptInit_ex(cipher_ctx, NULL, NULL, ctx->key, ctx->iv)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }

    if (1 != EVP_EncryptUpdate(cipher_ctx, NULL, &len, aad, aad_len)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }

    if (1 != EVP_EncryptUpdate(cipher_ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(cipher_ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, AES256_TAG_SIZE, tag)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(cipher_ctx);
    return ciphertext_len;
}

int aes256_gcm_decrypt(const AES256_CTX *ctx, const uint8_t *ciphertext, int ciphertext_len,
                       const uint8_t *aad, int aad_len,
                       const uint8_t *tag, uint8_t *plaintext) {
    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) return -1;

    int len, plaintext_len;

    if (1 != EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }

    if (1 != EVP_DecryptInit_ex(cipher_ctx, NULL, NULL, ctx->key, ctx->iv)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }

    if (1 != EVP_DecryptUpdate(cipher_ctx, NULL, &len, aad, aad_len)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }

    if (1 != EVP_DecryptUpdate(cipher_ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }
    plaintext_len = len;

    if (1 != EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG, AES256_TAG_SIZE, (void *)tag)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }

    if (1 != EVP_DecryptFinal_ex(cipher_ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(cipher_ctx);
    return plaintext_len;
}

int aes256_ctr_encrypt(const AES256_CTX *ctx, const uint8_t *plaintext, int plaintext_len,
                       uint8_t *ciphertext) {
    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) return -1;

    int len, ciphertext_len;

    if (1 != EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_ctr(), NULL, ctx->key, ctx->iv)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }

    if (1 != EVP_EncryptUpdate(cipher_ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(cipher_ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(cipher_ctx);
    return ciphertext_len;
}

int aes256_ctr_decrypt(const AES256_CTX *ctx, const uint8_t *ciphertext, int ciphertext_len,
                       uint8_t *plaintext) {
    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) return -1;

    int len, plaintext_len;

    if (1 != EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_ctr(), NULL, ctx->key, ctx->iv)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }

    if (1 != EVP_DecryptUpdate(cipher_ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(cipher_ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(cipher_ctx);
    return plaintext_len;
}
