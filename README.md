# AES-256 Encryption Wrapper for OpenSSL

This Wrapper/Library provides AES-256 encryption and decryption functions using GCM and CTR modes. It leverages OpenSSL for cryptographic operations and is designed to be fast and efficient.

## Features

- AES-256-GCM Encryption and Decryption
- AES-256-CTR Encryption and Decryption
- Easy-to-use C API
- Python bindings for testing

## Requirements

- OpenSSL library
- C compiler (e.g., GCC)
- Python 3.x
- `ctypes` module in Python

## Files

- `aes256.c`: C implementation of AES-256 encryption and decryption functions.
- `aes256.h`: Header file for AES-256 functions.
- `Makefile`: Makefile for building the shared library.
- `test_aes256.py`: Python script for testing the AES-256 functions.

## Installation

1. **Clone the repository:**
    ```sh
    git clone <repository-url>
    cd <repository-directory>
    ```

2. **Build the shared library:**
    ```sh
    make
    ```

    This will compile `aes256.c` and create the `libaes256.so` shared library.

## Usage

### C Library

Include the header file and link against the compiled shared library in your C project:

1. **Include the header:**
    ```c
    #include "aes256.h"
    ```

2. **Example usage:**
    ```c
    AES256_CTX ctx;
    uint8_t key[AES256_KEY_SIZE] = { ... }; // 32 bytes
    uint8_t iv[AES256_IV_SIZE] = { ... }; // 12 bytes for GCM
    uint8_t plaintext[] = "Hello, World!";
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t tag[AES256_TAG_SIZE]; // 16 bytes for GCM

    // Initialize context
    aes256_init(&ctx, key, iv);

    // Encrypt
    aes256_gcm_encrypt(&ctx, plaintext, sizeof(plaintext), NULL, 0, ciphertext, tag);

    // Decrypt
    uint8_t decrypted[sizeof(plaintext)];
    aes256_gcm_decrypt(&ctx, ciphertext, sizeof(ciphertext), NULL, 0, tag, decrypted);
    ```

### Python

The `test_aes256.py` script demonstrates how to use the shared library from Python using the `ctypes` module.

1. **Ensure the shared library is in the same directory as the Python script or in a directory included in your `LD_LIBRARY_PATH`.**

2. **Run the Python test script:**
    ```sh
    python3 test_aes256.py
    ```

    This script tests both AES-256-GCM and AES-256-CTR encryption and decryption functions and prints the results.

### Python Test Script

The `test_aes256.py` script tests the AES-256 encryption and decryption functions.

