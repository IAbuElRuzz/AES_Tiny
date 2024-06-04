import ctypes
import os
import random
import string

# Define constants
AES256_KEY_SIZE = 32
AES256_IV_SIZE = 12
AES256_TAG_SIZE = 16

# Load the shared library
lib = ctypes.CDLL('./libaes256.so')

# Define the AES256_CTX structure
class AES256_CTX(ctypes.Structure):
    _fields_ = [("key", ctypes.c_uint8 * AES256_KEY_SIZE),
                ("iv", ctypes.c_uint8 * AES256_IV_SIZE)]

# Define the function signatures
lib.aes256_gcm_encrypt.argtypes = [
    ctypes.POINTER(AES256_CTX),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint8)
]
lib.aes256_gcm_encrypt.restype = ctypes.c_int

lib.aes256_gcm_decrypt.argtypes = [
    ctypes.POINTER(AES256_CTX),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint8)
]
lib.aes256_gcm_decrypt.restype = ctypes.c_int

lib.aes256_ctr_encrypt.argtypes = [
    ctypes.POINTER(AES256_CTX),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_uint8)
]
lib.aes256_ctr_encrypt.restype = ctypes.c_int

lib.aes256_ctr_decrypt.argtypes = [
    ctypes.POINTER(AES256_CTX),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_uint8)
]
lib.aes256_ctr_decrypt.restype = ctypes.c_int

def random_bytes(length):
    return bytes(random.getrandbits(8) for _ in range(length))


def test_aes256_gcm():
    print('\n')
    key = random_bytes(AES256_KEY_SIZE)
    print('test_aes256_gcm() key:', key)
    iv = random_bytes(AES256_IV_SIZE)
    print('test_aes256_gcm() iv:', iv)
    plaintext = b"Hello, AES-256-GCM!"
    print('test_aes256_gcm() plaintext:', plaintext)
    aad = b"Additional Authenticated aad"
    print('test_aes256_gcm() aad:', aad)

    ctx = AES256_CTX((ctypes.c_uint8 * AES256_KEY_SIZE)(*key),
                     (ctypes.c_uint8 * AES256_IV_SIZE)(*iv))

    ciphertext = (ctypes.c_uint8 * (len(plaintext) + AES256_TAG_SIZE))()  # Extend size to accommodate tag
    tag = (ctypes.c_uint8 * AES256_TAG_SIZE)()

    enc_len = lib.aes256_gcm_encrypt(
        ctypes.byref(ctx),
        (ctypes.c_uint8 * len(plaintext))(*plaintext),
        len(plaintext),
        (ctypes.c_uint8 * len(aad))(*aad),
        len(aad),
        ciphertext,
        tag
    )

    assert enc_len > 0

    ciphertext = bytes(ciphertext[:enc_len])  # Slice ciphertext to remove extra zero padding
    print('test_aes256_gcm() encrypted ciphertext:', ciphertext)
    print('test_aes256_gcm() tag:', bytes(tag))

    decrypted = (ctypes.c_uint8 * len(plaintext))()
    dec_len = lib.aes256_gcm_decrypt(
        ctypes.byref(ctx),
        (ctypes.c_uint8 * len(ciphertext))(*ciphertext),
        enc_len,
        (ctypes.c_uint8 * len(aad))(*aad),
        len(aad),
        tag,
        decrypted
    )

    assert dec_len == len(plaintext)
    assert bytes(decrypted) == plaintext
    print('test_aes256_gcm() decrypted plaintext:', bytes(decrypted))
    print("AES-256-GCM Encryption and Decryption successful")

def test_aes256_ctr():
    print('\n')
    key = random_bytes(AES256_KEY_SIZE)
    print('test_aes256_ctr() key:', key)
    iv = random_bytes(AES256_IV_SIZE)
    print('test_aes256_ctr() iv:', iv)
    plaintext = b"Hello, AES-256-CTR!"
    print('test_aes256_ctr() plaintext:', plaintext)
    
    ctx = AES256_CTX((ctypes.c_uint8 * AES256_KEY_SIZE)(*key),
                     (ctypes.c_uint8 * AES256_IV_SIZE)(*iv))

    ciphertext = (ctypes.c_uint8 * len(plaintext))()
    decrypted = (ctypes.c_uint8 * len(plaintext))()

    enc_len = lib.aes256_ctr_encrypt(
        ctypes.byref(ctx),
        (ctypes.c_uint8 * len(plaintext))(*plaintext),
        len(plaintext),
        ciphertext
    )

    assert enc_len == len(plaintext)

    print('test_aes256_ctr() encrypted ciphertext:', bytes(ciphertext))

    dec_len = lib.aes256_ctr_decrypt(
        ctypes.byref(ctx),
        ciphertext,
        enc_len,
        decrypted
    )

    assert dec_len == len(plaintext)
    assert bytes(decrypted) == plaintext
    print('test_aes256_ctr() decrypted plaintext:', bytes(decrypted))
    print("AES-256-CTR Encryption and Decryption successful")
 
if __name__ == "__main__":
    test_aes256_gcm()
    test_aes256_ctr()
    

 