import ctypes
import os
import random

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


def encrypt_aes256_gcm(key, iv, plaintext, aad):
    """
    Encrypts plaintext using AES-256 GCM mode.
    
    Args:
        key (bytes): Encryption key (256 bits).
        iv (bytes): Initialization vector (96 bits).
        plaintext (bytes): Data to encrypt.
        aad (bytes): Additional authenticated data.

    Returns:
        tuple: Encrypted ciphertext and tag.
    """
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

    if enc_len < 0:
        raise ValueError("Encryption failed")

    return bytes(ciphertext[:enc_len]), bytes(tag)
	
	
	
def decrypt_aes256_gcm(key, iv, ciphertext, tag, aad):
    """
    Decrypts ciphertext using AES-256 GCM mode.
    
    Args:
        key (bytes): Encryption key (256 bits).
        iv (bytes): Initialization vector (96 bits).
        ciphertext (bytes): Data to decrypt.
        tag (bytes): Authentication tag.
        aad (bytes): Additional authenticated data.

    Returns:
        bytes: Decrypted plaintext.
    """
    ctx = AES256_CTX((ctypes.c_uint8 * AES256_KEY_SIZE)(*key),
                     (ctypes.c_uint8 * AES256_IV_SIZE)(*iv))

    plaintext = (ctypes.c_uint8 * len(ciphertext))()

    dec_len = lib.aes256_gcm_decrypt(
        ctypes.byref(ctx),
        (ctypes.c_uint8 * len(ciphertext))(*ciphertext),
        len(ciphertext),
        (ctypes.c_uint8 * len(aad))(*aad),
        len(aad),
        (ctypes.c_uint8 * AES256_TAG_SIZE)(*tag),
        plaintext
    )

    if dec_len < 0:
        raise ValueError("Decryption failed")

    return bytes(plaintext[:dec_len])


def encrypt_aes256_ctr(key, iv, plaintext):
    """
    Encrypts plaintext using AES-256 CTR mode.
    
    Args:
        key (bytes): Encryption key (256 bits).
        iv (bytes): Initialization vector (96 bits).
        plaintext (bytes): Data to encrypt.

    Returns:
        bytes: Encrypted ciphertext.
    """
    ctx = AES256_CTX((ctypes.c_uint8 * AES256_KEY_SIZE)(*key),
                     (ctypes.c_uint8 * AES256_IV_SIZE)(*iv))

    ciphertext = (ctypes.c_uint8 * len(plaintext))()

    enc_len = lib.aes256_ctr_encrypt(
        ctypes.byref(ctx),
        (ctypes.c_uint8 * len(plaintext))(*plaintext),
        len(plaintext),
        ciphertext
    )

    if enc_len < 0:
        raise ValueError("Encryption failed")

    return bytes(ciphertext[:enc_len])

def decrypt_aes256_ctr(key, iv, ciphertext):
    """
    Decrypts ciphertext using AES-256 CTR mode.
    
    Args:
        key (bytes): Encryption key (256 bits).
        iv (bytes): Initialization vector (96 bits).
        ciphertext (bytes): Data to decrypt.

    Returns:
        bytes: Decrypted plaintext.
    """
    ctx = AES256_CTX((ctypes.c_uint8 * AES256_KEY_SIZE)(*key),
                     (ctypes.c_uint8 * AES256_IV_SIZE)(*iv))

    plaintext = (ctypes.c_uint8 * len(ciphertext))()

    dec_len = lib.aes256_ctr_decrypt(
        ctypes.byref(ctx),
        (ctypes.c_uint8 * len(ciphertext))(*ciphertext),
        len(ciphertext),
        plaintext
    )

    if dec_len < 0:
        raise ValueError("Decryption failed")

    return bytes(plaintext[:dec_len])



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

    ciphertext, tag = encrypt_aes256_gcm(key, iv, plaintext, aad)
    print('test_aes256_gcm() encrypted ciphertext:', ciphertext)
    print('test_aes256_gcm() tag:', tag)

    decrypted = decrypt_aes256_gcm(key, iv, ciphertext, tag, aad)
    print('test_aes256_gcm() decrypted plaintext:', decrypted)
    
    assert decrypted == plaintext
    print("AES-256-GCM Encryption and Decryption successful")

def test_aes256_ctr():
    print('\n')
    key = random_bytes(AES256_KEY_SIZE)
    print('test_aes256_ctr() key:', key)
    iv = random_bytes(AES256_IV_SIZE)
    print('test_aes256_ctr() iv:', iv)
    plaintext = b"Hello, AES-256-CTR!"
    print('test_aes256_ctr() plaintext:', plaintext)
    
    ciphertext = encrypt_aes256_ctr(key, iv, plaintext)
    print('test_aes256_ctr() encrypted ciphertext:', ciphertext)

    decrypted = decrypt_aes256_ctr(key, iv, ciphertext)
    print('test_aes256_ctr() decrypted plaintext:', decrypted)
    
    assert decrypted == plaintext
    print("AES-256-CTR Encryption and Decryption successful")

if __name__ == "__main__":
    test_aes256_gcm()
    test_aes256_ctr()