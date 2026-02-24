import os
import hmac

from hmac_utils import hmac_sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def aes_encrypt(key: bytes, plaintext: bytes):
    # Initialization vector
    iv = os.urandom(16)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size)) # 16 bytes multiple
    return iv + ciphertext  # plaintext != ciphertext


def aes_decrypt(key: bytes, ciphertext: bytes):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)


def encrypt_then_mac(enc_key: bytes, mac_key: bytes, message: bytes):
    ciphertext = aes_encrypt(enc_key, message)
    tag = hmac_sha256(mac_key, ciphertext)
    return ciphertext, tag


def verify_then_decrypt(enc_key: bytes, mac_key: bytes, ciphertext: bytes, tag: bytes):
    expected_tag = hmac_sha256(mac_key, ciphertext)

    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("Authentication failed!")

    return aes_decrypt(enc_key, ciphertext)
