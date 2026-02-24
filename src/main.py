import hmac

from aes_utils import aes_decrypt, aes_encrypt, encrypt_then_mac, verify_then_decrypt
from hmac_utils import hashlib, hmac_sha256


def hmac_computation() -> None:

    key = b"secret_key"
    message = b"hello world"

    result = hmac_sha256(key, message)
    print("HMAC-SHA256:", result.hex())

    expected = hmac.new(key, message, hashlib.sha256).digest()
    print("Matches built-in:", result == expected)

    return None


def aes_hmac_computation() -> None:

    enc_key = hashlib.sha256(b"encryption_key").digest()  # 32 bytes
    mac_key = hashlib.sha256(b"mac_key").digest()

    message = b"Hello world 123"

    ciphertext, tag = encrypt_then_mac(enc_key, mac_key, message)

    print("Ciphertext:", ciphertext.hex())
    print("Tag:", tag.hex())

    decrypted = verify_then_decrypt(enc_key, mac_key, ciphertext, tag)
    print("Decrypted:", decrypted)

    return None


def main() -> None:
    # hmac_computation()
    aes_hmac_computation()

    return None


if __name__ == "__main__":
    main()
