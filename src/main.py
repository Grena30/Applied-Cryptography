import hmac

from hmac_utils import hashlib, hmac_sha256

if __name__ == "__main__":
    key = b"secret_key"
    message = b"hello world"

    result = hmac_sha256(key, message)
    print("HMAC-SHA256:", result.hex())

    expected = hmac.new(key, message, hashlib.sha256).digest()
    print("Matches built-in:", result == expected)
