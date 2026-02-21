import hashlib

BLOCK_SIZE = 64  # 512-bit blocks for SHA-256 (block - 64 bytes, output - 32 bytes)


# HMAC(K, m) = H( (K ⊕ opad) || H( (K ⊕ ipad) || m ) )
def hmac_sha256(key: bytes, message: bytes) -> bytes:
    if len(key) > BLOCK_SIZE:
        key = hashlib.sha256(key).digest()

    # Pad key to block size
    if len(key) < BLOCK_SIZE:
        key = key + b"\x00" * (BLOCK_SIZE - len(key))

    # HMAC standard
    ipad = bytes([0x36] * BLOCK_SIZE)
    opad = bytes([0x5C] * BLOCK_SIZE)

    key_xor_ipad = bytes([k ^ i for k, i in zip(key, ipad)])
    key_xor_opad = bytes([k ^ o for k, o in zip(key, opad)])

    # Inner hash
    inner_hash = hashlib.sha256(key_xor_ipad + message).digest()

    # Outer hash
    hmac_result = hashlib.sha256(key_xor_opad + inner_hash).digest()

    return hmac_result
