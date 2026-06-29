# Encryption.py
# Person 3 — AES-256-GCM Encryption

import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def prepare_key(shared_secret: int) -> bytes:
    """
    Convert Person 1's Diffie-Hellman shared secret integer
    into a 32-byte AES-256 key using SHA-256.
    """
    secret_bytes = shared_secret.to_bytes(
        (shared_secret.bit_length() + 7) // 8, byteorder='big'
    )
    return hashlib.sha256(secret_bytes).digest()


def encrypt_message(aes_key: bytes, plaintext: str) -> tuple:
    """
    Encrypt a message using AES-256-GCM.
    Returns: (nonce, ciphertext) as bytes
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce, ciphertext


def decrypt_message(aes_key: bytes, nonce: bytes, ciphertext: bytes) -> str:
    """
    Decrypt and verify a message using AES-256-GCM.
    Returns the plaintext string, or an error message if tampered.
    """
    aesgcm = AESGCM(aes_key)
    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext_bytes.decode()
    except Exception:
        return "[ERROR] Decryption failed — message was tampered!"


def demonstrate_tampering(aes_key: bytes, nonce: bytes, ciphertext: bytes):
    """
    Flip one byte in the ciphertext to show GCM detects tampering.
    """
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF
    result = decrypt_message(aes_key, nonce, bytes(tampered))
    print(f"  Tamper test result: {result}")


if __name__ == "__main__":

    print("=" * 50)
    print("  AES-256-GCM Encryption Demo — Person 3")
    print("=" * 50)

    simulated_shared_secret = 123456789

    aes_key = prepare_key(simulated_shared_secret)
    print(f"\n[Key] AES-256 key (hex): {aes_key.hex()}")

    message = "Hello! This message is fully encrypted."
    nonce, ciphertext = encrypt_message(aes_key, message)
    print(f"\n[Encrypt]")
    print(f"  Original:   {message}")
    print(f"  Nonce:      {nonce.hex()}")
    print(f"  Ciphertext: {ciphertext.hex()}")

    decrypted = decrypt_message(aes_key, nonce, ciphertext)
    print(f"\n[Decrypt]")
    print(f"  Decrypted:  {decrypted}")

    print(f"\n[Tamper Test] Flipping one byte in ciphertext...")
    demonstrate_tampering(aes_key, nonce, ciphertext)

    print("\n" + "=" * 50)
    print("  Demo complete!")
    print("=" * 50)