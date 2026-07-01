import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


def prepare_key(shared_secret: int) -> bytes:

    secret_bytes = shared_secret.to_bytes(
        (shared_secret.bit_length() + 7) // 8, byteorder='big'
    )
    return hashlib.sha256(secret_bytes).digest()


def encrypt_message(aes_key: bytes, plaintext: str) -> tuple:

    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce, ciphertext


def decrypt_message(aes_key: bytes, nonce: bytes, ciphertext: bytes) -> str:

    aesgcm = AESGCM(aes_key)
    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext_bytes.decode()
    except InvalidTag:
        return "[ERROR] Decryption failed — message was tampered!"


def demonstrate_tampering(aes_key: bytes, nonce: bytes, ciphertext: bytes):

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