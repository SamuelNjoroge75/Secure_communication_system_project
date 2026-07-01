import random

p = 23   # prime modulus
g = 5    # primitive root / base


alice_private = random.randint(2, p - 2)
bob_private   = random.randint(2, p - 2)


alice_public = pow(g, alice_private, p)
bob_public   = pow(g, bob_private,   p)


alice_shared = pow(bob_public,   alice_private, p)
bob_shared   = pow(alice_public, bob_private,   p)

assert alice_shared == bob_shared, "ERROR: Shared secrets do not match!"
shared_secret = alice_shared


if __name__ == "__main__":
    print("=" * 50)
    print("DIFFIE-HELLMAN KEY EXCHANGE")
    print("=" * 50)

    print(f"\n[Step 1] Public Parameters")
    print(f"  Prime (p) = {p}")
    print(f"  Generator (g) = {g}")

    print(f"\n[Step 2] Private Keys (never shared)")
    print(f"  Alice's private key (a) = {alice_private}")
    print(f"  Bob's   private key (b) = {bob_private}")

    print(f"\n[Step 3] Public Keys (exchanged over channel)")
    print(f"  Alice's public key (A = g^a mod p) = {alice_public}")
    print(f"  Bob's   public key (B = g^b mod p) = {bob_public}")

    print(f"\n[Step 4] Shared Secret Derivation")
    print(f"  Alice computes: B^a mod p = {alice_shared}")
    print(f"  Bob   computes: A^b mod p = {bob_shared}")

    print(f"\n[Result] Shared Secret = {shared_secret}")
    print("  ✓ Both parties derived the same secret.")
    print(f"\n  → Hand off to Person 3 (Encryption): key = {shared_secret}")
    print("=" * 50)