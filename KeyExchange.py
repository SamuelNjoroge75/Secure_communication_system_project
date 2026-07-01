"""
Person 1 — Key Exchange
Diffie-Hellman Key Exchange
Produces a shared secret for use by Person 3 (Encryption)
"""

import random

# ─────────────────────────────────────────────
# Step 1: Public parameters (p must be prime, g is primitive root)
# ─────────────────────────────────────────────
p = 23   # prime modulus
g = 5    # primitive root / base

print("=" * 50)
print("DIFFIE-HELLMAN KEY EXCHANGE")
print("=" * 50)
print(f"\n[Step 1] Public Parameters")
print(f"  Prime (p) = {p}")
print(f"  Generator (g) = {g}")

# ─────────────────────────────────────────────
# Step 2: Generate private keys (kept secret)
# ─────────────────────────────────────────────
alice_private = random.randint(2, p - 2)
bob_private   = random.randint(2, p - 2)

print(f"\n[Step 2] Private Keys (never shared)")
print(f"  Alice's private key (a) = {alice_private}")
print(f"  Bob's   private key (b) = {bob_private}")

# ─────────────────────────────────────────────
# Step 3: Compute public keys  A = g^a mod p
# ─────────────────────────────────────────────
alice_public = pow(g, alice_private, p)
bob_public   = pow(g, bob_private,   p)

print(f"\n[Step 3] Public Keys (exchanged over channel)")
print(f"  Alice's public key (A = g^a mod p) = {alice_public}")
print(f"  Bob's   public key (B = g^b mod p) = {bob_public}")

# ─────────────────────────────────────────────
# Step 4: Derive shared secret
#   Alice computes: B^a mod p
#   Bob   computes: A^b mod p
#   Both arrive at the same result
# ─────────────────────────────────────────────
alice_shared = pow(bob_public,   alice_private, p)
bob_shared   = pow(alice_public, bob_private,   p)

print(f"\n[Step 4] Shared Secret Derivation")
print(f"  Alice computes: B^a mod p = {alice_shared}")
print(f"  Bob   computes: A^b mod p = {bob_shared}")

assert alice_shared == bob_shared, "ERROR: Shared secrets do not match!"

shared_secret = alice_shared
print(f"\n[Result] Shared Secret = {shared_secret}")
print("  ✓ Both parties derived the same secret.")
print(f"\n  → Hand off to Person 3 (Encryption): key = {shared_secret}")
print("=" * 50)
