import os
import hmac
import hashlib
import random

SHARED_KEY = b"placeholder_key_from_person1"   # used for standalone testing
seen_nonces = set()      #Stores all the nonce values that had been previously used/seen.

def sign(message: str) -> dict:

    nonce = os.urandom(8).hex() #Generates a random nonce and converts it into hexadecimal string formart.    
    payload = f"{nonce}:{message}".encode() #Message and nonce combined and converted into bytes format.
    signature = hmac.new(SHARED_KEY, payload, hashlib.sha256).hexdigest() #Computes the HMAC-SHA256 tag.
    return {"message": message, "nonce": nonce, "hmac": signature} 


def verify(packet: dict) -> tuple:

    if packet["nonce"] in seen_nonces:
        return False, "[*]REPLAY ATTACK — nonce already used" #This detects Replay attacks by checking re-used nonces.

    payload = f"{packet['nonce']}:{packet['message']}".encode()
    expected = hmac.new(SHARED_KEY, payload, hashlib.sha256).hexdigest() #This generates the expected HMAC signature for comparison with the one sent to check for tampering.

    if not hmac.compare_digest(expected, packet["hmac"]):
        return False, "[*]TAMPERED — HMAC mismatch"

    seen_nonces.add(packet["nonce"])
    return True, packet["message"]


if __name__ == "__main__":
    print("=" * 50)
    print("  HMAC AUTHENTICATION DEMO")
    print("=" * 50)

    pkt = sign("Transfer ksh 1000 to Alice")
    print(f"\n[Signed Packet]")
    print(f"  message : {pkt['message']}")
    print(f"  nonce   : {pkt['nonce']}")
    print(f"  hmac    : {pkt['hmac']}")

    ok, result = verify(pkt)
    print(f"\n[Verify 1 — Original]")
    print(f"  Result: {ok} — {result}")

    tampered = dict(pkt)
    tampered["message"] = "Attacker transfering ksh 9000 to himself"
    ok, result = verify(tampered)
    print(f"\n[Verify 2 — Tampered]")
    print(f"  Result: {ok} — {result}")

    ok, result = verify(pkt)
    print(f"\n[Verify 3 — Replay]")
    print(f"  Result: {ok} — {result}")

    print("\n" + "=" * 50)
    print("  Demo complete!")
    print("=" * 50)
