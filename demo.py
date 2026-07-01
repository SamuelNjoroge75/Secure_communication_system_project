from flask import Flask, render_template, jsonify, request
import Authentication
from Key_exchange import shared_secret, p, g, alice_private, bob_private, alice_public, bob_public, alice_shared, bob_shared
from Encryption import prepare_key, encrypt_message, decrypt_message
import threading
import webbrowser

app = Flask(__name__)

# Transfers Person 1's shared secret into Person 2's authentication layer ──
Authentication.SHARED_KEY = shared_secret.to_bytes(
    (shared_secret.bit_length() + 7) // 8, byteorder='big'
)

# Derives AES key from shared secret for Person 3
aes_key = prepare_key(shared_secret)

# Stores last signed packet and encrypted packet
last_packet = {}
last_enc    = {}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/keyexchange")
def key_exchange_info():
    return jsonify({
        "p": p, "g": g,
        "alice_private": alice_private,
        "bob_private":   bob_private,
        "alice_public":  alice_public,
        "bob_public":    bob_public,
        "alice_shared":  alice_shared,
        "bob_shared":    bob_shared,
        "shared_secret": shared_secret,
        "match": alice_shared == bob_shared
    })


@app.route("/api/sign", methods=["POST"])
def sign():
    global last_packet, last_enc
    data    = request.json
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"error": "Message cannot be empty"}), 400
    # Reset state for a fresh demo run
    Authentication.seen_nonces.clear()
    last_packet = Authentication.sign(message)
    last_enc    = {}
    return jsonify(last_packet)


@app.route("/api/verify", methods=["POST"])
def verify_original():
    if not last_packet:
        return jsonify({"error": "Sign a message first"}), 400
    ok, result = Authentication.verify(dict(last_packet))
    return jsonify({"success": ok, "result": result})


@app.route("/api/tamper", methods=["POST"])
def verify_tampered():

    if not last_packet:
        return jsonify({"error": "Sign a message first"}), 400
    import hmac, hashlib
    tampered = dict(last_packet)
    tampered["message"] = "Transfer 9999 KES to Attacker"
    payload  = f"{tampered['nonce']}:{tampered['message']}".encode()
    expected = hmac.new(Authentication.SHARED_KEY, payload, hashlib.sha256).hexdigest()
    tag_matches = hmac.compare_digest(expected, tampered["hmac"])
    return jsonify({
        "success": tag_matches,
        "result": "AUTHENTIC" if tag_matches else "TAMPERED — HMAC mismatch",
        "tampered_message": tampered["message"]
    })


@app.route("/api/replay", methods=["POST"])
def verify_replay():

    if not last_packet:
        return jsonify({"error": "Sign a message first"}), 400
    # If nonce hasn't been recorded yet, verify first then replay
    if last_packet["nonce"] not in Authentication.seen_nonces:
        Authentication.verify(dict(last_packet))   # record the nonce
    ok, result = Authentication.verify(dict(last_packet))
    return jsonify({"success": ok, "result": result})


@app.route("/api/encrypt", methods=["POST"])
def encrypt():
    global last_enc
    data    = request.json
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"error": "Message cannot be empty"}), 400
    nonce, ciphertext = encrypt_message(aes_key, message)
    last_enc = {
        "original":   message,
        "nonce":      nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "aes_key":    aes_key.hex()
    }
    return jsonify(last_enc)


@app.route("/api/decrypt", methods=["POST"])
def decrypt():
    if not last_enc:
        return jsonify({"error": "Encrypt a message first"}), 400
    try:
        nonce      = bytes.fromhex(last_enc["nonce"])
        ciphertext = bytes.fromhex(last_enc["ciphertext"])
        result     = decrypt_message(aes_key, nonce, ciphertext)
        success    = not result.startswith("[ERROR]")
        return jsonify({"result": result, "success": success})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/encrypt_tamper", methods=["POST"])
def encrypt_tamper():
    if not last_enc:
        return jsonify({"error": "Encrypt a message first"}), 400
    try:
        nonce      = bytes.fromhex(last_enc["nonce"])
        ciphertext = bytes.fromhex(last_enc["ciphertext"])
        tampered   = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        result     = decrypt_message(aes_key, nonce, bytes(tampered))
        return jsonify({"result": result, "success": False})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    
    print("\n" + "=" * 55)
    print("  Secure Communication System — Dashboard")
    print("  Open your browser at: http://127.0.0.1:5000")
    print("=" * 55 + "\n")

        # Open browser after short delay to give Flask time to start
    threading.Timer(1.2, lambda: webbrowser.open("http://127.0.0.1:5000")).start()

    app.run(debug=False, port=5000)