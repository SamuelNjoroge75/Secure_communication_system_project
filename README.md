# Secure_communication_system_project
This is a school cryptographic project done by three students.

# Secure Communication System

This is a cryptography project built by three students demonstrating a secure end-to-end communication pipeline using Diffie-Hellman key exchange, HMAC-SHA256 authentication, and AES-256-GCM encryption.

---

## Team

| Person | Module | Technology |
|--------|--------|------------|
| P1-Tayshaun Gitonga | Key Exchange | Diffie-Hellman |
| P2-Samuel Njoroge | Authentication | HMAC-SHA256 |
| P3-Willis Nyaramba | Encryption | AES-256-GCM |

---

## How it works

The system is built in three layers that work together in sequence:

1. **Key Exchange** — Alice and Bob agree on a shared secret number over a public channel without ever transmitting the secret itself. This is done using Diffie-Hellman key exchange. The shared secret is then used as the key for the two layers below.

2. **Authentication** — Every message is signed using HMAC-SHA256 before it is sent. The receiver verifies the signature to confirm the message came from a legitimate party and was not tampered with in transit. A nonce system prevents replay attacks.

3. **Encryption** — The message is encrypted using AES-256-GCM so that its contents are unreadable to anyone who intercepts it. GCM mode also detects any tampering with the ciphertext.

---

## Project structure

```
Secure_communication_system_project/
│
├── KeyExchange.py        # Diffie-Hellman key exchange — Person 1
├── Authentication.py     # HMAC-SHA256 authentication — Samuel
├── Encryption.py         # AES-256-GCM encryption — Person 3
├── demo.py               # Flask server connecting all three modules
│
└── templates/
    └── index.html        # Live demo dashboard (runs in browser)
```

---

## Requirements

- Python 3.8 or higher
- Flask
- cryptography

Install dependencies:

```bash
pip install flask cryptography
```

---

## Running the project

### Run the full dashboard

```bash
python demo.py
```

Then open your browser and go to:

```
http://127.0.0.1:5000
```

### Run individual modules

Each module can also be run on its own for testing:

```bash
python KeyExchange.py
python Authentication.py
python Encryption.py
```

---

## Branches

| Branch | Owner | Purpose |
|--------|-------|---------|
| `main` | All | Final integrated code |
| `key-exchange` | Person 1 | Diffie-Hellman implementation |
| `authentication` | Samuel | HMAC authentication implementation |
| `encryption` | Person 3 | AES-256-GCM implementation |

---

## Course

**Unit:** Cryptography
**Institution:** Strathmore University
