## UAHP v0.5.4 Cryptographic Parameters

### Critical: HKDF Shared Secret Derivation

All implementations MUST use these **exact** parameters for X25519 key exchange:

Algorithm: X25519 (Curve25519 ECDH)
KDF: HKDF-SHA256
- salt: null (empty bytes, not zero-filled)
- info: "UAHP_SESSION_v0.5" (exact string, UTF-8 encoded)
- output length: 32 bytes

**Python Reference Implementation:**
```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

shared_secret = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,  # CRITICAL: Must be None, not b''
    info=b"UAHP_SESSION_v0.5",  # CRITICAL: Exact bytes
).derive(raw_x25519_shared_secret)
```

**JavaScript/TypeScript Reference Implementation:**
```javascript
const { hkdfSync } = require('crypto');

// CRITICAL: Use hkdfSync, NOT a custom implementation
const sharedSecret = hkdfSync(
    'sha256',
    rawX25519SharedSecret,
    '',           // salt: empty string (not null in Node)
    'UAHP_SESSION_v0.5',
    32
);
```

**Common Implementation Errors:**
1. **Wrong salt**: Using `b''` (empty bytes) instead of `None` in Python
2. **Wrong info string**: Using `"UAHP_SESSION_v0.6"` or `"uahp_session_v0.5"`
3. **Case sensitivity**: Info string must be exactly `"UAHP_SESSION_v0.5"`
4. **Wrong length**: Deriving 16 or 64 bytes instead of 32
5. **Custom HKDF**: Implementing HKDF-Expand manually instead of using standard library

### X25519 Key Format
- Public keys: 32 bytes, base64-encoded
- Private keys: 32 bytes, clamped according to RFC 7748

### Ed25519 Signature Format
- Signatures: 64 bytes, base64-encoded
- Public keys: 32 bytes, base64-encoded
- Signing: RFC 8785 canonical JSON → UTF-8 bytes → Ed25519 sign

### AES-256-GCM Encryption
- Key: 32 bytes from HKDF output
- Nonce: 12 random bytes, base64-encoded in transmission
- Ciphertext: base64-encoded
- Tag: 16 bytes, appended to ciphertext (standard GCM)

### Verification

Test your implementation against the debug endpoint:
```bash
curl -X POST http://localhost:8000/debug/crypto/e2e \
  -H "Content-Type: application/json" \
  -d '{
    "alice_identity": {"uid": "...", "public_key": "..."},
    "bob_identity": {"uid": "...", "public_key": "..."},
    "payload": {"test": "data"}
  }'
```

Both `alice_secret_hex` and `bob_secret_hex` MUST match exactly.

### Known Incompatible Implementations

| Library | Issue | Fix |
|---------|-------|-----|
| `tweetnacl-js` HKDF | Custom implementation | Use `crypto.hkdfSync` |
| `libsodium.js` | Different HKDF default salt | Explicitly set salt to `null` |
| Python `cryptography` < 3.0 | HKDF API differences | Upgrade to latest |

### Test Vectors

```plain
X25519 shared secret (hex):
  (derive from alice_private × bob_public and bob_private × alice_public)

Expected HKDF output (hex):
  First 16 bytes: 7a3f... (TBD - run debug endpoint to get actual)
```

Run `python -m uahp.test_vectors` to generate cross-language test vectors.
