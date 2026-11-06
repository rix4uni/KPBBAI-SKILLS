---
name: classical-cipher-analysis
description: Classical cipher identification and cryptanalysis — Caesar/ROT13, Vigenère (Kasiski/IC analysis), substitution ciphers (frequency analysis), Playfair, Rail Fence, columnar transposition, XOR cipher analysis, and CTF cipher identification workflow.
sources: hack_skills, bug_bounty_reports
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
---

# SKILL: Classical Cipher Analysis — Identification & Cryptanalysis

> **AI LOAD INSTRUCTION**: Classical ciphers appear frequently in CTF challenges. Covers identification techniques (letter frequency, digrams, keyword patterns), automated analysis tools, and manual cryptanalysis workflows for all major cipher types. Base models often skip the identification step and jump to wrong cipher type, or miss that text may be base64/hex encoded before the cipher is applied.

## 0. RELATED ROUTING

- steganography-techniques — cipher text may be hidden in steganographic media
- hash-attack-techniques — if the "cipher" is actually a hash function

---

## 1. IDENTIFICATION WORKFLOW

```
Received ciphertext → Analyze:
1. Character set? (A-Z only? hex? base64? mixed?)
2. All caps / lowercase? (may indicate specific cipher)
3. Spaces preserved? (usually preserved in classical ciphers)
4. Length statistics (letter frequencies)
5. Try online tools: quipqiup.com, cryptoclub.org, dcode.fr
```

### Character Set Clues

| Character Set | Likely Encoding/Cipher |
|---|---|
| `0-9, A-F` only | Hex encoded — decode first |
| `A-Za-z0-9+/=` | Base64 — decode first |
| `A-Z` only, 25-char freq dist | Substitution cipher |
| Numbers only | Baconian, Polybius, or simple number-to-letter |
| `[`, `]`, `.`, `,` | Brainfuck, ook!, or other esoteric languages |
| Binary (`0` and `1`) | Binary encoding, Baudot, Morse |
| Symbols only | Symbol substitution (Wingdings, etc.) |

---

## 2. CAESAR CIPHER / ROT-13

**Identification**: single-shift substitution, same frequency distribution as plaintext, uniform character mapping.

### Brute Force

```python
def caesar_brute(ciphertext):
    for shift in range(1, 26):
        decoded = ""
        for c in ciphertext:
            if c.isalpha():
                offset = 65 if c.isupper() else 97
                decoded += chr((ord(c) - offset - shift) % 26 + offset)
            else:
                decoded += c
        print(f"Shift {shift:2d}: {decoded[:60]}")

caesar_brute("KHOOR ZRUOG")
```

### ROT-13 (Special Case: shift=13)

```python
import codecs
print(codecs.encode("URYYB JBEYQ", 'rot_13'))  # → HELLO WORLD

# Bash:
echo "URYYB JBEYQ" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

---

## 3. VIGENÈRE CIPHER

**Identification**: repeating key, frequency distribution closer to flat (more uniform than Caesar).

### Kasiski Test (Find Key Length)

```python
def find_key_length_kasiski(ciphertext, min_len=3, max_len=5):
    # Find repeated trigrams and their distances
    ciphertext = ciphertext.replace(" ", "").upper()
    distances = []
    
    for size in range(min_len, max_len + 1):
        for i in range(len(ciphertext) - size):
            gram = ciphertext[i:i+size]
            for j in range(i+size, len(ciphertext) - size):
                if ciphertext[j:j+size] == gram:
                    distances.append(j - i)
    
    # Find GCD of distances → likely key length
    from math import gcd
    from functools import reduce
    if distances:
        key_len = reduce(gcd, distances)
        print(f"Likely key length: {key_len}")
        print(f"All distances: {distances[:10]}")
```

### Index of Coincidence (IC)

```python
def index_of_coincidence(text):
    text = ''.join(c for c in text.upper() if c.isalpha())
    n = len(text)
    if n < 2: return 0
    freq = [text.count(chr(i + 65)) for i in range(26)]
    return sum(f * (f - 1) for f in freq) / (n * (n - 1))
# IC ≈ 0.065 → English plaintext (monoalphabetic cipher)
# IC ≈ 0.038 → random / polyalphabetic
```

### Vigenère Decryption (Known Key)

```python
def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    result = []
    ki = 0
    for c in ciphertext.upper():
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - 65
            result.append(chr((ord(c) - 65 - shift) % 26 + 65))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)
```

### Automated Tools

```bash
# Online: www.dcode.fr/vigenere-cipher (auto key length detection)
# quipqiup.com (monoalphabetic)

# Python: pycipher
pip install pycipher
python3 -c "import pycipher; print(pycipher.Vigenere('KEY').decipher('CIPHERTEXT'))"
```

---

## 4. MONOALPHABETIC SUBSTITUTION

**Identification**: 26 unique letter mapping, same frequency distribution as English but shifted/replaced.

### Frequency Analysis

```python
def frequency_analysis(ciphertext):
    ciphertext = ''.join(c for c in ciphertext.upper() if c.isalpha())
    freq = {}
    for c in ciphertext:
        freq[c] = freq.get(c, 0) + 1
    
    # Sort by frequency
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    
    # English frequency order (most to least common):
    # E T A O I N S H R D L C U M W F G Y P B V K J X Q Z
    
    print("Cipher freq → Likely English:")
    english = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    for i, (char, count) in enumerate(sorted_freq[:13]):
        print(f"  {char} ({count}) → {english[i] if i < len(english) else '?'}")
```

### Online Tools

```
quipqiup.com    → Automated frequency analysis solver
dcode.fr        → Comprehensive classical cipher toolkit
cryptoclub.org  → Visual frequency analysis tool
```

### Common Cipher Alphabets (Atbash)

```python
# Atbash: A→Z, B→Y, C→X, etc.
def atbash(text):
    return ''.join(chr(90 - (ord(c.upper()) - 65)) if c.isalpha() else c for c in text)

atbash("HELLO")  # → "SVOOL"
```

---

## 5. PLAYFAIR CIPHER

**Identification**: digram cipher (letter pairs), no J (or Q), 25-letter key matrix.

**Clues**: even-length ciphertext, rare letters like X appear frequently (padding), I and J treated same.

### Automated Analysis

```bash
# Online: dcode.fr/playfair-cipher
# Or use cryptanalysis tool with known plaintext
```

---

## 6. RAIL FENCE / TRANSPOSITION CIPHERS

### Rail Fence

```python
def rail_fence_decrypt(ciphertext, rails):
    n = len(ciphertext)
    # Build rail pattern
    rail = [[] for _ in range(rails)]
    direction = 1
    r = 0
    
    # Count positions per rail
    for i in range(n):
        rail[r].append(i)
        if r == 0: direction = 1
        elif r == rails - 1: direction = -1
        r += direction
    
    # Assign characters to rails
    idx = 0
    char_at = [''] * n
    for r in rail:
        for pos in r:
            char_at[pos] = ciphertext[idx]
            idx += 1
    
    return ''.join(char_at)

rail_fence_decrypt("HOLELWRD", 2)  # → "HELLOWORLD"
```

### Columnar Transposition

```python
# Columns are rearranged based on alphabetical order of key
def columnar_decrypt(ciphertext, key):
    num_cols = len(key)
    num_rows = len(ciphertext) // num_cols
    
    # Order columns by sorted key
    key_order = sorted(range(len(key)), key=lambda x: key[x])
    
    # Reconstruct grid
    col_len = num_rows
    cols = {}
    idx = 0
    for k in key_order:
        cols[k] = list(ciphertext[idx:idx + col_len])
        idx += col_len
    
    # Read row by row
    result = ''
    for r in range(num_rows):
        for c in range(num_cols):
            result += cols[c][r]
    return result
```

---

## 7. XOR CIPHER ANALYSIS

### Single-Byte XOR

```python
def xor_decrypt_single_byte(ciphertext_bytes):
    best_score = -1
    best_key = 0
    best_plaintext = ""
    
    for key in range(256):
        plaintext = bytes([b ^ key for b in ciphertext_bytes])
        try:
            text = plaintext.decode('ascii')
            # Score based on common English characters
            score = sum(1 for c in text.lower() if c in ' etaoinshrdlu')
            if score > best_score:
                best_score = score
                best_key = key
                best_plaintext = text
        except:
            pass
    
    print(f"Key: 0x{best_key:02X} ({chr(best_key) if 32 <= best_key < 127 else '?'})")
    print(f"Plaintext: {best_plaintext}")

# Usage:
import binascii
hex_cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
xor_decrypt_single_byte(binascii.unhexlify(hex_cipher))
```

### Repeating Key XOR (Vigenère-like)

```python
# Find key length via Hamming distance:
def hamming_distance(b1, b2):
    return sum(bin(a ^ b).count('1') for a, b in zip(b1, b2))

def find_xor_key_length(ciphertext, max_keysize=40):
    scores = []
    for keysize in range(2, max_keysize + 1):
        # Compare first N blocks of keysize bytes
        block1 = ciphertext[:keysize]
        block2 = ciphertext[keysize:2*keysize]
        distance = hamming_distance(block1, block2) / keysize
        scores.append((distance, keysize))
    
    scores.sort()
    return [s[1] for s in scores[:3]]  # Return top 3 likely key lengths
```

---

## 8. COMMON CTF CIPHER PATTERNS

### Bacon's Cipher (Binary-ish encoding)

```
A=AAAAA, B=AAAAB, C=AAABA, ... Z=BBBBB
Or use two alphabets/font sizes
```

### Polybius Square

```
  1  2  3  4  5
1 A  B  C  D  E
2 F  G  H  IJ K
3 L  M  N  O  P
4 Q  R  S  T  U
5 V  W  X  Y  Z

41 → Q, 11 → A, etc.
```

### Morse Code

```bash
# Decode Morse from text:
# ... .- -- .--. .-.. .
# Online: morsecode.world

# Python:
MORSE_CODE = {'.-':'A','-...':'B',etc.}
```

---

## 9. QUICK IDENTIFICATION TOOL

```python
def identify_cipher(ciphertext):
    ct = ''.join(c for c in ciphertext.upper() if c.isalpha())
    n = len(ct)
    
    # Character frequency
    freq = {c: ct.count(c) / n for c in set(ct)}
    unique_chars = len(freq)
    
    # Index of coincidence
    ic = sum(f * (n * f - 1) for f in freq.values()) / (n - 1) if n > 1 else 0
    
    print(f"Unique chars: {unique_chars}")
    print(f"IC: {ic:.4f} (English=0.0665, Random=0.0385)")
    
    if unique_chars <= 2:
        print("→ Binary encoding, Morse, or Bacon's cipher")
    elif unique_chars < 26 and ic > 0.06:
        print("→ Monoalphabetic substitution or Caesar cipher")
    elif unique_chars == 26 and ic > 0.06:
        print("→ Caesar or Atbash (all 26 letters, good IC)")
    elif ic < 0.045:
        print("→ Polyalphabetic (Vigenère) or strong cipher")
    elif 0.045 < ic < 0.06:
        print("→ Vigenère with medium key length, or transposition")
    else:
        print("→ Monoalphabetic substitution cipher")
```
