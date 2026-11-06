---
name: steganography-techniques
description: Steganography detection and extraction — LSB steganography (zsteg/stegsolve), DCT steganography (Steghide/F5), audio steganography (Sonic Visualizer/MP3Stego), file carving (binwalk/foremost), metadata analysis, whitespace/Unicode steganography, and CTF-focused stego workflow.
sources: hack_skills, bug_bounty_reports
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
---

# SKILL: Steganography Techniques — Detection & Extraction Playbook

> **AI LOAD INSTRUCTION**: Steganography hides data inside media files (images, audio, video, documents). This skill covers detection, analysis, and extraction workflows for all major stego techniques. Primarily relevant to CTF challenges. Base models often miss the systematic workflow and forget to check for multiple layers of hiding.

## 0. RELATED ROUTING

- classical-cipher-analysis — extracted data may be further encoded/encrypted
- hash-attack-techniques — if stego uses hash-based passwords for extraction

---

## 1. TRIAGE WORKFLOW (CTF)

```
Received file → Apply this order:
1. file <target>           # What type is it really?
2. strings <target>        # Visible ASCII strings
3. exiftool <target>       # Metadata
4. binwalk <target>        # Embedded files/signatures
5. xxd <target> | head    # Hex dump - check magic bytes
6. For images: stegsolve, zsteg, steghide
7. For audio: Audacity/Sonic Visualizer, Steghide
8. For text: whitespace, Unicode, invisible chars
```

---

## 2. IMAGE STEGANOGRAPHY

### 2.1 zsteg (PNG/BMP — LSB)

```bash
# Install:
gem install zsteg

# Basic scan (all channels):
zsteg image.png

# Specific bit plane:
zsteg -a image.png                    # All options
zsteg image.png -b 1 -o xy -v         # 1-bit LSB, xy order
zsteg image.png --lsb                  # LSB extraction
zsteg image.png --msb                  # MSB extraction
```

### 2.2 Steghide (JPEG/BMP/WAV/AU)

```bash
# Extract with no password:
steghide extract -sf image.jpg -p ""

# Extract with password:
steghide extract -sf image.jpg -p "password123"

# Try common passwords:
for p in "" "password" "secret" "flag" "ctf" "steghide"; do
  steghide extract -sf image.jpg -p "$p" 2>/dev/null && echo "Password: $p" && break
done

# Brute force with stegseek:
stegseek image.jpg /usr/share/wordlists/rockyou.txt

# Embed data (for creation):
steghide embed -cf image.jpg -sf secret.txt -p "password"
```

### 2.3 Stegsolve (LSB Visual Analysis)

```bash
# Java tool for visual analysis:
java -jar Stegsolve.jar

# Useful operations:
# File Format → shows file info
# Data Extract → manual LSB/MSB extraction
# Bit Plane → view each bit plane visually
# Stereo → compare two images
```

### 2.4 LSB Manual Analysis (Python)

```python
from PIL import Image

img = Image.open('image.png')
pixels = img.load()
width, height = img.size

# Extract LSB from red channel:
bits = []
for y in range(height):
    for x in range(width):
        r, g, b = pixels[x, y][:3]
        bits.append(r & 1)

# Convert bits to bytes:
message = []
for i in range(0, len(bits) - 8, 8):
    byte = int(''.join(str(b) for b in bits[i:i+8]), 2)
    if byte == 0:
        break
    message.append(chr(byte))
print(''.join(message))
```

### 2.5 F5 Steganography (JPEG DCT)

```bash
# F5 embeds data in JPEG DCT coefficients
# Detect: analyze histogram of DCT coefficients
# Extract:
java F5 x -e output.txt image.jpg          # Extract
# Or:
java F5 x -e output.txt -p password image.jpg
```

---

## 3. AUDIO STEGANOGRAPHY

### 3.1 Sonic Visualizer / Audacity

```bash
# Open in Sonic Visualizer and check:
# Spectrogram view (Layer → Add Spectrogram)
# → Data hidden in high frequencies often visible
# Check slow/fast channels

# Audacity: Analyze → Spectrum
# Look for unusual patterns in spectrogram
```

### 3.2 MP3Stego / WAV Steganography

```bash
# MP3Stego extraction:
mp3stego-decode -X input.mp3 -P password output.txt

# Steghide on WAV:
steghide extract -sf audio.wav -p "password"
```

### 3.3 DTMF Tones

```bash
# Decode DTMF tones (phone dial tones):
multimon-ng -t wav -a DTMF audio.wav

# Or online: dtmf.linesider.com
```

### 3.4 Morse Code Audio

```bash
# Decode Morse code from audio:
fldigi  # Amateur radio decoder, can decode Morse from audio
# Or: librewire/morse-decode
```

---

## 4. FILE CARVING

### 4.1 binwalk (Embedded Files)

```bash
# Scan for embedded files:
binwalk image.jpg

# Extract embedded files:
binwalk -e image.jpg         # Extract to _image.jpg.extracted/
binwalk --dd=".*" image.jpg  # Extract all signatures

# Common findings: embedded ZIP, PNG inside JPG, hidden text files
```

### 4.2 foremost (File Recovery)

```bash
# Carve files from raw data:
foremost -t all -o output/ image.jpg
foremost -i image.jpg -o carved/
```

### 4.3 Volatility (Memory Images)

```bash
# If input is a memory dump:
volatility -f memory.dmp imageinfo
volatility -f memory.dmp --profile=Win7SP1x64 filescan
volatility -f memory.dmp --profile=Win7SP1x64 dumpfiles -Q OFFSET -D output/
```

---

## 5. METADATA ANALYSIS

### exiftool

```bash
# Extract all metadata:
exiftool image.jpg

# Common hidden fields:
# Comment: (may contain data)
# XMP: (extended metadata)
# Artist, Copyright, Description fields
# GPS coordinates
# Software field (reveals editing history)
```

### Strings Analysis

```bash
# Extract all printable strings:
strings -n 8 image.jpg | head -50

# Look for Base64:
strings image.jpg | grep -E "[A-Za-z0-9+/]{20,}={0,2}"

# Look for hex-encoded data:
strings image.jpg | grep -E "[0-9a-fA-F]{16,}"
```

---

## 6. TEXT/WHITESPACE STEGANOGRAPHY

### Whitespace Steganography

```bash
# SNOW: hides data in trailing whitespace and tabs
# Extract:
snow -C -m "message" -p "password" input.txt

# Manual: check for unusual whitespace
cat -A input.txt  # Shows trailing spaces as $, tabs as ^I
```

### Unicode Steganography

```bash
# Zero-width characters used for steganography:
# U+200B (zero-width space)
# U+200C (zero-width non-joiner)
# U+200D (zero-width joiner)
# U+FEFF (BOM / zero-width no-break space)

# Detection:
python3 -c "
with open('text.txt', 'r', encoding='utf-8') as f:
    content = f.read()
    for i, c in enumerate(content):
        if ord(c) in [0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060, 0x2061]:
            print(f'Hidden char at pos {i}: U+{ord(c):04X}')
"

# Unicode stego tools:
# Unicode Steganography with Zero-Width Characters (zwsp.lol)
```

---

## 7. QR CODE / BARCODE

```bash
# Decode QR code from image:
zbarimg image.png

# Or use pyzbar:
python3 -c "
from pyzbar.pyzbar import decode
from PIL import Image
img = Image.open('image.png')
decoded = decode(img)
for d in decoded: print(d.data.decode('utf-8'))
"
```

---

## 8. CTF STEGO QUICK REFERENCE

```bash
# Standard toolkit commands:
file suspicious.jpg                    # File type
exiftool suspicious.jpg                # Metadata
strings suspicious.jpg                 # Strings
binwalk -e suspicious.jpg              # Embedded files
zsteg suspicious.png                   # LSB (PNG)
steghide extract -sf suspicious.jpg -p "" # Steghide (JPEG)
stegseek suspicious.jpg rockyou.txt    # Brute-force steghide
xxd suspicious.jpg | head -20          # Hex header

# Audio specific:
audacity audio.wav                     # Visual analysis
sonic-visualiser audio.wav             # Spectrogram
steghide extract -sf audio.wav -p ""   # Steghide on WAV
multimon-ng -t wav -a DTMF audio.wav   # DTMF decode
```
