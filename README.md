# RUBIK Cipher v2

A custom symmetric block cipher built as an educational cryptography project. Implements an 8-round substitution-permutation network with AES-derived primitives, PBKDF2 key derivation, and CBC mode encryption.

## Algorithm Overview

| Property | Value |
|---|---|
| Block size | 128 bits (4×4 byte grid) |
| Key derivation | PBKDF2-SHA256, 100 000 iterations, 512-byte output |
| Rounds | 8 |
| S-Box | Keyed Fisher-Yates shuffle (256 entries) |
| ShiftRows | Per-round, per-row rotation amounts from key material |
| MixColumns | AES GF(2^8) matrix with full inverse |
| Whitening | Pre/post XOR with key-derived 16-byte blocks |
| Mode | CBC with random 16-byte IV |
| Padding | PKCS7 |
| Output | Base64-encoded (text) or raw bytes (files) |

### Encryption Round (repeated 8 times)

```
SubBytes → ShiftRows → MixColumns → AddRoundKey
```

Pre-whitening applied before round 1; post-whitening applied after round 8.

### Key Material Layout (512 bytes)

```
master[  0:256] — S-Box seed (Fisher-Yates shuffle)
master[256:272] — Pre-whitening key
master[272:288] — Post-whitening key
master[288:320] — Row-shift amounts (4 bytes × 8 rounds)
master[320:448] — Round keys (16 bytes × 8 rounds)
```

## Project Structure

```
rubik_cipher/
├── rubik_cipher_v2/
│   ├── __init__.py          # Public API exports + __version__
│   ├── core/
│   │   ├── cipher.py        # RubikCipher — CBC encrypt/decrypt, file I/O
│   │   ├── key_scheduler.py # KeyScheduler — PBKDF2 + key material derivation
│   │   └── rubik_block.py   # RubikBlock — mutable 4x4 block operations
│   ├── analysis/
│   │   └── security_analysis.py  # SecurityAnalyzer — avalanche, entropy, benchmarks
│   ├── gui/
│   │   └── app.py           # RubikCipherApp — tkinter GUI (Catppuccin Mocha theme)
│   └── tests/
│       └── test_cipher.py   # pytest suite (15 tests)
├── demo.py                  # Command-line demonstration
├── main.py                  # GUI entry point
├── requirements.txt
└── pyproject.toml
```

## Quick Start

**Requirements:** Python 3.10+, no runtime dependencies.

```bash
# Run the GUI
python main.py

# Run the CLI demo
python demo.py

# Run tests
python -m pytest rubik_cipher_v2/tests/ -v
```

## Usage

### Python API

```python
from rubik_cipher_v2 import RubikCipher, SecurityAnalyzer

cipher = RubikCipher("my-secret-key")

# Text encryption (returns Base64 string)
ciphertext = cipher.encrypt("Hello, world!")
plaintext  = cipher.decrypt(ciphertext)

# File encryption (raw bytes output)
cipher.encrypt_file("document.pdf", "document.pdf.rubik")
cipher.decrypt_file("document.pdf.rubik", "document_out.pdf")

# Security analysis
analyzer = SecurityAnalyzer(cipher)
print(analyzer.avalanche_test(n_trials=500))
print(analyzer.compare_with_classics())
```

### GUI

The GUI provides two tabs:

- **Cipher** — paste text or load a file, enter a key, encrypt or decrypt, copy or save the result
- **Analysis** — run all security tests and view an interactive report (avalanche effect, entropy, key space, benchmark, comparison table)

## Security Properties

| Metric | Value |
|---|---|
| Avalanche effect | ~50% (ideal) |
| Entropy score | >7 bits/byte on uniform input |
| Key security (16-char ASCII key) | ~104 bits |
| Brute-force resistance | No (comparable to AES key schedule quality) |

**Note:** This is an educational cipher. It has not undergone professional cryptanalysis and should not be used to protect sensitive data in production.

## Testing

```bash
python -m pytest rubik_cipher_v2/tests/test_cipher.py -v
```

Test coverage includes: encrypt/decrypt round-trips, empty and Unicode strings, wrong-key rejection, random IV uniqueness, Base64 output validity, 100 KB messages, binary file encryption, avalanche threshold, key space report, entropy scoring, benchmark timings, and comparison table format.
