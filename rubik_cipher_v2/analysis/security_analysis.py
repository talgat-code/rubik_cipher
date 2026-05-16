"""Cryptographic analysis utilities for RUBIK Cipher v2."""
import base64
import math
import os
import random
import time

_COL_W: int = 22
_KEY_LENGTHS: list[int] = [8, 12, 16, 20, 24]


class SecurityAnalyzer:
    """Runs statistical and comparative security tests on a RubikCipher instance."""

    def __init__(self, cipher) -> None:
        """Attach the analyzer to an existing cipher.

        Args:
            cipher: A fully initialised RubikCipher instance.
        """
        self.cipher = cipher

    # ── avalanche ─────────────────────────────────────────────────────────────

    def avalanche_test(self, n_trials: int = 500) -> dict:
        """Measure the avalanche effect: single-bit input flip → output bit changes.

        For each trial a random 16-byte block is encrypted, then re-encrypted
        with one random bit flipped.  Differing output bits are counted.

        Args:
            n_trials: Number of random trials.

        Returns:
            Dict with keys avg_bits, avg_pct, min, max.
        """
        changes: list[int] = []
        for _ in range(n_trials):
            block = list(os.urandom(16))
            modified = block.copy()
            modified[random.randint(0, 15)] ^= 1 << random.randint(0, 7)
            enc1 = self.cipher._encrypt_block(block)
            enc2 = self.cipher._encrypt_block(modified)
            diff = sum(bin(enc1[i] ^ enc2[i]).count("1") for i in range(16))
            changes.append(diff)
        avg = sum(changes) / len(changes)
        return {
            "avg_bits": avg,
            "avg_pct": avg / 128 * 100,
            "min": min(changes),
            "max": max(changes),
        }

    # ── key space ─────────────────────────────────────────────────────────────

    def key_space_report(self) -> dict:
        """Compute key-space size and bit-security for common password lengths.

        Assumes printable ASCII (95 characters) for each position.

        Returns:
            Dict keyed by password length (8, 12, 16, 20, 24).
            Each value is a dict with 'combinations' and 'bit_security'.
        """
        result: dict[int, dict] = {}
        for n in _KEY_LENGTHS:
            combos = 95 ** n
            result[n] = {
                "combinations": combos,
                "bit_security": math.log2(combos),
            }
        return result

    # ── frequency / entropy ───────────────────────────────────────────────────

    def frequency_analysis_test(self, plaintext: str) -> dict:
        """Encrypt 100 identical characters and measure ciphertext byte distribution.

        A high Shannon entropy (≈ 8 bits) indicates excellent diffusion.

        Args:
            plaintext: Source string; its first character is repeated 100 times.

        Returns:
            Dict with unique_bytes, total_bytes, entropy_score.
        """
        sample = (plaintext[0] if plaintext else "A") * 100
        ct_bytes = base64.b64decode(self.cipher.encrypt(sample))[16:]  # skip IV
        freq: dict[int, int] = {}
        for b in ct_bytes:
            freq[b] = freq.get(b, 0) + 1
        total = len(ct_bytes)
        entropy = -sum(c / total * math.log2(c / total) for c in freq.values())
        return {
            "unique_bytes": len(freq),
            "total_bytes": total,
            "entropy_score": entropy,
        }

    # ── comparison table ──────────────────────────────────────────────────────

    def compare_with_classics(self) -> str:
        """Return a formatted multi-line comparison table of classical vs RUBIK ciphers.

        Columns: Caesar, Vigenère, RUBIK v1, RUBIK v2.
        Data sourced from the RUBIK Cipher v2 specification.
        """
        W = _COL_W
        sep = "=" * (20 + W * 4)
        hdr = (
            f"{'Property':<20}"
            f"{'Caesar':>{W}}{'Vigenere':>{W}}{'RUBIK v1':>{W}}{'RUBIK v2':>{W}}"
        )
        rows = [
            ("Key space (16-char)", "25",         "6.6e15",      "4.4e31",      "4.4e31"),
            ("Key derivation",      "none",        "none",        "LCG (weak)",  "PBKDF2-SHA256"),
            ("Freq. resistance",    "none",        "partial",     "good",        "excellent"),
            ("Avalanche effect",    "~0%",         "~0%",         "3.9% (bad)",  "~50% (ideal)"),
            ("Rounds",              "1",           "1",           "4",           "8"),
            ("MixColumns",          "no",          "no",          "no",          "yes (GF 2^8)"),
            ("CBC mode",            "no",          "no",          "yes",         "yes"),
            ("Brute-force viable?", "Yes (<1 ms)", "No (IC)",     "Unlikely",    "No"),
        ]
        lines = [hdr, sep]
        for label, *vals in rows:
            lines.append(f"{label:<20}" + "".join(f"{v:>{W}}" for v in vals))
        lines += [
            "",
            "  RUBIK v2 key material : 512 bytes via PBKDF2-SHA256 (100 000 iterations)",
            "  Effective key security : 448 bits of derived state",
        ]
        return "\n".join(lines)

    # ── benchmark ─────────────────────────────────────────────────────────────

    def benchmark(self, message_size_kb: int = 10) -> dict:
        """Time encryption and decryption of a random message.

        Args:
            message_size_kb: Size of the test message in kilobytes.

        Returns:
            Dict with message_size_kb, encrypt_ms, decrypt_ms,
            encrypt_kbps, decrypt_kbps.
        """
        data = os.urandom(message_size_kb * 1024).decode("latin-1")
        t0 = time.perf_counter()
        encrypted = self.cipher.encrypt(data)
        enc_ms = (time.perf_counter() - t0) * 1000
        t0 = time.perf_counter()
        self.cipher.decrypt(encrypted)
        dec_ms = (time.perf_counter() - t0) * 1000
        return {
            "message_size_kb": message_size_kb,
            "encrypt_ms": enc_ms,
            "decrypt_ms": dec_ms,
            "encrypt_kbps": message_size_kb / (enc_ms / 1000),
            "decrypt_kbps": message_size_kb / (dec_ms / 1000),
        }
