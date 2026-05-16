#!/usr/bin/env python3
"""CLI demo for RUBIK Cipher v2 — matches expected output format."""
import sys

sys.stdout.reconfigure(encoding="utf-8")

from rubik_cipher_v2.core.cipher import RubikCipher
from rubik_cipher_v2.analysis.security_analysis import SecurityAnalyzer

SEP = "═" * 50  # ══...
KEY = "MySecretKey2024!"
MSG = "Attack at dawn!"


def _section(n: int, title: str) -> None:
    print(f"\n[{n}] {title}")


def main() -> None:
    """Run all six demo sections in sequence."""
    print(SEP)
    print("  RUBIK Cipher v2 — Demo")
    print(SEP)

    cipher = RubikCipher(KEY)

    # ── [1] Basic encrypt / decrypt ──────────────────────────────────────
    _section(1, "Basic encrypt / decrypt")
    ct = cipher.encrypt(MSG)
    dec = cipher.decrypt(ct)
    print(f"  Key        : {KEY!r}")
    print(f"  Plaintext  : {MSG!r}")
    print(f"  Ciphertext : {ct}")
    print(f"  Decrypted  : {dec!r}")
    print(f"  Match      : {MSG == dec}")

    # ── [2] Randomized IV ────────────────────────────────────────────────
    _section(2, "Randomized IV")
    ct1 = cipher.encrypt(MSG)
    ct2 = cipher.encrypt(MSG)
    print(f"  Encrypt 1  : {ct1}")
    print(f"  Encrypt 2  : {ct2}")
    print(f"  Different  : {ct1 != ct2}")

    # ── [3] Wrong key ────────────────────────────────────────────────────
    _section(3, "Wrong key")
    try:
        RubikCipher("WrongKey!!!!!!!!").decrypt(ct)
    except ValueError as exc:
        print(f"  ValueError : {exc}")

    # ── [4] Block state visualization ─────────────────────────────────────
    _section(4, "Block state (hex 4×4)")
    padded = list(cipher._pad(MSG.encode("utf-8")))
    pt_block = padded[:16]
    ct_block = cipher._encrypt_block(pt_block)
    print("  Plaintext block:       Ciphertext block:")
    for r in range(4):
        pt_hex = " ".join(f"{pt_block[r * 4 + c]:02X}" for c in range(4))
        ct_hex = " ".join(f"{ct_block[r * 4 + c]:02X}" for c in range(4))
        arrow = "   →   " if r == 1 else "         "
        print(f"  {pt_hex}{arrow}   {ct_hex}")

    # ── [5] S-Box sample ─────────────────────────────────────────────────
    _section(5, "S-Box sample (first 16):")
    print("  " + " ".join(f"{v:02X}" for v in cipher.ks.sbox[:16]))

    # ── [6] Avalanche ────────────────────────────────────────────────────
    _section(6, "Avalanche (10 trials):")
    av = SecurityAnalyzer(cipher).avalanche_test(n_trials=10)
    mark = "✓" if av["avg_pct"] >= 30 else "✗"
    print(f"  Avg: ~{av['avg_pct']:.0f}% bit flip  {mark}")


if __name__ == "__main__":
    main()
