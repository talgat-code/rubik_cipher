#!/usr/bin/env python3
"""CLI demo for RUBIK Cipher v2."""
import time

from rubik_cipher_v2.core.cipher import RubikCipher
from rubik_cipher_v2.analysis.security_analysis import SecurityAnalyzer

SEP = "=" * 60


def main():
    print(SEP)
    print("        RUBIK Cipher v2 — Demo")
    print(SEP)

    key = "demo_secret_key_2024"
    message = "Hello from RUBIK Cipher v2! This is a secure test message."

    print(f"\n  Key       : {key}")
    print(f"  Plaintext : {message}")

    print(f"\n  [1/3] Deriving key material (PBKDF2, 100k iterations)...")
    cipher = RubikCipher(key)

    start = time.perf_counter()
    ciphertext = cipher.encrypt(message)
    enc_ms = (time.perf_counter() - start) * 1000

    start = time.perf_counter()
    decrypted = cipher.decrypt(ciphertext)
    dec_ms = (time.perf_counter() - start) * 1000

    print(f"\n  Ciphertext (b64): {ciphertext[:60]}...")
    print(f"  Decrypted       : {decrypted}")
    print(f"  Encrypt time    : {enc_ms:.2f} ms")
    print(f"  Decrypt time    : {dec_ms:.2f} ms")
    print(f"  Round-trip OK   : {message == decrypted}")

    print(f"\n{SEP}")
    print("  Security Analysis")
    print(SEP)

    print("\n  [2/3] Avalanche effect (128 single-bit flips)...")
    analyzer = SecurityAnalyzer(key)
    av = analyzer.avalanche_effect()
    print(f"    Avg bits changed : {av['avg_bits_changed']:.2f} / 128  ({av['avg_percentage']:.1f}%)")
    print(f"    Min / Max        : {av['min_bits_changed']} / {av['max_bits_changed']}")

    print("\n  [3/3] Key sensitivity & speed...")
    ks = analyzer.key_sensitivity()
    sp = analyzer.encryption_speed(10)
    print(f"    Key sensitivity  : {ks['bits_changed']} / 128 bits differ ({ks['percentage']:.1f}%)")
    print(f"    Encrypt speed    : {sp['encrypt_speed_kbps']:.1f} KB/s")
    print(f"    Decrypt speed    : {sp['decrypt_speed_kbps']:.1f} KB/s")

    print(f"\n{SEP}")
    print("  Demo complete.")
    print(SEP)


if __name__ == "__main__":
    main()
