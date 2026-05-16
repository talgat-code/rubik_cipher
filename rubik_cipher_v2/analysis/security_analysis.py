import os
import time
import statistics

from ..core.key_scheduler import KeyScheduler
from ..core.rubik_block import RubikBlock
from ..core.cipher import RubikCipher


class SecurityAnalyzer:
    def __init__(self, key: str):
        self.key = key
        self.ks = KeyScheduler(key)
        self.rb = RubikBlock(self.ks)
        self.cipher = RubikCipher.__new__(RubikCipher)
        self.cipher.scheduler = self.ks
        self.cipher.block = self.rb

    def avalanche_effect(self, plaintext: str = "Hello, World!  ") -> dict:
        block = plaintext.encode("utf-8")[:16].ljust(16, b"\x00")
        original = self.rb.encrypt(bytes(block))

        bit_changes = []
        for byte_idx in range(16):
            for bit_idx in range(8):
                modified = bytearray(block)
                modified[byte_idx] ^= 1 << bit_idx
                enc_modified = self.rb.encrypt(bytes(modified))
                changed = sum(
                    bin(original[i] ^ enc_modified[i]).count("1") for i in range(16)
                )
                bit_changes.append(changed)

        return {
            "min_bits_changed": min(bit_changes),
            "max_bits_changed": max(bit_changes),
            "avg_bits_changed": statistics.mean(bit_changes),
            "total_bits": 128,
            "avg_percentage": statistics.mean(bit_changes) / 128 * 100,
        }

    def key_sensitivity(self, plaintext: str = "Test message 123") -> dict:
        block = plaintext.encode("utf-8")[:16].ljust(16, b"\x00")
        enc1 = self.rb.encrypt(bytes(block))

        alt_key = self.key[:-1] + chr(ord(self.key[-1]) ^ 1) if self.key else "a"
        ks2 = KeyScheduler(alt_key)
        rb2 = RubikBlock(ks2)
        enc2 = rb2.encrypt(bytes(block))

        changed = sum(bin(enc1[i] ^ enc2[i]).count("1") for i in range(16))
        return {
            "bits_changed": changed,
            "total_bits": 128,
            "percentage": changed / 128 * 100,
        }

    def encryption_speed(self, data_size_kb: int = 10) -> dict:
        data = os.urandom(data_size_kb * 1024).decode("latin-1")

        start = time.perf_counter()
        encrypted = self.cipher.encrypt(data)
        encrypt_time = time.perf_counter() - start

        start = time.perf_counter()
        self.cipher.decrypt(encrypted)
        decrypt_time = time.perf_counter() - start

        return {
            "data_size_kb": data_size_kb,
            "encrypt_time_s": encrypt_time,
            "decrypt_time_s": decrypt_time,
            "encrypt_speed_kbps": data_size_kb / encrypt_time,
            "decrypt_speed_kbps": data_size_kb / decrypt_time,
        }

    def run_all(self) -> dict:
        return {
            "avalanche": self.avalanche_effect(),
            "key_sensitivity": self.key_sensitivity(),
            "speed": self.encryption_speed(10),
        }
