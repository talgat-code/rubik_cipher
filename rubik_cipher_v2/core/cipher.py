import os
import base64

from .key_scheduler import KeyScheduler
from .rubik_block import RubikBlock

BLOCK_SIZE = 16


class RubikCipher:
    def __init__(self, key: str):
        self.scheduler = KeyScheduler(key)
        self.block = RubikBlock(self.scheduler)

    def _pad(self, data: bytes) -> bytes:
        pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data: bytes) -> bytes:
        if not data:
            raise ValueError("Empty data after decryption")
        pad_len = data[-1]
        if pad_len < 1 or pad_len > BLOCK_SIZE:
            raise ValueError("Invalid PKCS7 padding value")
        if any(data[-(i + 1)] != pad_len for i in range(pad_len)):
            raise ValueError("Invalid PKCS7 padding bytes")
        return data[:-pad_len]

    def encrypt(self, plaintext: str) -> str:
        data = self._pad(plaintext.encode("utf-8"))
        iv = os.urandom(BLOCK_SIZE)
        ciphertext = b""
        prev = iv
        for i in range(0, len(data), BLOCK_SIZE):
            block = bytes(data[i + j] ^ prev[j] for j in range(BLOCK_SIZE))
            encrypted = self.block.encrypt(block)
            ciphertext += encrypted
            prev = encrypted
        return base64.b64encode(iv + ciphertext).decode("utf-8")

    def decrypt(self, ciphertext_b64: str) -> str:
        raw = base64.b64decode(ciphertext_b64)
        if len(raw) < BLOCK_SIZE or (len(raw) - BLOCK_SIZE) % BLOCK_SIZE != 0:
            raise ValueError("Invalid ciphertext length")
        iv = raw[:BLOCK_SIZE]
        ciphertext = raw[BLOCK_SIZE:]
        plaintext = b""
        prev = iv
        for i in range(0, len(ciphertext), BLOCK_SIZE):
            block = ciphertext[i : i + BLOCK_SIZE]
            decrypted = self.block.decrypt(block)
            plaintext += bytes(decrypted[j] ^ prev[j] for j in range(BLOCK_SIZE))
            prev = block
        return self._unpad(plaintext).decode("utf-8")
