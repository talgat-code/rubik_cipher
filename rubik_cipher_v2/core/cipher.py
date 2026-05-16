"""High-level RUBIK Cipher v2 API — CBC mode with PKCS7 padding."""
import base64
import os

from .key_scheduler import KeyScheduler
from .rubik_block import RubikBlock

ROUNDS: int = 8
BLOCK_SIZE: int = 16


class RubikCipher:
    """RUBIK Cipher v2: symmetric block cipher in CBC mode.

    Encrypts / decrypts UTF-8 strings and binary files using a
    key-derived 8-round substitution–permutation network with
    GF(2⁸) column mixing, pre/post whitening, and a random IV.
    """

    def __init__(self, key: str) -> None:
        """Derive all key material from *key* and build the cipher.

        Args:
            key: Plaintext password; any non-empty string.
        """
        self.ks = KeyScheduler(key)
        self.sbox: list[int] = self.ks.sbox
        self.inv_sbox: list[int] = self.ks.inv_sbox

    # ── block-level operations (public for testing / demo) ─────────────

    def _encrypt_block(self, block: list[int]) -> list[int]:
        """Encrypt a single 16-byte block (no CBC, no padding).

        Args:
            block: 16 plaintext bytes as integers.

        Returns:
            16 ciphertext bytes as integers.
        """
        rb = RubikBlock(block)
        rb.xor_key(self.ks.pre_whitening_key)
        for rnd in range(ROUNDS):
            rb.substitute(self.sbox)
            rb.shift_rows(self.ks.get_row_shifts(rnd))
            rb.mix_columns()
            rb.xor_key(self.ks.get_round_key(rnd))
        rb.xor_key(self.ks.post_whitening_key)
        return rb.to_bytes()

    def _decrypt_block(self, block: list[int]) -> list[int]:
        """Decrypt a single 16-byte block (no CBC, no padding).

        Args:
            block: 16 ciphertext bytes as integers.

        Returns:
            16 plaintext bytes as integers.
        """
        rb = RubikBlock(block)
        rb.xor_key(self.ks.post_whitening_key)
        for rnd in range(ROUNDS - 1, -1, -1):
            rb.xor_key(self.ks.get_round_key(rnd))
            rb.unmix_columns()
            rb.unshift_rows(self.ks.get_row_shifts(rnd))
            rb.unsubstitute(self.inv_sbox)
        rb.xor_key(self.ks.pre_whitening_key)
        return rb.to_bytes()

    # ── text encrypt / decrypt ─────────────────────────────────────────

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a UTF-8 string and return a Base64-encoded ciphertext.

        A random 16-byte IV is prepended to the output.  The same
        plaintext encrypted twice produces different ciphertext.

        Args:
            plaintext: Any UTF-8 string (including empty).

        Returns:
            Base64 string encoding [IV | ciphertext blocks].
        """
        data = self._pad(plaintext.encode("utf-8"))
        iv = os.urandom(BLOCK_SIZE)
        ct = b""
        prev = list(iv)
        for i in range(0, len(data), BLOCK_SIZE):
            block = [data[i + j] ^ prev[j] for j in range(BLOCK_SIZE)]
            enc = self._encrypt_block(block)
            ct += bytes(enc)
            prev = enc
        return base64.b64encode(iv + ct).decode("utf-8")

    def decrypt(self, ciphertext_b64: str) -> str:
        """Decrypt a Base64-encoded ciphertext produced by *encrypt*.

        Args:
            ciphertext_b64: Base64 string from *encrypt*.

        Returns:
            Original UTF-8 plaintext.

        Raises:
            ValueError: If the ciphertext length is invalid or padding is corrupt.
        """
        raw = base64.b64decode(ciphertext_b64)
        if len(raw) < BLOCK_SIZE or (len(raw) - BLOCK_SIZE) % BLOCK_SIZE != 0:
            raise ValueError("Invalid ciphertext length.")
        iv = list(raw[:BLOCK_SIZE])
        ct = raw[BLOCK_SIZE:]
        pt = b""
        prev = iv
        for i in range(0, len(ct), BLOCK_SIZE):
            block = list(ct[i : i + BLOCK_SIZE])
            dec = self._decrypt_block(block)
            pt += bytes(d ^ p for d, p in zip(dec, prev))
            prev = block
        return self._unpad(pt).decode("utf-8")

    # ── file encrypt / decrypt ─────────────────────────────────────────

    def encrypt_file(self, input_path: str, output_path: str) -> None:
        """Encrypt a binary file and write ciphertext to *output_path*.

        Args:
            input_path:  Path to the source file.
            output_path: Destination path; receives [IV | ciphertext].
        """
        with open(input_path, "rb") as f:
            raw = f.read()
        data = self._pad(raw)
        iv = os.urandom(BLOCK_SIZE)
        ct = b""
        prev = list(iv)
        for i in range(0, len(data), BLOCK_SIZE):
            block = [data[i + j] ^ prev[j] for j in range(BLOCK_SIZE)]
            enc = self._encrypt_block(block)
            ct += bytes(enc)
            prev = enc
        with open(output_path, "wb") as f:
            f.write(iv + ct)

    def decrypt_file(self, input_path: str, output_path: str) -> None:
        """Decrypt a file produced by *encrypt_file*.

        Args:
            input_path:  Path to the encrypted file.
            output_path: Destination path for the recovered plaintext.

        Raises:
            ValueError: If the file length is invalid or padding is corrupt.
        """
        with open(input_path, "rb") as f:
            raw = f.read()
        if len(raw) < BLOCK_SIZE or (len(raw) - BLOCK_SIZE) % BLOCK_SIZE != 0:
            raise ValueError("Invalid ciphertext length.")
        iv = list(raw[:BLOCK_SIZE])
        ct = raw[BLOCK_SIZE:]
        pt = b""
        prev = iv
        for i in range(0, len(ct), BLOCK_SIZE):
            block = list(ct[i : i + BLOCK_SIZE])
            dec = self._decrypt_block(block)
            pt += bytes(d ^ p for d, p in zip(dec, prev))
            prev = block
        with open(output_path, "wb") as f:
            f.write(self._unpad(pt))

    # ── PKCS7 helpers ──────────────────────────────────────────────────

    def _pad(self, data: bytes) -> bytes:
        """Apply PKCS7 padding to *data* so its length is a multiple of BLOCK_SIZE."""
        pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data: bytes) -> bytes:
        """Remove and validate PKCS7 padding.

        Raises:
            ValueError: If the padding is absent or malformed.
        """
        if not data:
            raise ValueError("Empty data after decryption.")
        pad_len = data[-1]
        if pad_len < 1 or pad_len > BLOCK_SIZE:
            raise ValueError("Invalid PKCS7 padding.")
        if any(data[-(i + 1)] != pad_len for i in range(pad_len)):
            raise ValueError("Invalid PKCS7 padding.")
        return data[:-pad_len]
