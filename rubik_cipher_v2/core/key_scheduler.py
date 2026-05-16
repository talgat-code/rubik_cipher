"""Key schedule for RUBIK Cipher v2 — derives all key material via PBKDF2."""
import hashlib

# Memory layout of the 512-byte master key
_MASTER_LEN = 512
_SBOX_OFFSET = 0          # [0   : 256] Fisher-Yates seed
_PRE_WK_OFFSET = 256      # [256 : 272] pre-whitening key
_POST_WK_OFFSET = 272     # [272 : 288] post-whitening key
_ROW_SHIFT_OFFSET = 288   # [288 : 320] row shifts (8 rounds × 4 rows)
_ROUND_KEY_OFFSET = 320   # [320 : 448] round keys  (8 rounds × 16 bytes)
_ROUNDS = 8
_BLOCK_SIZE = 16


class KeyScheduler:
    """Derives and stores all sub-keys from a user-supplied password.

    Uses PBKDF2-SHA256 (100 000 iterations) to produce 512 bytes of
    key material.  All subsequent per-round values are sliced from that
    single master buffer so that a single password uniquely determines
    the entire cipher state.
    """

    def __init__(self, key: str) -> None:
        """Derive master key material and build the S-Box permutation.

        Args:
            key: Plaintext password; may be any non-empty string.
        """
        self.key = key
        self.master: bytes = self._derive_master()
        self.sbox: list[int]
        self.inv_sbox: list[int]
        self.sbox, self.inv_sbox = self._build_sbox()

    # ------------------------------------------------------------------ private

    def _derive_master(self) -> bytes:
        """Return 512 bytes of PBKDF2-SHA256 key material."""
        salt = hashlib.sha256(self.key.encode("utf-8")).digest()[:16]
        return hashlib.pbkdf2_hmac(
            "sha256",
            self.key.encode("utf-8"),
            salt=salt,
            iterations=100_000,
            dklen=_MASTER_LEN,
        )

    def _build_sbox(self) -> tuple[list[int], list[int]]:
        """Build a key-derived S-Box via Fisher-Yates and its inverse."""
        sbox = list(range(256))
        j = 0
        for i in range(256):
            j = (j + sbox[i] + self.master[_SBOX_OFFSET + i]) % 256
            sbox[i], sbox[j] = sbox[j], sbox[i]
        inv_sbox = [0] * 256
        for i, v in enumerate(sbox):
            inv_sbox[v] = i
        return sbox, inv_sbox

    # ------------------------------------------------------------------ public

    @property
    def pre_whitening_key(self) -> list[int]:
        """16-byte pre-whitening key derived from master[256:272]."""
        return list(self.master[_PRE_WK_OFFSET : _PRE_WK_OFFSET + _BLOCK_SIZE])

    @property
    def post_whitening_key(self) -> list[int]:
        """16-byte post-whitening key derived from master[272:288]."""
        return list(self.master[_POST_WK_OFFSET : _POST_WK_OFFSET + _BLOCK_SIZE])

    def get_row_shifts(self, round_num: int) -> list[int]:
        """Return 4 row-shift amounts (each in 0–3) for the given round.

        Args:
            round_num: Round index in [0, 7].
        """
        base = _ROW_SHIFT_OFFSET + round_num * 4
        return [self.master[base + r] % 4 for r in range(4)]

    def get_round_key(self, round_num: int) -> list[int]:
        """Return the 16-byte round key for the given round.

        Args:
            round_num: Round index in [0, 7].
        """
        base = _ROUND_KEY_OFFSET + round_num * _BLOCK_SIZE
        return list(self.master[base : base + _BLOCK_SIZE])
