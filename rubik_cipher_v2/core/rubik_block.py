"""Mutable 4×4 block with in-place cipher operations for RUBIK Cipher v2."""

_ROWS = 4
_COLS = 4


# ── GF(2⁸) helpers ────────────────────────────────────────────────────────────

def _xtime(b: int) -> int:
    """Multiply b by 2 in GF(2⁸) with the AES reduction polynomial."""
    return ((b << 1) ^ 0x1B) & 0xFF if b & 0x80 else (b << 1) & 0xFF


def _mix_col(col: list[int]) -> list[int]:
    """Apply the AES MixColumns matrix to one column in GF(2⁸)."""
    a, b, c, d = col
    return [
        _xtime(a) ^ _xtime(b) ^ b ^ c ^ d,
        a ^ _xtime(b) ^ _xtime(c) ^ c ^ d,
        a ^ b ^ _xtime(c) ^ _xtime(d) ^ d,
        _xtime(a) ^ a ^ b ^ c ^ _xtime(d),
    ]


def _inv_mix_col(col: list[int]) -> list[int]:
    """Apply the inverse AES MixColumns matrix to one column in GF(2⁸)."""
    a, b, c, d = col

    def x2(v: int) -> int: return _xtime(v)
    def x4(v: int) -> int: return x2(x2(v))
    def x8(v: int) -> int: return x2(x4(v))
    def x9(v: int) -> int: return x8(v) ^ v
    def xb(v: int) -> int: return x8(v) ^ x2(v) ^ v
    def xd(v: int) -> int: return x8(v) ^ x4(v) ^ v
    def xe(v: int) -> int: return x8(v) ^ x4(v) ^ x2(v)

    return [
        xe(a) ^ xb(b) ^ xd(c) ^ x9(d),
        x9(a) ^ xe(b) ^ xb(c) ^ xd(d),
        xd(a) ^ x9(b) ^ xe(c) ^ xb(d),
        xb(a) ^ xd(b) ^ x9(c) ^ xe(d),
    ]


# ── Block class ────────────────────────────────────────────────────────────────

class RubikBlock:
    """Mutable 4×4 block; all cipher operations modify *self.grid* in place.

    *self.grid* is a list of 4 rows, each a list of 4 integers in [0, 255].
    Row-major order: grid[row][col] = byte at position row*4+col.
    """

    def __init__(self, data: list[int]) -> None:
        """Initialise the block from a flat 16-element list.

        Args:
            data: Exactly 16 integer bytes in [0, 255].
        """
        self.grid: list[list[int]] = [
            list(data[r * _COLS : r * _COLS + _COLS]) for r in range(_ROWS)
        ]

    def to_bytes(self) -> list[int]:
        """Return the block as a flat 16-element list."""
        return [b for row in self.grid for b in row]

    # ── substitution ────────────────────────────────────────────────────

    def substitute(self, sbox: list[int]) -> None:
        """Replace every byte with its S-Box image (forward SubBytes).

        Args:
            sbox: 256-entry substitution table.
        """
        for r in range(_ROWS):
            for c in range(_COLS):
                self.grid[r][c] = sbox[self.grid[r][c]]

    def unsubstitute(self, inv_sbox: list[int]) -> None:
        """Replace every byte with its inverse S-Box image (InvSubBytes).

        Args:
            inv_sbox: 256-entry inverse substitution table.
        """
        for r in range(_ROWS):
            for c in range(_COLS):
                self.grid[r][c] = inv_sbox[self.grid[r][c]]

    # ── row shifts ──────────────────────────────────────────────────────

    def shift_rows(self, amounts: list[int]) -> None:
        """Rotate each row LEFT by the corresponding amount.

        Args:
            amounts: 4 rotation distances, each in [0, 3].
        """
        for r in range(_ROWS):
            n = amounts[r]
            self.grid[r] = self.grid[r][n:] + self.grid[r][:n]

    def unshift_rows(self, amounts: list[int]) -> None:
        """Rotate each row RIGHT by the corresponding amount (inverse ShiftRows).

        Args:
            amounts: 4 rotation distances, each in [0, 3].
        """
        for r in range(_ROWS):
            n = (4 - amounts[r]) % 4
            self.grid[r] = self.grid[r][n:] + self.grid[r][:n]

    # ── column mixing ───────────────────────────────────────────────────

    def mix_columns(self) -> None:
        """Apply the AES GF(2⁸) MixColumns transform to every column."""
        for c in range(_COLS):
            col = [self.grid[r][c] for r in range(_ROWS)]
            mixed = _mix_col(col)
            for r in range(_ROWS):
                self.grid[r][c] = mixed[r]

    def unmix_columns(self) -> None:
        """Apply the inverse AES GF(2⁸) MixColumns transform to every column."""
        for c in range(_COLS):
            col = [self.grid[r][c] for r in range(_ROWS)]
            mixed = _inv_mix_col(col)
            for r in range(_ROWS):
                self.grid[r][c] = mixed[r]

    # ── key XOR ─────────────────────────────────────────────────────────

    def xor_key(self, key_16: list[int]) -> None:
        """XOR every byte with the corresponding key byte (AddRoundKey / whitening).

        Args:
            key_16: 16-element key; key_16[r*4+c] is applied to grid[r][c].
        """
        for r in range(_ROWS):
            for c in range(_COLS):
                self.grid[r][c] ^= key_16[r * _COLS + c]
