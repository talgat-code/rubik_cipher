from .key_scheduler import KeyScheduler


def _xtime(b: int) -> int:
    return ((b << 1) ^ 0x1B) & 0xFF if b & 0x80 else (b << 1) & 0xFF


def _mix_col(col: list) -> list:
    a, b, c, d = col
    return [
        _xtime(a) ^ _xtime(b) ^ b ^ c ^ d,
        a ^ _xtime(b) ^ _xtime(c) ^ c ^ d,
        a ^ b ^ _xtime(c) ^ _xtime(d) ^ d,
        _xtime(a) ^ a ^ b ^ c ^ _xtime(d),
    ]


def _inv_mix_col(col: list) -> list:
    a, b, c, d = col

    def x2(v): return _xtime(v)
    def x4(v): return x2(x2(v))
    def x8(v): return x2(x4(v))
    def x9(v): return x8(v) ^ v
    def xb(v): return x8(v) ^ x2(v) ^ v
    def xd(v): return x8(v) ^ x4(v) ^ v
    def xe(v): return x8(v) ^ x4(v) ^ x2(v)

    return [
        xe(a) ^ xb(b) ^ xd(c) ^ x9(d),
        x9(a) ^ xe(b) ^ xb(c) ^ xd(d),
        xd(a) ^ x9(b) ^ xe(c) ^ xb(d),
        xb(a) ^ xd(b) ^ x9(c) ^ xe(d),
    ]


class RubikBlock:
    def __init__(self, scheduler: KeyScheduler):
        self.ks = scheduler

    def encrypt(self, block: bytes) -> bytes:
        state = list(block)
        state = [state[i] ^ self.ks.pre_whitening[i] for i in range(16)]
        for rnd in range(8):
            state = self._sub_bytes(state)
            state = self._shift_rows(state, rnd, encrypt=True)
            state = self._mix_columns(state)
            state = self._add_round_key(state, rnd)
        state = [state[i] ^ self.ks.post_whitening[i] for i in range(16)]
        return bytes(state)

    def decrypt(self, block: bytes) -> bytes:
        state = list(block)
        state = [state[i] ^ self.ks.post_whitening[i] for i in range(16)]
        for rnd in range(7, -1, -1):
            state = self._add_round_key(state, rnd)
            state = self._inv_mix_columns(state)
            state = self._shift_rows(state, rnd, encrypt=False)
            state = self._inv_sub_bytes(state)
        state = [state[i] ^ self.ks.pre_whitening[i] for i in range(16)]
        return bytes(state)

    def _sub_bytes(self, state: list) -> list:
        return [self.ks.sbox[b] for b in state]

    def _inv_sub_bytes(self, state: list) -> list:
        return [self.ks.inv_sbox[b] for b in state]

    def _shift_rows(self, state: list, rnd: int, encrypt: bool) -> list:
        matrix = [state[r * 4 : r * 4 + 4] for r in range(4)]
        for r in range(4):
            n = self.ks.get_row_shift(rnd, r)
            if encrypt:
                matrix[r] = matrix[r][n:] + matrix[r][:n]
            else:
                n = (4 - n) % 4
                matrix[r] = matrix[r][n:] + matrix[r][:n]
        result = []
        for row in matrix:
            result.extend(row)
        return result

    def _mix_columns(self, state: list) -> list:
        result = [0] * 16
        for c in range(4):
            col = [state[r * 4 + c] for r in range(4)]
            mixed = _mix_col(col)
            for r in range(4):
                result[r * 4 + c] = mixed[r]
        return result

    def _inv_mix_columns(self, state: list) -> list:
        result = [0] * 16
        for c in range(4):
            col = [state[r * 4 + c] for r in range(4)]
            mixed = _inv_mix_col(col)
            for r in range(4):
                result[r * 4 + c] = mixed[r]
        return result

    def _add_round_key(self, state: list, rnd: int) -> list:
        rk = self.ks.get_round_key(rnd)
        return [state[i] ^ rk[i] for i in range(16)]
