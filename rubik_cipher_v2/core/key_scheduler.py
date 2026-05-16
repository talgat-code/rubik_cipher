import hashlib


class KeyScheduler:
    def __init__(self, key: str):
        self.key = key
        self.master = self._derive_master()
        self.sbox, self.inv_sbox = self._build_sbox()
        self.pre_whitening = self.master[256:272]
        self.post_whitening = self.master[272:288]

    def _derive_master(self) -> bytes:
        salt = hashlib.sha256(self.key.encode("utf-8")).digest()[:16]
        return hashlib.pbkdf2_hmac(
            "sha256",
            self.key.encode("utf-8"),
            salt=salt,
            iterations=100_000,
            dklen=512,
        )

    def _build_sbox(self):
        sbox = list(range(256))
        j = 0
        for i in range(256):
            j = (j + sbox[i] + self.master[i]) % 256
            sbox[i], sbox[j] = sbox[j], sbox[i]
        inv_sbox = [0] * 256
        for i, v in enumerate(sbox):
            inv_sbox[v] = i
        return sbox, inv_sbox

    def get_row_shift(self, round_num: int, row: int) -> int:
        return self.master[288 + round_num * 4 + row] % 4

    def get_round_key(self, rnd: int) -> bytes:
        return self.master[320 + rnd * 16 : 320 + rnd * 16 + 16]
