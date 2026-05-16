import unittest

from rubik_cipher_v2.core.key_scheduler import KeyScheduler
from rubik_cipher_v2.core.rubik_block import RubikBlock
from rubik_cipher_v2.core.cipher import RubikCipher


class TestKeyScheduler(unittest.TestCase):
    def setUp(self):
        self.ks = KeyScheduler("test_key")

    def test_master_length(self):
        self.assertEqual(len(self.ks.master), 512)

    def test_sbox_is_permutation(self):
        self.assertEqual(sorted(self.ks.sbox), list(range(256)))

    def test_inv_sbox_round_trip(self):
        for i in range(256):
            self.assertEqual(self.ks.inv_sbox[self.ks.sbox[i]], i)

    def test_pre_post_whitening_length(self):
        self.assertEqual(len(self.ks.pre_whitening), 16)
        self.assertEqual(len(self.ks.post_whitening), 16)

    def test_round_key_length(self):
        for rnd in range(8):
            self.assertEqual(len(self.ks.get_round_key(rnd)), 16)

    def test_row_shift_in_range(self):
        for rnd in range(8):
            for row in range(4):
                shift = self.ks.get_row_shift(rnd, row)
                self.assertIn(shift, range(4))

    def test_deterministic(self):
        ks2 = KeyScheduler("test_key")
        self.assertEqual(self.ks.master, ks2.master)


class TestRubikBlock(unittest.TestCase):
    def setUp(self):
        self.rb = RubikBlock(KeyScheduler("my_secret_key"))

    def test_encrypt_decrypt_round_trip(self):
        block = b"0123456789abcdef"
        self.assertEqual(self.rb.decrypt(self.rb.encrypt(block)), block)

    def test_all_zeros(self):
        block = b"\x00" * 16
        self.assertEqual(self.rb.decrypt(self.rb.encrypt(block)), block)

    def test_all_ones(self):
        block = b"\xff" * 16
        self.assertEqual(self.rb.decrypt(self.rb.encrypt(block)), block)

    def test_different_keys_different_output(self):
        block = b"0123456789abcdef"
        rb2 = RubikBlock(KeyScheduler("other_key"))
        self.assertNotEqual(self.rb.encrypt(block), rb2.encrypt(block))

    def test_output_length(self):
        block = b"A" * 16
        self.assertEqual(len(self.rb.encrypt(block)), 16)
        self.assertEqual(len(self.rb.decrypt(self.rb.encrypt(block))), 16)


class TestRubikCipher(unittest.TestCase):
    def setUp(self):
        self.cipher = RubikCipher("password123")

    def test_encrypt_decrypt(self):
        msg = "Hello, RUBIK Cipher v2!"
        self.assertEqual(self.cipher.decrypt(self.cipher.encrypt(msg)), msg)

    def test_nondeterministic_encryption(self):
        msg = "test"
        self.assertNotEqual(self.cipher.encrypt(msg), self.cipher.encrypt(msg))

    def test_long_message(self):
        msg = "A" * 1000
        self.assertEqual(self.cipher.decrypt(self.cipher.encrypt(msg)), msg)

    def test_empty_message(self):
        msg = ""
        self.assertEqual(self.cipher.decrypt(self.cipher.encrypt(msg)), msg)

    def test_unicode_message(self):
        msg = "Привет мир! Cipher v2"
        self.assertEqual(self.cipher.decrypt(self.cipher.encrypt(msg)), msg)

    def test_exactly_one_block(self):
        msg = "0123456789abcdef"
        self.assertEqual(self.cipher.decrypt(self.cipher.encrypt(msg)), msg)

    def test_wrong_key_fails(self):
        ct = self.cipher.encrypt("secret")
        wrong = RubikCipher("wrong_password")
        with self.assertRaises(Exception):
            wrong.decrypt(ct)

    def test_output_is_base64(self):
        import base64
        ct = self.cipher.encrypt("hello")
        base64.b64decode(ct)


if __name__ == "__main__":
    unittest.main()
