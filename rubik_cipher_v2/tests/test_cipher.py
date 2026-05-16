"""
Pytest tests for RUBIK Cipher v2.
Run:  python -m pytest rubik_cipher_v2/tests/test_cipher.py -v
      python -m pytest rubik_cipher_v2/tests/test_cipher.py -v -x
"""
import os
import pytest

from rubik_cipher_v2.core.cipher import RubikCipher
from rubik_cipher_v2.analysis.security_analysis import SecurityAnalyzer

KEY = "test_secret_key_rubik_v2"


@pytest.fixture(scope="module")
def cipher():
    return RubikCipher(KEY)


@pytest.fixture(scope="module")
def analyzer(cipher):
    return SecurityAnalyzer(cipher)


# ------------------------------------------------------------------ core cipher

def test_encrypt_decrypt_roundtrip(cipher):
    for msg in ["a", "Hello!", "x" * 15, "x" * 16, "x" * 17, "x" * 100]:
        assert cipher.decrypt(cipher.encrypt(msg)) == msg


def test_empty_string(cipher):
    assert cipher.decrypt(cipher.encrypt("")) == ""


def test_unicode_input(cipher):
    for msg in ["Привет мир", "中文测试", "café résumé", "αβγδ"]:
        assert cipher.decrypt(cipher.encrypt(msg)) == msg


def test_wrong_key_raises():
    ct = RubikCipher("correct_key").encrypt("secret message 123")
    with pytest.raises(Exception):
        RubikCipher("wrong_key_!!!").decrypt(ct)


def test_random_iv_produces_different_ct(cipher):
    msg = "same plaintext every time"
    assert cipher.encrypt(msg) != cipher.encrypt(msg)


def test_output_is_valid_base64(cipher):
    import base64
    ct = cipher.encrypt("hello")
    base64.b64decode(ct)  # must not raise


def test_long_message(cipher):
    msg = "B" * (100 * 1024)
    assert cipher.decrypt(cipher.encrypt(msg)) == msg


# ------------------------------------------------------------------ file I/O

def test_file_encrypt_decrypt(cipher, tmp_path):
    content = b"Binary\x00\x01\x02\xff data\nwith newlines\r\n"
    src = tmp_path / "source.bin"
    enc = tmp_path / "source.bin.rubik"
    dec = tmp_path / "source_out.bin"

    src.write_bytes(content)
    cipher.encrypt_file(str(src), str(enc))
    cipher.decrypt_file(str(enc), str(dec))

    assert dec.read_bytes() == content


def test_file_encrypt_produces_different_files(cipher, tmp_path):
    src = tmp_path / "test.txt"
    src.write_bytes(b"same content")
    out1 = tmp_path / "out1.rubik"
    out2 = tmp_path / "out2.rubik"

    cipher.encrypt_file(str(src), str(out1))
    cipher.encrypt_file(str(src), str(out2))
    assert out1.read_bytes() != out2.read_bytes()  # random IVs


# ------------------------------------------------------------------ security

def test_avalanche_above_30_pct(analyzer):
    result = analyzer.avalanche_test(n_trials=200)
    assert result["avg_pct"] >= 30.0


def test_avalanche_keys(analyzer):
    result = analyzer.avalanche_test(n_trials=200)
    assert "avg_bits" in result
    assert "min" in result
    assert "max" in result
    assert result["min"] >= 0
    assert result["max"] <= 128


def test_key_space_report(analyzer):
    report = analyzer.key_space_report()
    assert set(report.keys()) == {8, 12, 16, 20, 24}
    assert report[16]["bit_security"] > 100


def test_frequency_entropy(analyzer):
    result = analyzer.frequency_analysis_test("A")
    assert result["entropy_score"] > 6.0  # well-distributed ciphertext


def test_benchmark_returns_timings(analyzer):
    result = analyzer.benchmark(message_size_kb=1)
    assert result["encrypt_ms"] > 0
    assert result["decrypt_ms"] > 0
    assert result["encrypt_kbps"] > 0


def test_compare_with_classics_is_string(analyzer):
    table = analyzer.compare_with_classics()
    assert isinstance(table, str)
    assert "RUBIK v2" in table
    assert "Caesar" in table
