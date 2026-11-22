"""
Uji untuk modules/key_generation.py (Orang 1).

Cara menjalankan dari folder utama repo (RSA-Cryptography/):
    python -m unittest tests.test_key_generation -v
atau, jika pytest terpasang:
    pytest tests/test_key_generation.py -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.key_generation import (  # noqa: E402
    ENCODING_ALPHABET26,
    ENCODING_ASCII,
    balikan_mod,
    euclid_diperluas,
    generate_keys,
    generate_keys_from_primes,
    generate_prime,
    is_prime,
    max_chars_per_block,
    max_digits_per_block,
    pbb,
    validate_keys,
)


def _prima_naif(n):
    if n < 2:
        return False
    i = 2
    while i * i <= n:
        if n % i == 0:
            return False
        i += 1
    return True


class TestMatematikaDasar(unittest.TestCase):
    def test_pbb_contoh_dosen(self):
        self.assertEqual(pbb(79, 3220), 1)      # slide 14
        self.assertEqual(pbb(3220, 79), 1)
        self.assertEqual(pbb(12, 18), 6)

    def test_euclid_diperluas(self):
        g, x, y = euclid_diperluas(79, 3220)
        self.assertEqual(g, 1)
        self.assertEqual(79 * x + 3220 * y, 1)

    def test_balikan_mod_contoh_dosen(self):
        self.assertEqual(balikan_mod(79, 3220), 1019)   # slide 15-16
        self.assertEqual(balikan_mod(4, 9), 7)           # slide 2
        self.assertEqual(balikan_mod(3, 40), 27)         # slide 21
        self.assertEqual(balikan_mod(5, 72), 29)         # slide 35
        self.assertEqual(balikan_mod(7, 40), 23)         # slide 36

    def test_balikan_mod_tidak_ada(self):
        with self.assertRaises(ValueError):
            balikan_mod(10, 20)


class TestBilanganPrima(unittest.TestCase):
    def test_is_prime_cocok_dengan_uji_naif(self):
        for n in range(0, 5000):
            self.assertEqual(is_prime(n), _prima_naif(n), n)

    def test_is_prime_carmichael(self):
        for n in (561, 1105, 1729, 41041):
            self.assertFalse(is_prime(n), n)

    def test_generate_prime_panjang_bit(self):
        for bits in (8, 16, 32, 64, 128):
            p = generate_prime(bits)
            self.assertEqual(p.bit_length(), bits)
            self.assertTrue(is_prime(p))


class TestContohDosen(unittest.TestCase):
    def test_p47_q71_e79(self):
        k = generate_keys_from_primes(47, 71, 79)
        self.assertEqual(k["n"], 3337)
        self.assertEqual(k["phi"], 3220)
        self.assertEqual(k["d"], 1019)
        self.assertEqual(k["public_key"], (79, 3337))
        self.assertEqual(k["private_key"], (1019, 3337))

    def test_contoh_kecil_slide(self):
        self.assertEqual(generate_keys_from_primes(5, 11, 3)["d"], 27)
        self.assertEqual(generate_keys_from_primes(7, 13, 5)["d"], 29)
        self.assertEqual(generate_keys_from_primes(3, 11, 3)["d"], 7)

    def test_cipher_hari_ini_slide_24_26(self):
        k = generate_keys_from_primes(47, 71, 79)
        e, d, n = k["e"], k["d"], k["n"]
        blok = [726, 582, 733, 273, 787, 3]
        cipher = [pow(b, e, n) for b in blok]
        self.assertEqual(cipher, [215, 776, 1743, 933, 1731, 158])
        self.assertEqual([pow(c, d, n) for c in cipher], blok)


class TestGenerateKeysAcak(unittest.TestCase):
    def test_berbagai_ukuran_bit(self):
        for bits in (16, 17, 24, 32, 64, 128, 256, 512, 1024):
            for _ in range(3):
                k = generate_keys(bits)
                self.assertEqual(k["n"].bit_length(), bits)
                self.assertNotEqual(k["p"], k["q"])
                ok, cek = validate_keys(k)
                self.assertTrue(ok, (bits, cek))

    def test_2048_bit(self):
        k = generate_keys(2048)
        self.assertEqual(k["n"].bit_length(), 2048)
        self.assertTrue(validate_keys(k)[0])

    def test_hasil_lengkap(self):
        k = generate_keys(64)
        for kunci in ("p", "q", "n", "phi", "e", "d", "public_key", "private_key"):
            self.assertIn(kunci, k)
        self.assertEqual(k["public_key"], (k["e"], k["n"]))
        self.assertEqual(k["private_key"], (k["d"], k["n"]))
        self.assertEqual(k["n"], k["p"] * k["q"])
        self.assertEqual(k["phi"], (k["p"] - 1) * (k["q"] - 1))

    def test_e_kustom(self):
        k = generate_keys(64, e=17)
        self.assertEqual(k["e"], 17)
        self.assertTrue(validate_keys(k)[0])

    def test_e_default_65537_untuk_kunci_besar(self):
        self.assertEqual(generate_keys(256)["e"], 65537)

    def test_putar_balik_pesan(self):
        k = generate_keys(64)
        for m in (0, 1, 2, 12345, k["n"] - 1):
            self.assertEqual(pow(pow(m, k["e"], k["n"]), k["d"], k["n"]), m)


class TestEncodingDanBlok(unittest.TestCase):
    def test_digit_per_blok_contoh_dosen(self):
        self.assertEqual(max_digits_per_block(3337), 3)   # slide 23

    def test_chars_per_blok(self):
        self.assertEqual(max_chars_per_block(3337, ENCODING_ALPHABET26), 2)
        self.assertEqual(max_chars_per_block(3337, ENCODING_ASCII), 1)

    def test_blok_selalu_lebih_kecil_dari_n(self):
        for bits in (16, 24, 64, 256):
            for enc, basis in ((ENCODING_ALPHABET26, 26), (ENCODING_ASCII, 128)):
                k = generate_keys(bits, encoding=enc)
                kk = k["chars_per_block"]
                self.assertGreaterEqual(kk, 1)
                self.assertLess(basis ** kk - 1, k["n"])
            self.assertLess(10 ** k["digits_per_block"] - 1, k["n"])

    def test_tanpa_encoding(self):
        k = generate_keys(64)
        self.assertIsNone(k["encoding"])
        self.assertIsNone(k["chars_per_block"])

    def test_encoding_salah(self):
        with self.assertRaises(ValueError):
            generate_keys(64, encoding="foo")
        with self.assertRaises(ValueError):
            max_chars_per_block(3337, "foo")


class TestValidasiInput(unittest.TestCase):
    def test_bit_di_luar_rentang(self):
        for bad in (0, 8, 15, 4097, 99999, -5):
            with self.assertRaises(ValueError, msg=str(bad)):
                generate_keys(bad)

    def test_bit_bukan_integer(self):
        for bad in ("abc", 64.5, None, True):
            with self.assertRaises(ValueError, msg=str(bad)):
                generate_keys(bad)

    def test_e_kustom_tidak_valid_tidak_hang(self):
        for bad in (2, 1, 0, -3, 4, True, 10 ** 9 + 1):
            with self.assertRaises(ValueError, msg=str(bad)):
                generate_keys(16, e=bad)

    def test_p_q_tidak_valid(self):
        with self.assertRaises(ValueError):
            generate_keys_from_primes(4, 71, 79)      # p bukan prima
        with self.assertRaises(ValueError):
            generate_keys_from_primes(47, 91, 79)     # q bukan prima
        with self.assertRaises(ValueError):
            generate_keys_from_primes(47, 47, 79)     # p == q
        with self.assertRaises(ValueError):
            generate_keys_from_primes(47.0, 71, 79)   # bukan integer

    def test_e_tidak_valid_untuk_p_q(self):
        with self.assertRaises(ValueError):
            generate_keys_from_primes(47, 71, 10)     # tidak relatif prima
        with self.assertRaises(ValueError):
            generate_keys_from_primes(47, 71, 5000)   # e >= phi
        with self.assertRaises(ValueError):
            generate_keys_from_primes(47, 71, 1)      # e <= 1

    def test_validate_keys_mendeteksi_kunci_rusak(self):
        k = generate_keys_from_primes(47, 71, 79)
        k["d"] = 1018
        ok, cek = validate_keys(k)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
