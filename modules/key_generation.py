"""
key_generation.py
=================
Modul pembangkitan pasangan kunci RSA (tugas Orang 1).

Mengikuti prosedur di materi dosen (slide 13):
    1. Pilih dua bilangan prima p dan q          (rahasia)
    2. Hitung n = p * q                           (publik)
    3. Hitung m = (p - 1)(q - 1)                  (rahasia)
    4. Pilih e dengan PBB(e, m) = 1               (publik)
    5. Hitung d dari e*d = 1 (mod m)              (rahasia)

Kunci publik = (e, n), kunci privat = (d, n).

Fungsi utama yang dipakai web / modul lain:
    generate_keys(bit_size)            -> dict hasil lengkap (p, q, n, m, e, d, ...)
    generate_keys_from_primes(p, q, e) -> dict hasil dari p, q manual (mis. 47, 71, 79)
    validate_keys(keys)                -> (bool, list pesan pemeriksaan)

Catatan ukuran blok (setiap blok plainteks harus < n):
    chars_per_block  -> dipakai untuk TEKS BEBAS (alamat, kalimat, simbol).
                        Karakter digabung dalam basis 128 (ASCII) atau 26 (A-Z).
    digits_per_block -> hanya untuk cara slide dosen (kode ASCII 2 digit digabung),
                        yang hanya aman untuk huruf besar dan spasi (kode 32-99).
Kunci tidak bergantung pada isi teks, jadi satu kunci dapat dipakai untuk teks apa pun.
"""

import secrets

# Batas bawah ukuran n (bit). Di bawah ini p dan q terlalu kecil / tidak cukup variasi.
MIN_BIT_SIZE = 16
MAX_BIT_SIZE = 4096

_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97,
]

DEFAULT_E = 65537  # eksponen publik standar yang dipakai RSA di dunia nyata
MAX_PERCOBAAN = 2000  # batas percobaan cari p, q agar tidak berputar selamanya


# ---------------------------------------------------------------------------
# Matematika dasar (dari materi: PBB, Euclidean diperluas, balikan modulo)
# ---------------------------------------------------------------------------
def pbb(a, b):
    """PBB dengan algoritma Euclidean."""
    while b != 0:
        a, b = b, a % b
    return a


def euclid_diperluas(a, b):
    """Mengembalikan (g, x, y) dengan a*x + b*y = g = PBB(a, b)."""
    if b == 0:
        return a, 1, 0
    g, x, y = euclid_diperluas(b, a % b)
    return g, y, x - (a // b) * y


def balikan_mod(e, m):
    """Balikan e modulo m (kunci privat d)."""
    g, x, _ = euclid_diperluas(e, m)
    if g != 1:
        raise ValueError("balikan tidak ada: PBB(e, m) != 1")
    return x % m


# ---------------------------------------------------------------------------
# Bilangan prima
# ---------------------------------------------------------------------------
def is_prime(n, rounds=40):
    """Uji keprimaan Miller-Rabin (probabilistik, 40 putaran => peluang salah
    dapat diabaikan). Bilangan kecil dicek dulu dengan pembagi prima kecil."""
    if n < 2:
        return False
    for sp in _SMALL_PRIMES:
        if n == sp:
            return True
        if n % sp == 0:
            return False

    # tulis n - 1 = 2^s * r dengan r ganjil
    r, s = n - 1, 0
    while r % 2 == 0:
        r //= 2
        s += 1

    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)  # a di [2, n-2]
        x = pow(a, r, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    """Bangkitkan bilangan prima acak dengan panjang tepat `bits` bit.
    Dua bit teratas di-set 1 agar p*q pasti berukuran tepat 2*bits (atau 2*bits-1)."""
    if bits < 2:
        raise ValueError("bits minimal 2")
    while True:
        kandidat = secrets.randbits(bits)
        kandidat |= (1 << (bits - 1))  # pastikan panjang bit penuh
        if bits >= 3:
            kandidat |= (1 << (bits - 2))
        kandidat |= 1  # pastikan ganjil
        if is_prime(kandidat):
            return kandidat


# ---------------------------------------------------------------------------
# Memilih e
# ---------------------------------------------------------------------------
def choose_e(m):
    """Pilih e dengan 1 < e < m dan PBB(e, m) = 1 (langkah 4)."""
    if m <= 3:
        raise ValueError("m terlalu kecil untuk memilih e")
    if DEFAULT_E < m and pbb(DEFAULT_E, m) == 1:
        return DEFAULT_E
    # untuk kunci kecil: cari e acak yang relatif prima dengan m
    while True:
        e = 3 + secrets.randbelow(m - 3)  # e di [3, m-1]
        if pbb(e, m) == 1:
            return e


# ---------------------------------------------------------------------------
# Metode encoding yang bisa dipilih user (info ukuran blok)
# ---------------------------------------------------------------------------
ENCODING_ASCII = "ascii"            # kode ASCII 0-127
ENCODING_ALPHABET26 = "alphabet26"  # A=0 ... Z=25

# jumlah simbol per metode (dipakai untuk menghitung ukuran blok)
ENCODING_SYMBOLS = {
    ENCODING_ASCII: 128,
    ENCODING_ALPHABET26: 26,
}


def max_digits_per_block(n):
    """Jumlah digit desimal terbesar untuk satu blok agar pasti 0 <= blok < n.
    Cara ala slide dosen: n = 3337 (4 digit) -> blok 3 digit.
    Hanya untuk contoh dosen (huruf besar + spasi); untuk teks bebas pakai
    max_chars_per_block."""
    return max(len(str(n)) - 1, 1)


def max_chars_per_block(n, encoding):
    """Jumlah karakter terbanyak per blok jika karakter digabung dalam basis
    (basis 128 untuk ASCII, basis 26 untuk 26 huruf), dengan syarat nilai blok < n.
    Selalu minimal 1."""
    if encoding not in ENCODING_SYMBOLS:
        raise ValueError(
            f"encoding harus salah satu dari {list(ENCODING_SYMBOLS)}"
        )
    basis = ENCODING_SYMBOLS[encoding]
    k = 0
    while basis ** (k + 1) <= n:
        k += 1
    return max(k, 1)


# ---------------------------------------------------------------------------
# Pembentukan kunci
# ---------------------------------------------------------------------------
def _susun_hasil(p, q, e, encoding=None):
    n = p * q
    m = (p - 1) * (q - 1)
    d = balikan_mod(e, m)
    return {
        "p": p,
        "q": q,
        "n": n,
        "m": m,
        "e": e,
        "d": d,
        "bit_length": n.bit_length(),
        "public_key": (e, n),
        "private_key": (d, n),
        "encoding": encoding,
        "digits_per_block": max_digits_per_block(n),
        "chars_per_block": (
            max_chars_per_block(n, encoding) if encoding else None
        ),
    }


def generate_keys_from_primes(p, q, e=None, encoding=None):
    """Bentuk kunci dari p dan q yang ditentukan sendiri (mis. contoh dosen 47, 71, 79).

    Raises ValueError jika input tidak valid.
    """
    if not (isinstance(p, int) and isinstance(q, int)):
        raise ValueError("p dan q harus bilangan bulat")
    if not is_prime(p):
        raise ValueError(f"p = {p} bukan bilangan prima")
    if not is_prime(q):
        raise ValueError(f"q = {q} bukan bilangan prima")
    if p == q:
        raise ValueError("p dan q harus berbeda")
    if encoding is not None and encoding not in ENCODING_SYMBOLS:
        raise ValueError(
            f"encoding harus salah satu dari {list(ENCODING_SYMBOLS)}"
        )
    # setiap karakter (kode 0 .. basis-1) harus < n agar tidak rusak saat dekripsi
    if encoding is not None and p * q < ENCODING_SYMBOLS[encoding]:
        raise ValueError(
            f"n = p x q = {p * q} terlalu kecil untuk metode {encoding}: "
            f"n harus >= {ENCODING_SYMBOLS[encoding]}"
        )

    m = (p - 1) * (q - 1)
    if e is None:
        e = choose_e(m)
    else:
        if not isinstance(e, int):
            raise ValueError("e harus bilangan bulat")
        if not (1 < e < m):
            raise ValueError(f"e harus memenuhi 1 < e < m = {m}")
        if pbb(e, m) != 1:
            raise ValueError(f"e = {e} tidak relatif prima dengan m = {m}")

    return _susun_hasil(p, q, e, encoding)


def generate_keys(bit_size=1024, e=None, encoding=None):
    """Bangkitkan pasangan kunci RSA acak dengan ukuran n = `bit_size` bit.

    bit_size : ukuran n yang diinginkan pengguna (16 - 4096).
               p dan q masing-masing sekitar bit_size/2 bit.
    e        : opsional; jika None dipilih otomatis (65537 bila memungkinkan).
    encoding : opsional, "ascii" atau "alphabet26" (ENCODING_ASCII /
               ENCODING_ALPHABET26). Jika diisi, hasil memuat chars_per_block.

    Mengembalikan dict:
        p, q, n, m, e, d, bit_length, public_key=(e, n), private_key=(d, n),
        encoding, digits_per_block, chars_per_block
    """
    if encoding is not None and encoding not in ENCODING_SYMBOLS:
        raise ValueError(
            f"encoding harus salah satu dari {list(ENCODING_SYMBOLS)}"
        )
    if not isinstance(bit_size, int) or isinstance(bit_size, bool):
        raise ValueError("bit_size harus bilangan bulat")
    if bit_size < MIN_BIT_SIZE or bit_size > MAX_BIT_SIZE:
        raise ValueError(
            f"bit_size harus antara {MIN_BIT_SIZE} dan {MAX_BIT_SIZE} bit"
        )

    if e is not None:
        if not isinstance(e, int) or isinstance(e, bool):
            raise ValueError("e harus bilangan bulat")
        if e < 3 or e % 2 == 0:
            raise ValueError("e harus bilangan ganjil dan >= 3 (m selalu genap)")

    bits_p = bit_size // 2
    bits_q = bit_size - bits_p

    percobaan = 0
    while True:
        percobaan += 1
        if percobaan > MAX_PERCOBAAN:
            raise ValueError(
                "gagal menemukan p dan q yang cocok dengan e tersebut; "
                "coba e yang lebih kecil atau ukuran bit yang lebih besar"
            )
        p = generate_prime(bits_p)
        q = generate_prime(bits_q)
        if p == q:
            continue
        # n harus tepat bit_size bit (dua bit teratas sudah di-set, tapi cek saja)
        if (p * q).bit_length() != bit_size:
            continue
        m = (p - 1) * (q - 1)
        try:
            if e is None:
                e_pakai = choose_e(m)
            else:
                if not (1 < e < m) or pbb(e, m) != 1:
                    # e dari pengguna tidak cocok dengan p, q ini -> coba p, q lain
                    continue
                e_pakai = e
        except ValueError:
            continue

        hasil = _susun_hasil(p, q, e_pakai, encoding)
        if hasil["d"] == e_pakai:  # hindari kasus d == e (kunci lemah)
            continue
        return hasil


# ---------------------------------------------------------------------------
# Validasi hasil (langkah 7 tugas Orang 1)
# ---------------------------------------------------------------------------
def validate_keys(keys):
    """Periksa apakah kunci valid. Mengembalikan (semua_lolos, daftar_pemeriksaan).

    daftar_pemeriksaan = list of (deskripsi, True/False)
    """
    p, q, n = keys["p"], keys["q"], keys["n"]
    m, e, d = keys["m"], keys["e"], keys["d"]

    cek = [
        ("p prima", is_prime(p)),
        ("q prima", is_prime(q)),
        ("p != q", p != q),
        ("n = p x q", n == p * q),
        ("m = (p-1)(q-1)", m == (p - 1) * (q - 1)),
        ("1 < e < m", 1 < e < m),
        ("PBB(e, m) = 1", pbb(e, m) == 1),
        ("e x d = 1 (mod m)", (e * d) % m == 1),
    ]

    # uji putar-balik: enkripsi lalu dekripsi satu pesan percobaan
    uji = 2 + secrets.randbelow(max(n - 3, 1))
    cek.append(("uji enkripsi-dekripsi", pow(pow(uji, e, n), d, n) == uji))

    return all(ok for _, ok in cek), cek
