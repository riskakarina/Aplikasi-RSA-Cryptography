"""
encoding.py
===========
Modul encoding / decoding pesan (tugas Orang 2).

Dua metode (sama dengan konstanta di key_generation.py):
    ENCODING_ASCII      -> kode ASCII 0-127            (basis 128)
    ENCODING_ALPHABET26 -> A=0, B=1, ..., Z=25         (basis 26)

Alur:  teks -> kode per karakter -> digabung jadi blok bilangan (< n)

Penggabungan blok mengikuti ukuran `chars_per_block` dari key_generation.py:
k karakter digabung dalam basis B:
    blok = c1*B^(k-1) + c2*B^(k-2) + ... + ck
dan k dipilih terbesar sehingga B^k <= n  => setiap blok pasti < n.

Padding: jika jumlah karakter bukan kelipatan k, blok terakhir diisi kode 0.
Jumlah padding (pad_count) dikembalikan terpisah agar bisa dibuang saat decoding
(tidak memakai karakter khusus, jadi 'A' / NUL asli tidak ikut terhapus).
"""

from key_generation import (
    ENCODING_ASCII,
    ENCODING_ALPHABET26,
    ENCODING_SYMBOLS,
    max_chars_per_block,
)

# pad_count dienkripsi sebagai (pad_count + PAD_OFFSET) agar tidak jatuh ke
# nilai 0 / 1 (yang hasil enkripsinya selalu sama dengan nilainya sendiri).
PAD_OFFSET = 2


def _cek_encoding(encoding):
    if encoding not in ENCODING_SYMBOLS:
        raise ValueError(
            f"encoding harus salah satu dari {list(ENCODING_SYMBOLS)}"
        )
    return ENCODING_SYMBOLS[encoding]


# ---------------------------------------------------------------------------
# Validasi karakter
# ---------------------------------------------------------------------------
def validate_plaintext(text, encoding):
    """Periksa apakah teks sah untuk metode encoding.
    Mengembalikan (ok, daftar_pesan_error)."""
    _cek_encoding(encoding)
    if not isinstance(text, str):
        return False, ["plaintext harus berupa teks (string)"]
    if text == "":
        return False, ["plaintext tidak boleh kosong"]

    if encoding == ENCODING_ASCII:
        salah = sorted({c for c in text if ord(c) > 127})
        if salah:
            return False, [
                "karakter di luar ASCII (0-127): " + " ".join(repr(c) for c in salah)
            ]
    else:
        salah = sorted({c for c in text if not ("A" <= c <= "Z")})
        if salah:
            return False, [
                "metode 26 huruf hanya menerima huruf besar A-Z tanpa spasi/angka/simbol; "
                "karakter tidak valid: " + " ".join(repr(c) for c in salah)
            ]
    return True, []


def normalize_alphabet26(text):
    """Bantuan untuk metode 26 huruf: ubah ke huruf besar, buang selain A-Z."""
    return "".join(c for c in text.upper() if "A" <= c <= "Z")


# ---------------------------------------------------------------------------
# Teks <-> kode karakter
# ---------------------------------------------------------------------------
def encode_text(text, encoding):
    """Teks -> list kode per karakter (ASCII: ord(c); 26 huruf: A=0..Z=25)."""
    ok, pesan = validate_plaintext(text, encoding)
    if not ok:
        raise ValueError("; ".join(pesan))
    if encoding == ENCODING_ASCII:
        return [ord(c) for c in text]
    return [ord(c) - ord("A") for c in text]


def decode_codes(codes, encoding):
    """List kode per karakter -> teks."""
    basis = _cek_encoding(encoding)
    for c in codes:
        if not (0 <= c < basis):
            raise ValueError(f"kode {c} di luar rentang 0-{basis - 1} untuk {encoding}")
    if encoding == ENCODING_ASCII:
        return "".join(chr(c) for c in codes)
    return "".join(chr(c + ord("A")) for c in codes)


# ---------------------------------------------------------------------------
# Kode <-> blok bilangan
# ---------------------------------------------------------------------------
def block_size(n, encoding):
    """Jumlah karakter per blok untuk modulus n."""
    _cek_encoding(encoding)
    return max_chars_per_block(n, encoding)


def codes_to_blocks(codes, n, encoding):
    """Gabungkan kode menjadi blok bilangan. Mengembalikan (blocks, pad_count)."""
    basis = _cek_encoding(encoding)
    k = block_size(n, encoding)
    codes = list(codes)
    pad_count = (-len(codes)) % k
    codes += [0] * pad_count

    blocks = []
    for i in range(0, len(codes), k):
        nilai = 0
        for c in codes[i:i + k]:
            nilai = nilai * basis + c
        blocks.append(nilai)
    return blocks, pad_count


def blocks_to_codes(blocks, n, encoding, pad_count=0):
    """Pecah blok bilangan menjadi kode karakter, lalu buang padding."""
    basis = _cek_encoding(encoding)
    k = block_size(n, encoding)
    if not (0 <= pad_count < k):
        raise ValueError(f"pad_count harus antara 0 dan {k - 1}")

    codes = []
    for b in blocks:
        if not (0 <= b < basis ** k):
            raise ValueError(
                f"blok {b} tidak bisa didecode untuk metode {encoding} "
                f"(kunci atau ciphertext salah?)"
            )
        digit = []
        for _ in range(k):
            b, sisa = divmod(b, basis)
            digit.append(sisa)
        codes.extend(reversed(digit))

    if pad_count:
        if pad_count > len(codes):
            raise ValueError("pad_count lebih besar dari jumlah karakter")
        codes = codes[:-pad_count]
    return codes


# ---------------------------------------------------------------------------
# Fungsi utama
# ---------------------------------------------------------------------------
def encode_message(text, n, encoding):
    """Teks -> dict: codes, block_size, blocks, pad_count (untuk ditampilkan di web)."""
    codes = encode_text(text, encoding)
    blocks, pad_count = codes_to_blocks(codes, n, encoding)
    return {
        "encoding": encoding,
        "codes": codes,
        "block_size": block_size(n, encoding),
        "blocks": blocks,
        "pad_count": pad_count,
    }


def decode_message(blocks, n, encoding, pad_count=0):
    """Blok bilangan -> teks."""
    return decode_codes(blocks_to_codes(blocks, n, encoding, pad_count), encoding)
