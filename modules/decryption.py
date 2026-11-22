"""
decryption.py
=============
Dekripsi RSA (tugas Orang 2):   m = c^d mod n
"""

import re

from encoding import PAD_OFFSET, block_size, blocks_to_codes, decode_codes
from encryption import encrypt


def parse_ciphertext(teks):
    """String 'c1 c2 c3' (dipisah spasi / koma / baris baru) -> list int."""
    if isinstance(teks, (list, tuple)):
        bagian = list(teks)
    else:
        bagian = [t for t in re.split(r"[\s,;]+", str(teks).strip()) if t]
    if not bagian:
        raise ValueError("ciphertext tidak boleh kosong")
    try:
        angka = [int(x) for x in bagian]
    except (ValueError, TypeError):
        raise ValueError("ciphertext harus berupa bilangan bulat dipisah spasi atau koma")
    if any(a < 0 for a in angka):
        raise ValueError("ciphertext tidak boleh bernilai negatif")
    return angka


def decrypt_block(c, d, n):
    """m = c^d mod n untuk satu blok (syarat 0 <= c < n)."""
    if not (0 <= c < n):
        raise ValueError(f"blok ciphertext {c} harus memenuhi 0 <= blok < n = {n}")
    return pow(c, d, n)


def decrypt(ciphertext, private_key, encoding):
    """Dekripsi ciphertext (string atau list) dengan kunci privat (d, n).

    Mengembalikan dict: cipher_blocks, cipher_pad, plain_blocks, pad_count,
    block_size, codes, plaintext.
    """
    d, n = private_key
    semua = parse_ciphertext(ciphertext)
    if len(semua) < 2:
        raise ValueError("ciphertext minimal berisi 1 blok data + 1 blok pad")

    cipher_blocks, cipher_pad = semua[:-1], semua[-1]
    plain_blocks = [decrypt_block(c, d, n) for c in cipher_blocks]
    pad_count = decrypt_block(cipher_pad, d, n) - PAD_OFFSET

    k = block_size(n, encoding)
    if not (0 <= pad_count < k):
        raise ValueError("blok pad tidak valid (kunci atau ciphertext salah?)")

    codes = blocks_to_codes(plain_blocks, n, encoding, pad_count)
    return {
        "encoding": encoding,
        "cipher_blocks": cipher_blocks,
        "cipher_pad": cipher_pad,
        "plain_blocks": plain_blocks,
        "pad_count": pad_count,
        "block_size": k,
        "codes": codes,
        "plaintext": decode_codes(codes, encoding),
    }


def verify_roundtrip(plaintext, public_key, private_key, encoding):
    """Enkripsi lalu dekripsi; True jika hasilnya sama dengan plaintext awal."""
    hasil = encrypt(plaintext, public_key, encoding)
    kembali = decrypt(hasil["ciphertext"], private_key, encoding)
    return kembali["plaintext"] == plaintext
