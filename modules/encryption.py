"""
encryption.py
=============
Enkripsi RSA (tugas Orang 2):   c = m^e mod n

Format ciphertext: [c1, c2, ..., cN, c_pad]
    c1..cN : enkripsi tiap blok plainteks
    c_pad  : enkripsi (pad_count + PAD_OFFSET), supaya dekripsi tahu berapa
             karakter padding yang harus dibuang di blok terakhir.
"""

from encoding import PAD_OFFSET, encode_message


def encrypt_block(m, e, n):
    """c = m^e mod n untuk satu blok (syarat 0 <= m < n)."""
    if not (0 <= m < n):
        raise ValueError(f"blok {m} harus memenuhi 0 <= blok < n = {n}")
    return pow(m, e, n)


def encrypt(plaintext, public_key, encoding):
    """Enkripsi teks dengan kunci publik (e, n).

    Mengembalikan dict:
        plaintext, encoding, codes, block_size, plain_blocks, pad_count,
        cipher_blocks   (c1..cN),
        cipher_pad      (blok pad),
        ciphertext_blocks (cipher_blocks + [cipher_pad]),
        ciphertext      (string, dipisah spasi; siap ditempel ke menu dekripsi)
    """
    e, n = public_key
    if n <= PAD_OFFSET + 1:
        raise ValueError("n terlalu kecil")
    enc = encode_message(plaintext, n, encoding)

    cipher_blocks = [encrypt_block(b, e, n) for b in enc["blocks"]]
    cipher_pad = encrypt_block(enc["pad_count"] + PAD_OFFSET, e, n)
    semua = cipher_blocks + [cipher_pad]

    return {
        "plaintext": plaintext,
        "encoding": encoding,
        "codes": enc["codes"],
        "block_size": enc["block_size"],
        "plain_blocks": enc["blocks"],
        "pad_count": enc["pad_count"],
        "cipher_blocks": cipher_blocks,
        "cipher_pad": cipher_pad,
        "ciphertext_blocks": semua,
        "ciphertext": " ".join(str(c) for c in semua),
    }
