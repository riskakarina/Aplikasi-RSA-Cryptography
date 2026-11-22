"""
app.py
======
Aplikasi web RSA Cryptography (Streamlit) - tugas Orang 3.

Menggabungkan modul:
    modules/key_generation.py  (Orang 1)
    modules/encoding.py        (Orang 2)
    modules/encryption.py      (Orang 2)
    modules/decryption.py      (Orang 2)

Jalankan di lokal:
    streamlit run app.py
"""

import sys
from pathlib import Path

import streamlit as st

# ---------------------------------------------------------------------------
# Agar modul di folder modules/ bisa di-import.
# (encoding.py memakai `from key_generation import ...`, jadi folder modules/
#  harus ada di sys.path.)
# ---------------------------------------------------------------------------
MODULES_DIR = Path(__file__).resolve().parent / "modules"
if str(MODULES_DIR) not in sys.path:
    sys.path.insert(0, str(MODULES_DIR))

import key_generation as kg  # noqa: E402
import encoding as enc  # noqa: E402
import encryption as encr  # noqa: E402
import decryption as decr  # noqa: E402

# ---------------------------------------------------------------------------
# Konfigurasi halaman
# ---------------------------------------------------------------------------
st.set_page_config(page_title="RSA Cryptography", page_icon="🔐", layout="wide")

ENCODING_LABEL = {
    kg.ENCODING_ASCII: "ASCII (kode 0-127)",
    kg.ENCODING_ALPHABET26: "26 Huruf (A=0 ... Z=25)",
}
ENCODING_OPTIONS = list(ENCODING_LABEL.keys())

MENU_KEY = "🔑 Key Generation"
MENU_ENC = "🔒 Encryption"
MENU_DEC = "🔓 Decryption"
MENU_ABOUT = "ℹ️ Tentang"


# ---------------------------------------------------------------------------
# Fungsi bantu
# ---------------------------------------------------------------------------
def parse_int(teks, nama, wajib=True):
    """Ubah teks menjadi int dengan pesan error yang jelas."""
    teks = (teks or "").strip()
    if teks == "":
        if wajib:
            raise ValueError(f"{nama} tidak boleh kosong")
        return None
    try:
        return int(teks)
    except ValueError:
        raise ValueError(f"{nama} harus berupa bilangan bulat (tanpa huruf/spasi/koma)")


def tampil_nilai(label, nilai):
    """Tampilkan satu nilai (angka bisa sangat panjang) dengan tombol copy."""
    st.markdown(f"**{label}**")
    try:
        st.code(str(nilai), language=None, wrap_lines=True)
    except TypeError:
        # Streamlit versi lama belum punya parameter wrap_lines
        st.code(str(nilai), language=None)


def pilih_encoding(key, default=None):
    idx = ENCODING_OPTIONS.index(default) if default in ENCODING_OPTIONS else 0
    return st.selectbox(
        "Metode encoding",
        ENCODING_OPTIONS,
        index=idx,
        format_func=lambda x: ENCODING_LABEL[x],
        key=key,
    )


def kunci_dari_session():
    return st.session_state.get("keys")


def input_kunci(jenis):
    """Ambil kunci publik/privat dari hasil Key Generation atau input manual.

    jenis: "public" -> mengembalikan (e, n)
           "private" -> mengembalikan (d, n)
    Mengembalikan None (dan menampilkan pesan) jika input manual belum valid.
    """
    keys = kunci_dari_session()
    nama_eksp = "e" if jenis == "public" else "d"
    nama_kunci = "publik" if jenis == "public" else "privat"

    opsi = []
    if keys:
        opsi.append("Pakai kunci hasil Key Generation")
    opsi.append("Input manual")
    sumber = st.radio(f"Sumber kunci {nama_kunci}", opsi, horizontal=True,
                      key=f"sumber_{jenis}")

    if sumber == "Pakai kunci hasil Key Generation":
        kunci = keys["public_key"] if jenis == "public" else keys["private_key"]
        st.info(f"Kunci {nama_kunci} ({nama_eksp}, n) dipakai dari menu Key Generation "
                f"(n = {keys['bit_length']} bit).")
        with st.expander(f"Lihat kunci {nama_kunci}"):
            tampil_nilai(nama_eksp, kunci[0])
            tampil_nilai("n", kunci[1])
        return kunci

    c1, c2 = st.columns(2)
    with c1:
        eks_teks = st.text_input(f"{nama_eksp}", key=f"man_eks_{jenis}")
    with c2:
        n_teks = st.text_input("n", key=f"man_n_{jenis}")
    if not eks_teks.strip() and not n_teks.strip():
        st.info(f"Isi kunci {nama_kunci} ({nama_eksp}, n) di atas.")
        return None
    try:
        eksp = parse_int(eks_teks, nama_eksp)
        n = parse_int(n_teks, "n")
        if eksp < 1:
            raise ValueError(f"{nama_eksp} harus bilangan bulat positif")
        if n < 2:
            raise ValueError("n harus lebih besar dari 1")
    except ValueError as err:
        st.error(str(err))
        return None
    return (eksp, n)


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
st.sidebar.title("🔐 RSA Cryptography")
menu = st.sidebar.radio("Menu", [MENU_KEY, MENU_ENC, MENU_DEC, MENU_ABOUT])

st.sidebar.divider()
_k = kunci_dari_session()
if _k:
    st.sidebar.success(f"Kunci aktif: {_k['bit_length']} bit")
    if st.sidebar.button("Hapus kunci aktif"):
        for s in ("keys", "last_enc"):
            st.session_state.pop(s, None)
        st.rerun()
else:
    st.sidebar.warning("Belum ada kunci. Buat dulu di menu Key Generation, "
                       "atau isi kunci manual di menu Encryption/Decryption.")


# ---------------------------------------------------------------------------
# MENU 1: Key Generation
# ---------------------------------------------------------------------------
def halaman_key_generation():
    st.title("🔑 Key Generation")
    st.caption("Membentuk pasangan kunci RSA: p, q → n = p×q → φ(n) = (p−1)(q−1) "
               "→ e (PBB(e, φ(n)) = 1) → d = e⁻¹ mod φ(n).")

    mode = st.radio("Cara pembentukan kunci",
                    ["Acak (tentukan ukuran bit)", "Manual (input p dan q)"],
                    horizontal=True)
    encoding_pilihan = pilih_encoding("enc_keygen")
    st.caption("Metode encoding hanya dipakai untuk menghitung jumlah karakter per blok. "
               "Kunci yang dihasilkan bisa dipakai untuk metode mana pun.")

    if mode.startswith("Acak"):
        c1, c2 = st.columns([2, 1])
        with c1:
            bit_size = st.number_input(
                "Ukuran n (bit)", min_value=kg.MIN_BIT_SIZE, max_value=kg.MAX_BIT_SIZE,
                value=512, step=16,
                help=f"Antara {kg.MIN_BIT_SIZE} dan {kg.MAX_BIT_SIZE} bit. "
                     "p dan q masing-masing sekitar setengahnya.",
            )
        with c2:
            e_teks = st.text_input("e (opsional)", placeholder="kosong = otomatis",
                                   help="Kosongkan agar dipilih otomatis (65537 jika memungkinkan).")
        if bit_size > 2048:
            st.warning("Ukuran di atas 2048 bit bisa memakan waktu lama (Python murni).")

        if st.button("Generate Kunci", type="primary"):
            try:
                e_user = parse_int(e_teks, "e", wajib=False)
                with st.spinner("Mencari bilangan prima p dan q..."):
                    hasil = kg.generate_keys(int(bit_size), e=e_user, encoding=encoding_pilihan)
            except ValueError as err:
                st.error(f"Gagal membuat kunci: {err}")
            else:
                st.session_state["keys"] = hasil
                st.session_state.pop("last_enc", None)
                st.rerun()  # render ulang agar status kunci di sidebar langsung diperbarui

    else:
        c1, c2, c3 = st.columns(3)
        with c1:
            p_teks = st.text_input("p (bilangan prima)", placeholder="contoh: 47")
        with c2:
            q_teks = st.text_input("q (bilangan prima)", placeholder="contoh: 71")
        with c3:
            e_teks = st.text_input("e (opsional)", placeholder="contoh: 79")

        if st.button("Hitung Kunci", type="primary"):
            try:
                p = parse_int(p_teks, "p")
                q = parse_int(q_teks, "q")
                e_user = parse_int(e_teks, "e", wajib=False)
                hasil = kg.generate_keys_from_primes(p, q, e_user, encoding=encoding_pilihan)
            except ValueError as err:
                st.error(f"Input tidak valid: {err}")
            else:
                st.session_state["keys"] = hasil
                st.session_state.pop("last_enc", None)
                st.rerun()  # render ulang agar status kunci di sidebar langsung diperbarui

    # ---- tampilkan hasil ----
    keys = kunci_dari_session()
    if not keys:
        return

    st.success("Kunci berhasil dibuat.")
    st.subheader("Hasil Pembentukan Kunci")

    c1, c2 = st.columns(2)
    with c1:
        tampil_nilai("p", keys["p"])
        tampil_nilai("φ(n) = (p−1)(q−1)", keys["m"])
        tampil_nilai("e (public exponent)", keys["e"])
    with c2:
        tampil_nilai("q", keys["q"])
        tampil_nilai("n = p × q", keys["n"])
        tampil_nilai("d (private exponent)", keys["d"])

    st.subheader("Public Key & Private Key")
    c1, c2 = st.columns(2)
    with c1:
        tampil_nilai("Public Key (e, n)", f"({keys['public_key'][0]}, {keys['public_key'][1]})")
    with c2:
        tampil_nilai("Private Key (d, n)", f"({keys['private_key'][0]}, {keys['private_key'][1]})")
    st.warning("Private key bersifat rahasia. Jangan dibagikan.")

    st.subheader("Informasi Ukuran Blok")
    m1, m2, m3 = st.columns(3)
    m1.metric("Ukuran n", f"{keys['bit_length']} bit")
    m2.metric("Karakter per blok (ASCII)", kg.max_chars_per_block(keys["n"], kg.ENCODING_ASCII))
    m3.metric("Karakter per blok (26 huruf)",
              kg.max_chars_per_block(keys["n"], kg.ENCODING_ALPHABET26))

    st.subheader("Validasi Kunci")
    lolos, daftar = kg.validate_keys(keys)
    for deskripsi, ok in daftar:
        st.write(("✅ " if ok else "❌ ") + deskripsi)
    if lolos:
        st.success("Semua pemeriksaan lolos. Kunci valid.")
    else:
        st.error("Ada pemeriksaan yang gagal. Buat ulang kunci.")


# ---------------------------------------------------------------------------
# MENU 2: Encryption
# ---------------------------------------------------------------------------
def halaman_encryption():
    st.title("🔒 Encryption")
    st.caption("Rumus enkripsi RSA: c = mᵉ mod n (dilakukan per blok).")

    public_key = input_kunci("public")

    keys = kunci_dari_session()
    encoding_pilihan = pilih_encoding("enc_encrypt", keys["encoding"] if keys else None)

    if encoding_pilihan == kg.ENCODING_ALPHABET26:
        st.caption("Metode 26 huruf hanya menerima huruf besar A–Z (tanpa spasi, angka, simbol).")
        normalisasi = st.checkbox("Otomatis ubah ke huruf besar dan buang karakter selain A–Z",
                                  value=True)
    else:
        st.caption("Metode ASCII menerima semua karakter dengan kode 0–127 "
                   "(huruf, angka, simbol, spasi). Karakter seperti é, 你, atau emoji tidak diterima.")
        normalisasi = False

    plaintext = st.text_area("Plaintext", height=120, placeholder="Tulis pesan di sini...")

    if st.button("Enkripsi", type="primary"):
        if public_key is None:
            st.error("Kunci publik belum lengkap atau tidak valid.")
            return
        teks = enc.normalize_alphabet26(plaintext) if normalisasi else plaintext
        if normalisasi and teks != plaintext:
            st.info(f"Plaintext setelah normalisasi: {teks}")

        ok, pesan = enc.validate_plaintext(teks, encoding_pilihan)
        if not ok:
            for p in pesan:
                st.error(p)
            return

        try:
            hasil = encr.encrypt(teks, public_key, encoding_pilihan)
        except ValueError as err:
            st.error(f"Enkripsi gagal: {err}")
            return
        st.session_state["last_enc"] = hasil

    hasil = st.session_state.get("last_enc")
    if not hasil:
        return

    st.success("Enkripsi berhasil.")
    st.subheader("Hasil Enkripsi")
    tampil_nilai("Plaintext", hasil["plaintext"])
    tampil_nilai(f"Hasil encoding ({ENCODING_LABEL[hasil['encoding']]})",
                 " ".join(str(c) for c in hasil["codes"]))

    c1, c2 = st.columns(2)
    c1.metric("Karakter per blok", hasil["block_size"])
    c2.metric("Jumlah padding", hasil["pad_count"])

    tampil_nilai("Blok plaintext (m)", " ".join(str(b) for b in hasil["plain_blocks"]))
    tampil_nilai("Ciphertext (c1 ... cN, c_pad)", hasil["ciphertext"])
    st.caption("Salin ciphertext di atas ke menu Decryption. "
               "Blok terakhir adalah blok pad (jangan dibuang).")

    with st.expander("Detail per blok"):
        for i, (m, c) in enumerate(zip(hasil["plain_blocks"], hasil["cipher_blocks"]), 1):
            st.write(f"Blok {i}: m = {m}  →  c = {c}")
        st.write(f"Blok pad: {hasil['pad_count']} + {enc.PAD_OFFSET} → c = {hasil['cipher_pad']}")


# ---------------------------------------------------------------------------
# MENU 3: Decryption
# ---------------------------------------------------------------------------
def halaman_decryption():
    st.title("🔓 Decryption")
    st.caption("Rumus dekripsi RSA: m = cᵈ mod n (dilakukan per blok).")

    private_key = input_kunci("private")

    last = st.session_state.get("last_enc")
    keys = kunci_dari_session()
    default_enc = last["encoding"] if last else (keys["encoding"] if keys else None)
    encoding_pilihan = pilih_encoding("enc_decrypt", default_enc)
    st.caption("Pilih metode encoding yang sama dengan saat enkripsi.")

    if last and st.button("Pakai ciphertext dari menu Encryption"):
        st.session_state["cipher_input"] = last["ciphertext"]

    ciphertext = st.text_area("Ciphertext", key="cipher_input", height=120,
                              placeholder="Contoh: 1234 5678 9012 3456 (dipisah spasi/koma/baris baru)")

    if st.button("Dekripsi", type="primary"):
        if private_key is None:
            st.error("Kunci privat belum lengkap atau tidak valid.")
            return
        try:
            hasil = decr.decrypt(ciphertext, private_key, encoding_pilihan)
        except ValueError as err:
            st.error(f"Dekripsi gagal: {err}")
            return

        st.success("Dekripsi berhasil.")
        st.subheader("Hasil Dekripsi")
        tampil_nilai("Ciphertext", " ".join(str(c) for c in hasil["cipher_blocks"]
                                            + [hasil["cipher_pad"]]))
        tampil_nilai("Blok plaintext (m)", " ".join(str(b) for b in hasil["plain_blocks"]))
        c1, c2 = st.columns(2)
        c1.metric("Karakter per blok", hasil["block_size"])
        c2.metric("Jumlah padding", hasil["pad_count"])
        tampil_nilai(f"Hasil decoding ({ENCODING_LABEL[hasil['encoding']]})",
                     " ".join(str(c) for c in hasil["codes"]))
        tampil_nilai("Plaintext hasil dekripsi", hasil["plaintext"])

        # bandingkan dengan plaintext awal bila ciphertext sama dengan hasil enkripsi terakhir
        if last and decr.parse_ciphertext(ciphertext) == decr.parse_ciphertext(last["ciphertext"]):
            if hasil["plaintext"] == last["plaintext"]:
                st.success("✅ Hasil dekripsi SAMA dengan plaintext awal.")
            else:
                st.error("❌ Hasil dekripsi BERBEDA dengan plaintext awal "
                         "(kunci privat atau metode encoding tidak cocok).")


# ---------------------------------------------------------------------------
# MENU 4: Tentang
# ---------------------------------------------------------------------------
def halaman_tentang():
    st.title("ℹ️ Tentang Aplikasi")
    st.markdown(
        """
Aplikasi ini mendemonstrasikan algoritma **RSA**:

1. **Key Generation**: pilih p dan q prima, hitung n = p×q, φ(n) = (p−1)(q−1),
   pilih e dengan PBB(e, φ(n)) = 1, lalu hitung d = e⁻¹ mod φ(n).
2. **Encryption**: pesan di-encode (ASCII atau 26 huruf), digabung menjadi blok
   bilangan < n, lalu dienkripsi dengan c = mᵉ mod n.
3. **Decryption**: m = cᵈ mod n, blok dipecah kembali dan di-decode menjadi teks.

**Alur penggunaan:** Key Generation → Encryption → Decryption.

Proyek ini dibuat untuk pembelajaran. Jangan dipakai untuk mengamankan data sungguhan
(tidak ada padding seperti OAEP).
        """
    )


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
if menu == MENU_KEY:
    halaman_key_generation()
elif menu == MENU_ENC:
    halaman_encryption()
elif menu == MENU_DEC:
    halaman_decryption()
else:
    halaman_tentang()