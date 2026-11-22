# 🔐 RSA Cryptography

Aplikasi web interaktif untuk mempelajari dan mendemonstrasikan algoritma kriptografi **RSA**, dibangun dengan Python dan [Streamlit](https://streamlit.io). Aplikasi ini mencakup tiga tahap utama RSA: pembentukan kunci, enkripsi, dan dekripsi, lengkap dengan tampilan langkah-langkah perhitungannya.

> ⚠️ **Proyek ini dibuat untuk tujuan pembelajaran.** Jangan dipakai untuk mengamankan data sungguhan. Implementasi ini tidak memakai skema padding standar seperti OAEP.

---

## ✨ Fitur

- **Key Generation**
  - Mode **acak**: tentukan ukuran bit (16–4096 bit), bilangan prima `p` dan `q` dibangkitkan otomatis.
  - Mode **manual**: masukkan sendiri `p`, `q`, dan (opsional) `e`.
  - Menampilkan `p`, `q`, `n`, `φ(n)`, `e`, `d`, *public key*, *private key*, dan validasi kunci.
- **Encryption**
  - Pilihan encoding **ASCII** (kode 0–127) atau **26 huruf** (A = 0 … Z = 25).
  - Menampilkan plaintext, hasil encoding, blok plaintext, dan ciphertext.
- **Decryption**
  - Memakai kunci privat dari hasil Key Generation atau input manual.
  - Menampilkan blok ciphertext, blok plaintext, hasil decoding, dan plaintext akhir.
  - Mengecek otomatis apakah hasil dekripsi sama dengan plaintext awal.
- **Validasi input & penanganan error**: karakter yang tidak sesuai metode encoding, `p`/`q` bukan prima, angka tidak valid, ciphertext atau kunci yang salah, semuanya menampilkan pesan error yang jelas tanpa membuat aplikasi berhenti.
- **Sidebar status kunci**: menampilkan kunci yang sedang aktif dan tombol untuk menghapusnya.

---

## 📁 Struktur Proyek

```
RSA-Cryptography/
│
├── app.py                  # Aplikasi Streamlit (UI dan integrasi modul)
│
├── modules/
│   ├── key_generation.py   # Pembentukan kunci RSA (p, q, n, φ(n), e, d)
│   ├── encoding.py         # Encoding/decoding ASCII dan 26 huruf, pembentukan blok
│   ├── encryption.py       # Enkripsi RSA: c = m^e mod n
│   └── decryption.py       # Dekripsi RSA: m = c^d mod n
│
├── tests/
│   └── test_rsa.py         # Pengujian
│
├── requirements.txt        # Daftar dependensi
└── README.md
```

---

## 🚀 Cara Menjalankan (Lokal)

### 1. Prasyarat

- **Python 3.9 atau lebih baru**
- `pip` (sudah termasuk di instalasi Python / Anaconda)

### 2. Salin proyek

```bash
git clone <url-repository-kamu>
cd RSA-Cryptography
```

> Kalau tidak memakai Git, cukup unduh foldernya lalu buka terminal di dalam folder `RSA-Cryptography/`.

### 3. (Opsional, disarankan) Buat virtual environment

```bash
python -m venv venv

# macOS / Linux
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### 4. Pasang dependensi

```bash
pip install -r requirements.txt
```

### 5. Jalankan aplikasi

```bash
streamlit run app.py
```

Browser akan terbuka otomatis di `http://localhost:8501`. Kalau tidak, buka alamat itu secara manual. Untuk menghentikan aplikasi, tekan `Ctrl+C` di terminal.

---

## 📖 Cara Menggunakan

Alur penggunaan: **Key Generation → Encryption → Decryption**. Pindah antar-menu lewat sidebar di sebelah kiri.

### 1️⃣ Key Generation

1. Pilih cara pembentukan kunci:
   - **Acak**: atur ukuran bit lalu klik **Generate Kunci**. Kolom `e` boleh dikosongkan (dipilih otomatis).
   - **Manual**: isi `p` dan `q` (harus bilangan prima), `e` opsional, lalu klik **Hitung Kunci**.
2. Hasilnya langsung tampil di halaman, dan sidebar berubah menjadi **"Kunci aktif"**.
3. Periksa bagian **Validasi Kunci**. Semua poin harus bertanda ✅.

### 2️⃣ Encryption

1. Pilih sumber kunci publik: **kunci hasil Key Generation** atau **input manual** `(e, n)`.
2. Pilih **metode encoding** (ASCII atau 26 huruf).
3. Tulis plaintext, lalu klik **Enkripsi**.
4. Salin **ciphertext** dari hasil. Kalau mau, langsung lanjut ke menu Decryption.

### 3️⃣ Decryption

1. Pilih sumber kunci privat: hasil Key Generation atau input manual `(d, n)`.
2. Pilih metode encoding yang **sama** dengan saat enkripsi.
3. Tempel ciphertext, atau klik **"Pakai ciphertext dari menu Encryption"**.
4. Klik **Dekripsi**. Plaintext akan muncul beserta pengecekan kesamaan dengan plaintext awal.

---

## 🧮 Contoh Perhitungan

Memakai mode **Manual** dengan `p = 47`, `q = 71`, `e = 79`:

| Besaran | Nilai | Rumus |
|---|---|---|
| `n` | 3337 | p × q |
| `φ(n)` | 3220 | (p − 1)(q − 1) |
| `e` | 79 | PBB(e, φ(n)) = 1 |
| `d` | 1019 | e · d ≡ 1 (mod φ(n)) |
| Public Key | (79, 3337) | (e, n) |
| Private Key | (1019, 3337) | (d, n) |

**Contoh enkripsi `HELLO` (metode 26 huruf):**

| Tahap | Hasil |
|---|---|
| Encoding | `7 4 11 11 14` |
| Blok plaintext (2 karakter/blok) | `186 297 364` (blok terakhir diberi 1 padding) |
| Ciphertext | `1655 78 2812 158` |

Dekripsi ciphertext tersebut dengan `d = 1019` menghasilkan kembali `HELLO`.

---

## 🔤 Metode Encoding

| Metode | Karakter yang diterima | Kode |
|---|---|---|
| **ASCII** | Huruf, angka, simbol, dan spasi (kode 0–127) | Sesuai tabel ASCII |
| **26 Huruf** | Hanya huruf besar `A–Z` (tanpa spasi, angka, simbol) | A = 0, B = 1, …, Z = 25 |

Pada metode 26 huruf, tersedia opsi otomatis untuk mengubah teks ke huruf besar dan membuang karakter selain A–Z.

### Cara pembentukan blok

Beberapa karakter digabung menjadi satu blok bilangan (dalam basis 128 untuk ASCII, basis 26 untuk 26 huruf), dengan jumlah karakter per blok sebesar mungkin selama nilai blok tetap lebih kecil dari `n`. Jika jumlah karakter bukan kelipatan ukuran blok, blok terakhir diberi padding.

### Format ciphertext

```
c1 c2 ... cN c_pad
```

- `c1 … cN` adalah hasil enkripsi tiap blok plaintext.
- `c_pad` adalah blok khusus yang menyimpan jumlah padding, supaya dekripsi tahu berapa karakter yang harus dibuang. **Jangan dibuang saat menyalin ciphertext.**

---

## 🛠️ Pemecahan Masalah

| Masalah | Penyebab / Solusi |
|---|---|
| Halaman browser putih kosong | Pastikan `app.py` tidak kosong dan dijalankan dari folder `RSA-Cryptography/`. Lihat juga pesan error di terminal. |
| `ModuleNotFoundError: key_generation` | Folder `modules/` harus ada di sebelah `app.py`. Jangan memindahkan `app.py` keluar dari folder proyek. |
| `streamlit: command not found` | Jalankan `pip install -r requirements.txt`, atau pakai `python -m streamlit run app.py`. |
| Angka kunci panjang tidak terbungkus rapi | Terjadi di Streamlit versi lama. Fungsi tetap normal. Untuk tampilan lebih rapi: `pip install --upgrade streamlit`. |
| Pembentukan kunci lambat | Ukuran di atas 2048 bit bisa memakan waktu lama karena pencarian prima memakai Python murni. Mulai dari 512 atau 1024 bit. |
| Dekripsi gagal / hasil aneh | Pastikan kunci privat pasangan dari kunci publik yang dipakai mengenkripsi, metode encoding sama, dan ciphertext disalin utuh (termasuk blok terakhir). |
| Kunci hilang setelah refresh halaman | Kunci aktif disimpan di sesi browser. Catat `d`, `e`, dan `n`, lalu pakai opsi **Input manual** bila perlu. |

---

## ☁️ Deployment (Streamlit Community Cloud)

Tahap ini opsional dan dilakukan setelah proyek di-*push* ke GitHub:

1. Unggah proyek ke repository GitHub (pastikan `app.py`, `modules/`, dan `requirements.txt` ikut ter-*commit*).
2. Buka [share.streamlit.io](https://share.streamlit.io) dan login dengan akun GitHub.
3. Klik **New app**, pilih repository dan branch, lalu isi *Main file path* dengan `app.py`.
4. Klik **Deploy**.

---

## 👥 Pembagian Tugas

| Anggota | Peran | Output |
|---|---|---|
| Orang 1 | Key Generation & Mathematical Foundation | `modules/key_generation.py` |
| Orang 2 | Encoding, Encryption & Decryption | `modules/encoding.py`, `modules/encryption.py`, `modules/decryption.py` |
| Orang 3 | Web Development, Integrasi & Deployment | `app.py`, `requirements.txt`, repository GitHub, web ter-*deploy* |

---

## 🧰 Teknologi

- [Python](https://www.python.org)
- [Streamlit](https://streamlit.io)

---

## 📚 Dasar Teori Singkat

1. Pilih dua bilangan prima `p` dan `q`.
2. Hitung `n = p × q`.
3. Hitung `φ(n) = (p − 1)(q − 1)`.
4. Pilih `e` dengan `PBB(e, φ(n)) = 1`.
5. Hitung `d` sehingga `e · d ≡ 1 (mod φ(n))` (balikan modulo).
6. **Enkripsi:** `c = mᵉ mod n`
7. **Dekripsi:** `m = cᵈ mod n`

Kunci publik: `(e, n)` · Kunci privat: `(d, n)`