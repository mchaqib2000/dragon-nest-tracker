# Game Account Tracker

Aplikasi GUI (Tkinter) untuk mengelola banyak akun game beserta info
karakter dan status clear dungeon.

## Instalasi

1. Pastikan Python 3.9+ sudah terpasang.
2. Buka terminal/command prompt di folder ini, lalu jalankan:
   ```
   pip install -r requirements.txt
   ```
   (Di beberapa sistem Linux, `tkinter` perlu dipasang terpisah, misal:
   `sudo apt install python3-tk`)

## Menjalankan aplikasi

```
python login.py
```

- **Pertama kali dijalankan**: kamu akan diminta membuat *master password*.
  Password ini yang akan diminta setiap kali membuka aplikasi.
- Setelah login, kamu akan melihat tabel akun dengan kolom:
  `Char ID`, `Nama`, `Level`, `Job`, `Info Dungeon`.

## Fitur

- **Tambah Akun** – isi Character ID, password akun game, nama, level, job,
  dan centang status dungeon:
  - **Nest**: PKN HC, TKN HC, Guardian
  - **Dragon Fellowship**: Dragon Expedition Lv.60, Lv.70
- **Edit Akun** – klik dua kali baris di tabel, atau pilih baris lalu klik
  tombol "Edit Akun". Kosongkan field password kalau tidak ingin
  mengubahnya.
- **Hapus Akun**
- **Lihat Password** – menampilkan password akun (setelah didekripsi)
  untuk baris yang dipilih.
- **Ganti Master Password** (menu File) – semua password akun otomatis
  dienkripsi ulang dengan password master yang baru.

## Keamanan & penyimpanan data

- Semua data disimpan lokal di folder `data/` (dibuat otomatis di
  sebelah file `.py` ini):
  - `data/config.json` – hash master password + salt (bukan password asli)
  - `data/accounts.json` – data akun, dengan **password terenkripsi**
    (Fernet/AES, kunci diturunkan dari master password via PBKDF2)
- Field lain (Char ID, nama, level, job, status dungeon) disimpan sebagai
  teks biasa di `accounts.json`.
- **Jangan bagikan folder `data/`** ke orang lain.
- **Penting**: jika lupa master password, password akun yang tersimpan
  **tidak bisa dipulihkan**. Tidak ada fitur reset/lupa password by design,
  karena itulah yang membuat data terenkripsi aman.

## Menyesuaikan aplikasi

- Kolom dungeon (Nest & Dragon Fellowship) diatur di bagian atas
  `game_account_tracker.py` lewat variabel `NEST_LABELS` dan
  `DRAGON_LABELS` — tambah/ubah daftar dungeon di situ kalau perlu.
