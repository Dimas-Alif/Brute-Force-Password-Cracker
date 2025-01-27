# Pencarian Password dengan Brute Force dan Serangan Dictionary

Ini adalah program pencarian password yang memanfaatkan **brute force** dan **serangan dictionary** dengan dukungan **hashing**, termasuk SHA-256 dan bcrypt. Program ini juga dilengkapi kemampuan untuk **melanjutkan** dari status terakhir, mengelola **timeout**, dan menyimpan progress untuk menghindari memulai ulang proses. Selain itu, program ini mendukung algoritma hash kriptografi modern seperti **bcrypt**, **PBKDF2**, dan **SHA-256**.

## Fitur

- **Serangan Brute Force**: Program mencoba semua kombinasi karakter yang mungkin hingga panjang password yang ditentukan menggunakan set karakter yang diberikan.
- **Serangan Dictionary**: Program memeriksa password dari file dictionary, membandingkan hash dari setiap kata dengan target hash.
- **Penyimpanan Progress**: Secara otomatis menyimpan progress saat ini dan memungkinkan program untuk melanjutkan dari tempat yang terhenti jika terputus.
- **Mekanisme Timeout**: Program berhenti setelah batas waktu tertentu (10 menit) dan melaporkan status pada saat itu.
- **Multi-Threading**: Program memanfaatkan multi-threading untuk mempercepat proses serangan.

## Algoritma Hash yang Didukung

- **SHA-256**: Algoritma hash aman yang umum digunakan untuk hashing password.
- **bcrypt**: Algoritma hashing password yang dirancang agar lambat, membuat serangan brute force lebih sulit.
- **PBKDF2**: Fungsi derivasi kunci dengan jumlah iterasi yang dapat disesuaikan agar lebih tahan terhadap brute force.

## Persyaratan

- **Compiler C++** (GCC atau Clang disarankan)
- **Library OpenSSL** (untuk hashing SHA-256)
- **Library bcrypt** (untuk hashing bcrypt)
- **CMake** (untuk membangun proyek)
- **Dukungan Threading** (C++11 atau lebih tinggi)

## Instalasi

1. **Clone repositori:**
    ```bash
    git clone https://github.com/Dimas-Alif/Brute-Force-Password-Cracker.git
    cd password-cracker
    ```

2. **Instal dependensi:**
    - Pada Ubuntu, instal OpenSSL dan bcrypt:
      ```bash
      sudo apt-get install libssl-dev libbcrypt-dev
      ```

3. **Bangun proyek:**
    - Buat direktori build dan jalankan CMake:
      ```bash
      mkdir build
      cd build
      cmake ..
      make
      ```

## Penggunaan

1. **Siapkan file dictionary** (misalnya `dictionary.txt`) yang berisi daftar kata (satu kata per baris) untuk serangan dictionary.

2. **Jalankan program**:
    ```bash
    ./password-cracker
    ```

    Program akan:
    - Meng-hash password target menggunakan algoritma hash yang dipilih (misalnya, SHA-256 atau bcrypt).
    - Mencoba memecahkan password menggunakan serangan dictionary.
    - Jika serangan dictionary gagal, program akan beralih ke brute force.
    - Menyimpan progress setelah setiap kata atau kombinasi yang dicoba.
    - Berhenti setelah 10 menit atau ketika password ditemukan.

3. **Penyimpanan Progress**:
    - Program menyimpan progress dalam file (`progress.txt`), memungkinkan Anda untuk melanjutkan dari tempat terakhir jika terhenti.

## Contoh

```bash
$ ./password-cracker
Mencoba memecahkan password menggunakan sha256 hashing.
Password target (hash): 2cf24dba5fb0a30e26e83b2ac5b9e2d4
Memulai brute force attack...
Password ditemukan melalui brute force: password123
