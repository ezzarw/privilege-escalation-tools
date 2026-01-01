# Linux Privilege Escalation Scripts

Kumpulan script bash untuk otomatisasi enumerasi dan eksploitasi privilege escalation Linux, terutama untuk TryHackMe dan CTF.

## 📋 Daftar Script

### 1. **run_all_enums.sh** - Auto-Enumerator
Menjalankan semua script enumerasi sekaligus dan menghasilkan laporan lengkap.

### 2. **privilege_escalation_enum.sh** - Full Enumeration
Melakukan enumerasi lengkap sistem termasuk:
- Info sistem dan kernel
- User dan group
- Konfigurasi jaringan
- Proses yang berjalan
- File SUID dan SGID
- File/direktori yang dapat ditulis
- Konfigurasi sudo
- Cron jobs
- Capabilities
- SSH keys
- Password hunting
- History files

### 3. **suid_scanner.sh** - SUID Exploitation Helper
Memindai dan menganalisis file SUID untuk eksploitasi:
- Mendeteksi biner SUID yang rentan
- Mengidentifikasi biner dari GTFOBins
- Memberikan perintah eksploitasi untuk setiap biner
- Menganalisis biner SUID custom

### 4. **kernel_vuln_scanner.sh** - Kernel Vulnerability Scanner
Memeriksa kerentanan kernel:
- Versi kernel yang rentan
- CVE yang diketahui
- Integrasi dengan searchsploit
- Pengecekan Dirty COW dan Dirty Pipe
- Mekanisme proteksi (ASLR, Exec Shield)

### 5. **password_hunter.sh** - Password Hunting
Mencari kredensial di sistem:
- Pencarian password di direktori /home
- Analisis file history bash/zsh
- Pengecekan file konfigurasi
- Pencarian SSH keys
- Pencarian konfigurasi web application
- Pencarian string koneksi database
- Pengecekan environment variables
- Pencarian backup files
- Analisis log files

### 6. **sudo_exploit_scanner.sh** - Sudo & Environment Exploit Scanner
Menganalisis konfigurasi sudo dan environment:
- Pengecekan permission sudo
- Deteksi NOPASSWD dan ALL access
- Identifikasi biner yang dapat dieksploitasi
- Pengecekan LD_PRELOAD
- Pengecekan PATH yang dapat ditulis
- Pengecekan wildcards
- Deteksi versi sudo yang rentan

### 7. **cron_exploiter.sh** - Cron Job Exploiter
Menganalisis dan mengeksploitasi cron jobs:
- Analisis /etc/crontab
- Scanning direktori cron
- Pengecekan cron jobs user
- Identifikasi script yang dapat ditulis
- Pengecekan PATH manipulation
- Identifikasi wildcard injection
- Analisis script yang berjalan sebagai root

### 8. **docker_escape_scanner.sh** - Docker Escape Scanner
Memeriksa kemungkinan escape dari container:
- Deteksi container (Docker/LXC)
- Pengecekan group docker/lxd
- Analisis volume mounts
- Pengecekan privileged containers
- Analisis capabilities
- Teknik escape dari container

### 9. **capabilities_scanner.sh** - Linux Capabilities Scanner
Memindai dan menganalisis Linux capabilities:
- Identifikasi file dengan capabilities
- Deteksi capabilities berbahaya (CAP_SETUID, CAP_SYS_ADMIN, dll)
- Contoh eksploitasi untuk setiap capability
- Referensi lengkap capabilities

### 10. **quick_pe_summary.sh** - Quick Summary
Memberikan ringkasan cepat semua vector eskalasi:
- Checklist vektor eskalasi
- Rekomendasi eksploit
- Langkah-langkah berikutnya
- Referensi script lainnya

## 🚀 Cara Penggunaan

### Quick Start - Jalankan Semua Script
```bash
./run_all_enums.sh
```
Ini akan menjalankan semua script dan menyimpan hasilnya di `/tmp/pe_auto_TIMESTAMP/`

### Jalankan Script Individu
```bash
# Full enumeration
./privilege_escalation_enum.sh

# SUID analysis
./suid_scanner.sh

# Kernel vulnerability check
./kernel_vuln_scanner.sh

# Password hunting
./password_hunter.sh

# Sudo exploits
./sudo_exploit_scanner.sh

# Cron jobs
./cron_exploiter.sh

# Docker escape
./docker_escape_scanner.sh

# Capabilities
./capabilities_scanner.sh

# Quick summary
./quick_pe_summary.sh
```

## 📝 Output

Setiap script akan:
1. Menampilkan output ke terminal dengan pewarnaan
2. Menyimpan hasil lengkap ke file
3. Memberikan perintah eksploitasi spesifik
4. Memberikan referensi dan langkah-langkah

Output file biasanya disimpan di `/tmp/` dengan nama yang deskriptif.

## 🎯 Alur Kerja yang Disarankan

1. **Quick Scan Pertama**
   ```bash
   ./quick_pe_summary.sh
   ```
   Lihat ringkasan untuk identifikasi vector cepat

2. **Full Enumeration**
   ```bash
   ./privilege_escalation_enum.sh
   ```
   Dapatkan gambaran lengkap sistem

3. **Fokus pada Vector yang Ditemukan**
   - Jika SUID ditemukan: `./suid_scanner.sh`
   - Jika sudo access: `./sudo_exploit_scanner.sh`
   - Jika cron jobs: `./cron_exploiter.sh`
   - Jika capabilities: `./capabilities_scanner.sh`
   - Jika di docker: `./docker_escape_scanner.sh`

4. **Password Hunting**
   ```bash
   ./password_hunter.sh
   ```
   Cari kredensial yang tersimpan

5. **Kernel Check**
   ```bash
   ./kernel_vuln_scanner.sh
   ```
   Cari kerentanan kernel

## 🔧 Prerequisites

Script ini memerlukan:
- Bash shell (standar di Linux)
- Akses ke sistem sebagai user biasa
- Beberapa command mungkin butuh:
  - `getcap` (libcap2-bin)
  - `searchsploit` (exploitdb)
  - `docker` (untuk docker escape)
  - `lxc` (untuk LXD escape)

Install di Kali:
```bash
sudo apt update
sudo apt install -y libcap2-bin exploitdb
```

## 📚 Referensi Eksploitasi

### GTFOBins
https://gtfobins.github.io/ - Referensi eksploitasi biner Linux

### searchsploit
```bash
searchsploit "Linux Kernel"
searchsploit "sudo 1.8"
```

### CVE Penting untuk Dikenang
- CVE-2016-5195 (Dirty COW)
- CVE-2021-4034 (pkexec)
- CVE-2022-0847 (Dirty Pipe)
- CVE-2019-18634 (sudo 1.7.1 - 1.8.31p2)
- CVE-2019-14287 (sudo 1.8.28-)

## ⚠️ Catatan Penting

1. **Educational Purpose Only**
   - Script ini dibuat untuk tujuan edukasi
   - Gunakan hanya di sistem yang Anda miliki atau memiliki izin
   - Jangan gunakan untuk aktivitas ilegal

2. **Pewarnaan Terminal**
   - Hijau: Informasi umum
   - Kuning: Peringatan atau perhatian
   - Merah: Eksploit potensial atau kerentanan
   - Biru: Kategori informasi

3. **Output Files**
   - Semua output disimpan di `/tmp/`
   - File otomatis dibersihkan setelah reboot
   - Simpan pentingnya output ke lokasi lain

## 🎓 Tips untuk TryHackMe LinuxPrivEsc

1. Selalu mulai dengan enumerasi lengkap
2. Cek eksploitasi kernel dulu (kemenangan cepat)
3. Periksa SUID dan sudo
4. Cari cron jobs yang dapat ditulis
5. Cari kredensial di file history dan konfigurasi
6. Cek capabilities
7. Periksa environment (LD_PRELOAD, PATH)
8. Jangan lupa SSH keys dan authorized_keys

## 📖 Contoh Eksploitasi Umum

### SUID Biner
```bash
# Nmap
nmap --interactive
!sh

# Vim
vim /etc/shadow
:shell

# Find
find . -exec /bin/sh \; -quit

# Bash
./bash -p
```

### Sudo
```bash
# Full access
sudo su

# Specific binary
sudo -u root /bin/bash

# LD_PRELOAD (jika diizinkan)
sudo LD_PRELOAD=/tmp/lib.so <command>
```

### Capabilities
```bash
# CAP_SETUID
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

## 🤝 Kontribusi

Script ini dapat diperluas dengan:
- Menambahkan teknik eskalasi baru
- Memperbaiki bug
- Menambahkan deteksi eksploitasi baru

## 📄 Lisensi

Script ini dibuat untuk tujuan edukasi. Gunakan dengan tanggung jawab.

---

**Selamat hunting dan good luck dengan privilege escalation!** 🎯
