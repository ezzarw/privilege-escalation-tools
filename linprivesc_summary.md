# Rangkuman Eskalasi Hak Akses Linux untuk CTF/Kompetisi

## Teknik Penting yang Harus Diingat

### 1. Enumerasi
- **Informasi Sistem**: `uname -a`, `cat /etc/os-release`, `cat /etc/passwd`, `cat /etc/group`
- **Versi Kernel**: `cat /proc/version`, `dmesg | grep Linux`
- **Konfigurasi Jaringan**: `ip addr`, `cat /etc/hosts`, `netstat -tulpn`
- **Proses Berjalan**: `ps aux`, `ps aux | grep root`
- **Layanan**: `systemctl list-units --type=service --state=running`

### 2. Enumerasi Sistem File
- **Biner SUID**: `find / -perm -u=s -type f 2>/dev/null`
- **File/Direktori Dapat Ditulis**: `find / -writable -type d 2>/dev/null`
- **Hak Akses Sudo**: `sudo -l`
- **Tugas Cron**: `cat /etc/crontab`, `ls -la /etc/cron*`
- **Kunci SSH**: `find / -name id_rsa 2>/dev/null`, `find / -name authorized_keys 2>/dev/null`

### 3. Eksploitasi Kernel
- Cari kernel lama dengan kerentanan yang diketahui
- Gunakan tools seperti `searchsploit` untuk mencari eksploitasi kernel
- Target umum: kernel lama dengan dirtycow, CVE-2016-5195, dll.

### 4. Eksploitasi Sudo/SUID
- **GTFOBins**: Periksa apakah biner SUID dapat dieksploitasi menggunakan GTFOBins
- **Kesalahan Konfigurasi Sudo**: NOPASSWD, !root, dll.
- **LD_PRELOAD**: Jika diizinkan dalam lingkungan sudo

### 5. Pencarian Kata Sandi
- `grep -r password /home/* 2>/dev/null`
- Periksa kata sandi di:
  - File konfigurasi
  - File riwayat (`~/.bash_history`, `~/.zsh_history`)
  - File konfigurasi SSH
  - File database

### 6. Eksploitasi Layanan
- **NFS**: Ekspor yang salah konfigurasi dengan no_root_squash
- **Tugas Cron**: Skrip dapat ditulis, manipulasi PATH
- **Layanan dapat ditulis semua**: `/etc/passwd`, `/etc/sudoers`

### 7. Kemampuan (Capabilities)
- Periksa dengan: `getcap -r / 2>/dev/null`
- Eksploitasi kemampuan seperti `cap_setuid+ep`

### 8. Keluar dari Docker/Kontainer
- Periksa grup docker: `groups`
- Titik kaitan yang mungkin mengekspos sistem host

### 9. Trik SSH/Sudo
- `sudo su -` vs `sudo -i` vs `sudo su`
- Penyalahgunaan penerusan agen SSH
- Manipulasi kunci terotorisasi

### 10. Variabel Lingkungan
- Manipulasi PATH dalam skrip
- LD_PRELOAD untuk injeksi pustaka bersama
- Periksa info sensitif dalam variabel lingkungan

## Perintah Satu Baris untuk Enumerasi

```bash
# Skrip enumerasi dasar
cat > enum.sh << 'EOF'
#!/bin/bash
echo "=== Info Sistem ==="
uname -a
cat /etc/os-release
cat /etc/passwd
cat /etc/group

echo "=== Kernel ==="
cat /proc/version
dmesg | grep Linux

echo "=== Jaringan ==="
ip addr
netstat -tulpn

echo "=== Proses ==="
ps aux

echo "=== Hak Akses Sudo ==="
sudo -l

echo "=== Biner SUID ==="
find / -perm -u=s -type f 2>/dev/null

echo "=== File Dapat Ditulis ==="
find / -writable -type d 2>/dev/null

echo "=== Tugas Cron ==="
cat /etc/crontab
ls -la /etc/cron*

echo "=== File Kata Sandi ==="
grep -r password /home/* 2>/dev/null
EOF

# Jalankan dengan: bash enum.sh
```

## Referensi GTFOBins
Saat menemukan biner SUID, periksa GTFOBins:
- `find / -perm -u=s -type f 2>/dev/null` untuk menemukan biner SUID
- Kunjungi https://gtfobins.github.io/ untuk melihat apakah ada yang bisa dieksploitasi
- Contoh umum: `find`, `less`, `more`, `vim`, `nano`, `cp`, `mv`

## Jalur Umum untuk CTF
- `/home/user/.ssh/`
- `/var/www/`
- `/opt/`
- `/tmp/` dan `/var/tmp/`
- `/etc/passwd`, `/etc/shadow`
- `/root/` (jika dapat diakses)

## Perintah Berguna untuk Eskalasi
- `python -c 'import pty; pty.spawn("/bin/bash")'` (untuk TTY)
- `export TERM=xterm` (setelah mendapatkan TTY)
- `sudo -l` (cek apa yang bisa dijalankan sebagai sudo)
- `find / -perm -4000 2>/dev/null` (pencarian SUID alternatif)

## Ingat untuk Kompetisi
1. Selalu mulai dengan enumerasi menyeluruh
2. Periksa eksploitasi kernel terlebih dahulu (kemenangan cepat)
3. Cari layanan yang salah konfigurasi
4. Perhatikan layanan khusus yang sedang berjalan
5. Jangan lupa periksa lingkungan Docker atau kontainer
6. Simpan daftar kata sandi umum dan coba mereka
7. Gunakan LinEnum.sh atau LinPEAS.sh jika tersedia
8. Selalu coba kata sandi default dan kata sandi lemah umum
9. Periksa layanan yang berjalan di localhost yang mungkin bisa dieksploitasi
10. Cari file cadangan, file konfigurasi, dan log yang mungkin berisi kredensial
```

This summary contains the most important Linux privilege escalation techniques you'll need for competitions. When you have access to the actual TryHackMe LinPrivEsc content, you can add specific techniques and examples from that room to this summary.