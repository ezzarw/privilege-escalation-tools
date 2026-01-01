#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     PRIVILEGE ESCALATION ENUMERATION    ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"

mkdir -p /tmp/pe_enum_$$
output_dir="/tmp/pe_enum_$$"

echo -e "\n${BLUE}[+] System Information${NC}"
uname -a > "$output_dir/system_info.txt"
cat /etc/os-release >> "$output_dir/system_info.txt"
cat "$output_dir/system_info.txt"

echo -e "\n${BLUE}[+] User Information${NC}"
whoami > "$output_dir/user_info.txt"
id >> "$output_dir/user_info.txt"
cat /etc/passwd | grep -v nologin >> "$output_dir/user_info.txt"
cat "$output_dir/user_info.txt"

echo -e "\n${BLUE}[+] Network Configuration${NC}"
ip addr 2>/dev/null || ifconfig > "$output_dir/network.txt"
cat "$output_dir/network.txt"
netstat -tulpn 2>/dev/null > "$output_dir/netstat.txt" || ss -tulpn > "$output_dir/netstat.txt"
cat "$output_dir/netstat.txt"

echo -e "\n${BLUE}[+] Running Processes${NC}"
ps aux > "$output_dir/processes.txt"
cat "$output_dir/processes.txt"

echo -e "\n${BLUE}[+] SUID Files${NC}"
find / -perm -u=s -type f 2>/dev/null > "$output_dir/suid_files.txt"
cat "$output_dir/suid_files.txt"

echo -e "\n${BLUE}[+] SGID Files${NC}"
find / -perm -g=s -type f 2>/dev/null > "$output_dir/sgid_files.txt"
cat "$output_dir/sgid_files.txt"

echo -e "\n${BLUE}[+] Writable Directories${NC}"
find / -writable -type d 2>/dev/null > "$output_dir/writable_dirs.txt"
cat "$output_dir/writable_dirs.txt"

echo -e "\n${BLUE}[+] Writable Files in Critical Paths${NC}"
find /etc -writable -type f 2>/dev/null > "$output_dir/writable_etc.txt"
cat "$output_dir/writable_etc.txt"

echo -e "\n${BLUE}[+] Sudo Configuration${NC}"
sudo -l > "$output_dir/sudo_rights.txt" 2>&1
cat "$output_dir/sudo_rights.txt"
cat /etc/sudoers > "$output_dir/sudoers.txt" 2>/dev/null
cat "$output_dir/sudoers.txt" 2>/dev/null

echo -e "\n${BLUE}[+] Cron Jobs${NC}"
cat /etc/crontab > "$output_dir/crontab.txt" 2>/dev/null
ls -la /etc/cron* > "$output_dir/cron_dirs.txt" 2>/dev/null
cat "$output_dir/crontab.txt" 2>/dev/null
cat "$output_dir/cron_dirs.txt" 2>/dev/null

echo -e "\n${BLUE}[+] Capabilities${NC}"
getcap -r / 2>/dev/null > "$output_dir/capabilities.txt"
cat "$output_dir/capabilities.txt"

echo -e "\n${BLUE}[+] Kernel Version${NC}"
cat /proc/version > "$output_dir/kernel.txt"
cat "$output_dir/kernel.txt"
uname -r >> "$output_dir/kernel.txt"

echo -e "\n${BLUE}[+] Mounted Filesystems${NC}"
mount > "$output_dir/mount.txt"
cat "$output_dir/mount.txt"

echo -e "\n${BLUE}[+] SSH Keys${NC}"
find / -name "id_rsa" -o -name "id_dsa" -o -name "authorized_keys" 2>/dev/null > "$output_dir/ssh_keys.txt"
cat "$output_dir/ssh_keys.txt"

echo -e "\n${BLUE}[+] Password Hunting${NC}"
grep -r "password" /home/ 2>/dev/null > "$output_dir/passwords_home.txt"
grep -r "passwd" /home/ 2>/dev/null > "$output_dir/passwd_home.txt"
echo "Password strings in /home:"
cat "$output_dir/passwords_home.txt" 2>/dev/null | head -20

echo -e "\n${BLUE}[+] History Files${NC}"
find /home -name ".*history" -o -name ".bash_history" -o -name ".zsh_history" 2>/dev/null > "$output_dir/history_files.txt"
cat "$output_dir/history_files.txt"

echo -e "\n${BLUE}[+] World-readable files in /root${NC}"
find /root -readable -type f 2>/dev/null > "$output_dir/root_readable.txt"
cat "$output_dir/root_readable.txt"

echo -e "\n${BLUE}[+] Binary Information${NC}"
for file in $(find / -perm -4000 -type f 2>/dev/null | head -10); do
    ls -la "$file"
    file "$file"
done

echo -e "\n${GREEN}[+] Enumeration Complete! Results saved to: $output_dir${NC}"
