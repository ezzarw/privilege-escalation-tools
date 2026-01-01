#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║      PRIVILEGE ESCALATION SUMMARY       ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"

output_dir="/tmp/pe_summary_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$output_dir"
summary_file="$output_dir/summary.txt"

echo "Privilege Escalation Enumeration Summary" > "$summary_file"
echo "Generated: $(date)" >> "$summary_file"
echo "========================================" >> "$summary_file"

echo -e "\n${BLUE}[+] Quick System Info${NC}"
uname -a | tee -a "$summary_file"
id | tee -a "$summary_file"

echo -e "\n${BLUE}[+] Escalation Vector Checklist${NC}"
echo "========================================" >> "$summary_file"
echo "ESCALATION VECTORS:" >> "$summary_file"

exploits_found=0

echo -e "\n${YELLOW}[?] SUID Binaries${NC}"
suid_count=$(find / -perm -u=s -type f 2>/dev/null | wc -l)
echo "    SUID binaries found: $suid_count" | tee -a "$summary_file"
if [ "$suid_count" -gt 0 ]; then
    find / -perm -u=s -type f 2>/dev/null | tee -a "$summary_file"
    exploits_found=$((exploits_found + 1))
fi

echo -e "\n${YELLOW}[?] Sudo Access${NC}"
if sudo -l &>/dev/null; then
    echo -e "${GREEN}    Sudo access available${NC}" | tee -a "$summary_file"
    sudo -l 2>&1 | tee -a "$summary_file"
    if echo "$(sudo -l 2>&1)" | grep -q "(ALL)"; then
        echo -e "${RED}    [!] FULL SUDO ACCESS${NC}" | tee -a "$summary_file"
        exploits_found=$((exploits_found + 1))
    fi
else
    echo "    No sudo access" | tee -a "$summary_file"
fi

echo -e "\n${YELLOW}[?] Kernel Version${NC}"
kernel_version=$(uname -r)
echo "    Kernel: $kernel_version" | tee -a "$summary_file"
echo "    Check searchsploit for kernel exploits" | tee -a "$summary_file"

echo -e "\n${YELLOW}[?] Capabilities${NC}"
if command -v getcap &> /dev/null; then
    cap_count=$(getcap -r / 2>/dev/null | wc -l)
    echo "    Files with capabilities: $cap_count" | tee -a "$summary_file"
    if [ "$cap_count" -gt 0 ]; then
        getcap -r / 2>/dev/null | tee -a "$summary_file"
        if getcap -r / 2>/dev/null | grep -qi "setuid"; then
            echo -e "${RED}    [!] CAP_SETUID found${NC}" | tee -a "$summary_file"
            exploits_found=$((exploits_found + 1))
        fi
    fi
else
    echo "    getcap not available" | tee -a "$summary_file"
fi

echo -e "\n${YELLOW}[?] Cron Jobs${NC}"
if [ -f /etc/crontab ]; then
    cron_jobs=$(grep -v "^#" /etc/crontab | grep -v "^$" | wc -l)
    echo "    Cron jobs in /etc/crontab: $cron_jobs" | tee -a "$summary_file"
    if [ "$cron_jobs" -gt 0 ]; then
        grep -v "^#" /etc/crontab | grep -v "^$" | tee -a "$summary_file"
    fi
fi

if [ -d /etc/cron.d ]; then
    cron_d_jobs=$(ls /etc/cron.d/ | wc -l)
    echo "    Cron.d files: $cron_d_jobs" | tee -a "$summary_file"
    ls -la /etc/cron.d/ | tee -a "$summary_file"
fi

echo -e "\n${YELLOW}[?] Writable Files${NC}"
writable_etc=$(find /etc -writable -type f 2>/dev/null | wc -l)
echo "    Writable files in /etc: $writable_etc" | tee -a "$summary_file"
if [ "$writable_etc" -gt 0 ]; then
    find /etc -writable -type f 2>/dev/null | head -20 | tee -a "$summary_file"
    exploits_found=$((exploits_found + 1))
fi

writable_scripts=$(find /etc/cron* -writable -type f 2>/dev/null | wc -l)
echo "    Writable cron scripts: $writable_scripts" | tee -a "$summary_file"
if [ "$writable_scripts" -gt 0 ]; then
    find /etc/cron* -writable -type f 2>/dev/null | tee -a "$summary_file"
    exploits_found=$((exploits_found + 1))
fi

echo -e "\n${YELLOW}[?] SSH Keys${NC}"
ssh_keys=$(find /home -name "id_rsa*" -o -name "id_dsa*" 2>/dev/null | wc -l)
echo "    SSH keys found: $ssh_keys" | tee -a "$summary_file"
if [ "$ssh_keys" -gt 0 ]; then
    find /home -name "id_rsa*" -o -name "id_dsa*" 2>/dev/null | tee -a "$summary_file"
fi

echo -e "\n${YELLOW}[?] Passwords in Home${NC}"
passwords=$(grep -ri "password" /home/ 2>/dev/null | wc -l)
echo "    Password occurrences in /home: $passwords" | tee -a "$summary_file"
if [ "$passwords" -gt 0 ]; then
    grep -ri "password" /home/ 2>/dev/null | head -20 | tee -a "$summary_file"
fi

echo -e "\n${YELLOW}[?] User Groups${NC}"
groups | tee -a "$summary_file"
privileged_groups=("docker" "lxd" "lxc" "wheel" "sudo" "admin")
for group in "${privileged_groups[@]}"; do
    if groups | grep -q "$group"; then
        echo -e "${RED}    [!] User is in $group group${NC}" | tee -a "$summary_file"
        exploits_found=$((exploits_found + 1))
    fi
done

echo -e "\n${YELLOW}[?] Network Services${NC}"
netstat -tulpn 2>/dev/null | grep LISTEN | tee -a "$summary_file" || ss -tulpn | grep LISTEN | tee -a "$summary_file"

echo -e "\n${YELLOW}[?] Docker${NC}"
if command -v docker &> /dev/null; then
    echo -e "${GREEN}    Docker is available${NC}" | tee -a "$summary_file"
    if docker ps &>/dev/null; then
        echo -e "${RED}    [!] Can run docker commands${NC}" | tee -a "$summary_file"
        docker ps -a | tee -a "$summary_file"
        exploits_found=$((exploits_found + 1))
    fi
fi

echo -e "\n${YELLOW}[?] History Files${NC}"
find /home -name ".*history" 2>/dev/null | tee -a "$summary_file"

echo -e "\n${YELLOW}[?] Readable Config Files${NC}"
readable_conf=$(find /etc -maxdepth 1 -readable -type f 2>/dev/null | wc -l)
echo "    Readable files in /etc: $readable_conf" | tee -a "$summary_file"

echo -e "\n${YELLOW}[?] World-readable /root${NC}"
readable_root=$(find /root -readable -type f 2>/dev/null | wc -l)
echo "    Readable files in /root: $readable_root" | tee -a "$summary_file"
if [ "$readable_root" -gt 0 ]; then
    find /root -readable -type f 2>/dev/null | tee -a "$summary_file"
    exploits_found=$((exploits_found + 1))
fi

echo -e "\n${BLUE}[+] Exploit Recommendations${NC}"
echo "========================================" >> "$summary_file"
echo "RECOMMENDATIONS:" >> "$summary_file"

if [ "$exploits_found" -eq 0 ]; then
    echo -e "${GREEN}[+] No obvious exploits found${NC}"
    echo "    Try kernel exploits" | tee -a "$summary_file"
    echo "    Try password spraying" | tee -a "$summary_file"
    echo "    Check running services" | tee -a "$summary_file"
else
    echo -e "${RED}[!] Found $exploits_found potential exploit vectors${NC}" | tee -a "$summary_file"
fi

echo -e "\n${BLUE}[+] Next Steps${NC}"
cat << 'EOF' | tee -a "$summary_file"

1. If SUID found:
   - Run suid_scanner.sh for detailed analysis
   - Check GTFOBins: https://gtfobins.github.io/

2. If sudo access:
   - Run sudo_exploit_scanner.sh
   - Try sudo commands with !/bin/sh

3. If kernel old:
   - Search searchsploit for kernel version
   - Check Dirty COW (CVE-2016-5195)

4. If writable files:
   - Add reverse shell to cron scripts
   - Modify critical config files

5. If capabilities:
   - Run capabilities_scanner.sh
   - Try cap_setuid binaries

6. If docker access:
   - Run docker_escape_scanner.sh
   - Try mounting host filesystem

7. Always:
   - Check /etc/passwd and /etc/shadow
   - Look for passwords in config files
   - Check user command history
   - Verify network services
EOF

echo -e "\n${GREEN}[+] Summary complete${NC}"
echo -e "${YELLOW}Full summary saved to: $summary_file${NC}"
echo -e "${YELLOW}Output directory: $output_dir${NC}"

echo -e "\n${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     AVAILABLE ENUMERATION SCRIPTS       ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"

cat << 'EOF'

Run individual scripts for detailed analysis:
1. privilege_escalation_enum.sh   - Full enumeration
2. suid_scanner.sh                - SUID exploitation
3. kernel_vuln_scanner.sh         - Kernel vulnerabilities
4. password_hunter.sh             - Credential hunting
5. sudo_exploit_scanner.sh        - Sudo & environment exploits
6. cron_exploiter.sh              - Cron job analysis
7. docker_escape_scanner.sh       - Container escape
8. capabilities_scanner.sh        - Linux capabilities

EOF
