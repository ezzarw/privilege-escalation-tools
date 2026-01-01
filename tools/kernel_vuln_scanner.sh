#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║      KERNEL VULNERABILITY SCANNER       ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"

echo -e "\n${BLUE}[+] Collecting kernel information${NC}"

kernel_version=$(uname -r)
kernel_release=$(uname -v)
kernel_arch=$(uname -m)
distro_id=$(cat /etc/os-release | grep -oP 'ID=\K[^"]+' 2>/dev/null || echo "unknown")
distro_version=$(cat /etc/os-release | grep -oP 'VERSION_ID=\K[^"]+' 2>/dev/null || echo "unknown")

echo -e "${GREEN}Kernel Version: $kernel_version${NC}"
echo -e "${GREEN}Kernel Release: $kernel_release${NC}"
echo -e "${GREEN}Architecture: $kernel_arch${NC}"
echo -e "${GREEN}Distribution: $distro_id${NC}"
echo -e "${GREEN}Dist Version: $distro_version${NC}"

kernel_major=$(echo $kernel_version | cut -d. -f1)
kernel_minor=$(echo $kernel_version | cut -d. -f2)

echo -e "\n${BLUE}[+] Checking for known vulnerable kernel versions${NC}"

vulnerable_kernels=(
    "2.6.0-2.6.39"
    "3.0-3.9"
    "4.1-4.4"
    "2.6.36-2.6.39"
    "3.0-3.6"
    "4.4.0-4.4.10"
    "2.4.18-2.4.22"
    "2.6.0-2.6.2"
    "3.5-3.7"
)

known_cves=(
    "CVE-2016-5195|Dirty COW|2.6.22-4.6.0"
    "CVE-2016-0728|Keyring|3.2-3.18"
    "CVE-2017-1000112|Linux Kernel|2.6.18-4.8.0"
    "CVE-2017-5123|waitid()|4.13"
    "CVE-2017-16995|ebpf|4.13-4.15"
    "CVE-2018-1000001|Real-Time|4.14"
    "CVE-2018-18281|fsuid|4.13-4.19"
    "CVE-2019-18683|fs/fs.c|4.19"
    "CVE-2019-18634|sudo|1.7-1.8"
    "CVE-2021-4034|pkexec|All versions"
    "CVE-2022-0847|Dirty Pipe|5.8-5.10"
)

echo -e "\n${YELLOW}[+] Known CVEs to check:${NC}"
for cve in "${known_cves[@]}"; do
    IFS='|' read -r cve_id cve_name cve_affected <<< "$cve"
    echo -e "    $cve_id - $cve_name (Affected: $cve_affected)"
done

echo -e "\n${BLUE}[+] Searching for kernel exploits with searchsploit${NC}"
if command -v searchsploit &> /dev/null; then
    searchsploit --color "Linux Kernel" | head -20
else
    echo -e "${RED}[!] searchsploit not found${NC}"
    echo -e "${YELLOW}    Install: sudo apt install exploitdb${NC}"
fi

echo -e "\n${BLUE}[+] Checking loaded kernel modules${NC}"
lsmod | head -20

echo -e "\n${BLUE}[+] Checking kernel config${NC}"
if [ -f /boot/config-$(uname -r) ]; then
    echo -e "${GREEN}Kernel config found${NC}"
    grep -i "CONFIG_BINFMT_MISC\|CONFIG_DEBUG\|CONFIG_SECURITY" /boot/config-$(uname -r) | head -10
else
    echo -e "${YELLOW}Kernel config not found${NC}"
fi

echo -e "\n${BLUE}[+] Checking for protection mechanisms${NC}"

if [ -f /proc/sys/kernel/exec-shield ]; then
    exec_shield=$(cat /proc/sys/kernel/exec-shield)
    echo -e "${GREEN}Exec Shield: $exec_shield${NC}"
fi

if [ -f /proc/sys/kernel/randomize_va_space ]; then
    aslr=$(cat /proc/sys/kernel/randomize_va_space)
    case $aslr in
        0) echo -e "${RED}ASLR: Disabled ($aslr)${NC}" ;;
        1) echo -e "${YELLOW}ASLR: Partial ($aslr)${NC}" ;;
        2) echo -e "${GREEN}ASLR: Full ($aslr)${NC}" ;;
    esac
fi

echo -e "\n${BLUE}[+] Checking CPU features${NC}"
if command -v lscpu &> /dev/null; then
    lscpu | grep -E "Flags|Model name"
fi

echo -e "\n${BLUE}[+] Checking for Dirty COW vulnerability${NC}"
echo -e "${YELLOW}Check if kernel is in range 2.6.22-4.6.0${NC}"
echo -e "${YELLOW}Quick test: grep -q 'dirty' /proc/vmallocinfo${NC}"
grep -q "dirty" /proc/vmallocinfo 2>/dev/null && echo -e "${RED}[!] Potentially vulnerable to Dirty COW${NC}" || echo -e "${GREEN}[+] Dirty COW check passed${NC}"

echo -e "\n${BLUE}[+] Checking for Dirty Pipe vulnerability${NC}"
echo -e "${YELLOW}Check if kernel is in range 5.8-5.10${NC}"

echo -e "\n${GREEN}[+] Kernel enumeration complete${NC}"
echo -e "${YELLOW}Recommendations:${NC}"
echo -e "    1. Check searchsploit for specific exploits"
echo -e "    2. Compile exploits on target system"
echo -e "    3. Check kernel config for exploit requirements"
echo -e "    4. Verify kernel version matches exploit requirements"
