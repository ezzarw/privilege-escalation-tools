#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}╔════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     PRIVILEGE ESCALATION AUTO-ENUMERATOR      ║${NC}"
echo -e "${GREEN}║              TryHackMe LinuxPrivEsc           ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}"

script_dir=$(dirname "$0")
timestamp=$(date +%Y%m%d_%H%M%S)
output_dir="/tmp/pe_auto_$timestamp"
mkdir -p "$output_dir"

echo -e "\n${BLUE}[+] Output directory: $output_dir${NC}"

scripts=(
    "privilege_escalation_enum.sh:Full System Enumeration"
    "suid_scanner.sh:SUID Analysis"
    "kernel_vuln_scanner.sh:Kernel Vulnerabilities"
    "password_hunter.sh:Password Hunting"
    "sudo_exploit_scanner.sh:Sudo Exploits"
    "cron_exploiter.sh:Cron Jobs"
    "docker_escape_scanner.sh:Docker Escape"
    "capabilities_scanner.sh:Capabilities"
)

echo -e "\n${BLUE}[+] Running all enumeration scripts...${NC}\n"

for script_info in "${scripts[@]}"; do
    IFS=':' read -r script_name script_desc <<< "$script_info"
    script_path="$script_dir/$script_name"
    
    echo -e "${GREEN}═══════════════════════════════════════════${NC}"
    echo -e "${GREEN}[+] Running: $script_name${NC}"
    echo -e "${YELLOW}    Description: $script_desc${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════${NC}\n"
    
    if [ -x "$script_path" ]; then
        "$script_path" 2>&1 | tee "$output_dir/${script_name%.sh}_output.txt"
    elif [ -f "$script_path" ]; then
        bash "$script_path" 2>&1 | tee "$output_dir/${script_name%.sh}_output.txt"
    else
        echo -e "${RED}[!] Script not found: $script_path${NC}"
    fi
    
    echo -e "\n"
done

echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}[+] Running: quick_pe_summary.sh${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}\n"

if [ -x "$script_dir/quick_pe_summary.sh" ]; then
    "$script_dir/quick_pe_summary.sh" 2>&1 | tee "$output_dir/final_summary.txt"
elif [ -f "$script_dir/quick_pe_summary.sh" ]; then
    bash "$script_dir/quick_pe_summary.sh" 2>&1 | tee "$output_dir/final_summary.txt"
fi

echo -e "\n${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}[+] FINAL SUMMARY${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}\n"

echo -e "${BLUE}[+] All results saved to: $output_dir${NC}"
echo -e "\n${YELLOW}[+] Generated files:${NC}"
ls -lh "$output_dir"

echo -e "\n${BLUE}[+] Looking for potential exploits${NC}"
potential_exploits=0

if grep -q "POTENTIALLY EXPLOITABLE" "$output_dir"/suid_scanner_output.txt 2>/dev/null; then
    echo -e "${RED}[!] SUID exploits found${NC}"
    potential_exploits=$((potential_exploits + 1))
fi

if grep -q "FULL SUDO ACCESS\|NOPASSWD" "$output_dir"/sudo_exploit_scanner_output.txt 2>/dev/null; then
    echo -e "${RED}[!] Sudo exploits found${NC}"
    potential_exploits=$((potential_exploits + 1))
fi

if grep -q "CAP_SETUID\|CAP_SYS_ADMIN" "$output_dir"/capabilities_scanner_output.txt 2>/dev/null; then
    echo -e "${RED}[!] Capability exploits found${NC}"
    potential_exploits=$((potential_exploits + 1))
fi

if grep -q "WRITABLE" "$output_dir"/cron_exploiter_output.txt 2>/dev/null; then
    echo -e "${RED}[!] Cron exploits found${NC}"
    potential_exploits=$((potential_exploits + 1))
fi

if grep -q "docker\|lxd\|lxc" "$output_dir"/docker_escape_scanner_output.txt 2>/dev/null; then
    echo -e "${RED}[!] Container escape vectors found${NC}"
    potential_exploits=$((potential_exploits + 1))
fi

if [ "$potential_exploits" -gt 0 ]; then
    echo -e "\n${RED}[!] Total potential exploits: $potential_exploits${NC}"
    echo -e "${YELLOW}Review the output files for exploitation commands${NC}"
else
    echo -e "\n${GREEN}[+] No obvious exploits found${NC}"
    echo -e "${YELLOW}Check kernel vulnerabilities or manual exploitation${NC}"
fi

echo -e "\n${BLUE}[+] Quick Reference${NC}"
echo -e "${YELLOW}Full enumeration: cat $output_dir/privilege_escalation_enum_output.txt${NC}"
echo -e "${YELLOW}SUID analysis:    cat $output_dir/suid_scanner_output.txt${NC}"
echo -e "${YELLOW}Sudo exploits:    cat $output_dir/sudo_exploit_scanner_output.txt${NC}"
echo -e "${YELLOW}Capabilities:      cat $output_dir/capabilities_scanner_output.txt${NC}"
echo -e "${YELLOW}Password hunt:     cat $output_dir/password_hunter_output.txt${NC}"
echo -e "${YELLOW}Cron analysis:     cat $output_dir/cron_exploiter_output.txt${NC}"
echo -e "${YELLOW}Docker escape:     cat $output_dir/docker_escape_scanner_output.txt${NC}"
echo -e "${YELLOW}Kernel check:      cat $output_dir/kernel_vuln_scanner_output.txt${NC}"
echo -e "${YELLOW}Final summary:     cat $output_dir/final_summary.txt${NC}"

echo -e "\n${GREEN}[+] Auto-enumeration complete!${NC}"
echo -e "${YELLOW}Good luck with your privilege escalation!${NC}"
