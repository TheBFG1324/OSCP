# OSCP Notes

Personal study notes and playbooks for the **OffSec Certified Professional (OSCP)** exam. Each file is a self-contained, end-to-end playbook for a single phase or topic — designed to be opened mid-exam and worked top-down without re-reading.

---

## Contents

| File | Purpose | Status |
|---|---|---|
| [Enumeration.md](Enumeration.md) | Host discovery, nmap workflow, service-by-service enumeration for every common port | Complete |
| [Active-Directory.md](Active-Directory.md) | AD methodology — unauth → authed → BloodHound → DA. All major attack paths with detect/exploit/yield | Complete |
| [Linux-Priv-Esc.md](Linux-Priv-Esc.md) | Linux privesc playbook + LinPEAS deep dive (every output section explained) | Complete |
| [Windows-Priv-Esc.md](Windows-Priv-Esc.md) | Windows privesc playbook + winPEAS deep dive, Potato attacks, privilege abuse | Complete |
| [Web-Attacks.md](Web-Attacks.md) | Web vulnerability methodology (LFI/RFI, SQLi, file upload, SSRF, XXE, etc.) | Stub |
| [Public-Exploits.md](Public-Exploits.md) | searchsploit + exploit-db workflow: find, vet, modify, compile | Complete |
| [Password-Attacks.md](Password-Attacks.md) | Hash identification, hashcat/john, online brute force, custom wordlists | Complete |
| [File-Transfers.md](File-Transfers.md) | Moving files between attacker and target (Linux/Windows, every method) | Complete |
| [Reverse-Shells.md](Reverse-Shells.md) | Listeners, payloads (every language), TTY upgrade, encoding/evasion | Complete |
| [Metasploit.md](Metasploit.md) | MSF usage with OSCP exam rules in mind, msfvenom, multi/handler, post-ex | Complete |
| [Tunneling.md](Tunneling.md) | Port forwarding, pivoting, chisel, ligolo, ssh tunnels, proxychains | Stub |

---

## How to Use These During the Exam

1. **Start with [Enumeration.md](Enumeration.md)** on every box — the "Playbook — Order of Operations" section is the recommended first 30 minutes.
2. **Pivot based on what you find:**
   - Web port open → [Web-Attacks.md](Web-Attacks.md)
   - Service version with a known vuln → [Public-Exploits.md](Public-Exploits.md)
   - SMB / LDAP / Kerberos → [Active-Directory.md](Active-Directory.md)
   - Need to deliver a payload → [Reverse-Shells.md](Reverse-Shells.md) + [File-Transfers.md](File-Transfers.md)
3. **After foothold:**
   - Linux box → [Linux-Priv-Esc.md](Linux-Priv-Esc.md)
   - Windows box → [Windows-Priv-Esc.md](Windows-Priv-Esc.md)
4. **Got a hash or need to brute force?** → [Password-Attacks.md](Password-Attacks.md)
5. **Need to reach an internal network?** → [Tunneling.md](Tunneling.md)
6. **Metasploit usage** is restricted on the exam — see [Metasploit.md](Metasploit.md) §1 for the current rules.

---

## Conventions Used Across Files

- `<IP>` / `$IP` — target IP
- `<KALI>` / `10.10.14.5` — attacker IP (replace with actual tun0 IP)
- `<DOMAIN>` / `corp.local` — example AD domain
- Code blocks are paste-ready; placeholders are wrapped in `<...>` or set as shell variables at the top of the block
- "Gotcha" callouts flag the failure modes that cost the most time
- Tables show **inputs → outputs** so you can scan for what you need without reading prose

---

## Disclaimer

These notes are for **authorized security testing only** — OSCP exam, OSCP labs, Hack The Box, Proving Grounds, and other CTF/lab environments where you have explicit permission. Do not use these techniques against systems you do not own or have written authorization to test.
