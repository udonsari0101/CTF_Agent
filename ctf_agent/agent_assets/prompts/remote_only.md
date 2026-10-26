# Skill Module: remote-only target

No files ship — only a `host:port`. You have no dataset until you pull it from the wire, so: capture every byte to disk, classify offline, verify offline, then exploit deterministically. The category rule on top of the base phases is **first contact is one gentle touch; classify before you touch again, and never hammer the service.**

## 1. Parse the target (from `../chal_desc.md`, read-only)
```bash
grep -ioE '([a-z0-9.-]+\.[a-z]+|[0-9]{1,3}(\.[0-9]{1,3}){3}|localhost)(:[0-9]+)?' ../chal_desc.md
grep -ioE 'https?://[^ )]+' ../chal_desc.md
```
Shapes: `nc host 1337`, `host:1337`, `http://host:8080/path`, raw IP. Record `HOST/PORT/proto=tcp|http|tls` (and whether there's a PoW gate) in `notes/ANALYSIS.md`; do not invent connection info. **If `../chal_desc.md` lists no address**, run `request-remote "<what you need>"` to alert the operator, then re-read `../chal_desc.md` for the address they add (re-read it right before you connect, too — they may add it mid-run). Each `bash` call is a **fresh process** — for any stateful service write one `pwntools`/socket script (keep it as `solver.py`), don't chain `nc` calls; PoW → brute a sha256 leading-zero-bits gate (recipe in `../../skills/misc.md`). Keep all captured/scratch files under `tmp/`.

## 2. First contact — light, once
One connection: read what it volunteers, send at most one small probe (a newline, `1`, or `GET /`), disconnect. No looping/fuzzing/brute yet — you are sampling.
```bash
(printf '\n'; sleep 1) | nc -w 3 HOST PORT | tee recon.txt                  # raw TCP banner/menu
curl -sS -D recon_headers.txt -o recon_body.html http://HOST:PORT/          # HTTP: headers name the framework
openssl s_client -connect HOST:PORT -quiet 2>/dev/null | tee recon.txt      # TLS
```
Numbered menu? Grab the text, **stop**, enumerate options offline, then script one clean walk in phase 5.

## 3. Capture everything → local dataset
Every response is data you re-grep from files, never from scrollback. Keep raw bytes on disk; if binary, keep the file and note hexdump offsets rather than retyping bytes.
- `recon.txt` first-contact · `recon_headers.txt`/`recon_body.html` HTTP · `menu.txt` options verbatim · `samples/` one file per distinct response.

pwntools recon that mirrors the whole session to disk — run **once**, then read the files (don't re-run to "see it again", you already have it):
```python
#!/usr/bin/env python3
from pwn import *
context.log_level = 'debug'; context.log_file = 'recon_pwn.txt'   # full I/O mirrored to disk
io = remote('HOST', 1337)
open('samples/banner.bin','wb').write(io.recvrepeat(2))
io.sendline(b'1')                                                 # ONE gentle probe
open('samples/probe1.bin','wb').write(io.recvrepeat(2)); io.close()
```

## 4. Classify the service, then open `../../skills/<cat>.md`
Infer category from the captured bytes and switch into that playbook:

| Captured signal | Category → skill |
|---|---|
| Numbered menu over TCP; "how many bytes?", format-string echo, raw addresses | pwn → `../../skills/pwn.md` |
| "encrypt/decrypt/sign" + hex/base64 blobs | crypto → `../../skills/crypto.md` — grab ciphertexts for known plaintexts; length+entropy ⇒ ECB/CBC/stream/RSA |
| `Server:`/`X-Powered-By`, `session=` cookies, CSRF fields, template/stack errors | web → `../../skills/web.md` — fingerprint framework, hunt the handler that breaks its own safe idiom |
| Prompt asking for a number/guess | PRNG/logic → capture an output sequence to model the generator |
| Response echoes your input verbatim | injection (fmt-string/SSTI/cmd/SQL) → build the classifier offline first |

Record `category=` + the exact evidence bytes in `notes/ANALYSIS.md`, then open `../../skills/<cat>.md`.

## 5. Verify OFFLINE before spending remote round-trips
Remote round-trips are your scarce, watched resource — model the behavior locally and confirm against **held-out** captured data before you attack:
- **Crypto:** re-implement the scheme; predict a captured known-plaintext/ciphertext pair byte-for-byte before building the padding-oracle / ECB cut-and-paste / nonce-reuse / small-`e` attack.
- **PRNG/logic:** replay the captured sequence into your model, predict a value you withheld, verify before betting a remote guess.
- **Web/injection:** trigger the payload against a local parser or unit test first.
- **Pwn:** model the protocol; validate offsets against captured leaks.

Distill to a one-line primitive tied to captured bytes — *"reused nonce between msg A/B → XOR recovers keystream"*, *"opt3 leaks 6 bytes at fixed offset = libc base"*. Can't reproduce it offline ⇒ not ready.

## 6. Exploit — deterministic and gentle
Touch remote with intent, stay polite (rate-limits and bans are real):
- `recvuntil` a **known prompt** — never blind `sleep`; small delays between requests; no busy-loops or reconnect-storms on error.
- Bounded retries (fixed count + backoff); reconnect cleanly on drop. Keep it in `solver.py`, `HOST`/`PORT` parametrized, log the winning run.
```python
from pwn import *; import re, time
def attempt():
    io = remote('HOST', 1337); io.recvuntil(b'> ')   # sync on the real prompt
    io.sendline(payload)                              # proven offline in phase 5
    data = io.recvall(timeout=5); io.close(); return data
for _ in range(3):
    out = attempt()
    if re.search(rb'[A-Za-z0-9_]+\{', out): break
    time.sleep(2)                                     # be polite
open('exploit_out.txt','wb').write(out)
```
Confirm before claiming success: `grep -aoiE '[a-z0-9_]+\{[^}]*\}' exploit_out.txt`. If a binary or source is later pulled from the wire, treat it as a normal local build (see base §5) — any flag from a local instance is fake.
