# Skill Module: unknown (triage first)

Category is unknown. Turn the first cheap observations into a provisional category, open `../../skills/<cat>.md`, and revise that choice when new evidence warrants it. A supplied remote can be the only useful category signal: after reading the brief, make one protocol-appropriate, non-destructive first contact if it helps classify the target. Save the response under `tmp/` and inspect it before further requests; do not fuzz or brute-force during triage. For a target with no files, follow `../../skills/remote_only.md`. Do not start expensive decompilation or build an exploit before there is a concrete lead.

## Cheap signal sweep (before anything expensive)

```sh
ls -la                                 # every file incl. dotfiles
file *                                 # magic bytes (extensions lie — trust file(1))
# per interesting file:
wc -c <f>                              # tiny → key/ciphertext; huge → pcap/disk/media/model
head -c 64 <f> | xxd                   # magic when file(1) is unsure
strings -n 8 <f> | head -50            # cheap smell; never dump the whole thing
binwalk <f>; unzip -l <f>              # containers / trailing appended data
exiftool <img>                         # metadata / GPS (osint vs. in-file stego)
```

Use the cheap local checks that fit the supplied files. Avoid running `binwalk` or `strings` over a multi-gigabyte artifact by default; inspect a small sample or metadata first. A one-request remote banner, HTTP header, or protocol greeting can settle an otherwise ambiguous category. Record its observed result, then choose the next playbook.

## Verb map — read `../chal_desc.md` first, it often names the class

| Phrasing in the brief | Category |
|---|---|
| "decrypt / recover the key / break the cipher", RSA `(n,e,c)`, math prompt | crypto |
| "get a shell / read the flag file", remote binary, "overflow" | pwn |
| "recover the password / license / serial", "what does this do" | rev |
| "login as admin / find the bug in this app", a URL | web |
| "what did the attacker exfiltrate", "analyze the capture/dump" | forensics |
| "drain / exploit the contract", RPC URL, `challenge`/`setup` contract | blockchain |
| "make the model misclassify", "leak the system prompt", jailbreak a chatbot, a model/pickle file | ai-ml |
| "who / where is this", find a person/handle/photo, geolocate, username lookup | osint |
| custom protocol / guessing game / "talk to the service" behind `nc` | misc (ppc) |

Also record: remote host/port (network is OPEN), the flag format, files provided vs. remote-only.

## Magic-byte → category map (match `file(1)`, not the extension)

| `file(1)` / evidence | Category | Tie-breaker |
|---|---|---|
| `ELF … executable` / `… shared object` | pwn **or** rev | `checksec` + remote socket + memory-unsafe I/O ⇒ pwn; "find the right input" locally ⇒ rev |
| `PE32/PE32+`, `.exe`, `.dll`, `.NET assembly` | rev | pwn if Windows service with I/O |
| `.jar`/`.class`, `.pyc`, `.wasm`, `.apk`, Mach-O | rev | decompile it |
| `.sol`, `contracts/`, Hardhat/Foundry, RPC URL | blockchain | |
| `.pcap(ng)`, `tcpdump`, raw disk / filesystem image, EnCase | forensics | |
| `.pt/.pth/.h5/.onnx/.pb/.ckpt/.safetensors`, `.pkl`/pickle, PyTorch/TF/Keras/HF, a chatbot/model endpoint | ai-ml | a `.pkl`/`torch.load` you feed ⇒ pickle RCE = pwn; else adversarial input or prompt injection |
| PNG/JPG/GIF/BMP/WAV/mp3/PDF/media, esp. odd size or trailing bytes | forensics **or** osint | secret hidden *inside* the file (LSB/appended/`binwalk`) ⇒ forensics; EXIF/GPS/landmark pointing *outward* ⇒ osint |
| a photo / handle / name + "find X", nothing exploitable | osint | web research, not file-cracking |
| web-app source tree (`app.py`/Flask/Django, `index.php`, `routes/`, `package.json` server, `Dockerfile` exposing a port) | web | |
| ciphertext blob, `.pem`/`.key`, `.sage`, `output.txt` of big numbers | crypto | |
| `.py`/`.js`/`.rb` custom protocol behind `nc` | misc (ppc) | crypto if it's a cipher/oracle |
| plaintext / QR / esolang / puzzle | misc | |
| nothing downloadable, only `nc host port` | pwn (binary served) or misc — probe it | |

## The decisive fork: SOURCE vs. compiled BINARY vs. DATA

- **Readable source present** (`.py .php .js .go .rb .sol .c`) → **code-review** class (web / crypto / blockchain / ppc / ai-ml). Learn the framework's default-safe idiom, then find the one handler that opts out. Fast grep smells:
  - web: `@csrf_exempt`, `.execute(f"…{x}")` / string-built SQL, `|safe`/`mark_safe`, `pickle.loads`, `yaml.load`, `eval`/`exec`, missing `@login_required`, path joins on user input.
  - crypto: fixed IV/nonce, nonce reuse, ECB, `random`/custom PRNG for keys, textbook RSA, encrypt-without-MAC.
  - blockchain: missing access control, reentrancy, `delegatecall`, unchecked low-level `call`, `tx.origin` auth.
  - ai-ml: `pickle.loads`/`torch.load` on user data, raw user text concatenated into an LLM prompt, model endpoint with no input bounds.
- **Compiled artifact only** (ELF/PE/pyc/wasm) → **pwn or rev**. Remote service + memory-unsafe language + fixed-buffer `read`/`gets`/format string ⇒ pwn. Standalone "give the right key/serial" ⇒ rev. `checksec <elf>` sharpens.
- **Data, no code** → **forensics** if the secret is *inside* the artifact (media/capture/disk → stego/carving); **osint** if the artifact only *points to* a real-world person/place/handle you must research online; **ai-ml** if it's model weights / a serving endpoint.

## Commit and hand off

Stop triaging as soon as one observation or a small combination of clues gives a useful next action. Record the **evidence + provisional decision** in `notes/ANALYSIS.md` (`category: X — because <file/strings/service-banner/framework/magic-bytes>`), then open `../../skills/<cat>.md` and act as that module. A category label from the platform is a hint, not a gate; change playbooks when observations contradict it. **If a diff/patch or two source versions are provided, inspect the changed lines** as candidate sites; confirm reachability and behavior before calling any change the bug.

**Contradictory evidence** (an ELF *and* a web app *and* a pcap) ⇒ multi-stage. Pick the category of the **first artifact you must break to progress**, log the rest as later stages in `notes/NEXT.md`, and do that one. Don't run every playbook at once.

## Pivot when stuck = re-triage for a hidden second category

Most non-trivial challenges **chain categories** — solving one only unlocks the artifact for the next. When the chosen playbook stalls because the evidence stops fitting, don't grind: come back, re-read the signals, and hunt the hidden second category. Re-record the new call in `notes/ANALYSIS.md`; park the abandoned angle in `notes/NEXT.md`. Common combos:

- **forensics → pwn**: a PCAP/memory dump replays a binary exploit — carve out the served binary and it's a pwn.
- **web → crypto**: a JWT / signed cookie / "encrypted" token needs a crypto break (`alg:none`, weak key, padding oracle, ECB).
- **rev → crypto**: the binary just hands you the constants (S-box, modulus, key schedule) — the real work is inverting the cipher in crypto.
- **misc/jail → forensics**: a pyjail or SSRF/LFI yields an arbitrary file-read that's really the forensics/recon step (flag path, a memory file, `.git`).
- **ai-ml → pwn**: a `.pkl`/model `torch.load` is pickle deserialization — that's RCE, a pwn payload, not a data-science task.
- **web → ai-ml**: the app wraps an LLM/model — the bug is prompt injection or an unguarded model endpoint, not a classic web bug.
- **forensics ↔ osint**: image EXIF/GPS/landmark points *outward* — geolocation / handle research, not in-file stego.
- **crypto/rev ↔ ppc/misc**: an `nc` oracle is a crypto or rev attack you must **automate** over many queries, not a one-shot.

The classic single-category miss: a binary with **no memory bug** that only validates a serial is **rev, not pwn**. Cheap re-triage beats tunnelling on the wrong toolchain.
