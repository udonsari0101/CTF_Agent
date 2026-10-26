# Skill Module: forensics

Read-only playbook for forensics/stego — file / disk / memory / network. Usually **one artifact (or bundle) with one hidden channel**: identify it by bytes, hypothesize *where the flag hides*, extract that one channel. base.md owns the loop / submission / belief≠proof / per-file decomposition / anti-fabrication — this is only tactics+tools.

Files by role: extraction/recovery script → `solver.py`; artifact inventory + what each held → `notes/ANALYSIS.md`; the carrier + exactly how to extract it → `notes/VULN.md`; dead-ends + the next channel to try → `notes/NEXT.md`; carved/scratch/decoded files → `tmp/`; when an extracted payload is really another category (crypto/rev/web) → `../../skills/<cat>.md`.

## Triage — extensions lie, identify by bytes
Run the cheap tools, then extract the ONE hypothesized channel (metadata / appended-EOF / LSB / packet-metadata / deleted-file / macro / leftover-history). Every extracted output is a NEW artifact — re-run `file` on it; 3–4 nested wrappers is normal.
```
file suspect.*
xxd suspect.bin | head -8                                    # magic bytes = ground truth
strings -n8 -a suspect.bin | grep -iaE 'flag|ctf\{|pass|secret|BEGIN'
strings -e l suspect.bin ; strings -e b suspect.bin          # UTF-16 LE/BE that ascii strings misses
binwalk suspect.bin ; exiftool suspect.*                     # embedded sigs; media/office/pdf metadata
```
Flag format is in `../chal_desc.md`.

## Artifact → tool decision table
| Artifact | First move | Then |
|---|---|---|
| suspicious image (generic) | **Aperi'solve** — one shot runs zsteg/steghide/outguess/binwalk/exiftool + superimposes all planes | stegsolve *Data-Extract* / *Image-Combine* (XOR two near-identical imgs) |
| PNG/BMP/GIF | `zsteg -a` (ALL planes) | data after `IEND`; IHDR-height brute vs stored CRC; `pngcheck -v`; alpha plane; PLTE |
| JPEG | `stegseek img.jpg rockyou.txt` | `steghide`/`outguess -r`; ELA; `exiftool -b -ThumbnailImage`; **not** zsteg |
| WAV/audio | `sox -n spectrogram` / `ffmpeg showspectrumpic` | LSB; `multimon-ng` DTMF/Morse; SSTV; `sox … oops` (L−R); MP3Stego/DeepSound; `minimodem`/`fldigi` |
| video | `ffprobe` ALL streams (0:0 is a decoy) | subtitle/attachment stream; `np.maximum` frame composite |
| RF-IQ / logic capture | `inspectrum` · `rtl_433` · URH | `sigrok-cli` UART/I2C/SPI; check Manchester |
| .pcap | `--export-objects` + `-z credentials` FIRST | `-z io,phs` smallest = carrier; follow-stream; plot metadata |
| USB pcap | HID keycodes / mass-storage SCSI carve | mouse dx/dy plot; Caps-Lock-LED Morse |
| RAM dump | `windows.clipboard` FIRST | `malfind`; `filescan`+`dumpfiles`; Linux → raw scan / `aeskeyfind` |
| .vmem / .vmss+.vmem | `vmss2core -W snap.vmss snap.vmem` → raw | then Volatility |
| disk.img | `mmls` / `gdisk -l` → mount RO | `fls`/`icat`/`tsk_recover`; fsck+`lsdel`; carve slack |
| .docm/.xlsm | `olevba` | `oledump.py`; unzip XML |
| .pdf | `pdfid.py` / `pdf-parser.py` | dump stream; `pdfdetach` |
| locked archive | list; obvious pw; `bkcrack` known-plaintext | `*2john`→`john`/`hashcat`; fix hdr len@26/28 |
| container / repo | `docker history --no-trunc` | `git fsck --unreachable`; `.DS_Store` |

## Magic bytes & file repair
`FF D8 FF` JPEG · `89 50 4E 47` PNG · `47 49 46 38` GIF · `50 4B 03 04` ZIP/docx/jar/apk · `25 50 44 46` PDF · `52 61 72 21` RAR · `1F 8B` gzip · `42 5A 68` bzip2 · `FD 37 7A 58 5A` xz · `37 7A BC AF` 7z · `7F 45 4C 46` ELF · `49 49 2A 00`/`4D 4D 00 2A` TIFF.
`file` says "data" but you expect an image → header is broken. Corrupted-PNG challenges usually break IHDR width/height or a chunk CRC; `pngcheck -v` names the bad chunk. When magic looks wrong, check the **tail** for the real footer and rebuild the header from it (xz footer @ EOF-6, gzip isize, zstd frame). Patch a byte in place:
```
pngcheck -v broken.png
printf '\x89' | dd of=broken.png bs=1 seek=0 count=1 conv=notrunc
```

## Carving (appended / embedded / polyglot / nested)
The #1 stego move: data glued after a valid image's EOF, or a ZIP appended. A JPEG/PNG that `unzip` opens is a polyglot. Nested layers are the norm — carve, re-`file`/`binwalk` each output.
```
binwalk --dd='.*' -M suspect.png               # recursive: extract EVERY signature, follow nesting
foremost -o out/ suspect.dd                     # header/footer carve
dd if=suspect.png of=hidden.zip bs=1 skip=<offset> 2>/dev/null   # manual, offset from binwalk
unzip suspect.jpg                               # polyglot test
```
`photorec` / `bulk_extractor` when signatures are damaged (also auto-pulls emails/URLs/base64/PGP). docx/xlsx/apk/jar/epub/3mf are ZIPs; PDFs/PNGs commonly carry data after `%%EOF`/`IEND`.

## Images & stego
PNG/BMP → LSB tools; JPEG → DCT tools. Check metadata/comments/appended data *before* deep stego.
```
zsteg -a img.png                                # full LSB/channel scan — ALL planes, not just bit 0
zsteg -E 'b1,rgb,lsb,xy' img.png                # extract one channel guess
steghide extract -sf img.jpg                    # JPEG/BMP/WAV, prompts passphrase (try empty + rockyou)
outguess -r out.jpg msg.txt                     # JPEG algo distinct from steghide/jsteg
magick in.png -alpha extract a.png              # data hiding in fully-opaque alpha LSBs
```
- **After `IEND`** (PNG) / after `FF D9` (JPEG) = appended payload — carve trailing bytes.
- **Cropped PNG**: IHDR height was shrunk but IDAT still holds the full image — brute the height field, keep the value whose IHDR **CRC32 matches the stored CRC** (or set height large, let a lenient decoder render the rest).
- `exiftool -b -ThumbnailImage in.jpg` — embedded thumbnail often shows the UN-cropped/UN-edited original with the flag intact.
- **ELA** (`magick in.jpg -quality 90 r.jpg -compose difference` / FotoForensics) — pasted/edited regions glow when the hint is "find the added object."
- No-GUI plane read:
```
python3 -c "from PIL import Image;im=Image.open('img.png').convert('RGB');p=im.load();w,h=im.size;print(''.join(str(p[x,y][0]&1) for y in range(h) for x in range(w))[:512])"
```
LSB text is usually low bit of R (or across RGB), left→right top→bottom, 8 bits/char. Also try non-standard per-channel bitplanes, PLTE palette entries no pixel references, `xortool -c ff` on XOR'd chunks, and unscramble (Arnold cat-map iterate `(2x+y, x+y) mod N`) when noise has a sane histogram. QR/2D: `zbarimg` is QR-only — use `dmtxread` (DataMatrix), zxing (Aztec/PDF417); `qrazybox` to rebuild a damaged QR from anchors + known prefix.

## Audio / video / signals
```
sox in.wav -n spectrogram -o spec.png           # text drawn in the frequency domain
ffmpeg -i in.mp3 -lavfi showspectrumpic=s=1024x512 spec.png   # lossy formats
multimon-ng -a DTMF -a MORSE_CW in.wav          # touch-tones / Morse in a tone stream
```
- **SSTV** (image as audio) → `qsstv` / `sstv -d in.wav`. **FSK/RTTY/modem** tones → `minimodem --rx 1200`; digital modes (PSK31/Olivia/Hell) → `fldigi`.
- **Stereo tricks**: `sox in.wav out.wav oops` (L−R) isolates a signal hidden only in the channel difference. Also try `speed 0.5` / `reverse`.
- **MP3Stego** (`decode -X -P pass file.mp3`) and **DeepSound** (`deepsound2john.py file.wav | john`) hide during encoding — invisible to LSB/spectrogram.
- **Video**: `ffprobe -show_streams` — enumerate ALL; `0:0` is often a decoy, flag lives in subtitle/data/attachment (`ffmpeg -dump_attachment:t:0`). Flashing/single-frame content → extract frames, composite with `np.maximum`/`np.minimum`.
- **SDR/RF**: `inspectrum recording.cfile` to measure symbol rate; `rtl_433 -r cap.cu8` for ISM sensors/remotes; **URH** auto-demods ASK/FSK/PSK (433 MHz fobs, Flipper `.sub`). Logic captures → `PulseView`/`sigrok-cli` with stacked UART→I2C→SPI decoders; a doubled "UART" with no idle gaps is **Manchester** (transition = bit); sweep baud + try inverted polarity.

## PCAP / network
Corrupt/truncated → `pcapfix -d cap.pcap` first. Multi-file → `mergecap`/`reordercap`; huge → `editcap` split. Then **`--export-objects` + `-z credentials` FIRST** — may hand you the whole file / cleartext logins.
```
tshark -r cap.pcap --export-objects http,out/  # also smb/ftp/tftp/imf; NetworkMiner GUI carves non-HTTP
tshark -r cap.pcap -q -z credentials            # auto-dump FTP/HTTP/IMAP/POP creds
capinfos cap.pcap                               # counts, duration
tshark -r cap.pcap -q -z io,phs                 # protocol hierarchy — SMALLEST-count proto = the carrier
tshark -r cap.pcap -q -z follow,tcp,ascii,0     # reconstruct stream N (…,raw,N | xxd -r -p to carve a binary)
```
- HTTP map: `-Y http.request -T fields -e http.host -e http.request.uri`. A "TLS" stream whose raw bytes start `50 4b` (PK) is a disguised ZIP — check raw hex of "encrypted" streams. Many equal-size MD5-named HTTP files + one smaller = split archive fragments; order by the in-capture dir-listing, `cat`, extract.

**Covert channels hide in METADATA, not payload — plot the metadata:**
- **DNS exfil**: `-Y dns -T fields -e dns.qry.name | sort -u` — labels (hex/base32), or *last char of each qname*, or **NXDOMAIN oracle** (rcode = 1 bit/query). dnscat2 labels carry a 9-byte session/seq/ack header — strip it, dedupe retransmits. mDNS/DNS-SD TXT records often carry the XOR/decrypt key.
- **ICMP**: `-e data.data`, but also try payload **length** as char code, or byte-rotate+base64.
- **Timing**: inter-arrival gaps binned to symbols. **TCP fields**: low bits of flags/IP.ID/TTL/seq low byte.
Reassemble in packet order in `solver.py`. Last resort: `foremost -o carved/ cap.pcap`.

**Decrypting captures:**
- **TLS**: import `SSLKEYLOGFILE` (`CLIENT_RANDOM …` lines) via TLS→(Pre)-Master-Secret log — the only way to read ECDHE/forward-secret (and QUIC/HTTP2). RSA key-exchange only: `-o "tls.keys_list:ip,443,http,server.key"`; weak server cert → factor the modulus, `rsatool` → key.
- **WPA/WPA2**: `aircrack-ng -a2 -w rockyou.txt cap.pcapng` cracks the 4-way handshake; `airdecap-ng -p <pass> -e <SSID> cap` writes a decrypted pcap (then inspect IPP print-job names). WEP → `-a1`.
- **Kerberos**: `kerberos.cipher` from AS-REP → `$krb5asrep$` (`hashcat -m18200`), TGS-REP → `$krb5tgs$` (`-m13100`). **NTLMv2** from SMB: `ntlmssp.ntlmv2_response.ntproofstr`+user+challenge → `-m5600`.

### USB / peripheral capture
Keyboard HID = 8-byte reports: byte[0] modifier (`&0x22` Shift), bytes[2..7] up to 6 keycodes. **Skip release reports (byte[2]==0).** 0x04→'a'…0x1d→'z', 0x1e→'1'…0x27→'0', backspace 0x2a, arrows 0x51/0x52 (place text on the right line). Mouse reports *draw* the flag — accumulate dx/dy.
```
tshark -r usb.pcap -Y 'usb.transfer_type==1' -T fields -e usb.capdata   # HID interrupt data
tshark -r usb.pcap -Y 'usbhid.data' -T fields -e usbhid.data            # alternate field
```
Build the keymap/plot in `solver.py`. Other classes: **mass storage** — carve SCSI READ(10)/WRITE(10) bulk data into a mountable image; **LED Morse** — host→device SET_REPORT toggling Caps-Lock, the on/off durations (>300 ms = dash) are Morse; 6+ simultaneous keycodes = steno chording (Plover dict); isochronous (`-e usb.iso.data`) = raw PCM audio; Bluetooth `btrfcomm` fragments — sort by order byte, strip header, concat.

## Memory (Volatility 3)
Vol3 auto-detects OS (no profile). Scan → find the ONE interesting PID/file → dump *only that*. **Run `windows.clipboard` first.**
```
vol -f mem.raw windows.info                     # confirm OS/build
vol -f mem.raw windows.clipboard                # FIRST: pasted flags/passwords
vol -f mem.raw windows.pslist ; windows.pstree ; windows.cmdline
vol -f mem.raw windows.malfind                  # RWX region, NO file backing = injected code/flag
vol -f mem.raw windows.filescan | grep -iE 'flag|desktop|\.txt|\.png'
vol -f mem.raw windows.dumpfiles --virtaddr <addr>      # or --pid <pid>
```
Also: `netscan`, `consoles`/`cmdscan`, `hashdump` (NTLM→crack), `registry.printkey -K <path>`, `mftscan`. Linux: `linux.pslist`, `linux.bash` (history), `linux.pagecache`. vol2 extras when needed: `psxview` (hidden/unlinked procs), `mimikatz`, `mftparser` (resident `$DATA` of a deleted file).

**No symbol table / plugins return empty (KASLR/mismatch)?** Treat the dump as a raw blob:
```
strings -a mem.elf | grep -iaE 'flag|BEGIN|password'
strings mem.elf | grep -o 'UEsD[A-Za-z0-9+/=]*'   # UEsD = base64 PK\x03 → in-transit ZIP
aeskeyfind mem.elf                                # AES schedules from RAM (rsakeyfind for RSA; aesfix repairs bit-rot)
```
For a crypto target: anchor on a nearby path string (e.g. `enc_key.bin`), slide a 32-byte page-aligned window, decrypt the target's first block with each candidate, keep the one whose plaintext has a known magic (`%PDF`/`PK`/`\x89PNG`). Bank it in `solver.py`. Screenshots survive as raw framebuffer — stride-scan `PIL.Image.frombytes('RGB',(1920,100),chunk)`.

## Disk & filesystem recovery
```
mmls disk.img                                   # partition map → start sector (gdisk -l for GPT, kpartx -av to map)
mount -o ro,loop,offset=$((START*512)) disk.img /mnt/x   # ALWAYS read-only
```
Deleted files: `fls -rd disk.img` → `icat disk.img <inode> > out`; `tsk_recover -e disk.img out/`. Sleuth Kit (`fls/icat/fsstat/istat`) is scriptable — faster than Autopsy for one file. Slack/unallocated: `blkls disk.img | strings | grep -i flag`. FS-specific undelete:
- **ext**: `e2fsck -y` reconnects orphans to `/lost+found`; `debugfs`→`lsdel`, or `extundelete`.
- **btrfs/APFS**: deleted data persists in COW snapshots — `btrfs subvolume list -a` / scan for `APSB` magic then `icat -f apfs`.
- **FAT**: read clusters whose FAT entry == `0x0000` (freed but not zeroed). **RAID5**: rebuild the missing member by XOR-ing parity.
- **NTFS ADS**: `fls -r | grep ':'` then `icat` (Zone.Identifier is the tell); timestomp = `$STANDARD_INFORMATION` older than `$FILE_NAME`; `$Recycle.Bin` pairs `$I<rand>` (metadata) with `$R<rand>` (content).
`testdisk` recovers lost partitions; `photorec` recovers files by structure.

## Provenance & leftover history
The flag often survives in history even after `rm` — check what wasn't cleaned:
- **Docker**: `docker history --no-trunc <img>` shows every `RUN`/`ENV`; daemonless → `tar xf image.tar`, read `manifest.json`→config→`history[].created_by` (secrets `rm`'d in a later layer are permanent). `dive` for interactive.
- **Git**: `git fsck --unreachable`/`--lost-found` → dangling blobs; `git log --diff-filter=D --name-only` + `git log -p -- <path>`; `git reflog --all`, `git stash list`, packed-refs; `gitdumper.sh` to pull an exposed web `.git`.
- **`.DS_Store`**: stale dir listing → `python3 -m ds_store` to enumerate hidden paths.
- Also `.bash_history`, `.viminfo`, `*.swp`, thumbnail caches, EXIF GPS/serial; Windows Amcache/USN-journal (`$Extend\$J`); browser creds (Chrome `Local State`→AES-GCM `Login Data`; `firefox_decrypt`); offline SAM+SYSTEM → impacket `SAMHashes` dump.

## Office / PDF
Modern `.docx/.xlsx/.pptx` are ZIP: `unzip -l`, grep `word/document.xml`, `docProps/core.xml`, `word/media/`, custom XML.
```
olevba doc.docm                                 # extract+deobfuscate VBA macros (vbaProject.bin)
oledump.py doc.doc                              # enumerate OLE streams; -s N -d to dump one
pdfid.py doc.pdf                                # /JS /OpenAction /EmbeddedFile counts
pdf-parser.py doc.pdf ; pdf-parser.py -o <n> -f -d out doc.pdf   # object tree; decode stream
pdfdetach -saveall doc.pdf                      # embedded attachments
pdftotext doc.pdf - | grep -i flag              # hidden/overlaid/white-on-white text
```
Watch for text hidden under images and in PDF incremental-update revisions. A ZIP parses valid from either end — test whole-file byte-reversal (`data[::-1]`). Whitespace/zero-width stego: `stegsnow -C file.txt`; decode U+200B/200C/FEFF.

## Archives & cracking
```
7z l s.7z ; unzip -l s.zip                       # list, don't extract yet
zip2john locked.zip > h.txt                      # or rar2john/7z2john/pdf2john/office2john/keepass2john
hashcat -m 13600 h.txt rockyou.txt               # zip=13600 rar5=13000 pdf=10500 office=9600 keepass=13400
```
- **Known-plaintext ZipCrypto → `bkcrack`, not brute force.** 12+ known plaintext bytes: `bkcrack -C archive.zip -c target.ext -p known.txt` → internal keys → `bkcrack -C archive.zip -k <k0> <k1> <k2> -D out.zip` (or `-U` to re-key). Known file is often a header (a sibling's `[Content_Types].xml`, PNG magic, a shared license).
- **Corrupted ZIP header**: local-file-header stores name-length @ **offset 26** and extra-field-length @ **offset 28** (2-byte LE) — patch both to true values (cross-check central directory). `zip -FF broken.zip --out fixed.zip` recovers many cases; fallback `zlib.decompress(raw[off:], -15)` brute-forced over offsets.
- **Nested**: `binwalk --dd='.*'` unwraps recursively. **KeePass KDBX4/Argon2**: stock `keepass2john` fails → use the ivanmrsulja fork or `keepass4brute` (`hashcat -m13400`). `tar --occurrence=N -xO` extracts the Nth of duplicate-named entries. Magicless compressor → trial `brotli`/`zstd`/`lzma` until one succeeds.
- Try obvious passwords first (challenge name, empty, "password") and check metadata/sibling artifacts for the passphrase before burning hours.

## Encoding reflexes (final step)
Blob looks like text but isn't the flag → decode and re-`file`, repeat (3–4 nested wrappers is normal): base64/32/58/85/ascii85, hex (`xxd -r -p`), ROT13 (`tr 'A-Za-z' 'N-ZA-Mn-za-m'`), URL-encoding. Two equal-length arrays, neither readable → merge byte-by-byte keeping the printable one. Entropy/magic hints compression → `zlib-flate -uncompress < blob` / `gunzip`. CyberChef "Magic" + "Detect File Type" for multi-layer recipes.

## Category pitfalls
- Trusting the extension, or a tool's "nothing found" without the type-appropriate tool (`zsteg` is PNG/BMP only — use `steghide`/`stegseek`/`outguess` on JPEG).
- Assuming one layer — re-`file` every carved/decoded output.
- Reading only the payload on a covert-channel pcap — data is in packet **metadata** (length/timing/flags/qname) or a **decryptable** layer (keylog/handshake).
- Brute-forcing an archive before checking metadata/comments/siblings for the password, or before trying `bkcrack` when you have known plaintext.
