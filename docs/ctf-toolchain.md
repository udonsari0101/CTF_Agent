# Solver CTF toolchain

The production image carries the default Python and system toolchain from the
original `ctf_agent.zip` `setup.sh`, including radare2, and a pinned subset of
the original `--full` tools that the restored category playbooks call
directly. Keeping these programs in the image makes the playbooks executable
instead of leaving their commands as documentation only.

Debian 12 (bookworm) packages provide:

- binary analysis and tracing: GDB, GDB multiarch, binutils, QEMU user and x86
  system emulation, strace, ltrace, patchelf, GDB server and Apktool;
- forensics and steganography: Binwalk, Foremost, ExifTool, Sleuth Kit,
  Steghide, pngcheck, Poppler tools, MediaInfo, SoX, FFmpeg, Tesseract OCR,
  TShark, YARA, multimon-ng and TestDisk/PhotoRec;
- password, archive and kernel work: John the Ripper, p7zip and cpio;
- number theory: PARI/GP (`gp`);
- web and protocol analysis: headless Chromium through the `ctf-browser`
  job-local launcher, ffuf, sqlmap, nmap, DNS utilities, socat, whois, WABT and zbar;
- general analysis: Git, file, jq, ripgrep, netcat, OpenSSL, tmux and a C/C++
  build toolchain.

Radare2 is not shipped in bookworm. The image therefore installs the official
radare2 6.2.2 amd64 release package after verifying its pinned SHA-256 digest.
It installs the official statically linked ffuf 2.2.1 amd64 release the same
way. StegSeek 0.6 is installed from its verified upstream amd64 Debian package.
This repository and its deployment workflow target amd64.

Pwndbg 2026.10.22 is installed from its verified upstream Debian package and
provides the separate `pwndbg` debugger command. Websocat 1.14.1 is installed
from its verified static Linux release for interactive WebSocket problems.

Native decompilation uses Ghidra 12.1.4 headless with Temurin JDK 21; Android
and JVM bytecode decompilation uses JADX 1.5.6. All three upstream archives are
SHA-256 verified in the Docker build. `ghidra_headless` and `jadx` are on
`PATH`. The original reverse and pwn skill commands can call the installed
`DecompileAll.java` and `DecompileFn.java` scripts. They write C output under
the current job's `tmp/` directory by default, or to an explicit output path.
`GHIDRA_HEADLESS_MAXMEM` defaults to 4G and may be overridden for a large binary.

Apktool, GDB server, Nmap, sqlmap and TestDisk/PhotoRec are installed from
bookworm packages. Image smoke checks their executables and runs their version
commands where those are available. Apktool adds a Java runtime to the image;
it does not replace native reverse engineering with radare2 or angr.

The Python analysis set pins the mutually compatible native-wheel versions
used by CI: angr 9.2.223 with Capstone 5.0.6, Unicorn 2.1.2 and Z3 4.13.0.0;
fpylll 0.6.4 with its otherwise undeclared cysignals 1.12.6 runtime;
LIEF 0.17.6; owiener 1.0.10; pefile 2024.8.26; Volatility 3 2.28.0; and
yara-python 4.5.4. Volatility's `full` extra is deliberately not used because
its Pillow constraint conflicts with the image's current Pillow version; the
specific Capstone, cryptography, Pillow and YARA capabilities it needs are
already installed independently. NetworkX is a direct dependency for graph
and path puzzles.

CI checks this toolchain twice. The networkless image smoke runs representative
local operations: radare2 parses `/bin/true`, angr loads it, Claripy solves a
small constraint, fpylll reduces a lattice, LIEF parses an ELF, owiener recovers
a known weak RSA key, YARA compiles and matches a rule, and Volatility reports
the pinned framework version. It compiles and decompiles tiny native and Java
programs with Ghidra and JADX, evaluates a PARI/GP factorization, and checks
StegSeek startup. It also renders a local page to PNG through the
same `ctf-browser` launcher available to a solve. Pwndbg's `vmmap` command
and Websocat's CLI are checked in the image.
The worker readiness canary
repeats a compact set and the browser render through Codex's real AppArmor
command profile. It also attempts a
child-process strace and publishes `toolchain_trace_functional` as a capability
diagnostic. That check does not gate readiness because Docker's default seccomp
on some older kernels denies ptrace even though the AppArmor command boundary
is intact. It allocates separate writable `HOME`, `XDG_CACHE_HOME` and `TMPDIR`
directories below the dedicated job scratch so a parser never needs access to
the provider's credential home.

Solve jobs have direct DNS and Internet sockets, so the restored playbooks can
use curl, ffuf, pwntools, Git, public symbol downloads and remote RPC endpoints
the same way as the original CLI agent. A challenge command keeps local caches
below `codex-workdir/tmp` and sets `HOME`, `XDG_CACHE_HOME` and `TMPDIR` to
writable job paths. Job scratch is a dedicated disk-backed bind mount; Compose
does not impose a solver memory, process-count or scratch-size ceiling.
Archive expansion likewise has no default byte, member, time, compression-ratio
or helper-memory ceiling. Deployments can opt into each ceiling with
`CTF_SOLVER_ARCHIVE_MAX_*`; streamed writes always preserve
`CTF_SOLVER_MIN_FREE_BYTES` (1 GiB by default) on the scratch filesystem.

`ctf-browser` always uses headless Chromium with a fresh profile, cache, crash
directory and short runtime directory under the current job scratch. A solve
may request a DevTools port for browser automation; its address is fixed to
`127.0.0.1` inside that solver container. General Internet access remains
available to Chromium and every other challenge tool.

QEMU system emulation uses software TCG and can run with `-nographic` and
`-snapshot`. The solver can debug its own child processes with GDB or strace
when the host seccomp implementation permits it. Host KVM, GPU, USB, display
sockets, Docker control and privileged mode are not mounted into a solver:
each would give the challenge workload access to shared host resources and
therefore cannot satisfy the requirement that the server remain unaffected.

Bubblewrap is excluded because solver commands already run inside the enforced
host AppArmor execution domain with `no-new-privileges`. A nested user-namespace
sandbox cannot be relied on at that deployment boundary.

The remaining best-effort extras stay outside the core image: SageMath,
Foundry, REA, Ruby gem tools such as one_gadget, seccomp-tools and zsteg,
and format-specific packages such as Il2CppDumper and Blutter. Add them when a
matching input calls for them and a pinned build can pass the image smoke.
