# Skill Module: rev (reverse engineering)

Field manual for cracking a checker binary/artifact. The win condition is **inverting the check to produce the flag** — keygen / constraint-solve, not reading every instruction. Locate the decision point, model it, solve it, then feed the candidate back through the real binary.

## Triage: fingerprint before opening a decompiler
```
file ./chal
rabin2 -I ./chal                          # arch/bits/pic/nx/canary/lang in one shot
strings -n6 ./chal | grep -iE 'flag|ctf|correct|wrong|nope|key|pass'
strings -e l ./chal                       # UTF-16: Windows / .NET
nm -C ./chal 2>/dev/null | head           # symbols, or none = stripped
```

### Packer / obfuscation smell → action
| Smell | Meaning | Move |
|---|---|---|
| `UPX!` in strings | UPX packed | `upx -d ./chal`; if header mangled (CTF trick), fix magic bytes or dump from memory after the unpack stub |
| entropy ~8.0, one huge section, tiny `.text` | packed/encrypted | break after the unpack loop in gdb, `dump memory out.bin $s $e`, disasm the clean copy |
| thousands of near-identical BBs, indirect jumps, missing section headers | CFG-flattening / VM obf | don't read linearly — angr, or recover the VM (below) |

### Language ID drives the entire toolchain
| Signal | Lang | Tool |
|---|---|---|
| `runtime.`, `go:buildid`, `GOROOT`; giant static bin | Go | **GoReSym** restores names/types; read `main.main`/`main.check`; compares via `runtime.memequal`. Go strings are `{ptr,len}` (not NUL-terminated) so `strings` smears adjacent literals together — take the length from GoReSym/the slice header, don't trust the `strings` split |
| `core::panicking`, `rustc`, `_ZN` mangling | Rust | `rustfilt` to demangle; panic strings leak logic/paths |
| `mscoree`/`mscorlib`, CLR header, UTF-16 | .NET/C# | `dnSpy`/ILSpy/`ilspycmd` → near-source; obfuscated (ConfuserEx/.NET Reactor)? run **de4dot** first, then decompile — never Ghidra |
| `_Z` mangling, vtables, `std::` | C++ | `c++filt`/`nm -C`; expect STL-heavy control flow |
| `pyi`, `_MEI` | PyInstaller | `pyinstxtractor` → **`pycdc`** on the `.pyc` (handles Py 3.9+ where `uncompyle6`/`decompyle3` die), or `dis` the bytecode |
| `.jar`/`.class`, `.apk`/`.dex` | Java/Android | `procyon`/`cfr`, or **`jadx`**; `apktool d` for resources/smali. Logic in a bundled `.so`? if `RegisterNatives` binds the JNI handler dynamically its symbol is hidden — dump the `RegisterNatives` table, **or rebuild a stub app with the same package/class names and call the `.so` directly** |
| `libil2cpp.so` + `global-metadata.dat` | Unity/IL2CPP | **Il2CppDumper** (feed it both files) restores C# names → dummy DLLs + a Ghidra script for the native blob |
| `libapp.so`/`libflutter.so`, `kDart` | Flutter/Dart | **Blutter** (build it for the *exact* Dart/Flutter version) recovers Dart classes/methods |
| wasm magic `\0asm` | WASM | `wasm2wat`, or run under node and hook |

**dogbolt.org** runs many decompilers at once — diff them when one emits garbage. Every decompiler's output is an **UNTRUSTED hypothesis**: a wrong signature/cast/implicit type silently corrupts the logic. Confirm the algorithm dynamically (`ltrace`/gdb) before you transcribe any constant or branch into a solver.

## Find the decision point — work backward from the verdict
Highest-leverage move: xref the success/failure string; the function that branches to it is the check.
```
r2 -A ./chal
afl~main                # functions matching main
axt @ str.Correct       # xrefs to the win string  -> the check fn
pdf @ sym.main
```
The comparison just before the win branch is your target. Capture the **good addr** (prints "Correct") and **bad addr** (prints "Wrong") — angr needs both. Record the two addrs + the check-fn entry in **`notes/VULN.md`** (they *are* the recovered check/key-condition); keep "what the binary does" in `notes/ANALYSIS.md` and tried-tools/dead-ends in `notes/NEXT.md`.

Ghidra headless when you want the algorithm as C (script it; don't camp in the GUI):
```
$GHIDRA/support/analyzeHeadless /tmp/proj rev -import ./chal \
  -postScript DecompileAll.java -deleteProject
```
`objdump -d -M intel ./chal` for a quick linear pass.

## Pick the cheapest tool that fits (do NOT read every instruction)
Classify the check, then solve at the lowest tier that works:
| Check shape | Tool |
|---|---|
| Each byte checked independently (`flag[i]^k == c[i]`) | per-byte Python, no solver — O(N·95) |
| You fully understand the transform | reimplement the inverse in `solver.py` — usually fastest |
| Coupled but algebraic (sums, perms, matrix mix, hash-like) | **z3** |
| Stateful transform / path explosion / opaque predicates | **angr** symbolic exec |
| One self-contained opaque routine you'd rather run than read | **unicorn** emulate it as a black box |

## Dynamic ground truth (frequently hands you the flag)
```
ltrace -s200 ./chal     # strcmp/memcmp/strncmp often expose the flag verbatim
strace -f ./chal        # open/read, ptrace (anti-debug), network
```
Many checkers do a single `memcmp` against the real flag — break it and read the *other* operand:
```
gdb -q ./chal
b memcmp                 # or: b *0xADDR
run
x/s $rsi                 # reference string is whichever arg isn't your input ($rdi/$rsi)
```
**Frida** for stripped/JIT/managed/live targets — intercept the compare, log args.
Foreign arch (ARM/MIPS/RISC-V on x86): `qemu-<arch> -g 1234 ./chal` + `gdb-multiarch`.

### Oracle-ification — turn a compare into a byte-by-byte brute
A checker that does one `memcmp`/`strcmp` leaks its match *length*. `LD_PRELOAD` a shim that logs the count of matching bytes, then greedily fix each position — **O(95·N) instead of O(95^N)**:
```c
// gcc -shared -fPIC preload.c -o p.so ; LD_PRELOAD=./p.so ./chal
int memcmp(const void*a,const void*b,size_t n){
  const unsigned char*x=a,*y=b; size_t i=0;
  while(i<n && x[i]==y[i]) i++;
  fprintf(stderr,"match=%zu\n", i);          // the oracle: longest correct prefix
  return i==n ? 0 : (x[i]<y[i]?-1:1);
}
```
| Defense | Oracle move |
|---|---|
| Fake "decrypting…" char-drip: `usleep` between `putchar`s | gdb `b putchar` → `commands`/`printf "%c",$rdi`/`continue` dumps it instantly; or `LD_PRELOAD` `usleep`/`nanosleep`→no-op |
| PRNG-seeded or time-gated check | `LD_PRELOAD` `time`→const and `srand`/`rand` deterministic to freeze it → reproducible runs |

## angr — find input that reaches success
Needs a good addr and a bad addr from Ghidra/r2.
```python
import angr, claripy
proj = angr.Project("./chal", auto_load_libs=False)

FLAG_LEN = 32
flag = claripy.BVS("flag", 8 * FLAG_LEN)
st = proj.factory.full_init_state(
    stdin=flag,
    add_options=angr.options.unicorn | {angr.options.LAZY_SOLVES,
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,      # tame path explosion:
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS},  # don't fork on fresh symbols
)
for b in flag.chop(8):                       # keep bytes printable
    st.add_constraints(b >= 0x20, b <= 0x7e)

sm = proj.factory.simulation_manager(st)
sm.explore(find=0x401337, avoid=0x401300)    # find AFTER the decisive branch
if sm.found:
    print(sm.found[0].posix.dumps(0))        # concrete stdin = flag
```
**Derive `find`/`avoid` from the win/lose *string* xref** (§Find the decision point), not a guessed block. `find=` just past the decisive branch, `avoid=` on early-reject blocks. Input via argv? model a symbolic bitvector arg / `angr.PointerWrapper` instead of stdin.
Path explosion: add `sm.use_technique(angr.exploration_techniques.DFS())` (bounds memory) plus the `ZERO_FILL_UNCONSTRAINED_*` options above. **Hook** expensive/opaque functions — `sha256`, `printf`, `sleep`, a custom mixer — with a `SimProcedure` (`proj.hook_symbol("sha256", MyProc())` or `proj.hook(addr, summary, length=n)`) so states neither fork nor stall.
angr still stuck? **Triton** for concolic single-path DSE (follow one concrete trace, collect its path constraints, solve); **Qiling** to fully emulate the binary/OS — it runs the *real* code, so it sidesteps ptrace anti-debug and missing-syscall failures.

## z3 — encode the arithmetic directly
When you've read the algorithm and it's equations over flag bytes.
```python
from z3 import *
N = 32
b = [BitVec(f"b{i}", 8) for i in range(N)]
s = Solver()
for x in b: s.add(x >= 0x20, x <= 0x7e)      # printable
# --- transcribe the check EXACTLY from the decompiler ---
T = [ ... ]                                   # real target bytes read from the binary
k = 0x5a
for i in range(N):
    s.add((b[i] ^ k ^ (i & 0xff)) == T[i])
    k = T[i]
assert s.check() == sat, s
print(bytes(s.model()[x].as_long() for x in b))
```
Transcribe constants/target arrays **verbatim** from tool output. Multiple `sat` models → pin the unique flag with the known prefix (`flag{`), known length, or a second constraint.

## unicorn — run one opaque function without reversing it
Map the code + a stack, set the input in the register/buffer the ABI uses, emulate `start→end`, read the output buffer. Ideal for VM opcode handlers and hash-like mixers where you just need to evaluate the transform over many candidate keys (brute wrapped around emulation).

## Anti-debug & self-modifying counters
Spot the guards first: `grep -aoE 'ptrace|rdtsc|IsDebuggerPresent|TracerPid|/proc/self/status' ./chal` or scan the imports.
| Trick | Counter |
|---|---|
| `ptrace(PTRACE_TRACEME)` returns -1 if already traced | `LD_PRELOAD` a stub `ptrace`→0, patch the branch, or `catch syscall ptrace` and force the return in gdb |
| `/proc/self/status` TracerPid, `rdtsc`/`clock` timing gates | patch/NOP the compare; under gdb, set the register after the read |
| INT3 (`0xCC`) / SIGTRAP self-checks | `handle SIGTRAP nostop noprint pass` so gdb passes the signal through |
| runtime-decrypted / self-modifying code | never trust static bytes — break after the decrypt loop, `dump memory out.bin $start $end`, disasm the clean copy |

**Patch it out for good (pwntools):** `elf=ELF("./chal"); elf.asm(elf.symbols.ptrace,"ret"); elf.save("./chal.patched")` neuters the guard at its call site — then reverse/run the clean copy.

## VM / bytecode obfuscation
Find the dispatch loop (big switch on an opcode byte, a "PC" index into a bytecode blob). Recover the handlers, write a disassembler for the custom ISA, and read the program it runs — tedious but decisive. Or emulate the whole VM with unicorn and treat it as a black box you feed candidate flags.

**Cut the interpreter overhead instead of reading it:**
| Move | How |
|---|---|
| Collapse dispatch into readable logic | lift each opcode handler to LLVM IR, `opt -O3`, then decompile the *optimized* IR — constant-folds the fetch/decode away |
| Isolate the real algorithm | **trace-diff**: run two inputs differing by ONE char under a tracer (qemu/pin/`gdb` logging), diff the instruction+memory traces → the ops that actually touch the flag stand out from the constant VM overhead |
| Control-flow flattening (dispatcher on a state var) | don't read it statically — **trace the state variable at runtime** to recover the true block order, then reassemble the blocks |

## Recognize the primitive by its constants
TEA/XTEA `0x9e3779b9`, **AES** S-box (`63 7c 77 7b f2 6b 6f c5…` / MixColumns `02 03 01`), **ChaCha/Salsa** sigma `expand 32-byte k`, MD5/SHA IVs, RC4 KSA (256-byte identity→permutation), base64 with a swapped alphabet, LCG PRNG. Name it on sight. For a **standard** primitive (AES/ChaCha/RSA/a real hash) don't reimplement by hand — recover the key/params and **hand it to the crypto skill**; only custom/rolled ciphers get inverted here. Don't invent constants — if you're guessing a value, stop and read it.

## Endgame
Reimplement the inverse in `solver.py`, print the flag, then **verify through the actual binary** before trusting it: `echo "flag{...}" | ./chal` (or feed the remote service) and confirm it prints success. Only a binary-confirmed flag is real; any flag baked into a local build is fake (see base §5). If a candidate is rejected, the usual culprits are off-by-one length, wrong endianness, unprintable bytes, or the wrong success branch — re-check those and try the alternate `sat` model.
