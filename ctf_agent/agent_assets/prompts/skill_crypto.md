# Skill Module: crypto

Classify the primitive and the actual win condition first. The weakness may be a parameter, implementation, protocol, reused state, or leaked information; do not assume there is exactly one bad constant. Choose a testable hypothesis, use the cheapest matching attack, and prove recovery on the supplied numbers or oracle.

**Where crypto artifacts go** (base owns the loop/phases): extract the real `n,e,c,IV,sig,curve,outputs…` by variable name into `notes/ANALYSIS.md` and classify there (never paste 4096-bit ints into prose); write the deviation as one line (`e=3 + no pad → cube root`) **plus the recovered primitive** (factors / keystream / RNG state / ECDSA `d`) into `notes/VULN.md`; log dead-end attacks + POISON in `notes/NEXT.md`; put the decrypt in `solver.py`, scratch in `tmp/`; cross-category → `../../skills/<cat>.md`.

## Classify first — tells by structure / length / entropy

| Observation | Scheme / next step |
|---|---|
| 32 / 40 / 64 / 96 / 128 hex chars | Compatible with common digest lengths, but also keys, tags or random bytes; establish what was hashed before trying a weak-input dictionary |
| Two huge decimal ints + small third (`n,e,c`) | RSA → RSA tree |
| Ciphertext len multiple of 16, high entropy | Possibly a padded block cipher; confirm the format, block size and mode from source or controlled queries |
| Repeated aligned 16-byte ciphertext block under one key | ECB is a candidate; test with repeated controlled plaintext before a byte-at-a-time or cut-and-paste attack |
| Low entropy, printable, len == plaintext | classical / XOR / stream keystream reuse |
| `(r,s,z)` tuples, point coords, named curve | ECDSA / ECC |
| Sequence of 32-bit ints, or `getrandbits`/`random()` in source | PRNG (MT19937 / LCG) |
| Bit/keystream from XOR-shift-rotate-CRC only | **linear over GF(2)** (see reflex) |
| Raw Merkle–Damgård hash `H(secret ‖ msg)` used as a MAC, and you can append data | consider length-extension; HMAC, SHA-3 and a suffix-secret construction do not follow this recipe |
| base64/hex wrapper | decode first (`base64 -d`, `xxd -r -p`), then re-classify |

Quick check: `python3 -c "d=open('f','rb').read();print(len(d),len(set(d)))"`; `file`, `xxd | head`.

## Reflex — is the primitive secretly LINEAR or broken-by-construction? (two cheap checks first)

**Linear over GF(2), when the entire relevant transformation is affine.** Fixed XORs, fixed shifts/rotates, bit permutations and CRC steps qualify; data-dependent shifts, modular addition, AND of unknown bits and S-boxes do not. First test `f(x ⊕ y) ⊕ f(0) == (f(x) ⊕ f(0)) ⊕ (f(y) ⊕ f(0))` on several distinct inputs. If it holds and the input width is tractable, feed the `n` unit vectors `e_i` through the black box, stack outputs as columns → matrix `M`; then `f(x)=M·x ⊕ f(0)`. Solve the matrix and verify the result against the original primitive. AES MixColumns alone is linear, but a full AES round with SubBytes is not, even with a known key schedule.

**Cheap structural checks, only when the supplied scheme warrants them:**
- **ElGamal / SRP-style protocols**: verify the group order, point validation and exceptional values. A public value equal to `−1 mod p` may constrain an exponent, but is not by itself proof that its exact exponent is `(p−1)/2` for the chosen generator.
- **Matrix / LFSR schemes** (`state ← A·state`): model fixed transitions as matrix powers and test against observed outputs before seeking a closed form.
- **ECC / RSA**: inspect discriminants and small or obviously structured group orders; bound factorization attempts rather than spending the whole solve on a large generic order.

## Tooling fast-path

- The image includes `gp` (PARI/GP), `fpylll`, `gmpy2`, `sympy`, `z3` and PyCryptodome. Start with the cheapest matching one. **SageMath is optional, not preinstalled**; check `command -v sage` before `sage script.sage` or `sage -python x.py`, and acquire it only if its algebraic operations are necessary.
- `from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime, inverse, GCD`; ciphers via `Crypto.Cipher`. `gmpy2` for fast bigint/iroot; `sympy` for `factorint, nextprime, discrete_log` (small).
- **z3 is installed; cvc5 is optional**. Constraint-solve PRNG/LCG/bit-twiddling when algebra is ugly. Large SMT/BKZ jobs may not scale; bound trials with `timeout` and compare distinct approaches.
- Check a supplied RSA modulus against FactorDB's public API when relevant: `curl -s "https://factordb.com/api?query=<N>"`. Treat its result as a lead, verify factors with `p*q==n`. `factordb-pycli` and `cado-nfs` are optional extras. Record recovered factors in `notes/VULN.md`.

---

## RSA — decision tree by tell (cheapest first)

**First move:** inspect `n,e,c` and test cheap structure (shared factors, small exponent, close primes, weak `d` via installed `owiener`); check FactorDB when useful. `RsaCtfTool` and `roca-detect` are optional, not image commands. If installed or acquired for this job, use them as additional hypotheses, then verify their output. Walk the branches by cost:
- **factordb hit** → decrypt.
- **e small (3,5,17), single ct, `m^e<n`** → integer e-th root `iroot(c,e)`; if inexact, `m` wrapped → retry `iroot(c+k·n,e)` small `k`.
- **e small, same `m` to ≥e recipients** → **Håstad broadcast**: CRT the `c_i mod n_i`, then e-th root. With affine pad `a_i m+b_i` → CRT + Coppersmith.
- **e small, related `m` same `n`** (`m`, `a·m+b`) → **Franklin–Reiter**: `gcd(x^e−c1,(ax+b)^e−c2)` in `Z_n[x]`. Unknown short pad → Coppersmith short-pad.
- **e huge / e≈n** (small `d<n^0.25`) → **Wiener** (`owiener` one-shot; continued fractions of `e/n`).
- **two moduli share a factor** (`gcd(n1,n2)≠1`) → one GCD breaks both. Many keys → **batch-GCD**.
- **same `n`, two `e` for same `m`, `gcd(e1,e2)=1`** → **common modulus**: `u·e1+v·e2=1`, `m=c1^u·c2^v mod n` (neg exp → invert).
- **p,q close** → **Fermat**: `a=⌈√n⌉`, inc until `a²−n` square.
- **`p−1` smooth** → **Pollard p−1**: `a=2; for j in 2..B: a=pow(a,j,n); p=gcd(a−1,n)`. (also Williams p+1.)
- **partial leak** (≥half bits of `p`, or high bits of `d`) → **Coppersmith** `small_roots` (Sage): poly **MONIC**, `beta=0.5`, `X`=true bound. `defund/coppersmith` for multivariate.
- **weak/low-entropy prime (<~90 bit)** → `sympy.factorint`/`yafu`/`pari`. **ROCA** fingerprint (`roca-detect`) → Coppersmith recovery.
- **LSB/parity or MSB oracle** (decrypt endpoint leaks `m mod 2` / half-plane per chosen ct) → RSA is multiplicatively homomorphic: submit `c·2^e mod n`, each reply halves the interval → binary-search `m` in `~log2(n)` queries. **PKCS#1 v1.5 pad oracle** → **Bleichenbacher/ROBOT** (adaptive CCA). OAEP timing → **Manger**.
- **`gcd(e,phi)≠1`** (e.g. e=2 Rabin) → e-th root via `Zmod(n)` roots / Rabin CRT; pick root with valid flag format.
- **known multiple of `phi`** (e.g. `e·d−1`) → factor via Miller-Rabin sqrt trick. Partial `dp/dq/qinv` leak → iterate `k`, test `(dp·e−1)/k+1` prime.

**Signature/oracle forgery bugs:** unpadded RSA is multiplicative → `S(a)·S(b)=S(ab)`; blacklisted msg → sign its factors. Verifier takes user `(n,e)` → set **e=1, n=sig−PKCS1_pad(msg)**. Single **RSA-CRT fault** sig `s'` → `p=gcd(m−s'^e, n)` (Bellcore). Homomorphic decrypt oracle → query `c·r^e`, divide out `r`.

```python
# Fermat
from sympy import integer_nthroot
def fermat(n):
    a,_=integer_nthroot(n,2); a+=1
    while True:
        b,ok=integer_nthroot(a*a-n,2)
        if ok: return a-b,a+b
        a+=1
# Coppersmith high bits of p (optional SageMath only): p=p_high+x, |x|<2^kbits, p~n^0.5
P.<x>=PolynomialRing(Zmod(n))                       # MONIC in x
x0=(p_high+x).small_roots(X=2^kbits,beta=0.5)[0]
p=int(p_high+x0); q=n//p
# Decrypt once factored (verify p*q==n first)
from Crypto.Util.number import inverse,long_to_bytes
d=inverse(e,(p-1)*(q-1)); print(long_to_bytes(pow(c,d,n)))
```

---

## AES / block-cipher — tells and attacks

- **ECB** (repeated pt→repeated ct): controlled prefix on block boundary → **byte-at-a-time** (brute one unknown byte/query) and **cut-and-paste** (rearrange ct blocks to splice an `admin` block).
- **CBC bit-flipping**: flip byte `i` of `C_{k−1}` → flips byte `i` of `P_k` (garbles block `k−1`). `P_k[i]^=(old^new)`. IV bit-flip edits block 0. A same-length substitution such as `role=guest`→`role=admin` may work if the positions and block boundaries are known and no integrity check rejects the ciphertext.
- **CBC/PKCS7 padding oracle** (server distinguishes bad-pad from other errors — incl. UnicodeDecodeError/length side-channels) → recover plaintext byte-from-tail (~128 q/byte) and **encrypt arbitrary plaintext** via chosen IVs. The single most common AES CTF. Tools: PadBuster, `padding-oracle`.
- **CTR/stream nonce reuse** (same key,nonce → same keystream): `C1^C2=P1^P2`. Crib-drag / known-plaintext to peel keystream. Never brute the key.
- **GCM nonce reuse**: ciphertexts under the same key and nonce reveal the XOR of plaintexts. If authenticated message/tag pairs and their lengths are known, analyze the GHASH equations for candidate authentication keys, then verify a forged tag against the oracle; two arbitrary ciphertexts alone do not guarantee a unique key recovery. Tool: `nonce-disrespect` when the instance fits its assumptions.
- **reduced-round AES** → integral/**square attack** (256-pt Λ-set, XOR-sum=0 distinguisher); modified/degenerate S-box (`len(set(sbox))<256`) → per-position key recovery.

```python
ks=bytes(a^b for a,b in zip(c1,known_p1))    # keystream from known plaintext
recovered=bytes(a^b for a,b in zip(c2,ks))   # CTR/stream reuse
```

## Classical, XOR & LFSR stream

- **Repeating-key XOR**: keylen by normalized Hamming distance (min at true size) / Kasiski, then each column is single-byte XOR — score by English freq (space `0x20` strongest tell).
- **Single-byte XOR**: brute 256, max freq score. **Many-time pad** (OTP reuse): `C1^C2^known_P` / crib-drag.
- **Sub/Vigenère/Caesar**: frequency analysis, ROT-N; bootstrap with the flag prefix as a known-plaintext crib. Auto: quipqiup.
- **XOR vs file header**: `file` says "data" but should be PNG/PDF/ZIP → XOR first bytes vs magic to derive repeating key; extend via trailer (`IEND`, `%%EOF`).
- **LFSR** keystream (from known-plaintext XOR): **Berlekamp-Massey** on 2L bits → minimal feedback poly + state → all past/future. Sage `berlekamp_massey(seq)`. Combined/nonlinear-filter generator with biased combiner → **correlation attack**. CRC/LFSR = GF(2)-linear (see reflex).

## ECC / ECDSA

**Solve the ECDLP — run `factor(E.order())` FIRST; the factorization picks the attack:**
- **`E.order()==p`** (anomalous) → **Smart's attack** (p-adic lift): instant at any bit-size.
- **discriminant `4a³+27b²≡0 (mod p)`** (singular) → maps to `(GF(p),+)` (cusp) or `GF(p)*`/`GF(p²)*` (node) → trivial DL.
- **smooth order** → **Pohlig–Hellman + BSGS** (`discrete_log` in Sage does both).
- **small embedding degree** (`n|p^k−1`, small `k`) → **MOV/Frey–Rück** into `GF(p^k)*`.
- **odd group** (`x²+y²=1` clock group order `p+1`, etc.) → check `p+1` smoothness. Otherwise curve is sound → look for a *protocol/parameter* bug, not the DLP.

**Signature bugs (ECDSA *and* DSA — same algebra):**
- **Nonce reuse** (same `k`/`r` twice) → `k=(z1−z2)/(s1−s2)`, then `d=(s1·k−z1)/r mod n`. One repeat = game over; any known *linear relation* between nonces breaks it identically.
- **Biased/short/partially-leaked nonce** (few bits of many `k`) → **HNP** → lattice (below). Tiny `k` → brute.
- **Invalid-curve / small-subgroup** (server skips on-curve check) → send points on weak curves, collect residues, CRT the scalar.

```python
k=((z1-z2)*inverse(s1-s2,n))%n               # generator order n (DSA too)
d=((s1*k-z1)*inverse(r,n))%n
```

## Lattices — universal solver for "modular-linear + something small"

**Trigger:** linear relations mod `q` with one unknown *small / biased / truncated / partially leaked*. Cases: **HNP** (partial-nonce ECDSA/DSA), **truncated/low-bit LCG**, **subset-sum/knapsack**, **Coppersmith** (small modular root), **LWE/CVP**, approximate-GCD. Build a basis whose short vectors encode the small unknown.

**Ladder (cheapest first):** installed `fpylll` LLL/BKZ → **Babai nearest-plane / CVP** (inhomogeneous "target" problems). SageMath's `M.LLL()`/`M.BKZ()`, `flatter`, `defund/coppersmith` and `jvdsn/crypto-attacks` are optional extras; verify availability before following their recipes.

**When LLL/BKZ returns garbage — the four usual bugs:**
1. **Scaling** — weight the columns holding the small unknowns so their term dominates; balance entry magnitudes.
2. **Centering** — residues in `[−q/2,q/2)`, not `[0,q)`.
3. **Too few samples** — HNP needs `bits_leaked·samples > bits(n)`; add rows.
4. **Wrong target** in CVP — recheck constant column / inhomogeneous embedding.

## Hashes

- **Length extension** (`H(secret‖msg)`, MD5/SHA1/SHA256): append data + forge MAC without the secret. The image includes Python `hashpumpy`, not the `hashpump` CLI; check `import hashpumpy` and use its `hashpump` function with the correct secret-length guess. This does not apply to HMAC or SHA-3.
- **Collisions**: reuse published pairs when the challenge structure permits. FastColl makes MD5 identical-prefix collisions; HashClash's `cpc.sh` handles chosen-prefix MD5 collisions (not bundled). SHA-1 SHAttered is a published collision pair, not a general chosen-prefix tool. **CRC** is linear, but a suffix-forging calculation depends on the exact CRC parameters and message layout.

## PRNG

- **MT19937 (Python `random`)**: 624 consecutive full 32-bit outputs can reveal the state and predict future outputs. Confirm the call pattern and output truncation before using `randcrack`; past outputs need separate state reversal. Truncated/float outputs need additional equations or samples.
- **LCG** (`x=a·x+c mod m`): infer a candidate `m` from differences, then solve `a(x1−x0) ≡ x2−x1 (mod m)`; ordinary modular division works only when the denominator is invertible modulo `m`. Check every recovered parameter against further outputs. Truncated outputs may need lattice/SMT methods.
- **V8 `Math.random()`**: inspect the target's runtime version and architecture before modelling its PRNG. Versions using xorshift128+ can be modeled with bit-vector constraints, but observed output order matters: current 64-bit V8 generates values on each call, while its 32-bit path uses a refill cache. Do not reverse samples by default; predict and verify the next real output before trusting recovered state.
- **time-seeded key/IV** (`random.seed(time())`/`srand(time())`) → bounded candidate timestamps when source or output timing supports it. File mtime is a candidate only if there is evidence that generation and file writing coincided; do not assume it is the seed. C `rand()` ≠ Python: if needed, reproduce the target libc implementation rather than Python's PRNG.

```python
# Optional package: `python3 -c 'import randcrack'` before using this example;
# install it in job-local scratch only when full 32-bit outputs justify it.
from randcrack import RandCrack
rc=RandCrack()
for out in outputs_624: rc.submit(out)       # 624 consecutive getrandbits(32)
predicted=rc.predict_getrandbits(32)
```

---

**Gate every break through a check:** `p*q==n`; recovered keystream against a known plaintext byte; `pow(pow(m,e,n),d,n)==m`; a re-signed message verifies. Name each script by hypothesis (`wiener.py`, `padding_oracle.py`) and cache working primitives. For oracle attacks (padding, invalid-curve, timing) script against the live remote — but test the query encoder in isolation first.
