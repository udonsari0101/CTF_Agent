# Skill Module: crypto

Crypto is won by finding the **one broken parameter** — the deviation from the safe idiom (e=65537, unique nonce, random key, constant-time pad check) — then *proving recovery on the given numbers*. Almost never brute force; classify by shape, pick the attack, gate it behind a check.

**Where crypto artifacts go** (base owns the loop/phases): extract the real `n,e,c,IV,sig,curve,outputs…` by variable name into `notes/ANALYSIS.md` and classify there (never paste 4096-bit ints into prose); write the deviation as one line (`e=3 + no pad → cube root`) **plus the recovered primitive** (factors / keystream / RNG state / ECDSA `d`) into `notes/VULN.md`; log dead-end attacks + POISON in `notes/NEXT.md`; put the decrypt in `solver.py`, scratch in `tmp/`; cross-category → `../../skills/<cat>.md`.

## Classify first — tells by structure / length / entropy

| Observation | Scheme / next step |
|---|---|
| 32 / 40 / 64 / 96 / 128 hex chars | MD5 / SHA1 / SHA256 / SHA384 / SHA512 — `hashcat`/`john`/crackstation only if input is weak |
| Two huge decimal ints + small third (`n,e,c`) | RSA → RSA tree |
| Ciphertext len multiple of 16, high entropy | AES/DES block — ECB (repeated blocks) vs CBC vs CTR |
| Repeated 32-hex (16-byte) chunk in ciphertext | **ECB** → byte-at-a-time / cut-and-paste |
| Low entropy, printable, len == plaintext | classical / XOR / stream keystream reuse |
| `(r,s,z)` tuples, point coords, named curve | ECDSA / ECC |
| Sequence of 32-bit ints, or `getrandbits`/`random()` in source | PRNG (MT19937 / LCG) |
| Bit/keystream from XOR-shift-rotate-CRC only | **linear over GF(2)** (see reflex) |
| `H(secret ‖ msg)` MAC + you control appended data | hash length-extension |
| base64/hex wrapper | decode first (`base64 -d`, `xxd -r -p`), then re-classify |

Quick check: `python3 -c "d=open('f','rb').read();print(len(d),len(set(d)))"`; `file`, `xxd | head`.

## Reflex — is the primitive secretly LINEAR or broken-by-construction? (two cheap checks first)

**Linear over GF(2).** Any custom hash / PRNG / MAC / "cipher" built ONLY from XOR, shifts, rotates, bit-permutations, CRC is an **affine map over GF(2)** — solve it, don't iterate. Feed the `n` unit vectors `e_i` (one bit set) through the black box, stack outputs as columns → matrix `M`; constant is `f(0)`. Then `f(x)=M·x ⊕ f(0)`; `M.solve_right(...)` / kernel over `GF(2)` gives forged preimages / recovered key in one shot. Same tell for a custom AES-like round with a stuck/known key schedule (GF(2^8) MixColumns is GF(2)-linear).

**Broken-by-construction — one-liner checks:**
- **Groth16 / pairing SNARK**: `vk_delta_2 == vk_gamma_2` (or either is identity) → forge a proof for ANY public input, no witness. (Also: unconstrained nullifier → replay.)
- **ElGamal**: published `B = p−1` (`g^x=−1`) → `x=(p−1)/2`. `A=0`/`A=n` in SRP-style → shared secret 0.
- **Matrix / LFSR schemes** (`state ← A·state`): diagonalize via **Jordan form** → `A^k` closed-form.
- **ECC / RSA textbook params** → run `factor(E.order())` / discriminant / `factordb` *before* any lattice.

## Tooling fast-path

- **SageMath is the fast path** for anything algebraic (factoring, Coppersmith, discrete log, curves, lattices/LLL): `sage script.sage` or `sage -python x.py`. Fall back to pycryptodome+sympy+z3 only if Sage is missing.
- `from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime, inverse, GCD`; ciphers via `Crypto.Cipher`. `gmpy2` for fast bigint/iroot; `sympy` for `factorint, nextprime, discrete_log` (small).
- **z3/cvc5**: constraint-solve PRNG/LCG/bit-twiddling when algebra is ugly. z3/cvc5/BKZ don't scale on cores — **race N processes** (different seeds/tactics) under `timeout`, take first hit.
- **factordb FIRST for every modulus**: `curl -s "http://factordb.com/api?query=<N>"` (or `factordb-pycli`). Many CTF `n` are pre-factored. Big/generic semiprime with no structure → `cado-nfs`. Record recovered factors in `notes/VULN.md`.

---

## RSA — decision tree by tell (cheapest first)

**First move:** `RsaCtfTool -n N -e E --uncipher C` auto-sweeps most branches; kick off `factordb` + `roca-detect` alongside. Then walk manually by cost:
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
# Coppersmith high bits of p (Sage): p=p_high+x, |x|<2^kbits, p~n^0.5
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
- **CBC bit-flipping**: flip byte `i` of `C_{k−1}` → flips byte `i` of `P_k` (garbles block `k−1`). `P_k[i]^=(old^new)`. IV bit-flip edits block 0. Flip `role=user`→`admin` with no key.
- **CBC/PKCS7 padding oracle** (server distinguishes bad-pad from other errors — incl. UnicodeDecodeError/length side-channels) → recover plaintext byte-from-tail (~128 q/byte) and **encrypt arbitrary plaintext** via chosen IVs. The single most common AES CTF. Tools: PadBuster, `padding-oracle`.
- **CTR/stream nonce reuse** (same key,nonce → same keystream): `C1^C2=P1^P2`. Crib-drag / known-plaintext to peel keystream. Never brute the key.
- **GCM nonce reuse**: two msgs under one (key,nonce) leak auth key `H` → **forge tags**. Solve the two GHASH equations over `GF(2^128)` (modulus `x^128+x^7+x^2+x+1`) for `H`, then tag the forged ct. Tool: `nonce-disrespect`.
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

**Ladder (cheapest first):** `M.LLL()` → `M.BKZ(block_size=20..35)` → **Babai nearest-plane / CVP** (inhomogeneous "target" problems). Use **`fpylll`** + **`flatter`** (far faster on big/ill-scaled bases); reach for **`defund/coppersmith`** (multivariate `small_roots`) and **`jvdsn/crypto-attacks`** (ready HNP/Coppersmith/LCG/LWE) rather than re-deriving.

**When LLL/BKZ returns garbage — the four usual bugs:**
1. **Scaling** — weight the columns holding the small unknowns so their term dominates; balance entry magnitudes.
2. **Centering** — residues in `[−q/2,q/2)`, not `[0,q)`.
3. **Too few samples** — HNP needs `bits_leaked·samples > bits(n)`; add rows.
4. **Wrong target** in CVP — recheck constant column / inhomogeneous embedding.

## Hashes

- **Length extension** (`H(secret‖msg)`, MD5/SHA1/SHA256): append data + forge MAC without the secret. `hashpump -s <sig> -d <known> -a <append> -k <secret_len>` (or `hashpumpy`).
- **Collisions**: reuse published pairs — MD5 chosen-prefix (`fastcoll`/`fastcol`), SHA1 SHAttered. Don't generate novel collisions under time pressure. **CRC** is linear → append 4 bytes to force any target (forge `CRC(msg‖secret)`).

## PRNG

- **MT19937 (Python `random`)**: 624 consecutive 32-bit outputs → full state → all past/future. `randcrack` (feed 624). Truncated/float outputs → z3 / `mt19937predictor` / GF(2) magic-matrix (`not_random`).
- **LCG** (`x=a·x+c mod m`): recover `m` from gcd of products of differences, then `a=(x2−x1)/(x1−x0)`, `c` follows. Truncated → HNP/lattice. z3 handles modular constraints cleanly.
- **V8 `Math.random()`** = **xorshift128+** (`xs128p`): collect 5–10 consecutive doubles served **in reverse (LIFO)** → *reverse your sample order*, recover 128-bit state with **z3** (`QF_BV`), roll forward. Tool: `v8_rand_buster`.
- **time-seeded key/IV** (`random.seed(time())`/`srand(time())`) → tiny seed space; **the challenge file's mtime IS often the seed** — `stat` it, try that value first, then brute a ±window. C `rand()` ≠ Python: call libc directly via `ctypes.CDLL('libc.so.6').srand/rand`.

```python
from randcrack import RandCrack
rc=RandCrack()
for out in outputs_624: rc.submit(out)       # 624 consecutive getrandbits(32)
predicted=rc.predict_getrandbits(32)
```

---

**Gate every break through a check:** `p*q==n`; recovered keystream against a known plaintext byte; `pow(pow(m,e,n),d,n)==m`; a re-signed message verifies. Name each script by hypothesis (`wiener.py`, `padding_oracle.py`) and cache working primitives. For oracle attacks (padding, invalid-curve, timing) script against the live remote — but test the query encoder in isolation first.
