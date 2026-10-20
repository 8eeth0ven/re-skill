# Blockchain Security

> Knowledge scope: the 2024-2026 public blockchain security knowledge base; the "Blockchain Security" category in the knowledge tree (node 1001264) has no stock articles. Amounts are in USD, valued at the time of each event.

## 0. Positioning and reading map

- Only want to see "where the money went" → §2 vulnerabilities + §6 cross-chain bridges + §8 case timeline
- Doing audits / taking engagements → §3 tools and methodology
- Doing on-chain tracing / anti-fraud / law enforcement → §4 + §7 forensics essentials
- Exchange / wallet product security → §5
- AI crossover → `ai-blockchain-crossover.md` in this directory

## 1. Ecosystem and chain-type overview

| Chain | Consensus/VM | Security-ecosystem traits | China case characteristics |
|---|---|---|---|
| Ethereum (ETH) | PoS / EVM | DeFi main battlefield, most mature auditing tooling; most reentrancy/oracle/flash-loan attacks | DApp project teams absconding, fake miner schemes |
| BSC (BNB Chain) | PoSA / EVM | Low gas, a gathering place for copycats; honeypot tokens and honeypot NFTs run rampant | **The largest hub of honeypot tokens and Ponzi schemes** (most victims in China) |
| Tron | DPoS / TVM | Main channel for off-chain USDT-TRC20 circulation | **The main laundering channel for money muling, gambling funds, and Ponzi schemes** (most funds frozen in cases) |
| Solana | PoH+TowerBFT / SVM (Rust) | Non-EVM; contracts in Anchor/Rust; bugs mostly in deserialization/account model | Memecoin phishing, fake plugin wallets |
| L2 (Arbitrum/Base/Optimism) | Rollup | Inherits EVM + adds sequencer/bridge risk | New case surface added 2024-2026 (USDT aggregation) |
| Consortium chains (Ant/domestic) | PBFT class | Domestic-made; attack surface in nodes and permissions | Government/enterprise projects, few public cases |

Scale intuition (Chainalysis): in 2024, **$2.2B** in crypto was stolen across the year (+21% YoY, 61% attributed to North Korea); **2025 had already reached $2.17B in H1 alone**, of which the Bybit case alone was $1.5B — the largest single incident ever.

## 2. Smart contract vulnerabilities (principle → case → fix)

### 2.1 Reentrancy

- Principle: an external call (the recipient's `fallback`/`receive`) executes before state is updated; a malicious contract recursively re-enters the withdrawal function and drains repeatedly while the balance is still un-zeroed.
- Case replay: **The DAO (2016-06)** — 3.6M ETH (~$60M at the time) stolen, directly causing the ETH hard fork (ETC was born of it); **Curve (2023-07)** — the Vyper compiler 0.2.15~0.3.0 reentrancy lock failed, ~$70M.
- Fixes: **checks-effects-interactions (CEI)**; Solidity 0.8+ `nonReentrant`; use pull-payment for transfers.
- Recognition signatures: SSTORE still happening after `call.value{...}`; external calls before state updates.

```solidity
// Vulnerable pattern (The DAO, abbreviated)
function withdraw() external {
    uint amount = balances[msg.sender];
    (bool ok, ) = msg.sender.call{value: amount}(""); // external call before effects
    require(ok);
    balances[msg.sender] = 0;                          // <- state updated last = reentrancy window
}
```

### 2.2 Integer overflow

- Principle: before 0.8, Solidity had no built-in overflow protection; `uint256` wraps around.
- Cases: **BEC MeiChain (2018-04)** — `amount * count` in `batchTransfer` overflowed into an astronomical number, maliciously minting tokens; BEC went to zero; one of the most influential contract cases in China; **Cetus (Sui, 2025-05)** — non-EVM chains fall too: missing `checked math` caused integer overflow, **$223M** stolen (partly frozen afterward), proving overflow is not an "old EVM ailment" but a universal error class on every chain.
- Fixes: Solidity >=0.8 defaults to checked; use SafeMath on older versions; explicit `checked_*` on Move/Rust chains.

### 2.3 Missing access control

- Principle: sensitive functions (owner mint/pause/upgrade/selfdestruct) have no modifier, or the permission check is written wrong.
- Cases: **Parity multisig wallet (2017)** — two incidents: in July a Solidity library bug lost 150k ETH ($31M); in November devops199 accidentally called `kill` on an uninitialized library, **513,000 ETH (~$150M+ at the time) permanently frozen** — "one call freezing hundreds of millions of dollars" is the classic textbook case of access control + selfdestruct combined; **Multichain (2023-07)** — centralized private-key management, $126M stolen.
- Fixes: `onlyOwner`/RBAC libraries (OpenZeppelin AccessControl); initializer modifiers on init functions; initialize library contracts immediately after construction.

### 2.4 Flash loan attacks

- Principle: borrow a fortune uncollateralized within one transaction, manipulate on-chain prices/governance, then repay — the attack leverages zero cost against all of a protocol's liquidity.
- Cases: **bZx (2020-02)** — the first famous battle, two incidents totaling ~$950k; **Beanstalk (2022-04)** — a flash loan borrowed massive STASH/BEAN to vote a malicious proposal through, ~$182M in total moved out including the loan (**governance attack**); **Euler Finance (2023-03)** — a flash loan with `donateToReserves` self-donation triggered liquidation logic, **$197M** (the hacker later returned it — a negotiation case); **Mango Markets (2022-10)** — pumped MNGO to manipulate collateral and shorted out $114M (the manipulator was convicted of fraud, a rare criminal closure).
- Fixes: on-chain pricing should trust only TWAP/oracles; governance proposals with timelock + snapshot voting; for flash-loan-sensitive operations, checking `tx.origin == msg.sender` is not enough — you need reentrancy/same-block protection.

```
[Generic flash-loan attack flow, self-drawn]
Lending protocol A --flash loan--> attack contract
Attack contract --massive sell pressure--> DEX pool X (price skewed)
Attack contract --uses skewed price--> victim protocol B (collateral overvalued / liquidation profit)
Victim protocol B --arbitrage payout--> attack contract
Attack contract --repay loan + interest--> lending protocol A
Completed atomically in one transaction; on failure everything reverts -> zero risk for the attacker
```

### 2.5 Price oracle manipulation

- Principle: the protocol prices with the "spot instant price" (DEX spot), which a flash loan can skew momentarily.
- Cases: Mango (above); masses of long-tail lending protocols (the high-frequency cause of death on rekt.news 2022-2024).
- Fixes: **decentralized oracle networks (DON)** like Chainlink; Uniswap V3 TWAP; multi-source aggregation + deviation circuit breakers.

### 2.6 Approval phishing

- Principle: after `ERC20.approve/increaseAllowance`, what gets spent is the allowance at **any later moment**; the phishing site scams not a transfer but a single approve, then quietly moves coins with `transferFrom` days later.
- Variants: **permit (EIP-2612) off-line signature phishing** — no gas, no on-chain transaction; one signature and the coins are gone; **Permit2 (Uniswap)** bulk unified authorization abused by phishing sites; in 2024-2025 phishing-as-a-service (Drainer families: Inferis/Pink/Angel Drainer etc.) industrialized, stealing millions per campaign.
- Protection: periodic revocation of wallet allowances (revoke.cash); wallets doing semantic transaction parsing + risky-address databases (SlowMist MistTrack labels, GoPlus); hot/cold separation.

### 2.7 MEV frontrunning and sandwiching

- Principle: transactions are visible in the public mempool; validators/searchers can insert ordering for profit — frontrunning (arbitrage), sandwiching (front-and-back attacks eating slippage), liquidation MEV (liquidation races). Academic origin: "Flash Boys 2.0" (Daian et al., 2019).
- Toolchain: Flashbots Protect, private mempools, mev-boost; observation: EigenPhi, Dune dashboards; libevm/flashbots-inspect for forensic replay.
- Protection (user side): tighten slippage, split orders, route privately (Flashbots Protect/MEV Blocker).

### 2.8 Function-selector confusion and signature replay

- Principle: external calls go by the 4-byte selector only (`bytes4(keccak256("transfer(address,uint256)"))`) and completely ignore parameter types — reinterpreting the parameters of `transfer(address,uint256)` with semantics other than `(address,uint256)` (e.g., treating the uint256 as a pointer), or disguising the library address. Multisig/proxy contracts are the most prone.
- Signature replay: off-chain signatures (`ECDSA.recover`) not bound to nonce/chainId/contract address get spent a second time elsewhere; cross-chain replay (an Ethereum mainnet signature reused on an L2) was the root cause of several 2021-2023 incidents.
- Fixes: OpenZeppelin `EIP712` (domain separator binding chainId + verifyingContract) + a unique nonce per use (a used mapping); Solidity 0.8's `abi.encodeCall` instead of hand-assembled calldata.

### 2.9 Storage collisions and delegatecall traps

- Principle: `delegatecall` executes library code in the caller's storage context — proxy/upgradeable contract storage layouts must align strictly; any misalignment means asset fields get read/written as permission fields. Mixing UUPS/transparent proxies, or forgetting to initialize library contracts, amplifies this.
- Case: Parity 2017-11 (uninitialized library + `delegatecall` into a suicide function) = 513k ETH frozen (see §2.3).
- Fixes: storage layout gaps, the OpenZeppelin Upgradeable contract series, upgrades via timelock + multisig, `initialize` with an initializer modifier.

### 2.10 Fake deposits (exchange bookkeeping layer)

- Principle: `transfer()` does not revert but returns false, and the exchange credits the deposit on event/call success; or deflationary tokens actually deliver less than face value; the false-Return attack on legacy TRON/USDT-OMNI chains. Result: no coins received but the user is credited, then the balance is drained via withdrawals.
- Fixes: bookkeeping verified by **balance-delta reconciliation**, not return values/events; dedicated deposit-address monitoring + reconciliation jobs; full onboarding test checklists for newly listed tokens.

## 3. Audit tools and methodology

### 3.1 Tool matrix

| Tool | Type | Language/stack | Highlights |
|---|---|---|---|
| Slither | Static analysis (SAT + dataflow) | Solidity | By Trail of Bits; 90+ detectors; scriptable custom analyses; fast with controllable false positives |
| Mythril | Symbolic execution + SMT | EVM bytecode | Deep-path bugs (integer/reentrancy/unprotected suicide) |
| Echidna | Property-based fuzzing | Solidity | Write invariant assertions; auto-mutation hunts counterexamples |
| Foundry (forge fuzz) | Fuzzing + unit tests | Solidity | Native fuzz in `forge test`; `invariant{}` continuously checks state invariants |
| Medusa | Parallel fuzzing | EVM | trailofbits, faster than Echidna |
| Certora SVT | Formal verification | Solidity | Rules as specifications; mathematically proves invariants |
| Manticore | Symbolic execution | EVM/WASM | Scriptable deep dives |
| Heimdall-rs / Dedaub | Decompilation | On-chain bytecode | Source-less auditing / post-mortem forensics |
| Anchors/Anchor + cargo audit | Static/lint | Solana (Rust) | Anchor's default account/permission checks are the baseline |

### 3.2 Audit methodology: the per-function checklist

Run every external/public function through this (common practice at audit firms, synthesizing Trail of Bits/SlowMist public checklists):

1. **Who can call it?** Auth modifiers, `tx.origin` misuse, anyone-triggerable?
2. **What state does it change?** CEI ordering; external calls sandwiched in between?
3. **How does money move in/out?** call/transfer for transfers? Recipient controls a callback?
4. **Parameter boundaries?** 0/extremes/overflow/precision (division truncation, 1e18 conversions)?
5. **External dependencies?** Price sources, external call targets swappable/forgeable?
6. **Upgrades and ownership?** proxy admin, timelock, multisig threshold, re-initializable?
7. **Signatures and randomness?** nonce unique? chainId bound? randomness manipulable?
8. **Events and kill switches?** Critical operations observable; who holds the pause key?
9. **Gas and DoS?** Loops + external calls, refund patterns?
10. **Composition with other contracts?** Fuzz the composite flash-loan/liquidation paths separately.

Deliverables: threat model → findings graded (Crit/High/Med/Low/Info) → PoC (Foundry reproduction) → fix recommendations → re-review.

### 3.3 Foundry PoC reproduction template (reentrancy example)

The most powerful audit deliverable is a one-command PoC reproduction; `forge test` prints the money lost directly:

```solidity
// test/Reentrancy.t.sol
// forge test --match-test test_reentrancy -vvv
contract Attacker {
    IVictim public victim;
    constructor(IVictim v) { victim = v; }
    function attack() external payable {
        victim.deposit{value: 1 ether}();
        victim.withdraw();
    }
    receive() external payable {
        if (address(victim).balance >= 1 ether) {
            victim.withdraw();               // reentrancy: balance not yet zeroed
        }
    }
}

function test_reentrancy() public {
    vm.deal(address(this), 2 ether);
    Attacker a = new Attacker(victim);
    (bool ok,) = address(a).call{value: 1 ether}(abi.encodeWithSignature("attack()"));
    assertTrue(ok);
    assertGt(address(a).balance, 1 ether);   // attacker leaves with more than they put in
    emit log_uint(address(victim).balance);  // victim contract drained
}
```

The same pattern applies to: overflow (boundary-value fuzzing), privilege escalation (calling sensitive functions as a different caller), oracles (skewing a mock price before the call). Echidna/forge `invariant` covers properties like "total assets conserved under any call sequence".

## 4. On-chain crime analysis

### 4.1 Identifying phishing / honeypots / rug pulls

- **Honeypot tokens**: buy works, sell doesn't. Techniques: 100% sell tax, owner checks inside transfer, dynamic blocklists blacklisting buyers. Detection: TokenSniffer, GoPlus honeypot detection, honeypot.is (simulated buy/sell); by hand, check the open-source contract's `_transfer` for owner-privileged branches.
- **Rug pulls**: (1) liquidity withdrawal (dev keeps LP unlocked, or unlocks after self-locking) — check Team Finance/Unicrypt lock records; (2) mint-and-dump (owner keeps mint rights); (3) gradually selling out holdings (watch holding concentration + holder-address behavior). Classic: Squid Game Token (2021-11, $3.38M).
- **Phishing sites / airdrop approval scams**: fake domains + urgency language, targeting approve/permit signatures rather than private keys; fake wallet extensions in plugin stores (MetaMask fake-extension history).

### 4.2 Mixing (Tornado Cash)

- Principle: fixed-denomination deposit/withdrawal pools; deposit notes and zero-knowledge withdrawal proofs decouple addresses, breaking on-chain linkage (100 ETH deposited by A -> 100 ETH withdrawn by B).
- Timeline: 2022-08-08 OFAC sanctioned Tornado Cash (the first sanction of a smart contract, citing >$7B laundered incl. Lazarus $455M); criminal prosecution of developers (Pertsev sentenced to 64 months in the Netherlands 2024-05-14; Roman Storm tried 2025-07, one of three counts — "conspiracy to operate an unlicensed money-transmitting business" — held); **2024-11-26 the Fifth Circuit (Van Loon v. Department of the Treasury) ruled immutable smart contracts are not "property" under IEEPA and OFAC lacks authority to sanction them — only abusers can be sanctioned**; **2025-03-21 the Treasury formally lifted the sanctions** (the Pertsev conviction stood).
- Tracing countermeasures: deposit/withdrawal timing correlation, gas sources, amount and count clustering, identical-behavior fingerprints — Chainalysis/SlowMist have both published methodologies.

### 4.3 On-chain tracing (Chainalysis class) and the stolen-funds tracking workflow

Tool lineage: Chainalysis (REACT), TRM Labs, Elliptic, SlowMist MistTrack, OKLink Chaintelligence ("on-chain eye"), Arkham/Dune/Nansen (labels + visualization), the Etherscan label library.

**Standard stolen-funds tracking workflow** (general for SRC / incident response):

1. **Freeze the evidence**: transaction hashes, block heights, timestamps, victim address, attacker contract address and its creation transaction; snapshot archives (browser archives + node RPC exports).
2. **Attribute the attacker**: the signer of the transaction that created the attack contract (usually a throwaway address), upstream addresses funding the gas, historical addresses with identical bytecode / identical nonce patterns (tools: `findmyfather`-class utilities, SlowMist automated profiling).
3. **Follow the funds**: multi-hop peeling → aggregation addresses → classify the exits (exchanges/mixers/cross-chain/cash-out). Exchange deposits = freezable points: immediately send an assistance request (Binance/OKX/Bitget etc. all have security mailboxes) + file a police report in parallel.
4. **Peel cross-chain and mixing**: Bridger/stargate hopping to Tron/BSC → hand off to that chain's eye; Tornado → heuristics like timing clustering (success not guaranteed; output probabilistic links).
5. **Freeze and recover**: stablecoin-issuer blocklists (Tether/Circle on-chain blacklists directly freeze USDT/USDC — the Ronin aftermath, multiple live uses in 2022); exchanges freezing inbound funds; judicial seizure and restitution procedures.
6. **Post-mortem report**: timeline + fund-flow diagram + root cause (contract/private key/frontend/social engineering).

## 5. Exchange and wallet security

### 5.1 Hot-wallet management and the Bybit review

- Standard architecture: cold wallets (offline / HSM signing), warm wallets (multisig + limits), hot wallets (small amounts for fast payout + auto-sweep); what matters is the **signer terminal** and **frontend integrity**.
- **Bybit (2025-02-21, $1.46B ~= 400k ETH, the largest ever; Chainalysis/THF attribute Lazarus; with ETH fluctuation and Chainalysis's reporting basis it is $1.5B — §8's timeline uses $1.5B throughout)**: the attack surface was not Bybit's code but the Safe{Wallet} frontend supply chain — the attackers compromised Safe's AWS/JS distribution layer, and the signer's browser ran a tampered UI: the screen showed a normal transfer while what was actually signed was malicious calldata rewriting the owners (blind signing). Funds were dispersed via instant swaps, cross-chain transfers, and P2P; most were never recovered.
- Lessons: (1) the signing terminal must be treated as a high-value target (supply chain/browser extensions/clipboard); (2) the multisig flow must verify **the bytes being signed**, not the UI rendering (HSM/air-gapped devices decode and display raw calldata); (3) frontend SRI/subresource integrity + hardened release pipelines.

### 5.2 Signature phishing (permit / increaseAllowance / blind signing)

- See §2.6; wallet-side evolution: transaction simulation (Tenderly/Blockaid class) pre-playing asset changes, semantic prompts like "this signature grants X full allowance"; permit-domain parsing and display for `eth_signTypedData_v4`.
- Enterprise side: large operations go through allowlisted addresses + delayed effect; separation of treasury and signing.

### 5.3 Fake wallet apps

- Shapes: SEO-hijacked lookalikes of the official imToken/TokenPocket/MetaMask sites, app-store clones, "fixed versions" sent through support channels; **entering the seed phrase hands over the assets** (the app beacons the seed to the attacker's server).
- Other variants: clipboard hijacking (replacing the recipient address on copy, abusing Android accessibility permissions), malicious browser extensions stealing private keys, fake support remotely guiding "asset verification".
- Forensic essentials: the fake app's exfiltration domain, signing certificate, and distribution channel often chain together a whole black-market crew.

## 6. Cross-chain bridge vulnerabilities (Wormhole / Ronin / Nomad reviews)

Bridges lock up enormous assets and "verifying message validity" is implemented in every which way — the category with the largest per-incident losses (bridge entries perennially top rekt.news).

| Case | Time | Loss | Root cause in one line |
|---|---|---|---|
| Poly Network | 2021-08 | $611M | keeper role key leak; the attacker could self-sign cross-chain messages (white hat returned funds) |
| Wormhole | 2022-02 | ~$324M | The Solana side called a deprecated `solana_core` bridge verification function; `signature_set` unverified; forged guardian signatures minted wETH |
| Ronin | 2022-03 | $624M | Lazarus social-engineered 4 of 5 validator keys (the 9/5 multisig was moot); **the theft went unnoticed for half a year** (exposed only when user withdrawals failed) |
| Harmony Horizon | 2022-06 | $100M | 2/5 multisig key leak — the threshold was moot |
| Nomad | 2022-08 | $190M | Initialization set the trusted root to zero; anyone could copy another's valid message and withdraw ("robbing the bank without picking the lock — just follow the person ahead") |
| Multichain | 2023-07 | $126M | Centralized keys (CEO sole control) lost control |

Shared lessons: (1) multisig key-set management (thresholds, geographic spread, endpoint security) decides a bridge's life or death; (2) message verification logic should **use mature libraries, never hand-rolled**; (3) heartbeat/reconciliation monitoring — Ronin was discovered only after half a year without reconciliation; (4) limits and circuit-breaker caps.

## 7. Interface with SRC/law enforcement: forensics essentials for crypto cases

### 7.1 Case types (China context)

- Property crimes: theft (private key/seed phrase stealing, internal transfers), fraud (honeypots, fake apps, romance pig-butchering with crypto).
- Money-laundering crimes: concealing criminal proceeds, assisting information-network crime (money muling via USDT-TRC20), illegal business (OTC forex/crypto exchange).
- Organizational crimes: pyramid schemes (tiered-commission tokens), illegal fundraising ICOs (the 9.24 Notice classifies virtual-currency-related business as illegal financial activity).
- Technical crimes: the boundary where DApp exploit "wool-pulling" gets charged as theft/fraud (amount + means).

### 7.2 Forensics essentials checklist

1. **On-chain data fixation**: hashes, blocks, raw calldata, event logs; export raw bytes via `getTransactionByHash`; third-party explorer screenshots must be cross-fixed with node data.
2. **Address profiling**: transaction-graph clustering (common-input heuristic, change addresses, behavioral fingerprints), label libraries (exchanges/mixers/black-market), correlation with addresses from known cases.
3. **Landing on a person**: exchange legal requests (deposit address -> KYC -> IP/device), fiat in/out channels (bank cards/third-party payment), wallet app local forensics (keystore/plaintext seed, clipboard, browser-extension data).
4. **Price determination**: price at incident time (exchange K-lines/indices); the disputed points — which time point, which market; disposal of involved tokens (compliant procedures for third-party commissioned sale).
5. **Where the proceeds went**: mixing-peel analysis reports (probabilistic links must state methodology and confidence, for prosecutorial/judicial review).
6. **Tools**: domestic on-chain-eye products (OKLink/SlowMist MistTrack both have law-enforcement editions), Chainalysis, Etherscan API + self-built ETL (Dune replay).

### 7.3 The blockchain surface from the SRC perspective

- Exchange/wallet-vendor SRCs: replay bugs, fake deposits (deposit-address ownership validation), API broken access control (viewing others' orders/identity), withdrawal risk-control bypass — direct migration of traditional web surfaces.
- DApp frontend XSS/supply chain → swapping contract addresses/clipboard; harm reaches assets directly, higher priority than ordinary XSS.
- Test environments: reproduce locally with anvil/hardhat forking mainnet; live attacks against mainnet are strictly forbidden (legal red line).

## 8. Master case timeline (quick reference)

| Time | Event | Loss | Root-cause class |
|---|---|---|---|
| 2016-06 | The DAO | ~$60M | Reentrancy |
| 2017-07/11 | Parity multisig | $31M + 513k ETH frozen | Access control/selfdestruct |
| 2018-04 | BEC MeiChain | Went to zero | Integer overflow |
| 2020-02 | bZx | ~$1M | Flash loan |
| 2021-08 | Poly Network | $611M | Multisig private keys |
| 2021-11 | Squid Token | $3.4M | Rug pull |
| 2022-02 | Wormhole | $324M | Bridge message verification |
| 2022-03 | Ronin | $624M | Multisig private keys (Lazarus) |
| 2022-04 | Beanstalk | $182M | Flash loan + governance |
| 2022-06 | Harmony | $100M | Multisig private keys |
| 2022-08 | Nomad | $190M | Initialization error |
| 2022-10 | Mango | $114M | Oracle manipulation |
| 2023-03 | Euler | $197M (returned) | Flash loan + liquidation logic |
| 2023-07 | Curve/Vyper | ~$70M | Compiler reentrancy-lock failure |
| 2023-07 | Multichain | $126M | Centralized private keys |
| 2024-07 | WazirX | ~$234.9M | Multisig blind signing: Liminal custody held the signing key while the signing UI mismatched the actual transaction payload (UI manipulation); attributed to Lazarus/North Korea; WazirX blamed Liminal's infrastructure (disputed), triggering a Singapore court restructuring |
| 2024-10 | Radiant | $53M | Signer-terminal compromise |
| 2025-02 | **Bybit** | **$1.5B (largest ever)** | Safe frontend supply chain + blind signing (Lazarus) |
| 2025-05 | Cetus | $223M | Integer overflow (Sui) |

## 9. Further reading

- Chainalysis Crypto Crime Report (2024: $2.2B for the year, North Korea 61%; 2025 H1 $2.17B / Bybit $1.5B)
- rekt.news (loss leaderboard and post-mortems), the SlowMist Hacked database (MistTrack)
- MEV: the Flash Boys 2.0 paper (Daian et al. 2019); Trail of Bits audit methodology (slither)
- Case details defer to official post-mortems: Wormhole's official postmortem, Ronin's official announcements, Bybit's CEO public statements
