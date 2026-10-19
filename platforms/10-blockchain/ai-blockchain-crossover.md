# AI x Blockchain Crossover Security

> Positioning: the crossover piece between `09-ai-security` and `10-blockchain`.

## 1. Why this crossover surface exists

From H2 2024, "on-chain AI Agents" became the crypto industry's new narrative: AI Agents holding wallets, autonomously issuing tokens/trading/tipping. Representative systems (a16z eliza, Virtuals Protocol's GAME, ARC, etc.) graft **every known LLM flaw** (prompt injection, tool abuse, excessive agency) directly onto **wallets that can move money**. Security-wise this is equivalent to: an entity manipulable by injection from arbitrary web content, holding irreversible transfer authority.

```
[On-chain Agent attack-surface stacking diagram, self-drawn]
┌────────────── LLM layer (inherits everything from chapter 09) ──────────────┐
│  Prompt injection / jailbreak / memory poisoning / tool poisoning          │
└───────────────────────┬───────────────────────────┘
                        │ Agent framework (eliza/GAME)
┌───────────────────────▼───────────────────────────┐
│  Agent layer: reading tweets on Twitter/Telegram = indirect-injection entry │
│  MCP/plugin tools, sandbox, memory store                                     │
└───────────────────────┬───────────────────────────┘
┌───────────────────────▼───────────────────────────┐
│  Chain layer (inherits everything from chapter 10): private-key custody,     │
│  approve permissions, MEV, contract bugs, rug pulls                          │
└─────────────────────────────────────────────────────┘
A breach at any layer reaches funds directly; injection cost << contract-bug cost
```

## 2. Incidents that already happened

### 2.1 Freysa: prompt injection wins the prize pool (2024-11)

- Freysa.ai is an adversarial game: the AI Agent Freysa guards a prize pool; the rule is "whoever persuades it to transfer out the pool wins all the funds", and each attempt costs a fee that feeds the pool. After many failed participants, someone succeeded with a single message — **essentially a prompt injection against the guardian prompt**: framing the model into an "the next transfer is already approved" context, until the Agent finally called the transfer function; the ~$47k pool was won (partly donated / partly to the winner).
- Significance: the first "publicly live, real money, the bounty IS the bug bounty" live-fire prompt-injection case — turning the laboratory risk of chapter 09 §2.1 into on-chain monetary loss.
- Later rounds iterated defenses and the community kept gaming it (winning approaches = exploiting its instruction/tool-call approval framing; per-round defense differences across versions have seen no systematic public review — defer to on-chain transactions).

### 2.2 Truth Terminal and GOAT (2024-10)

- A semi-autonomous AI Agent plugged into crypto culture (Truth Terminal) received a BTC tip after interacting with a16z founder Marc Andreessen; the associated memecoin GOAT then exploded in market cap, becoming the origin of the "AI Agent millionaire" narrative.
- Security perspective: (1) the Agent's "beliefs/recommendations" can be influenced by **social engineering and token-holding incentives** — on-chain AI shills have no information-disclosure boundary; (2) the community immediately spawned fake Agents issuing tokens to harvest (GOAT/Fartcoin were not issued by the Agent itself but sniped by anonymous third parties; copycats appeared in bulk on Solana/Pump.fun; pump-and-dump/rug became routine; landmark price event: 2024-10-25, tokens it endorsed fell double digits).
- This kind of event turns "Agent reputation" itself into an attack asset: phish a lookalike Agent account → lure victims into buying copycat tokens.

### 2.3 Agent-issued tokens = a natural rug surface

- When an AI Agent issues a token (owner = Agent wallet), LP locking, mint rights, and tax logic all depend on the deployer's good faith; "the Agent autonomously deciding to dump/pull liquidity" has zero constraint in code (individual case: ai16z, issued 2024-10, peak market cap ~$2.4B, renamed ELIZAOS in 2025-01 over a16z trademark concerns, declared dead by its founder in 2025-12 with the token going effectively to zero; surface-level stat: ~$6B in 2025 rug-pull losses, 92% of which was the single Mantra case; academic side: code-level analysis of 2024 rug cases ~$85.4M in losses).
- Reuses the honeypot detection from chapter 10 §4.1: GoPlus/honeypot detection applies equally to AI-issued tokens.

## 3. Oracle trust: two new problems in the AI era

1. **AI-source oracles**: feeding LLM/Agent output as oracle data (e.g., an "AI sentiment index" settling on-chain) — LLM hallucination and prompt injection turn directly into **on-chain price manipulation**; the design must run multi-source consensus + deviation circuit breakers over AI output, treating it as an untrusted signal.
2. **The poisoning surface of oracle DONs themselves**: Chainlink-class decentralized oracle networks assume node data sources are independent; **publicly documented oracle-manipulation losses concentrate in low-liquidity DEX feeds and single-source dependency** (41 incidents, $403.2M in 2022; in 2024 the Venus protocol had LST collateral twisted via a low-liquidity Curve pool into ~$110M of bad debt). No confirmed case of "Chainlink DON node data sources being co-opted in unison" was found — remain pending; AI-scraping nodes (news/Twitter sentiment) inheriting the full multimodal-injection risk does hold.

## 4. zkML / on-chain verified inference

- Direction: use zero-knowledge proofs to verify on-chain that "this model, on that input, really did produce this output" (toolchains like EZKL, Giza, Modulus Labs), to settle AI decisions on-chain (e.g., AI-driven strategy vaults).
- Security essentials: (1) what is proven is **correct execution**, not **a correct model** — an injected model output can still be "correctly proven"; (2) circuit bugs/quantization error are the new audit objects; (3) model weights on-chain = public (the supply-chain pickle risk equally exists in the circuit-generation stage).
- Status: research/prototype stage, no major fund incidents yet (as of 2026-10).

## 5. Defense and engineering advice (specific to the crossover)

1. **Agent wallet limits**: on-chain Agents should always use "limited + time-delayed + revocable" wallets (like Safe's modular permissions/spending limit), per-transaction and daily caps, human-reviewed multisig for large amounts — the on-chain landing of chapter 09 §6.4's permission minimization.
2. **Treat social input as untrusted data streams**: the pipeline where Agents read tweets/Telegram must filter injections (see chapter 09 §6.2 guardrails), never mixing with the instruction context.
3. **Token-pick disclosure and conflicts of interest**: any recommendation content from a token-holding Agent must carry an on-chain verifiable position statement (community norm, no mandatory standard yet).
4. **AI-issued tokens go through standard audits**: AI-deployed token contracts meet the same bar as human-written ones — the full Slither/Echidna suite + LP-lock verification (chapter 10 §3).
5. **On-chain Agent forensics**: keep traces of who custodies the Agent's private keys and where each signed transaction originated (which model version / which prompt triggered it) — after an incident you can attribute the "injection source" rather than seeing just one transfer.

## 6. Further reading

- Foundation chapters: [../09-ai-security/ai-security.md](../09-ai-security/ai-security.md) (injection and MCP), [blockchain-security.md](blockchain-security.md) (contracts and forensics)
- Continuous tracking: the rekt.news "AI" tag, SlowMist Hacked, arXiv cs.CR under the agent-security keywords
