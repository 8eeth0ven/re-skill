# Business Security Knowledge System (tree node 1001236)

> Division of labor: this machine already holds two canonical references on business security — `~/.zcode/skills/skill/知识库/cn-business-security.md` (Wooyun's ten-category taxonomy + China-specific scenarios) and `~/.zcode/skills/skill/知识库/race-condition-test.md` (race/logic actions) plus `~/.zcode/skills/skill/知识库/h1-高危害专项-业务逻辑与竞态资损.md` (international-platform perspective). This document acts as the **system-level overview**: it chains them into a complete map from the knowledge-base perspective, fills in the four blank areas — black/gray industry, risk control, data compliance, and the SRC ecosystem — and does not re-copy testing details.
> The business security node [1000973] in the WEB security tree covers the same topic and is absorbed into this document.

---

## 1. Business Logic Vulnerability System (overview)

> Business security = guaranteeing that business processes run by their intended rules. First lay out the business flow diagram, mark the differences between normal and abnormal user paths, and locate the attacker's profit points — this is the meta-method behind all logic vulnerability hunting.

### 1.1 Category quick reference (one line each; details live in the cross-linked canonical docs)

| Subcategory | High-frequency scenarios | Cross-links |
|------|---------|------|
| Broken access control (horizontal/vertical/IDOR) | Object IDs queried directly without owner checks; missing endpoint authorization | `~/.zcode/skills/skill/知识库/idor-test.md` + `~/.zcode/skills/skill/知识库/idor-supplement.md`; escalate to ATO → `~/.zcode/skills/skill/知识库/h1-高危害专项-IDOR升ATO.md` |
| Payments / monetary loss | Amount tampering, negative quantities, stacking discounts, refund abuse | This doc §3 + `race-condition-test.md business-logic chapter` |
| CAPTCHA | SMS bombing, universal codes / echo in response body, CAPTCHA reuse/bypass | "CAPTCHA" chapter of the ten categories in `~/.zcode/skills/skill/知识库/cn-business-security.md` + `~/.zcode/skills/skill/知识库/authbypass-test.md` |
| Password recovery | Predictable credentials, Host header poisoning, enumerable reset links | `cn-business-security.md recovery-flow taxonomy` |
| Race conditions | Concurrent coupon claiming, concurrent balance spending, vote manipulation | `~/.zcode/skills/skill/知识库/race-condition-test.md` + `~/.zcode/skills/skill/知识库/h1-高危害专项-业务逻辑与竞态资损.md` |
| Authentication / session | Session fixation, cookie spoofing, weak client-side crypto | `~/.zcode/skills/skill/知识库/authbypass-test.md`, `~/.zcode/skills/skill/知识库/oauth-jwt-test.md` |
| Out-of-order flows | Step-skipping (shipping before payment), state machine rollback | Ten categories in `~/.zcode/skills/skill/知识库/cn-business-security.md` |
| Endpoint replay | Payment callback replay, missing signatures | `~/.zcode/skills/api-pentest/知识库/fuzz与业务逻辑.md` |

### 1.2 Granular decomposition (Wooyun methodology)

Take the interface documentation (if unavailable, hand-decompose with an xmind) and break the business functions out one by one; for each function list "possible risk × detection time cost". While decomposing 100+ functional modules, overlooked holes surface naturally. Detect anomalies by contrasting user flows: normal is "register → login → query → place order → pay → receive goods"; a flow of "register → login → claim coupon" that then stops is anomalous (log dimensions: URL depth / access dispersion / 200-response ratio). Full version → Section 1 of `~/.zcode/skills/skill/知识库/cn-business-security.md`.

### 1.3 Chain composition perspective

A single logic flaw is usually medium severity; chaining can substantially increase its impact (read via broken access control → modify → transfer/takeover). Entry table → `~/.zcode/skills/skill/知识库/h1-组合攻击链短表.md` (check it first, top priority).

## 2. Account Security

### 2.1 Attack surface checklist

- **Credential stuffing**: leaked-credential databases + proxy pools + automated login; telltale signs = login without rate limiting / without device fingerprinting / error messages that reveal whether the user exists.
- **Bulk registration (account farming)**: SMS-receiving platforms (SIM merchants / SIM banks / MVNO number ranges) + CAPTCHA-solving services (AI solvers have replaced humans) to bypass CAPTCHA and mass-produce promo-abuse accounts; SMS-receiving platforms exposed as APIs (billed per code) are black-market infrastructure.
- **Account enumeration**: login/recovery endpoints answering differently to "user does not exist" vs "wrong password", registration endpoints echoing that an identifier is taken — attackers can map the valid-account surface before any database dump.
- **SMS/phone bombing**: endpoint without rate limiting, or a swappable uid parameter to bomb someone else's phone; frequent but low-severity in SRC programs — any claim about scale must pass the quantitative gate of `~/.zcode/skills/skill/知识库/闸门矩阵方法论.md` (local machine rule).
- **Account takeover combos**: re-binding phone/email without verifying the old credential, re-registering deleted accounts to take them over → belongs to `~/.zcode/skills/skill/知识库/h1-高危害专项-认证绕过与ATO.md`.

### 2.2 Defense design (attack/defense pairs; usable in both audit and blue-team directions)

| Attack | Defense | Common defensive flaws |
|------|------|-------------|
| Credential stuffing | Login rate limiting over three dimensions (account + IP + device) + slider-CAPTCHA escalation | Rate limiting by IP only (proxy pools break it instantly) |
| Bulk registration | Registration behavior scoring + device fingerprinting + SMS-platform number-range detection | Number-range databases lag behind |
| Enumeration | Uniform error copy; rate-limited registration + vague hints | Recovery endpoint left unfixed |
| Bombing | Per-number send interval + daily caps per IP/device + graphical CAPTCHA up front | Only the uid is limited, not the phone-number parameter |
| Takeover | Verify the old credential on rebind + step-up auth for sensitive actions | Inconsistent policies between rebind and unbind endpoints |

## 3. Payment Security

### 3.1 Defect pattern table

| # | Pattern | Variants | Truth criteria |
|---|------|------|---------|
| 1 | Client-controlled amount | price/amount/discount passed straight through; negative-amount top-ups; zero-cost purchases | Real if the order's actual settled price changes after tampering |
| 2 | Quantity/precision | Negative quantities, fractional stock, integer overflow, precision loss on huge numbers (backend language differences) | Order total deviates from expectation |
| 3 | Forged payment callback | Missing/weak signature verification (md5 concatenation), amount not bound to the order, async-notification replay | Whether a locally forged callback can flip the order to paid |
| 4 | Promotion abuse | Coupons claimed concurrently beyond limits, stacked threshold discounts mis-computed, self-referral rebate loops | Total credited after N repeated requests |
| 5 | Race-condition loss | Concurrent balance spending, concurrent withdrawals, flash-sale overselling | Double spend under concurrent bursts; details → `~/.zcode/skills/skill/知识库/race-condition-test.md` |
| 6 | Refund abuse | Refund-to-original-channel + rebound payout account, refund amount unchecked against the original order, duplicate refunds | Identity consistency along the refund chain |
| 7 | Order skipping | Calling shipping/pickup endpoints directly without paying (state machine out of order) | Order state replay |

### 3.2 Audit/testing entry points

- Traffic side: run the entire payment flow through Burp, mark every parameter feeding into "amount/quantity/discount/status", then apply a tampering matrix per parameter (negative / zero / decimal / huge / string).
- White-box side: search for payment gateway call sites; verify that the signing side and the verification side are symmetric, and whether the amount originates from the server-side order or from request parameters.
- Closed money-loop view (risk control): in the full deposit → spend → withdraw loop, any link that creates balance out of thin air is high severity; grade the report by "the path that causes actual monetary loss".

## 4. CAPTCHA and Credential Systems

- CAPTCHA types: graphical (broken by solvers), SMS (SMS-receiving platforms / bombing), slider-behavior (trajectory simulation), semantic (weak).
- Defect patterns: the code echoed in the CAPTCHA response body (code in response), one verification reused across multiple places, verification done on the client, deleting the CAPTCHA parameter to skip validation (empty/0 `after`), predictable timestamps (SMS token).
- Token/key systems: JWT weak keys / none algorithm → `~/.zcode/skills/skill/知识库/oauth-jwt-test.md`; encrypted-endpoint relay (breaking app API signatures) → `cn-business-security.md encrypted interface relay`.

## 5. Data Security (compliance / masking)

### 5.1 Data classification and grading (grade before auditing)

| Level | Examples | Leak consequences |
|------|----|---------|
| Core business data | Transaction records, pricing strategy | Monetary loss / competitive advantage |
| Sensitive personal information | ID number / bank card / biometrics / whereabouts | Heavy PIPL penalties + criminal liability |
| Personal information | Phone / email / address | Regulatory penalties |
| Business configuration | Internal endpoints / keys / topology | Attack footholds |

### 5.2 Regulatory baseline (China)

The Cybersecurity Law, Data Security Law, and Personal Information Protection Law (PIPL) plus MLPS 2.0; abroad GDPR/CCPA. Core obligations: minimal-necessary collection, informed consent, classification and grading, outbound-transfer assessment (Measures for Security Assessment of Data Export); violations escalate under "serious circumstances" to criminal liability (crime of infringing citizens' personal information).

### 5.3 Masking and encryption techniques

- **Masking**: static (SDM blocking production data from entering test databases), dynamic (mask at query time, e.g. `138****5678`), format-preserving encryption (FPE), tokenization (the PCI-DSS standard: card numbers swapped for tokens).
- **Storage**: passwords must use slow hashes (bcrypt/scrypt/argon2; never md5 with a fixed salt), field-level encryption (AES-GCM), key/data separation (KMS).
- **Transport**: site-wide TLS + HSTS; mTLS between internal services.

### 5.4 Common data vulnerabilities in SRC

- Endpoints returning ID numbers/phone numbers as full plaintext without masking (combined with broken access control = bulk extraction of personal information; high severity and legally actionable) → the object-graph batch playbook in `~/.zcode/skills/skill/知识库/idor-test.md`.
- Sensitive fields printed into logs, export endpoints without access control, GraphQL deep queries for bulk pulls (→ `~/.zcode/skills/skill/知识库/graphql-test.md`), search autocomplete echoing other users' data.
- Key surface: hardcoded AK/SK (white-box grep), configuration committed to git (→ `~/.zcode/skills/skill/知识库/insecure-scm-test.md`), public object-storage buckets.
- Reports involving personal information must cite compliance clauses for grading → `~/.zcode/rules/vuln-report-format.md` (local machine rule).

## 6. Risk-Control Adversarial Operations (cross-linked with the techniques library)

```
Risk signal layer: device fingerprint (hardware/sensor/system-parameter hashes) + behavior (trajectory/input rhythm)
+ environment (proxy/emulator/Root)
     ▲ adversarial                                                     │
Black-market tools: device spoofers (one-tap new device / parameter     ▼
randomization), device farms, cloud phones, fingerprint browsers
(multi-profile isolation), SMS-receiving/CAPTCHA solving, IP pools
(residential proxies)                                  Risk decisions: blocklists/rules/model scores/challenges (slider/SMS)
```

- **Device fingerprint**: app-side collection (Android ID/IMEI/sensors/system properties) and adversarial countermeasures (spoofing, hiding, consistency detection) → deep-dive canonical doc `../../techniques/04-evasion/device-fingerprint-risk.md`; full detection principles → `../../techniques/04-evasion/detection-landscape.md` in the same directory.
- **Behavioral adversarial operations**: request speed/frequency features are the black market's most exposed surface; device farms flatten per-device differences yet leave aggregate signatures (same device cluster).
- **Challenge escalation ladder**: funnel design of rules → model → challenge (invisible → slider → SMS); on the black-market side, real-device farms counter invisible challenges.
- Only by merging the detector's view with the detected side's view is the picture complete: when the offensive side must pass risk control (registration/login/marketing endpoints), read the adversarial chapters of the techniques library first, instead of looking only from the web layer.

## 7. SRC and Crowdtesting Ecosystem

### 7.1 Platform landscape

- Company-run SRCs (TSRC/ASRC/BSRC style), public-interest SRCs (backed by CNVD/CNNVD), commercial crowdtesting platforms (Butian / Vulbox style), international bounties (HackerOne/Bugcrowd).
- Process: register → hunt (within authorized scope) → report → triage and grading → fix → score/rank → reward (cash/points/credit); duplicate-report merge rules.
- White-hat boundaries: the authorization letter and the test scope are your lifeline (unauthorized testing is a crime, Criminal Law Articles 285/286); data never lands on disk, is never retained, and is wiped right after testing; disclosure deadlines follow the platform agreement.

### 7.2 Grading mindset (how to write business vulnerabilities up as high)

| Element | Explanation |
|------|------|
| Harm substance | Monetary-loss scale? Data sensitivity? Takeover scope? |
| Exploitability | Preconditions required (accounts / interaction / internal parameters)? |
| Impact scope | Single user / all users / a specific high-value population |
| Chain escalation | Single medium flaw → chained into ATO/RCE/bulk database dumps → high (`~/.zcode/skills/skill/知识库/h1-组合攻击链短表.md`) |
| Quantitative closure | Scale claims like "batchable/unlimited" must carry a hard numeric floor (local gate-matrix rule) |

Official format → `~/.zcode/rules/vuln-report-format.md`. Vulnerability distribution and cases in the China business context → the entirety of `~/.zcode/skills/skill/知识库/cn-business-security.md` (distilled from 1,269 Wooyun write-ups).

## 8. Black/Gray Industry Adversarial Chain Map

```
Upstream (infrastructure)     Midstream (operations)         Downstream (monetization)
┌──────────────────┐      ┌───────────────────┐      ┌───────────────────┐
│ Goods: leaked-cred DBs/  │      │ Promo abuse/rebate       │      │ Money laundering:      │
│ accounts                │      │ self-referral loops      │      │ money-mule platforms   │
│ SMS platforms (SIM      │ ──▶ │ Credential stuffing/     │ ──▶ │ USDT/virtual cards     │
│ merchants)              │      │ account theft/scam       │      │ e-commerce cash-out/   │
│ CAPTCHA solving/proxy    │      │ traffic                  │      │ fenced goods           │
│ IP pools                 │      │ Gambling/porn-redirect/  │      │ Ad fraud (clicks)      │
│ Tools: device spoofers/  │      │ scam sites               │      │ Data resale            │
│ farms/cloud phones/      │      │ Astroturfing/opinion     │      │                        │
│ fingerprint browsers     │      │ manipulation/DDoS        │      │                        │
└──────────────────┘      └───────────────────┘      └───────────────────┘
  Countermeasures: real-name phone registration & one-ID-many-SIMs governance, payment
  direct-connect bans, app filing, AI risk control, targeted crackdown campaigns
```

- **Governance-side measures**: the "Card Breaking" operation (against SIM merchants), real-name registration plus onboarding identity verification, payment limits and direct-connect bans (funds), cloud-vendor content security (gambling sites), targeted crackdowns (MPS "Clean Net" campaigns).
- **Offense/defense research value**: once you can recognize the industry chain's division of labor, you can predict in SRC work "would the black market actually use this hole" → which directly decides the report's harm grading (e.g., a bulk-registration surface = account-farming infrastructure = high severity).
- **Promo-abuse crews / human cheaters** differ from automated cheating: human crowdsourcing (task-assignment platforms) is the hardest to stop with device fingerprints; it takes closed money-loop and behavioral-cluster detection.

## 9. Representative corpus content and cross-links

- Dedicated business-security posts are scarce in the community (the tree having zero entries in this category proves it); the valuable content concentrates on **app-side adversarial work** (a Beike app pentest write-up: a JSBridge auth bypass that is really a business-surface flaw) and risk control (tree node 1001669, risk-control adversarial section).
- WEB security overview → [../05-web/web-security.md](../05-web/web-security.md)
- White-box logic vulnerability hunting → [../05-web/code-audit.md](../05-web/code-audit.md) §7
- App side → `techniques/04-evasion/` (device fingerprinting / traffic interception / Root hiding)
- All logic/race testing details → `~/.zcode/skills/skill/知识库/` (idor-test / race-condition-test / authbypass-test / cn-business-security / h1-组合攻击链短表)
