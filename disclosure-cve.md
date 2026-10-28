# Vulnerability Disclosure & CVE Application (A Hands-on Manual from Finding to ID)

> Positioning: **the full ID-acquisition flow** — after finding a bug, whom to report to, how, how long until you get an ID, and what to do if rejected. How to find bugs (root cause/exploitation) is not this document's job → `platforms/11-root-cause/`, `techniques/`; the Chinese SRC report format → the global rules `vuln-report-format`.
> Currency: the source document records **online verification in 2026-10**; this editorial revision has not reverified external services, CNA membership, counts, redirects, or response-time promises. Recheck the official channel before preparing a submission. **Historical snapshot, not a guarantee of current behavior.** The CVE ecosystem went through a funding crisis and governance restructuring from 2025-04 (§1.2); treat each channel's official page as authoritative for timelines; old claims marked [Outdated] are background only — don't follow them.

---

## 0. The Big Picture: Three Paths from a Vulnerability to an ID

```
                    You found a vulnerability (reproducible evidence in hand)
                              │
              ┌───────────────┼─────────────────┐
              ▼               ▼                 ▼
      Path A: vendor/CNA    Path B: GitHub SA    Path C: fallback
      (target has a CNA     (open-source, incl.  (no CNA / vendor MIA /
       or official                             vendor declines)
       PSIRT/SRC)           third-party
                             reporting)
              │               │                 │
     Official-channel       Draft → Request CVE   cve.org contact form
     submission             → ID within 72h      → MITRE CNA-LR
     (portal/email/form)    → publish            processing
              │               │                 │
              ▼               ▼                 ▼
     Vendor fixes +          GHSA + CVE dual ID  CVE ID (longest wait,
     assigns the ID          (fastest            days~weeks)
     (timeline set by        open-source path)
     the vendor)
              └───────────────┴─────────────────┘
                              ▼
      After publication: sync to CNVD/CNNVD (domestic recognition, optional)
```

The three paths are not mutually exclusive: report to the vendor first (get the fix); if the vendor won't take it, use the fallback; open source can run dual channels (GitHub SA for the ID + notify the vendor). **One independently fixable vulnerability should have exactly one CVE** (CNA Rules: one root cause spanning multiple products must not be split into multiple IDs).

---

## 1. Where CVE IDs Come From (State of 2026)

### 1.1 The CNA System: Whose Bug Goes to Whom

The CVE Program's current number-allocation structure (verified 2026-10):

| Role | Function | 2026 status |
|------|------|-----------|
| TL-Root (Top-Level Root) | Top-level roots: CISA (US) and MITRE (secretariat) each manage one tree | Structure unchanged since 2025-04 |
| Root | Intermediate roots (e.g. GitHub, Red Hat, Japan's JPCERT managing subordinate CNAs) | — |
| CNA (CVE Numbering Authority) | Issues IDs for vulnerabilities **within its own scope**: vendors for their own products, open-source projects for their own repos | **500~550+** (2026-04 said 500+; year-end official count 550+); ~96,000 CVEs expected in 2026 |
| CNA-LR (CNA of Last Resort) | Fallback: bugs nobody owns go to MITRE CNA-LR | Form flow in §1.3 |

**To find who owns your target — use only the official list**: `https://www.cve.org/PartnerInformation/ListofPartners` (filterable by name/country/Root). Third-party aggregators like cvedetails are **not authoritative**: whether a vendor is a CNA and where its scope ends is defined by the Scope text on the official partner page. No CNA found ≠ no ID obtainable — go to CNA-LR.

Quick common sense (before requesting an ID, think "do they issue their own numbers"):
- **Microsoft, Google, Apple, Adobe, Oracle, Cisco, the Linux kernel (kernel.org), GitHub, Apache, Python/PSF, Red Hat/SUSE/Canonical, the major clouds** are all CNAs — for these targets, **do not** ask CNA-LR for an ID; report to the vendor directly and let them issue it.
- Domestic China: **Huawei, Alibaba, ByteDance, Tencent, Qihoo 360, QiAnXin, WeBank, Sangfor, CNCERT/CNVD** etc. are already CNAs; report vulnerabilities in their own products to their PSIRT/SRC to get a CVE.

### 1.2 [Major 2025-2026 Changes] The Governance Crisis and the CVE Foundation

This section is the underlying logic of the 2026 process — read it:

- **2025-04**: MITRE's CVE operations contract with CISA briefly expired without renewal (a first in 25 years), shaking the community; CISA extended it 11 months; on 2025-04-16 the CVE Board announced the independent non-profit **CVE Foundation** to take over long-term governance.
- **2026 status**: the CVE Foundation is operating as an entity; data/numbering services (cve.org, the CVE Services API) were never interrupted; the effect on submitters at the **operational level is nil** — channels, forms, and CNA duties are unchanged. But MITRE's secretariat role is in transition; don't be surprised by page redirects or old/new forms coexisting (see §1.3).
- In the same period NIST has been shrinking NVD's enrichment role, and CISA proposed a "quality first" framework in 2026-09 — **IDs are multiplying while review tightens**: low-quality reports (no reproduction, no impact scope) are more likely to be bounced by CNAs in 2026.

[Outdated] "MITRE exclusively issues CVEs" / "email cve@mitre.org to request an ID" — pre-2020 talk, long retired; CVE IDs were never allocated via that mailbox.

### 1.3 Official MITRE/CVE Program Application (the Fallback When There Is No CNA)

**Current entry (verified 2026)**: `https://cveform.mitre.org/` now 302-redirects to the new **"Contacting the CVE Program"** page (mitre.github.io/mitre-cve-roles); the legacy cveform is being retired. The new page is a categorized web form:

| Form type | Use |
|---------|------|
| CVE ID Requests | Request an ID from MITRE CNA-LR (open to suppliers and finders alike) |
| CVE Record Updates | Update an existing record |
| General Support | General questions (formerly "Other", routed by the secretariat) |
| Report a Reserved But Public (RBP) | **_Reporting a reserved ID that is already publicly referenced while its record is empty_** (use when someone squats an ID without filling it) |
| Domain Verification / CNA Registration | For organizations: verify a DNS domain into CVE Services, or apply to become a CNA |

Process and expectations:
1. Form submitted → an auto-acknowledgment email with a tracking number (**write it down** — all follow-ups and nudges depend on it).
2. CNA-LR verification: is the bug real, is there truly no CNA to own it, is it a duplicate of something already public.
3. Pass → **CVE ID reserved** (you hold CVE-2026-XXXXX); once you fill in the description/affected versions/references, the record flips to **Published**. Reserving without publishing = others see an empty ID, and you may get RBP-reported.
4. Timeline: officials no longer promise fixed day counts; community experience is **days to weeks**, longer with follow-ups or duplication disputes. CNA-LR explicitly disclaims any link to bounties or timeliness commitments.

**[Clarification: CVE Services ≠ public self-service ID vending]** CVE Services (the API/Web service on cve.org, cveawg) is for **CNAs and their authorized accounts** to reserve/publish records automatically; it is **not open for ordinary researchers to self-register and self-serve IDs**. The official path for outsiders is still "target CNA → CNA-LR form". Any claim of "self-service application on CVE Services, register an account and get IDs" refers either to internal CNA operations or is outdated/misinformation.

### 1.4 GitHub Security Advisory: The Fastest ID Path for Open Source

GitHub is a CNA (covering open-source repos on github.com); `repo → Security → Advisories` is fully online, no email, no forms:

1. **Create the draft** (maintainer): New draft security advisory; fill in ecosystem/package/affected versions/severity (CVSS computed inline)/description. Third-party finders: go through the repo's **Report a vulnerability** (repo needs a security policy configured); it transfers privately to the maintainer.
2. **Request CVE ID**: one click on the draft page. GitHub issues the ID directly in its CNA role (via CVE Services under the hood); **drafts are not public**. The official line is usually **within 72 hours**; in 2025-2026, with record submission volume, the community widely reports **3~5+ business days** — past that, open a ticket with GitHub Support (the discussion board has whole batches of such nudge threads).
3. **Fix privately**: develop the fix PR in a temporary private fork (note: private forks don't run Actions; run tests locally).
4. **Publish**: publishing the advisory → simultaneously enters the GitHub Advisory Database (GHSA ID + CVE ID as dual identifiers), can drive Dependabot alerts; the private fork is auto-deleted.
5. Want a bounty: GitHub Security Advisories themselves have no general bounty, but open-source projects can set their own; some vendors (e.g. Google for their OSS) run an OSS VRP.

Typical end-to-end (find → publish): **1~3 weeks**; the pure ID step can be **hour-level** (field case §6.1).

---

## 2. Submission Channel Cheat Sheet by Target Type (verified 2026-10)

| Target type | Submission entry (primary link) | How the ID comes | Reward magnitude | Typical timeline | Key notes |
|---------|------------------|---------|---------|-----------|---------|
| Open-source software | Repo security policy / GitHub SA; absent a policy, see SECURITY.md/website | GitHub CNA issues; or the project's own CNA (Apache/PSF etc.) | Mostly none; exceptions like Google OSS VRP | ID in 72h~days; 1-3 weeks total | Report privately first; opening a public issue directly is forbidden |
| Android apps/frameworks | Android's official vulnerability form (source.android.com → vulnerability form, routed to Issue Tracker `b/`); SRC-class apps go to each vendor's SRC | Google is a CNA; IDs issued when the Android Security Bulletin publishes | Mobile VRP: T1 $300k/150k, T2 $150k/75k, T3 $45k/22.5k (from 2025) | Monthly security bulletin cadence; bounty separate | Complete report elements (device/version/PoC); vendor-custom ROM bugs go to the OEM |
| Android kernel/drivers/Pixel | Same as above (Google); upstream Linux subsystem bugs also go to kernel.org | Google or the Kernel CNA | Mobile VRP top tiers cover kernel chains | Fixes follow the bulletins | OEM drivers belong to the OEM PSIRT |
| Windows/all Microsoft | MSRC researcher portal `https://msrc.microsoft.com` (online submission/tracking/bounty/Zero Day Quest) | Microsoft (CNA) issues for its own products | MSRC Bounty up to $250k+ (higher caps for Defender/cloud) | Patch Tuesday cadence; cases run weeks~months | A well-formatted report = entry into Zero Day Quest; Microsoft makes no fixed public-timeline promise |
| Linux kernel | `security@kernel.org` + subsystem maintainer CC'd | **kernel.org has self-served as CNA since 2023**, batch-backfilling IDs for fixed bugs | No bounty | Fix goes public immediately (no embargo pre-announcement); CVE policy = 90 days after report or 30 days after the patch lands, whichever first | See §2.1 for kernel details; **do not post to public mailing lists** |
| All Apple | `https://support.apple.com/102549` (product-security@apple.com) | Apple (CNA) issues with security updates | Apple Security Bounty tops out at $1M+ (zero-click kernel chains etc.) | With iOS/macOS security updates; slow replies are the norm | Bounties require an exploitable PoC; SRD-device findings get a bonus |
| Chrome/browsers | Chrome VRP (bughunters.google.com, Chrome rules page); Firefox: bugzilla.mozilla.org (security group); Safari goes through Apple | Their respective CNAs | Chrome up to $250k per issue (a paid $250k sandbox escape has occurred) | Chrome's biweekly release cadence | Chrome bug details go public with the release; bounties are first-reported-first-served per VRP rules |
| IoT/ICS/general vendors | Vendor PSIRT/security page, security.txt; nowhere found: CERT/CC or CNA-LR | Vendor CNA issues if it is one; otherwise CNA-LR; ICS can go through ICS-CERT (US) | Mostly none; a few pay | No standard; weeks~months | Zombie vendors: preserve evidence → self-publish after 90 days (§5) |
| Domestic channel CNVD | `https://www.cnvd.org.cn` (register + real-name → vulnerability reporting) | CNVD ID; **can also apply for a CVE** (general-type via its process) | No cash; issues an **original vulnerability certificate** | Weekly batch issuance after archiving; 1-2 months total (§2.2) | The general-type certificate needs ~10 instances; real-name required |
| Domestic channel CNNVD | `https://www.cnnvd.org.cn` (website reporting/email) | CNNVD ID (its own numbering, not CVE) | No cash; no CNVD-style original-certificate system | Inclusion speed varies | Positioning = national vuln-db inclusion; for CVE recognition, worse than going straight to a CNA |

### 2.1 Linux Kernel Special Topic (the most counterintuitive flow, spelled out separately)

Current (docs.kernel.org/process/security-bugs.html, verified 2026):

1. **Whom to report to**: the affected subsystem's maintainer + CC `security@kernel.org`. **Do not** post to public lists (LKML/mailing lists); do not open public issues.
2. **Embargo model**: the kernel runs **limited embargo** — fixes are developed in a small private maintainer circle, but the patch becomes public the moment it merges into the public git tree; **distributions no longer get advance notice** (the kernel team withdrew from the linux-distros pre-notice flow around 2024, still true now).
3. **Who issues the CVE**: kernel.org itself (self-appointed CNA since 2023-02). Already-fixed bugs get CVEs **batch-backfilled** (the community disputes this, but it is current practice); policy: public 90 days after report, or 30 days after the patch hits mainline, whichever comes first.
4. **The linux-distros list** (`linux-distros@vs.openwall.org`): the mutual embargo list of distributions, **membership-based** (needs an existing member's sponsorship + accepting the terms); individual researchers generally skip it; its terms: the embargo must lift 7 days after disclosure, or 14 days total, whichever first. For upstream-fixed kernel issues, a researcher publishing technical details directly is no longer a violation (the kernel side holds no embargo anyway), but **giving a 90-day window first is industry custom**.
5. [Outdated] "Report kernel bugs to MITRE for a CVE" — the pre-2023 flow; now the kernel CNA. "Report to linux-distros for coordination" — no longer applicable to the kernel, but still applies to **distribution-specific components** (e.g. some distro's patch).

### 2.2 The Domestic Dual Track: CNVD and CNNVD

| Dimension | CNVD (cncert.org.cn system) | CNNVD (China Information Technology Security Evaluation Center) |
|------|---------------------------|------------------------------|
| Positioning | National information security vulnerability sharing platform | National information security vulnerability database |
| Reporting | Website registration (**real-name required**) → reporting entry; submit a structured report (description/reproduction/impact/vendor info, usually a doc attached) | Website entry/email (vulpro mailbox); strict format requirements |
| Bug classes | General-type (affecting a general product/platform) vs event-type (a specific site) | Mostly inclusion |
| Certificates | **Original vulnerability certificate**: general-type needs ~10 black-box instances with ≥3 documented reproductions; event-type limited to high/medium-risk issues in the three major carriers. Flow: tier-1 → tier-2 → reproduction → disposition → archiving; certificates issued weekly for the prior week's archive | No equivalent certificate system (support-unit/report rankings are separate) |
| Timeline | Submission → archive ~1 month+; 1-2 months end-to-end (public walkthroughs, fastest ~60 days) | Inclusion time varies |
| Relation to CVE | General-type can apply for a CVE via CNVD's process (CNVD is a CNA); but **the fastest path to a CVE is still the vendor CNA/GitHub** | Own CNNVD numbering; does not issue CVEs |
| Recognition | Domestic employers/awards/job-hunting recognize the "CNVD original certificate" | Appears in government/enterprise notification contexts; not recognized internationally |
| Who it suits | Those needing a domestic written credential; batch instances of general-type flaws | Supplementary notification |

Practical advice: target overseas and a CNA → use the vendor channel directly for the CVE, and **while you're at it** sync the published CVE into CNVD/CNNVD inclusion (domestic visibility); vendor MIA / no CNA → CNA-LR for the CVE + the CNVD dual track; purely domestic SRC business bugs → go through the SRC, don't force a CVE (post-authentication bugs mostly get no ID, §3).

---

## 3. The Judgment Gate: What Findings Are Worth Reporting, and What Gets No ID

### 3.1 The Three Requirements (self-check before reporting)

1. **A security policy was violated**: confidentiality (unauthorized read) / integrity (unauthorized write) / availability (unauthorized denial of service) — at least one, and you can name the specific mechanism bypassed (authn/sandbox/type isolation…). "Behavior the developer didn't expect" ≠ vulnerability; there must be a security consequence.
2. **Proof of exploitability**: a minimal reproduction (PoC or step-by-step recipe) + the attacker's preconditions spelled out (unauthenticated? needs intranet? needs a local account?). Don't report "theoretically possible" — build the actual primitive first, then report.
3. **Impact scope**: affected products and version ranges, whether default configs are affected, the fix version (if known). A vague impact scope is the number-one reason CNAs bounce reports.

### 3.2 The Common No-ID List (CNA Rules inapplicability standards, still true in 2026)

Applying for a CVE for the following will most likely be rejected — **don't waste queue time**:

- Requires **purely physical access / device possession** to trigger (teardown, debug ports);
- **Self-XSS** (you inject the payload into your own page) — unless an extra chain upgrades it to stored/reflected;
- **Theoretical DoS / resource exhaustion**: making the TCP stack jitter by flooding packets, maxing CPU with overlong strings, without evidence of a structural defect;
- **CSRF logout, pure UI clickjacking (UI redressing)** and similar items with no substantive security consequence;
- **HTTP response splitting** by itself doesn't qualify (needs an exploitable downstream consumer);
- **Pure brute force / spam / phishing** classes with no protocol-layer weakness;
- **Insecure by Design**: behavior documented as intended, features the vendor declares IBD;
- **Software never publicly released** (internal/custom builds never publicly obtainable) — no public impact surface;
- Merely a **misconfiguration** while the software is secure by default (the default config lacks the issue);
- Post-authentication, same-tenant-only "privilege escalation" that is really a product's functional boundary, not a defect (belongs to SRC business bugs, not CVEs; see below).

**The divide between CVEs and SRC post-auth bugs**: business-logic bugs reported to SRCs (price tampering, unauthorized orders) mostly can't get CVEs — they fail "general software defect + a technical security boundary was broken". Run the two tracks separately: business bugs → SRC (for the bounty), general bugs → CNA (for the ID). Don't take business bugs to queue at CNA-LR.

### 3.3 Duplicates and One-Bug-Many-IDs

- One **independently fixable** bug across multiple products: CNA Rules forbid splitting it into multiple CVEs (one fix resolves = one ID); the exceptions are independent fixes in separate codebases, and protocol-layer defects fixed separately per implementation (Samba and Microsoft each taking an ID is this class; Zerologon was the precedent).
- Dedup before reporting: NVD/GHSA/vendor advisories/the target's git history; already-fixed-but-unannounced bugs (kernel batch backfills) often "collide with a fix" — diff the target version's fix log before submitting.
- Handling a duplicate call: if the CNA judges it a duplicate it closes directly and references you to the primary CVE; if you disagree → appeal with evidence of "different root cause / different fix" (§5.3).

---

## 4. Report Templates (Copy Directly)

### 4.1 Report Body Template

```markdown
# [Component] [bug type] leading to [core consequence] (CVE-2026-XXXXX, to be assigned)

## 1. Summary
One paragraph: which component, which version, which defect, which preconditions, what consequence, what severity.

## 2. Affected Component and Versions
- Component: vendor/product
- Affected: < x.y.z (state whether default configs are affected)
- Not affected / fixed: x.y.z (commit <hash>)
- Platform / preconditions: e.g. needs a low-privilege account, needs the same NAT intranet, needs a specific compile option

## 3. Severity
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N ... (= 9.8 Critical)
(add a CVSS 3.1 backup value for legacy-system compatibility)

## 4. Technical Details
Defect location: file/function/line number or API
Root cause: which security assumption was broken (bounds/authn/lifetime...)

## 5. Reproduction Steps
1. Environment: docker image or distro + exact version
2. Steps a/b/c (full command/request for each step)
3. Expected vs actual

## 6. PoC
See the 4.2 conventions; attach the minimal script/request packet

## 7. Impact
Direct harm + composable follow-on exploitation (takeover/lateral movement/data exfil);
attack cost and reliability (100% trigger / needs a race window)

## 8. Fix Recommendations
Short-term mitigation (config/WAF rules) + root fix (patch idea, diff welcome)

## 9. Timeline (update as it progresses)
- YYYY-MM-DD discovered
- YYYY-MM-DD reported to <channel> (receipt no. xxx)
- YYYY-MM-DD vendor confirmed / assigned / fixed
- YYYY-MM-DD planned disclosure (suggested: report date + 90 days)

## 10. References
Public material / related CVEs / raw test output (attachment)
```

### 4.2 PoC Conventions: Self-contained + Harmless + Sanitized

**Self-contained**:
- Runs as a single file (script / a single HTTP request packet); state dependency versions; environment via a public image or one `docker run` line;
- No dependence on your machine's private data / intranet hosts / sessions from packet captures;
- The reader's acceptance bar: copy-paste and see the "expected vs actual" difference.

**Harmless (red line)**:
- Stop at proving "control flow / data flow hijacked": popping calc → change to `id` / print a marker; for RCE use `id`/`whoami`, no real C2 callbacks;
- Forbidden: modifying/destroying real data, stopping production services, lateral movement, planting backdoors, database dumping; demo data exfil with one self-created test record;
- DoS class: prove the crash on a self-built instance (with crash dump); no load-testing online targets;
- Wormable / automated weaponization does not go into the PoC.

**Sanitized**:
- Mask real tokens/accounts/phone numbers/intranet IPs in request packets; your **own** test-account credentials may stay in the clear (labeled "test account, this environment only");
- Scrub screenshots of irrelevant page elements and PII;
- Before the vendor publishes, the PoC does not go into public repos/direct-download links; release it with the advisory (or first leave a request-access link).

### 4.3 Severity and CVSS Versions (2026 status)

- **CVSS 4.0 is the current standard** (FIRST's current page is v4.0; v3.1 moved to archives): new metric groups CVSS-B/BT/BE/BTE, the new Attack Requirements (AT), Scope retired, Temporal→Threat, supplemental metrics include Safety/Automatable/Recovery, strengthened for OT/safety scenarios.
- Practice: GitHub SA and most CNAs accept 4.0; many enterprise risk platforms still compute 3.1. **Give both in the report** (4.0 primary, 3.1 in parentheses) to avoid downstream conversion disputes.
- Note CVSS ≠ the vendor's final rating: MSRC/Google rate by their own standards; don't fight the vendor over CVSS — put the argument into impact.

---

## 5. Timelines and the Game

### 5.1 Baseline Timelines per Party (2026)

| Party | Timeline | Notes |
|------|--------|------|
| Industry custom | Disclose 90 days after report | Written or tacit for Google/MSRC/CNVD |
| Google P0 | **90+30**: 90 days for the vendor to fix + a 30-day user patching window; a **14-day grace** extension near the deadline; in-the-wild 0days get only **3 days**; weekend/holiday expiries auto-slide to the next business day | Current after the 2025 adjustment; see the projectzero.google policy page |
| MSRC | No fixed commitment; ships on Patch Tuesday | Cases run 2 weeks~6 months; Zero Day Quest gets direct engagement |
| Linux kernel | Fix public immediately; CVE record follows "90 days after report / 30 days after patch, whichever first" | No embargo pre-notice (§2.1) |
| GitHub SA | 72-hour ID promise; reality 3-5+ business days; nudge via Support | 1-3 weeks end-to-end |
| CNVD | Archive ~1 month+; 1-2 months to certificate | General-type certificate cases ~60 days (§6.3) |

### 5.2 Rules During Embargo

- Inside embargo: details stay in the reporting channel and vendor-confirmed private channels; **never** leak fingerprints in conference-talk abstracts / social feeds / CTF problems / merchandise (selling bugs);
- Near day 90 the vendor asks for an extension: demand a **written** new deadline + reason; one grace extension (≤14 days) is the industry's tolerance ceiling; vendor silent / refuses to fix → publish on the original deadline (a P0-style stance, not an obligation; preserve the full evidence chain before publishing);
- Distro-side embargoes for kernel/distro-specific components: 7 days after disclosure, 14 days total, whichever first (Openwall terms); confirm the terms allow before forwarding patches.

### 5.3 If the CNA Says No (escalate in order)

1. **Demand written reasons**: pinned to specific CNA Rules clauses (inapplicability list §3.2 / out of scope / duplicate);
2. **Appeal with more evidence**: reply on the same channel adding "exploitability + impact" proof; if rejected because "another CNA covers that scope", refile per their guidance;
3. **Switch channels**:
   - Believe the CNA assignment was wrong → re-check the official partner list, refile with the correct CNA;
   - No CNA will take it → the MITRE CNA-LR form (the new cveform, §1.3), track via the receipt number;
   - Open source and the maintainer ignores you → you fork the fix + file your own GitHub SA (works when the derived-distribution package name is yours); or just write a public advisory (number-less technical disclosure, PSA/GHSA community submission);
4. **Squatted-but-empty IDs**: report via the RBP form;
5. **Final weapon**: at day 90, publish the technical write-up yourself (with the complete evidence timeline). Post-publication, most CNAs issue the number after the fact (duplicate judgments also get more careful under public pressure); this is routine industry practice, not a flame war.

### 5.4 When to Publish the Technical Blog Post

- **Optimal**: vendor fix already shipped + advisory/ID issued → follow within 48 hours with the deep dive (patch diff analysis, exploitation preconditions, detection); traffic and reputation both win;
- **Vendor overdue, unfixed**: publish on the day-90 date, with the full responsible-disclosure timeline in the content (proving the process was proper); title it "[Coordinated Disclosure]";
- **Don't**: publish mid-embargo (even "hinting" details), or drop the exploitation chain before the fix has propagated (leave users at least one patching window — cf. the P0 +30 philosophy);
- Channels: personal blog + link to the vendor advisory; sync GHSA/CNVD inclusion; WeChat-focused folks, don't screenshot unpublished details out.

---

## 6. Case Studies: Three Routes Walked End to End (Public Records)

### 6.1 The GitHub SA Route: SpiceDB CVE-2022-21646 (open source, hour-level ID)

- **Finding**: late 2021-12 — SpiceDB (open-source authorization engine) LookupResources had a permission-decision flaw under intersection/exclusion + wildcard combinations, allowing unauthorized access grants (v1.3.0 affected).
- **Actions**: repo Security → New draft advisory (ecosystem/package/versions/CVSS); opened a **temporary private fork** to fix quietly (private forks don't run Actions; tested locally with `go test` + act); the fix was deployed to their own production before publication.
- **Getting the ID**: Request CVE ID on the draft page; **CVE-2022-21646 arrived within 1 hour** (the UI said up to 3 days).
- **Publication**: fix merged to main, release tagged, patched versions backfilled → publish advisory; GHSA-7p8f-8hjm-wm92 and the CVE both went live; v1.3.0 auto-marked insecure.
- **End-to-end**: a little over 2 weeks from finding to publication. Lesson: for self-developed open-source projects, GitHub SA is the shortest ID path; but after the 2025-2026 submission explosion, the 72-hour promise is no longer reliable (§1.4) — leave nudge margin.

### 6.2 The MSRC Route: Zerologon CVE-2020-1472 (Microsoft, a textbook disclosure cadence)

- **Finding**: Secura researcher Tom Tervoort analyzed the Netlogon remote protocol (MS-NRPC): AES-CFB8 with a fixed all-zero IV lets you blank a domain controller's machine-account password → straight takeover of the AD domain.
- **Reporting**: privately to the MSRC portal; Microsoft folded the fix into the 2020-08-11 Patch Tuesday; the advisory issued CVE-2020-1472 (CVSS 10.0); the initial advisory was extremely thin on detail.
- **Publication**: 2020-09-11 Secura published the technical blog (reproduction analysis); only after community PoCs followed (late September) did the industry grasp the severity, triggering a global emergency patching push; Microsoft's enforcement, originally 2020-10, slipped to 2021-02. Samba, independently implementing the same protocol flaw, issued its own advisory (the precedent for one flaw, multiple implementations).
- **Lesson**: MSRC IDs ship with the patch — fast and steady; but **the first advisory has almost no detail** — if you want the world to take it seriously, publish the deep technical analysis yourself after the fix lands, supplying the impact argument; phased enforcement is Microsoft's standard rhythm for big changes.

### 6.3 The CNVD Route: An Individual Gets an Original Vulnerability Certificate in 60 Days (the domestic dual track)

- **Background**: a public walkthrough published 2025-11 (an individual white hat, general-type vulnerability).
- **Actions**: website registration + **real-name verification** → the reporting entry, submitted per the official template (description/reproduction steps/verification code/severity/vendor info, with a doc attached); for the general-type class, provided **~10 internet instances** per the platform's bar and documented detailed reproductions of 3+ in the write-up.
- **Flow**: tier-1 review (completeness) → tier-2 review → reproduction verification → disposition → archiving; after archiving, the platform **weekly** batch-issues original vulnerability certificates for the prior week's qualifying bugs.
- **End-to-end**: submission → certificate in about **60 days**; rejections mostly for incomplete materials / too few instances — supplement and requeue.
- **Lesson**: the CNVD certificate follows "domestic written credential" logic (real-name + instance count + batch cycles), different from the CVE's "general technical defect" logic; for CVE recognition, still run the vendor-CNA/GitHub mainline for the same bug, with CNVD as the synced inclusion.

---

## 7. Quick Main Entrances (front doors only; search within sites for detail)

| Channel | Entrance |
|------|------|
| CVE official site / CNA list / CNA Rules | https://www.cve.org |
| CVE Program contact form (CNA-LR fallback, ex-cveform) | https://cveform.mitre.org |
| CVE Foundation (governance news) | https://www.thecvefoundation.org |
| GitHub Security Advisories docs | https://docs.github.com (→ repository security advisories) |
| MSRC portal | https://msrc.microsoft.com |
| Google VRP main entrance / Chrome / Mobile rules | https://bughunters.google.com |
| Android security reporting guide | https://source.android.com (→ security → report) |
| Linux kernel security bugs | https://www.kernel.org (→ doc → Security bugs); linux-distros: https://oss-security.openwall.org |
| Apple reporting / bounty | https://support.apple.com/102549 ; https://security.apple.com/bounty |
| Project Zero disclosure policy | https://projectzero.google/vulnerability-disclosure-policy.html |
| CVSS 4.0 | https://www.first.org/cvss/v4.0 |
| CNVD | https://www.cnvd.org.cn |
| CNNVD | https://www.cnnvd.org.cn |
| Mozilla security reporting | https://bugzilla.mozilla.org (security group) |

> Cross-links: hunting techniques → `../techniques/`; root-cause analysis → `../platforms/11-root-cause/`; Windows/kernel CVE patterns → `platforms/01-windows/win-vuln/kernel-pool-cve-patterns.md`, `../techniques/07-kernel/`; the Chinese SRC report format → global rules `vuln-report-format.md`.
