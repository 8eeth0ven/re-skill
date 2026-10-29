# WEB Security Knowledge System (tree node 1000965, 43 nodes, 16 second-level)

> Division of labor: **specific vulnerability-type testing (SQLi/XSS/CSRF/SSRF/IDOR/deserialization/upload/logic/race conditions, etc.)** is already deeply covered by `<local-skills-root>/skill/知识库/` (40+ articles) and `<local-skills-root>/api-pentest/`; in this area each type gets only a 1-line summary table + cross-links. This area digs deep into the **knowledge-base perspective**: penetration testing methodology, protocol analysis, WAF/firewalls, ops security, incident response, and social engineering.
> Off-tree relations: CTF writeup > Web [1001262] (under CTF writeup 1001414, not the KCTF tournament tree 1001027), Android protocol analysis [1001535], Windows decryption series > protocol analysis [1000270] — cross-link `../02-android/` and `../01-windows/`.

## 1. Website Security [1000966] + Basic Theory [1001189]

One-liner: website security = attack-surface convergence on every link of the whole request chain "DNS resolution -> CDN -> WAF -> middleware -> application -> database".

- **Basic theory at a glance**: same-origin policy (SOP) and the CORS relaxation boundary, cookie attributes (Secure/HttpOnly/SameSite) and session fixation, CSP content security policy, the three assertion models JWT/OAuth/SAML -> details cross-linked at `<local-skills-root>/skill/知识库/oauth-jwt-test.md`.
- **Deployment surface** (recognize the stack before pentesting): middleware (Tomcat/Nginx/IIS/Apache) historical bugs — Tomcat PUT upload (CVE-2017-12615), Nginx parsing bug/alias traversal (CVE-2017-7529 OOB read), IIS short filename/PUT; panels (BaoTa/phpMyAdmin/Adminer); gateways (the admin APIs of APISIX/Kong) -> cross-link `<local-skills-root>/skill/知识库/api-gateway-test.md`.
- Hardening baseline: minimal version exposure, directory permissions, default credentials zeroed out, management-plane isolation.

## 2. Penetration Testing [1000969] — core deep dive of this area

The knowledge-base node carries the full PTES/OSSTMM-style process. Representative posts: "A Route into Penetration Testing - WEB Security" (a learning path split by month/week; month 4 is already intranet pentesting + proxy tunnels); for the red-team curriculum see the community red-team book list.

### 2.1 Full-process pipeline (self-drawn ASCII)

```
[Authorization/scope definition]
      │
      ▼
① Reconnaissance ── Passive: whois/ICP registrations/CT logs (crt.sh)/GitHub exposures/cloud storage
│                     Search syntax: FOFA/Shodan/Hunter/Quake/Google Dork
│   Active: subdomains (subfinder/OneForAll) → liveness (httpx) → ports (nmap/masscan)
│          → directories (ffuf/dirsearch) → fingerprints (Wappalyzer/EHole) → JS assets (LinkFinder)
      │
      ▼
② Vulnerability scanning ── xray/AWVS/W13Scan/nuclei (PoC templates) + manual verification
│                           Burp as the full-traffic proxy workbench
      │
      ▼
③ Exploitation ── Public exploits (CVE reproduction) / weak passwords / logic flaws / social engineering and phishing for initial access
      │
      ▼
④ Post-exploitation ── Persistence (webshell/in-memory webshell/scheduled task) → credential access (mimikatz)
│                      → internal reconnaissance → proxy tunnels (frp/Neo-reGeorg/ew) → lateral movement
      │
      ▼
⑤ Test cleanup + report (paths/evidence/remediation)
```

### 2.2 Key points per stage

- **Information gathering**: the quality of information gathering decides the efficiency of everything downstream. Subdomains -> same C-segment -> sibling sites -> APIs/keys inside JS -> deep-dive cross-links `<local-skills-root>/skill/知识库/recon-methodology.md`, `<local-skills-root>/skill/知识库/js-reverse-guide.md`, `<local-skills-root>/skill/知识库/info-leak-test.md`.
  - Passive first (never touching the target): certificate transparency `crt.sh`, ICP-filing reverse lookup, GitHub/Gitee leaks (keys/internal domain names), netpan/wenku document leaks; cyberspace-mapping syntax (FOFA `domain=""`/`icon_hash=""`/`body=""`).
  - Active convergence: subdomain brute force + permutation (mutations) + JS-reference extraction -> liveness (httpx, filtering CDN/wildcard DNS) -> port layering (one full-range masscan pass + nmap top1000 fine scan) -> layered directory-brute-force dictionaries (common + framework-specific) + backup files (`.svn/.git/WEB-INF/web.xml`, `.rar/.tar.gz/.bak`).
  - Fingerprinting decides the playbook: identify framework/middleware/CMS -> strike the known 1day surfaces directly (nuclei tags), an order of magnitude faster than blind testing.
- **Vulnerability scanning**: passive scanning (proxy mode: Burp+xray chaining, W13Scan) and active scanning (nuclei templates) complement each other; scanner results must be manually re-verified to guard against false positives.
  - Manual mainline: after login, walk the full business flow through the proxy so the traffic passively passes the scanner; then hand-test the high-risk surfaces (payment/recovery/upload/export).
  - API surface: exposed swagger -> object-graph batch id swapping (-> `<local-skills-root>/api-pentest/知识库/鉴权与对象图.md`).
- **Exploitation**: public CVEs first (1day against unpatched assets); logic bugs via business-flow comparison -> `../08-business/business-security.md`; combo chains upgrade single bugs -> `<local-skills-root>/skill/知识库/h1-组合攻击链短表.md`.
- **Post-exploitation**: the intranet is essentially information gathering (the community free-course viewpoint); the four classics of domain penetration (Kerberoasting/AS-REP/Golden/Silver Ticket), NTLM Relay; pick tunnels by protocol (ICMP/DNS/HTTP tunnels); for C2 secondary development see the representative posts "CS 4.4 Secondary-Development Notes: The Basics", "The Enhancements", and "CobaltStrike Analysis 2 - Beacon Parsing".
  - Persistence tiers: webshell (easy to detect) -> memory shell (§7.2) -> scheduled tasks/services (system layer) -> BIOS/Bootkit (hardware layer; in-tree cross-link Windows>Rootkit/BIOS).
  - Lateral movement: credential reuse (password-sync rate), fscan-style one-click subnet sweeping, abuse of management channels such as WSUS/SCCM/PAM.
- **App pentesting (the mobile surface folded into the WEB playbook)**: "Beike APP Penetration Test WP" (JSBridge auth bypass / TOKEN written into sdcard logs / cookies sent in HTTP plaintext), "UNI-APP Penetration Testing - Traffic Capture"; deeper hook/capture counterplay -> `../../techniques/04-evasion/capture-all-scenarios.md`.
  - The interface between app pentesting and WEB: most app business bugs ultimately land on the HTTP API layer (broken access control/replay/logic); the only differences are transport encryption (signing/certificate pinning) and client-side storage; once the anti-analysis layer is stripped off, it reverts to the WEB playbook.

### 2.3 Penetration testing vs red team vs SRC bug hunting (concept layering)

| Dimension | Penetration testing | Red-team exercise | SRC hunting |
|---|---|---|---|
| Goal | Find bugs in authorized systems | Simulate the full real APT chain | Collect bugs within a company's public scope |
| Constraints | Scope/time window | Rules of engagement (ROE) | Platform rules + legal boundaries |
| Depth | Depth within one system | Initial access -> persistence -> lateral movement -> objective | Single bug + combo-chain impact proof |
| Report | Fix-oriented | Tactical reconstruction + detection gaps | Platform grading |

The knowledge base's penetration-testing node covers the first two perspectives; the SRC perspective (this machine's main workflow) -> `<local-rules-root>/src-value-hunting.md`, `<local-rules-root>/dig-scope-workflow.md`.

### 2.4 Toolchain matrix

| Stage | Representative tools |
|---|---|
| Information gathering | FOFA/Shodan/Hunter/Quake, subfinder, httpx, nmap, masscan, EHole, ffuf, LinkFinder |
| Proxy workbench | Burp Suite (dedicated in-tree node 1001520), mitmproxy, Charles |
| Scanning | xray, AWVS, nuclei, W13Scan (in-tree node 1001521), Nessus |
| Exploitation | sqlmap (in-tree injection-tools node 1001522), metasploit, assorted public EXPs |
| Post-exploitation | CobaltStrike (the 4.4 secondary-development posts), frp/ew/Neo-reGeorg, mimikatz, fscan |
| Passwords | hydra, medusa, Hashcat |

### 2.5 Attack methods [1001527] and the ATT&CK mapping

A WEB entry point maps to ATT&CK initial access (T1190 exploit public-facing application) + execution (T1505.003 web shell) + defense evasion (T1027 obfuscation/T1562 impair defenses); the Windows tree additionally has an ATT&CK node [1001352], cross-link `../01-windows/malware.md`.

## 3. WEB Vulnerabilities [1000971] + Vulnerability Analysis [1001496] — full-category summary table (1 line per type, details cross-linked)

> Division of labor with the skill knowledge base: this table is an index only; testing techniques/payloads/confirmation criteria all live in the right column.

| Tree sub-node | ID | One-liner | Cross-link (skill knowledge base) |
|---|---|---|---|
| SQL injection | 1000967 | Unsanitized query strings spliced into SQL | `<local-skills-root>/skill/知识库/injection-test.md` |
| XSS | 1000968 | Reflected input echoed back and executed in the browser | `<local-skills-root>/skill/知识库/xss-test.md` |
| Stored XSS | 1001517 | Persisted in the DB, triggers for every visitor | `<local-skills-root>/skill/知识库/xss-test.md` |
| CSRF | 1001515 | Sends cross-site requests riding the user's session | `<local-skills-root>/skill/知识库/csrf-test.md` |
| SSRF | 1001511 | The server issues intranet requests on the attacker's behalf | `<local-skills-root>/skill/知识库/ssrf-test.md` + `<local-skills-root>/skill/知识库/h1-手法-SSRF信息泄露与配置.md` |
| Command injection | 1001502 | Spliced into a system command | `<local-skills-root>/skill/知识库/rce-面定位.md` |
| Command execution | 1001510 | Directly invokes execution functions | `<local-skills-root>/skill/知识库/rce-面定位.md` |
| Code execution | 1001514 | eval/dynamic code injection | `<local-skills-root>/skill/知识库/ssti-专题.md` |
| File inclusion | 1001505 | LFI/RFI | `<local-skills-root>/skill/知识库/path-traversal-lfi-test.md` |
| File read | 1001508 | Path traversal reads arbitrary files | `<local-skills-root>/skill/知识库/path-traversal-lfi-test.md` |
| Upload vulnerability | 1001503 | Upload an executable to get a shell | `<local-skills-root>/skill/知识库/file-upload-test.md` + `<local-skills-root>/skill/知识库/h1-高危害专项-文件上传链.md` |
| Deserialization | 1001512 | Java/PHP object injection to RCE | `<local-skills-root>/skill/知识库/deserialization-test.md` + `<local-skills-root>/skill/知识库/deserialization-gadgets.md` (chain analysis -> the code-audit article in this directory) |
| XXE injection | 1001507 | XML external entity reads files/SSRF | `<local-skills-root>/skill/知识库/h1-高危害专项-SQLi反序列化XXE.md` |
| CORS hijacking | 1001513 | Overly broad cross-origin policy (**local rule: do not hunt**) | `<local-skills-root>/skill/知识库/cors-test.md` (reference material only) |
| JSON hijacking | 1001509 | JSON interfaces readable by third-party pages | `<local-skills-root>/skill/知识库/idor-test.md`, object-graph approach reused |
| Logic vulnerability | 1001506 | Business-flow defect | `../08-business/business-security.md` + `<local-skills-root>/skill/知识库/race-condition-test.md` |
| Java vulnerabilities | 1000994 | Fastjson/Shiro/Log4j etc. | [code-audit.md](code-audit.md) §4 |
| Information disclosure | 1001504 | Source/keys/backups exposed | `<local-skills-root>/skill/知识库/info-leak-test.md` |
| URL redirect | 1001516 | Open redirect | `<local-skills-root>/skill/知识库/open-redirect-test.md` |
| Others | 1001519 | Prototype pollution/cache poisoning/request smuggling etc. | `<local-skills-root>/skill/知识库/prototype-pollution-test.md`, `<local-skills-root>/skill/知识库/cache-poisoning-test.md`, `<local-skills-root>/skill/知识库/http-smuggling-test.md`, `<local-skills-root>/skill/知识库/websocket-test.md`, `<local-skills-root>/skill/知识库/subdomain-takeover-test.md`, `<local-skills-root>/skill/知识库/webshell-管理.md` |

Combo-chain perspective (chaining multiple bugs for escalation) -> `<local-skills-root>/skill/知识库/h1-组合攻击链短表.md` (top priority).

## 4. Protocol Analysis [1001395] — deep dive of this area

```
Application layer: GraphQL   HTTP/2   HTTP/1.1   WebSocket
                       │      Frames   Messages    │ Upgrade handshake
            └────────┴─────────┴──────────┘
                         TLS 1.3 (encryption layer)
                          │
                      HTTP/3 = QUIC (UDP 443, built-in TLS1.3)
```

- **HTTP/1.1**: method/status-code semantics, Keep-Alive, why pipelining was abandoned; the root of classic request smuggling (CL/TE ambiguity) -> `<local-skills-root>/skill/知识库/http-smuggling-test.md`.
- **HTTP/2** (RFC 9113): binary framing + multiplexing + HPACK header compression; h2c upgrade smuggling, cleartext h2c-to-backend smuggling; cache-key ambiguity.
- **HTTP/3 / QUIC** (RFC 9114): UDP transport, 0-RTT replay risk, connection migration (Connection ID); capture requires QUIC decryption (Wireshark support is limited).
- **TLS 1.3**: 1-RTT handshake, forward secrecy by default; MITM debugging relies on mitmproxy/Charles with a trusted root certificate; app-side SSL-pinning bypass -> `../../techniques/04-evasion/ssl-pinning-bypass.md`.
- **WebSocket**: Upgrade handshake, missing Origin validation = cross-site WebSocket hijacking (CSWSH), session abuse when auth runs only once -> `<local-skills-root>/skill/知识库/websocket-test.md`.
- **GraphQL**: introspection full-schema leak, batching against rate limits, deep-query DoS, field-level broken access control (an IDOR variant) -> `<local-skills-root>/skill/知识库/graphql-test.md` + `<local-skills-root>/api-pentest/知识库/fuzz与业务逻辑.md`.
- **App-private protocols**: capture and restoration of protobuf/custom encrypted bodies -> `../../techniques/04-evasion/capture-all-scenarios.md`.
- API panorama (REST/RPC auth matrix, object graph) -> `<local-skills-root>/api-pentest/知识库/鉴权与对象图.md`.

## 5. Firewalls [1001400] + Tools & Scripts > waf [1001523] — WAF and bypass overview

### 5.1 WAF form factors and deployment positions (self-drawn ASCII)

```
User → CDN (cloud WAF: Alibaba Cloud Shield/Tencent T-Sec/Knownsec) → reverse proxy (software: ModSecurity/Naxsi/SafeLine)
     → appliances (F5 ASM/Imperva) → application-side RASP (Contrast/JRASP)
                                        │
              Detection engines: regex/semantic analysis/machine learning/frequency and reputation (tree node 1001523 classifies these as tools)
```

### 5.2 Detection principles and bypass overview

- Detection: signature regexes (SQLi/XSS features), semantic parsing (AST level), machine learning (abnormal parameter distributions), behavior (rate/UA/reputation).
- Major bypass classes: **syntactic mutation** (comments/case/encoding/equivalent functions), **protocol layer** (chunked transfer/HPP/parameter pollution/unchecked encoding paths/multiple Content-Type ambiguity), **architecture layer** (hunting non-standard ports/hitting the origin IP directly/stale version caches), **resource layer** (oversized parameters, performance-exhaustion degradation).
- The full technique set and confirmation criteria -> `<local-skills-root>/skill/知识库/waf-bypass.md` (not repeated here); for the WAF-detection module of plugin-style scanners like W13Scan see §9.
- Network-layer firewalls and application-layer WAFs complement each other; classic firewall rule bypasses (fragmentation/protocol tunneling) belong to the ops-security perspective in §6.

## 6. Ops Security [1001383]

- **Exposed-surface governance**: converge the public exposure of management ports (22/3389/6379/3306/9200), bastion hosts, jump hosts.
- **Containers and cloud-native**: Docker 2375 unauthenticated access, K8s API 6443 anonymous/etcd 2379/dashboard, the image delivery chain; cross-link `../07-iot/` for the ICS surface and `<local-skills-root>/ops-pilot/` for the deployment-side perspective.
- **CI/CD**: Runner command execution, artifact poisoning, secrets leakage -> `<local-skills-root>/skill/知识库/insecure-scm-test.md`, `<local-skills-root>/skill/知识库/cloud-ide-codex-rce-chain.md`.
- **Configuration audit**: misconfiguration is the top root-cause class (cloud storage buckets, object listing, hardcoded keys); baseline tools (lynis/CIS-CAT).
- Logging: access-log retention and alerting are the fuel of incident response (§7).

## 7. Incident Response [1001497] — deep dive (tracing/forensics/persistence hunting)

Community representative posts: "Solar Incident-Response Public Monthly CTF, February 2025 - Writeups" (Autopsy/FTK Imager forensics), "1st Solar Cup Incident-Response Challenge - Official WP" (Geoserver intrusion where the webshell had already been deleted; hunting residual attack traces), "Building Linux Tools with AI: the Boot Manager" (a persistence-hunting scenario).

### 7.1 The six PDCERF stages

```
Preparation P → Detection D → Containment C (disconnect/block IP/take offline) → Eradication E (remove backdoors/patch flaws)
                          → Recovery R (redeploy/rotate keys) → Follow-up F (review/harden)
```

### 7.2 Hunting tree (self-drawn)

```
Linux: processes (ps -aux/top for abnormal CPU; netstat -antp for outbound connections; lsof -p)
 ├─ Scheduled tasks: crontab -l /etc/cron.* / systemd timer
 ├─ Startup: /etc/rc.local / init.d / systemd / ~/.ssh/authorized_keys
 ├─ Files: find / -mtime -3 -type f; sh/php/jsp files of unusual size
 ├─ Logs: /var/log/secure·auth (brute force), wtmp/btmp (last/lastb), history
 └─ rootkit: chkrootkit / rkhunter
Windows: processes (wmic process get), services, scheduled tasks, registry Run keys, event logs (4624/4625 logon, 4720 account creation), IPC$/net user
Web: cluster access logs by time+uri to reconstruct the attack path → locate webshells (timestamp/size/signatures)
 ├─ Webshell detection/removal: D-Shield/Hippo/CloudWalker
 └─ Java in-memory webshells: arthas sc *Filter / javaagent class dumps; identify dynamically registered classes absent from web.xml
```

- **Tracing**: replay from the first anomalous request -> the entry point (CVE/weak credentials/upload) -> the lateral path; attribute via IP/UA/tool fingerprints (the default sqlmap UA, etc.).
- **Forensics**: volatile data first (order: memory > network connections > processes > disk); image with dd/dcfldd, analyze with Autopsy/FTK Imager/volatility; chain of custody (hash fixing, timeline).
- **Persistence-technique inventory** (what to check): webshell/memory shell/scheduled tasks/system services/SSH key/backdoor accounts/BOOTKIT; the Windows deep layer (BIOS/implants) -> `../01-windows/malware.md`.

### 7.3 Web-intrusion hunting quick command reference

| Purpose | Linux | Windows |
|---|---|---|
| Anomalous processes/outbound connections | `ps -aux --sort=-%cpu`, `netstat -antp`, `ls -l /proc/<pid>/exe` | `wmic process get name,commandline`, `netstat -ano` |
| Scheduled tasks | `crontab -l -u <user>`, `ls /etc/cron.*`, `systemctl list-timers` | `schtasks /query /fo list`, Task Scheduler |
| Autostart entries | `chkconfig`/`systemctl list-unit-files`, `cat ~/.ssh/authorized_keys` | Registry Run/RunOnce keys, services via `sc query` |
| New/modified files | `find / -mtime -3 -type f -size -100k`, `find /var/www -name "*.jsp"` | forfiles by date, Everything sorted by size |
| Login traces | `last`/`lastb`, `grep Accepted /var/log/secure` | Events 4624/4625/4720, `Log Parser` |
| Web-log forensics | `grep -E "(select\|union\|eval\|whoami)" access.log \| sort \| uniq -c` | Same as left (IIS: ex*.log) |

- **Webshell-locating signatures**: unreferenced orphan files, mtime matching the intrusion window, abnormally small size, encoded obfuscation (long gzip/base64 strings), `ANTSWORD`/`cmd` parameter patterns; when scanner false positives run high, converge manually on the three conditions "time window + directory + size".
- **Memory-shell hunting (Java sites)**: compare the Filters/Servlets/Listeners registered via web.xml/annotations against the set of classes actually loaded at runtime (arthas `sc`/`sm`, javaagent dump); for the Spring flavor check the RequestMapping annotation table; the Agent flavor requires dumping the post-transform bytecode for comparison.
- **Database exfiltration (forensic surface)**: general_log/mysql-bin time-window analysis, abnormally large slow-log queries, cross-database access by the application account.

### 7.4 Tracing and forensics standards

- Chain-of-custody fixing: `md5sum` the image and key logs immediately; keep an operation timeline (who did what, when); the original disk is read-only, analysis happens on the copy.
- Entry-point reconstruction: replay the logs along the attack chain (first 4xx probe -> first 200 successful exploit -> webshell creation -> outbound connection), and hand the remediation team the triple "timeline + attack surface + impact scope".
- Reporting as required: major incidents are reported by severity under the "Cybersecurity Incident Emergency Response Plan"; customer data breaches trigger Personal Information Protection Law notification obligations.

## 8. Social Engineering [1000970]

### 8.1 Attack taxonomy

| Type | Technique | Technical crossover |
|---|---|---|
| Spear phishing | Customized email + macro documents/LNK/HTML redirects | Macro reversing -> `../01-windows/malware.md` malicious scripts |
| Credential phishing | Fake login page + adversary-in-the-middle (Evilginx-class reverse proxies relaying MFA) | OAuth/sessions -> `<local-skills-root>/skill/知识库/oauth-jwt-test.md` |
| Watering hole | Browser exploits planted on sites the target visits often | -> `../06-binary-vuln/` browser section |
| Vishing/impersonation | Impersonating IT/a vendor to induce an MFA reset | Account security -> `../08-business/business-security.md` §2 |
| OSINT intelligence | LinkedIn/job boards/Gitee/net drives aggregated into org charts and keys | GitHub dorks -> `<local-skills-root>/skill/知识库/insecure-scm-test.md` |

### 8.2 Detection and defense

- Technical defense: the DMARC/SPF/DKIM trio, URL sandbox detonation, password managers against keylogging, FIDO2 hardware keys (hard to relay even for AiTM).
- Process defense: dual review for wire transfers/password changes, out-of-band verification channels (call-back confirmation); red-team phishing exercises measure click rate and report rate.
- Adjacent surface: the phishing post cluster — "Common Phishing Techniques", "Emergency Forensics for Phishing Files: The Methods", and the phishing email -> info-stealer full chain (the attack-perspective master copy belongs in `../08-business/`).

## 9. Tools & Scripts [1000972] — six third-level nodes in depth

| Sub-node | ID | Positioning |
|---|---|---|
| Kali | 1001518 | The attack distribution, toolset management (recon/wireless/exploit) |
| Burpsuite | 1001520 | The WEB testing workbench: Proxy/Intruder/Repeater/Scanner/extensions (Turbo Intruder for race conditions) |
| W13Scan | 1001521 | Open-source passive scanner (Python, proxy mode + plugin-style detection, domestic) |
| Injection tools | 1001522 | sqlmap (tamper to bypass WAF)/NoSQL injection tools |
| waf | 1001523 | WAF detection/identification tools (the wafw00f class) + countermeasure scripts |
| Others | 1001719 | nuclei/xray/ffuf and the modern chain (see §2.4) |

Deep dives on the Burp ecosystem (extension development/batch automation) and AI assistance -> `<local-skills-root>/skill/知识库/token-spray-ai-dast.md`.

## 10. Remaining nodes in one line

- **Code analysis [1001382]**: static/dynamic analysis of source-less targets to locate bugs, JS decompilation and restoration -> `<local-skills-root>/skill/知识库/js-reverse-guide.md`; the binary surface -> `../06-binary-vuln/`.
- **Experience sharing [1001498]**: scattered posts, already merged into each section's representative posts.
- **CTF Web**: hangs in the tree under CTF writeup>Web [1001262]; the training-ground perspective (ssti/deserialization/JS library bugs) cross-links `../02-android/malware-and-ctf.md` §CTF.

## 11. Cross-link summary

- Vulnerability-type testing -> `<local-skills-root>/skill/知识库/` (§3 table)
- API/auth -> `<local-skills-root>/api-pentest/知识库/`
- White box -> this directory's companion [code-audit.md](code-audit.md) + `<local-skills-root>/secure-code-audit/`
- Business -> [../08-business/business-security.md](../08-business/business-security.md)
- App-side counterplay -> `techniques/`
