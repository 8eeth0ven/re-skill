# Code Audit (tree nodes: Code Audit 1001381 + Code Analysis 1001382 + Vulnerability Analysis > Java Vulnerabilities 1000994)

> Division of labor: the local `secure-code-audit` skill (audit process & report / sink quick reference for Java, PHP, Go, Node) is the operational master copy; this article takes the **knowledge-base perspective**: the methodology framework + a deep expansion of historical CVE patterns in the Java ecosystem (the essentials track holds the Fastjson/CC1/URLDNS chain analyses) + diff auditing.
> Community representative posts: fastjson vulnerability analysis (the full line from 1.2.68 expectClass to 1.2.80, with WAF bypass); "Java Deserialization Vulnerabilities: Commons Collections 1 Study Notes" (ConstantTransformer/ChainedTransformer/InvokerTransformer dissected class by class); Fastjson: "The 1.2.24 TemplatesImpl Payload Line", "vulhub Reproduction + IDEA Debugging", and the "The Sorrow of Java JSON Deserialization" series; the MCMS 0day is noted in §8.

## 1. White-box audit methodology: entry -> sink -> taint

### 1.1 Three-stage model (self-drawn)

```
[source entry] ──propagation──▶ [sanitizer?] ──▶ [dangerous sink]
 request.getParam   assignment/concatenation/containers   escapeSql/parameter binding   Runtime.exec
 getHeader/Cookie   interprocedural passing               allowlist checks              OGNL/SpEL/MVEL
 JSON/XML body      reflection/deserialization           safe when the chain is broken SQL concatenation/JNDI lookup
 Upload name/body                                                                          template render/file write
```

- **Entry-point location**: WEB container mappings (servlet/filter in web.xml, struts.xml) -> annotation routing (Spring `@RequestMapping`) -> framework interceptor chains; the entry set = the attack-surface inventory.
- **Taint propagation**: variables passed across methods/classes; audit tools (CodeQL/Tabby/fortify) automate it; manual auditing relies on IDE call-chain backtracking (IntelliJ Analyze Dataflow).
- **Sanitizer judgment**: parameter binding (PreparedStatement) breaks the chain; `StringEscapeUtils` is only effective for its matching context; allowlists beat denylists; common fake sanitization (only stripping quotes, only one round of URL decoding) is the bypass point.
- The master copy of process/report/verdict criteria -> `~/.zcode/skills/secure-code-audit/知识库/审计流程与报告.md`; the full sink tables -> `~/.zcode/skills/secure-code-audit/知识库/sink速查-Java.md` / `~/.zcode/skills/secure-code-audit/知识库/sink速查-PHP.md` / `~/.zcode/skills/secure-code-audit/知识库/sink速查-Go-Node.md`.

### 1.2 Audit entry order (experience-based priority)

1. Run the dependency manifest (pom.xml/composer.json/requirements.txt) against known CVEs (highest 1day density) — snyk/dependency-check.
2. Globally grep sinks (deserialization/template/command/reflection), then backtrack to sources.
3. Auth chains (filter/interceptor/middleware): find allowlist-path omissions -> the unauthenticated surface.
4. Configuration files (application.yml/production keys).
5. Business-flow comparison (orders/payment/recovery) -> logic bugs, filed under `../08-business/business-security.md`.

## 2. PHP auditing (ThinkPHP / Laravel)

### 2.1 Framework bug patterns

- **ThinkPHP 3.x**: `preg_replace /e` execution, `assign` variable overwrite, I-function filter injection, where-injection.
- **ThinkPHP 5.x** classic RCE: 5.0.x core `invokeFunction` (triggered via cache file names/language-pack routing, the December 2018 vulnerability burst); 5.0.23 captcha-route RCE; the pattern = the framework reflectively invokes user input into method names/arguments.
- **Laravel**: `.env` leaking APP_KEY -> old-version X-CSRF-TOKEN signature deserialization RCE (CVE-2018-15133); the Ignition component RCE (CVE-2021-3129, phar/file double-write of log files); debug pages (Debug=True) information disclosure.
- **The CMS family**: the DedeCMS variable-overwrite series, phpunit CVE-2017-9841 (eval-stdin).

### 2.2 PHP generic sinks and POP-chain construction

- High-risk function mnemonic (fatal once the argument is controllable): `eval/assert/preg_replace(/e)/call_user_func/array_map($cb)` / `system/exec/shell_exec/passthru/popen/backtick` / `include/require(+URL with data streams)` / `unserialize/phar://`.
- POP-chain mining method (build the graph backwards): globally grep the magic methods `__destruct/__wakeup` (entry triggers) -> in derived classes find `__toString/__call/__get` (relays) -> endpoints `eval`/`call_user_func`/file writes. Tools: PHPStan + custom rules, phpggc (the ready-made chain library: Laravel/Monolog/Smarty/Guzzle).
- phar deserialization: file functions such as `file_exists/unlink/file_get_contents` accept a `phar://` stream and trigger metadata deserialization — breaking the "there is no unserialize point" deadlock.
- Language traps: `==` loose comparison (the MD5 0e-prefix scientific-notation bypass), `in_array` loose mode, intval truncation, `$_REQUEST` precedence, CLI entries with `register_argc_argv` enabled.

## 3. Python / .NET

- **Python (Django/Flask)**: Django SECRET_KEY leak -> signed cookie/session deserialization (the old pickle serializer); `DEBUG=True` stacks leak source and environment; Jinja2 template SSTI (`{{7*7}}`, the sandbox-escape CLASS bypass); Flask PIN calculation (forgeable when machine info is predictable); pickle deserialization (yaml.load unsafe loading, same root).
- **.NET**: ViewState deserialization (machineKey leak/default empty key, ysoserial.net generates the payload); the SharePoint/Exchange historical RCE chains (ProxyLogon/ProxyShell series, deserialization + SSRF combos); dnSpy/ILSpy decompilation audits; *.aspx directory browsing and web.config leaks.

## 4. Java ecosystem auditing (the key deep dive)

### 4.1 Deserialization panorama (self-drawn)

```
Entry: ObjectInputStream.readObject / JSON.parseObject(autoType) /
       XMLDecoder / Shiro rememberMe AES(CBC) decryption followed by readObject / RMI·JNDI
        │
        ▼ [gadget chain]
 URLDNS: HashMap→hashCode→URL.hashCode→DNS lookup (non-destructive probe of a deserialization entry)
 CC1: LazyMap→AnnotationInvocationHandler.invoke→ChainedTransformer→InvokerTransformer
      (depends on the AnnotationInvocationHandler implementation before JDK≤8u71)
 CC3: TrAXFilter+TemplatesImpl avoids Runtime signatures by loading bytecode
 CC6: TiedMapEntry→LazyMap (HashSet path, not sensitive to JDK version; preferred in practice)
 CB: Commons-Beanutils dependency chain (included in Shiro environments; combine with dependency-free output)
        │
        ▼ [final sink]
 Runtime.exec / TemplatesImpl bytecode loading / JNDI lookup→LDAP/RMI remote class loading
```

- URLDNS/CC1: the full CC1 chain notes (ConstantTransformer fixed return -> ChainedTransformer chained hand-off -> InvokerTransformer reflective invocation; the LazyMap trigger surface); CC3/CC6 are advanced entries of the same family, covered by the JSON deserialization series; URLDNS, as the dependency-free probing chain, appears across the reproduction posts. The generic master copy: `~/.zcode/skills/skill/知识库/deserialization-gadgets.md` + `~/.zcode/skills/skill/知识库/deserialization-test.md`.
- Chain endpoints pivoting to JNDI -> `~/.zcode/skills/skill/知识库/jndi-injection-test.md` (JNDIExploit/LDAP response-body dispatching).

### 4.2 Historical component-bug patterns (memorize by "trigger surface")

| Component | CVE/ID | Pattern | One-liner |
|---|---|---|---|
| Struts2 | S2-045/046 | OGNL | The Content-Type header flows into OGNL parsing (the multipart error-handling path) |
| Struts2 | S2-057 | OGNL | The namespace goes through URL double evaluation |
| Struts2 | S2-061/062 | OGNL | Second evaluation of tag attributes / bypass of the fix |
| Spring | CVE-2022-22965 | Property binding | Spring4Shell: on JDK9+ the Class property chain writes the Tomcat AccessLogValve to drop a shell |
| Spring | CVE-2022-22947 | SpEL | SpEL injection in the Gateway Actuator route expressions |
| Spring | CVE-2022-22978 | Auth bypass | The Security regex's differing behavior on `\n` bypasses path matching |
| Fastjson | 1.2.24->1.2.80 | autoType | See §4.3 |
| Shiro | CVE-2016-4437 (Shiro-550) | Deserialization | The rememberMe default AES key (kPH+bIxk5D2deZiIxcaaaA==) -> CBC decrypt is readObject |
| Shiro | CVE-2019-12422 (Shiro-721) | Padding Oracle | rememberMe Padding Oracle; no key needed, forge valid ciphertext byte by byte |
| Log4j | CVE-2021-44228 | JNDI lookup | `${jndi:ldap://}` in a message triggers JNDI loading; the 2.15 fix was bypassed by CVE-2021-45046 (non-default configs) |
| Jackson | Multiple | polymorphic | enableDefaultTyping is the autoType-equivalent surface |
| MyBatis | — | SQL | `#{}` safe precompilation vs `${}` concatenation (the first grep in an audit) |

- Pattern summary: **OGNL/SpEL/MVEL expression engines + user input = RCE**; **default keys + encrypted deserialization = RCE**; **property binding/reflective binding onto sensitive objects = RCE**.
- Java memory shells (the persistence form a bug lands in): dynamically register malicious components along the request chain Listener->Filter->Servlet (Servlet 3.0 API / Spring Controller / Interceptor / JavaAgent flavors); injection vectors = JSP/deserialization/JNDI; detection = arthas `sc *Filter` or agent-dumped classes compared against web.xml to find "dynamically registered classes with no configuration". The community carries this in paid courses (Behinder/AntSword Java memory-shell detection and defense); the off-site master copies = the Anquanke Filter-type memory shell, javasec.org MemoryShell, gv7.me detection.

### 4.3 The Fastjson evolution line (community-verified)

- 1.2.24: autoType on by default, `@type` arbitrary class loading -> JNDI (the classic JdbcRowSetImpl).
- 1.2.25-1.2.47: checkAutoType allow/deny lists introduced; 1.2.47 abuses the `java.lang.Class` cache bypass (**no autoType enablement needed**, the most damaging wave).
- 1.2.48: the cache bypass fixed.
- 1.2.68: the expectClass mechanism introduced yet another surface (when safeMode is off).
- 1.2.80: the expectClass judgment flaw (the Throwable subclass chain).
- 1.2.83+ / fastjson2: autoType converged, safeMode disables it globally.
- Audit actions: pin the version -> the autoType/safeMode configuration -> the egress surface (JNDI needs outbound access or a local chain) -> WAF mutations on the `@type` signature (`\x74` and other encoding bypasses, see that post's WAF-bypass section).

### 4.4 Spring framework audit essentials

- Routing and auth: interceptor excludePathPatterns wildcard omissions (a high-frequency auth bypass); `@PathVariable` loose matching (`/user/{id}/../admin`).
- SpEL: user-controllable `@Value`, direct hits on SpelExpressionParser.
- Actuator: env/heapdump leaks (mine keys from the heapdump) -> route-registration RCE.
- Spring EL and templates (thymeleaf/FreeMarker SSTI) -> `~/.zcode/skills/skill/知识库/ssti-专题.md`.

### 4.5 The Java audit hands-on route (from code to bug)

1. **Build the project view**: import into IDEA (maven dependency resolution) + decompile the dependency jars; first read web.xml/the SpringBoot bootstrap class and the Filter/Interceptor registration chain.
2. **Draw the auth matrix first**: which paths are allowlisted, which annotations carry custom auth (`@RequiresPermission`-style) -> the difference set is the unauthenticated surface (a high-frequency bug spot).
3. **Backward sink grep**: `readObject|parseObject|XMLDecoder|getMethod.invoke|Runtime|ProcessBuilder|SpelExpressionParser|ScriptEngine|MVEL|new File(|FileOutputStream` -> backtrack each to its source.
4. **SQL surface**: full-text search for `${}` (MyBatis) -> determine whether it sits where parameter binding is impossible (order by/limit — a common true positive) -> `~/.zcode/skills/skill/知识库/injection-test.md`.
5. **Second-render surface**: whether freemarker/velocity template content can be written by users (a template-editing feature = a potential SSTI RCE).
6. **Key surface**: the secret/token encryption keys in `application.yml` -> determine what can be forged (JWT signatures/API signatures) -> `~/.zcode/skills/skill/知识库/oauth-jwt-test.md`.
7. Tooling acceleration: CodeQL (local database + predicate queries), Tabby (a 3-minute Java SCG, good for reachability calls on huge projects), Semgrep (lightweight rule batches).

## 5. Go / Node in one line

Go: template injection, SQL concatenation, SSRF (net/http does not validate protocols); Node: prototype pollution `__proto__` (-> `~/.zcode/skills/skill/知识库/prototype-pollution-test.md`), template injection, npm dependency-chain poisoning. The sink table -> `~/.zcode/skills/secure-code-audit/知识库/sink速查-Go-Node.md`.

## 6. Frontend/JS auditing

- DOM XSS source->sink positions (location->innerHTML/eval), postMessage without Origin validation; restoring packaged artifacts -> `~/.zcode/skills/skill/知识库/js-reverse-guide.md`.

## 7. Auth and business-flow auditing (finding broken access control white-box)

- White-box unauthenticated-access discovery: enumerate the filter/middleware allowlist against the actual routing table and take the difference set; horizontal escalation: object ids queried directly without owner checks (the taint tell: userId taken from parameters instead of session).
- Deep-dive master copy -> `~/.zcode/skills/api-pentest/知识库/鉴权与对象图.md` + `~/.zcode/skills/skill/知识库/idor-test.md`.

## 8. Code diff auditing (hunting 0days in patch diffs)

### 8.1 Process (self-drawn)

```
Monitor sources (security advisories/CVE-NVD/GitHub watch/vendor announcements)
  → Obtain diff (git log -p / commit compare: fix commit vs parent)
  → Locate changes: which condition changed or which check was added
  → Three questions: ① Is the fix complete (boundaries/encoding/length)? ② Where else does the same pattern occur (copy-pasted flaws)?
                     ③ Can a new input bypass the fix (0day variant)?
  → Artifacts: bypass PoC + nuclei template for batch asset verification
```

- Essentials: fix commits often carry test cases (lift the case and shift the boundaries); `git log --grep="CVE\|security\|inject"` fast-sifts historical fixes; cross-version diffs (adjacent minors) reveal patterns better than single commits.
- Classic case shapes: the patch only adds a denylist -> encoding/case bypass (most CMSs); the patch rewrites a regex -> backtrack the uncovered paths.
- The 1day/nday playbook (patch shipped, assets not updated) is a high-yield SRC surface, paired with FOFA fingerprint batching -> `~/.zcode/skills/skill/知识库/rce-面定位.md`.
- MCMS 0day: points to ve1kcon's Miku MCMS audit series (front-end injection + backend getshell). CMS-audit representative posts: the BlueCMS source audit, addslashes bypass x MacCMS, DedeCMS arbitrary front-end user password change, "A Bug-Hunting Record of a Certain CMS".

## 9. Tool matrix

| Stage | Tools |
|---|---|
| Static taint | CodeQL / Tabby (a Java graph database) / Fortify / Semgrep (lightweight rules) |
| IDE backtracking | IntelliJ Dataflow / VSCode + ripgrep |
| Decompilation | JD-GUI/CFR/Procyon (Java), dnSpy (.NET), Ghidra (binary) |
| Dependency CVEs | dependency-check / snyk / a homegrown pom scanner |
| Gadgets | ysoserial (CC/CB), ysoserial.net, marshalsec (Jackson/XStream) |
| Verification | nuclei templating, Burp replay |

### 9.1 CodeQL taint-query skeleton (Java SSRF example)

```ql
class SsrfConfig extends TaintTracking::Config {
  SsrfConfig() { this = "SSRF" }
  override predicate isSource(DataFlow::Node src) {
    src instanceof RemoteFlowSource   // All HTTP input parameters
  }
  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() = any(URL u | u = openURL(_))  // URL-opening sinks
  }
}
from SsrfConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where any(TaintTracking::Path p).hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SSRF: $@ → URL open", source, "user input"
```

Essentials: run the framework's built-in query set first (security-extended), then adapt source/sink to the business; with Tabby, compute reachability on very large projects before reading closely — an order of magnitude in time saved.

## 10. Cross-link summary

- Operational master copy: `~/.zcode/skills/secure-code-audit/` (SKILL.md process + 4 knowledge-base articles)
- Deserialization/JNDI -> `~/.zcode/skills/skill/知识库/deserialization-*.md`, `~/.zcode/skills/skill/知识库/jndi-injection-test.md`
- Injection/upload/XSS white-box counterparts -> `~/.zcode/skills/skill/知识库/injection-test.md`, `~/.zcode/skills/skill/知识库/file-upload-test.md`, `~/.zcode/skills/skill/知识库/xss-test.md`
- Business-logic white box -> `../08-business/business-security.md`
- Mobile (the Java/Android layer) -> `techniques/`
