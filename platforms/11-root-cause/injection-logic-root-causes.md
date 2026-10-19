# Injection and Logic Root Causes: Why Data Becomes Code

> Division of labor: techniques and test checklists live in [05-web/web-security.md](../05-web/web-security.md) and [05-web/code-audit.md](../05-web/code-audit.md) (black-box playbooks in `~/.zcode/skills/skill/`); this piece covers only **root causes** — why this class of bugs exists, why it keeps being reinvented, and why one kind of fix cures while another merely buys time. Sister pieces: memory-corruption root causes (stack/heap/UAF/races) in [memory-error-root-causes.md](memory-error-root-causes.md); the whole-repository mapping index in [root-cause-to-technique-map.md](root-cause-to-technique-map.md).

## 0. One-Sentence Overview

> **In a von Neumann architecture, code and data are the same bytes to begin with. The "code" vs "data" line is drawn manually at runtime by each layer of interpreter — an injection bug = the attacker's byte stream crossing that line in the wrong place, getting treated as part of the grammar instead of as a value.**

Hence the three leitmotifs of the whole text:
1. **The boundary problem** (§1): injection happens at the point of the "interpreter entrance", not inside any specific function
2. **The timing problem** (§3, §4.5): a time gap exists between validation and use (SSRF rebinding / concurrent debits) — TOCTOU's projection onto the network and business layers
3. **The model problem** (§4, §5): logic bugs and authorization failures are not mis-written code — they are **code correctly implementing a wrong mental model** — this class has no payload signature, and scanners are structurally blind to it

## 1. The Essence of Injection: The Interpreter Boundary

### 1.1 Where the Context Switch Happens

Any program is a nest of "interpreters". Taking one web request as an example, user input passes through:

```
HTTP body → 框架路由器 → 业务代码 → [SQL 引擎 | shell | 模板引擎 | LDAP | XPath]
         → 浏览器 HTML parser → HTML 里的 JS parser → 又可能拼回 SQL/HTML
```

Every bracket is a **Turing-complete or quasi-Turing-complete language runtime**. The necessary and sufficient conditions for injection:

1. The user-controllable byte stream **enters the input port of some interpreter** (instead of being passed along as a "value");
2. The byte stream **contains the target language's grammar metacharacters** (SQL quotes, shell `;|&`, HTML `<`, template `${`);
3. The program **fails to separate data from the grammar character set** before submission (parameterization/encoding).

Miss any one and there is no injection. This is also why "filtering ten thousand characters" never finishes: the metacharacter set is defined by the **target interpreter**, is a full set, and evolves with versions (wide bytes, new functions, the H2 pseudo-protocol); parameterization only needs to satisfy condition 3 and dismantles the whole class at once.

The common interpreter-entrance checklist (during audits, check each against "does the data go through the lexer or through bind"):

| Interpreter | Entrance API/syntax | Representative metacharacters | Parameterized form |
|-------------|--------------------|-------------------------------|--------------------|
| SQL engine | driver query | `'` `;` `--` | PreparedStatement bind |
| shell | system/popen/exec(String) | `;` `|` `$()` `&&` | argv array |
| HTML parser | innerHTML/document.write | `<` `"` | textContent/DOM API |
| JS engine | eval/Function/setTimeout(str) | the whole language | don't eval; callbacks |
| Template engine | evaluate/render(userStr) | `${` `#{` `<#` | pass a data model |
| Expression engine | SpEL/OGNL/EL evaluate | `#` `@` `T(` | don't accept user expressions |
| XPath/LDAP | query concatenation | `'` `)` `][` | variable binding (XPath rarely supports it) |
| XML parser | parse(userXml) | `<!ENTITY` | disable DTD (not binding — turning the capability off) |
| Regex engine | user-controllable pattern | backtracking/ReDoS (not injection, same boundary) | allowlist |
| Deserialization | readObject/yaml.load | protocol type fields | forbid type polymorphism/allowlist |
| LLM context | prompt concatenation | natural language (no metacharacters) | structured delimiting + instruction fencing |

This table is also "a predictor of new vulnerability families": whenever a new capability of "executing strings as a language" enters the system (a new ORM, a new rules engine, an Agent's tool-call DSL), the first question to ask is where its bind channel is.

### 1.2 String Concatenation = Implicitly Constructing the Syntax Tree

When a developer writes `"SELECT ... WHERE name='" + input + "'"`, the mental model is a **fill-in-the-blank**: the sentence skeleton is fixed; the input fills the blank. But the interpreter doesn't see "skeleton + blank"; it sees one whole byte stream, and its job is to **tokenize → build a syntax tree**. The act of concatenation amounts to:
- ceding part of the **"syntax-tree construction rights"** to the input;
- metacharacters in the input change the tree's shape at the lexing stage (prematurely closing literals, appending predicates, commenting out the second half of the statement).

I.e.: **string concatenation = letting data participate in constructing the syntax tree**. Injection is not "malicious content was entered"; it is "input acquired grammatical standing". This is isomorphic to memory corruption's root cause: a buffer overflow treats data as stack-frame structure (the return address); injection treats data as AST nodes — both are cases of "data acquiring structural interpretation rights".

### 1.3 The SQL Parser's View, Diagrammed

```
输入: input = "a' OR '1'='1"

字节流:  SELECT * FROM users WHERE name='a' OR '1'='1'
                                      ^^ └────┬─────┘└───┬───┘
                                      │   新谓词(攻击者的语法)│
                                      │                     │
Lexer 状态机(简化):
  [CODE 态] --遇 '--> [STRING 态] --遇 '--> [CODE 态] ...

  name='a'      → 正常:STRING 态吃掉 a,遇 ' 回 CODE
  a' OR ...     → 用户输入里的 ' 把状态机切回 CODE 态
                  之后每个字节都被当 SQL 语法重新分词:
                  OR 成为关键字,'1'='1' 成为谓词节点

  结果 AST:
  WHERE name='a'            (开发者意图的子树)
        OR ('1'='1')        ← 攻击者追加的兄弟节点,整棵 WHERE 恒真
```

Wide-byte injection is this same diagram proven along the encoding dimension: under GBK, `0xbf5c` (preceding the `\`) gets consumed as one Chinese character; the `\`'s escaping power vanishes and the quote is bare again — showing that **escaping must be aware of the target interpreter's character set**; escaping schemes and interpreters are tightly coupled, and data-side patches like "filter `'`" never touch the boundary at all.

### 1.4 Why Parameterized Queries Are the Radical Cure

```
预编译阶段(语法树已封闭):          执行阶段:
  Parse("... WHERE name = ?")        bind(1, "a' OR '1'='1")
        │                                   │
        ▼                                   ▼
  Stmt { WHERE: { op: =,              值作为叶子挂到 PARAM(1) 槽位
         col: name,                   —— 字节串从未进入 lexer,
         val: PARAM(1) } }              树的形状不可能改变
```

The mechanism of the parameterized cure is not "better filtering" but **splitting "constructing the tree" and "filling in values" into two phases, with user data appearing only in the second phase**. The generalized equivalent principle:

- **Separation of code tree and data** — SQL parameterization, the shell's `argv[]` array, `encodeURIComponent` for URLs, DOM `textContent` assignment (instead of innerHTML) are all instances of the same principle at different interpreter boundaries;
- Wherever phase separation is impossible (table names/column names/ORDER BY fields cannot be parameterized), the correct approach is **allowlist enumeration of the syntactic position**, because the input there genuinely needs grammatical standing — so allow it to draw only from a restricted set.

This yields the unified verdict for injection classes: **find the interpreter; see whether user data goes through the lexer (dangerous) or through bind (safe).** In audits this verdict is more reliable than any sink list.

## 2. Each Injection Surface's Root Cause, One by One

### 2.1 SQL Injection: Parsing Ambiguity

Root cause in one line: **the same byte stream, understood by the developer under "string-concatenation semantics" and by the database under "SQL grammar" — an ambiguity between two interpreters.** The second-order root cause (why it still produces today): the default-safety illusion of ORMs, but `order by`/`group by`/table names/`find_in_set` positions cannot be parameterized, and the first sorting requirement sends developers back to concatenation; in MyBatis, `${}` vs `#{}` differ by a single character — `${}` is raw concatenation. Detection and exploitation chains are in [05-web/code-audit.md](../05-web/code-audit.md); the black-box matrix is in the skill knowledge base's SQLi module.

### 2.2 XSS: The HTML Parsing State Machine; Why the Escaping Rules Differ Across Three Contexts

HTML is not a regular language; it is a **stateful parser** (the HTML5 spec defines 80 insertion states). Which state the user input lands in decides which bytes are metacharacters:

| Landing spot | Parse state | Metacharacters | Correct escaping |
|--------------|-------------|----------------|------------------|
| Between tags | Data state | `<` | `&lt;` (breaks tag opening) |
| Inside an attribute value | Attribute value state | `"` `'` `&` | `&quot;` (prevents jumping out of the attribute) |
| Inside `<script>` | Script data state | `</script` (and HTML escaping is **ineffective**) | handle per JS grammar, or JSON + `</script` escaping |

Why the rules differ: **escaping must target "the next interpreter down"**. Inside an attribute value, `<` is harmless (it cannot open a tag), but `"` can jump out of the attribute and become a new attribute (onerror); inside a script block, `&lt;` passes through verbatim (HTML entities are not decoded in script data state) — only `</script>` can terminate the block — which is why putting JSON into a script requires `replace(/</g,'\\u003c')`. Under multi-level nesting (HTML→JS→URL→HTML), the decoding order is fixed: HTML entity → JS unicode → URL; misunderstanding the order is the entire source of double-encoding/encoding-bypass bugs. CSP is "a fallback at the execution layer", not an escaping replacement: it concedes the boundary may fall, and downgrades the consequence from "execute arbitrary JS" to "execute allowlisted JS".

### 2.3 Command Injection: The argv Array vs the Shell String

The OS's program-execution interface `execve(path, argv[], envp)` has **array semantics**: each argument is an independent byte string; `;` `|` `$()` carry no syntactic meaning inside argv. The root cause of command injection is **downgrading array semantics to string semantics, with a Turing-complete tokenizer in between**:

- C `system(cmd)` → always goes through `/bin/sh -c` (necessarily through a shell);
- Java `Runtime.exec(String)` → internally tokenizes on whitespace (already a downgrade, and outright broken for paths containing spaces);
- PHP `shell_exec`/backticks, Python `os.system`/`os.popen` → shell strings;
- **Safe forms**: `ProcessBuilder(List).start()`, Python `subprocess.run([...], shell=False)`, direct `execve` — array semantics preserved; with `shell=False`, metacharacters are just ordinary bytes.

Audit verdict: seeing an `exec`/`system`/`popen` whose argument is a **concatenated string** is a root-cause hit; if the argument is a fixed-length array and user input fills only one element, the boundary holds. In device firmware, `sprintf(buf, "ping -c 1 %s", user)` followed by `system(buf)` is the high-frequency embedded form of this same root cause (case matrix in [07-iot/iot/router-practice.md](../07-iot/iot/router-practice.md), CVE injection matrix).

### 2.4 Path Traversal: Absolute-Path Concatenation vs the Validation Timing of Canonicalization

Root cause: **the path at the string layer and the path at the filesystem-semantics layer are not isomorphic**. `../` is a harmless character in a string; after FS parsing it is "a directory jump-up"; the concatenation `base + "/" + filename` assumes the filename contains no semantic jumps, and no mechanism enforces that assumption. The pitfalls of the fix are all in **timing**:

```
错误1: 先 startsWith(userPath, "..") 再拼 base     → 编码绕过(%2e%2e%2f、..\\、unicode)
错误2: canonical = File(base+name).getCanonicalPath();
       if (canonical.startsWith(root)) 打开(canonical)  → 可,但注意 ↓
错误3: startsWith("/var/www/uploads")               → "/var/www/uploads-secret" 也通过
正确:   canonical.startsWith(root + File.separator)
        且 canonicalize 之后**不再拼接任何用户输入**(否则回到 TOCTOU)
```

Unified principle: **validation must act on "the semantic form that will actually be used"** (post-resolve), with no further transformation between validation and use. This is the same principle as §3's pin-IP and §4.5's atomic debit: the validated object = the used object.

### 2.5 Template Injection (SSTI): The Renderer Is Turing-Complete

Template engines (Velocity/Freemarker/Jinja2/Thymeleaf) are essentially **Turing-complete languages embedded in the application**, usually with a reflection host (`$class.forName`, `freemarker.template.utility.Execute`). SSTI's root cause in one line: **treating user input as the template (program) instead of as the template's parameter (data)** — a direct violation of condition 1 in §1.1. `${7*7}` echoing 49 is the "engine evaluates" probe (only language evaluation does arithmetic). Second-order root cause on the defense side: engine sandboxes (Freemarker `TemplateClassResolver`, the Jinja2 sandbox) are off by default; "the engine is escapable by default" and XXE's "the parser enables entities by default" belong to the same **insecure-historical-defaults** family.

### 2.6 LDAP Injection and XXE: Forgotten DSLs and Over-Generous Parsers

- **LDAP**: the filter is itself a language (`(&(uid=x)(password=y))`); concatenating user input can close parentheses and rewrite predicates (anonymous login / unauthorized queries). The mechanism is perfectly isomorphic to SQL — only the interpreter differs.
- **XXE**: the XML spec (1998) made DTD external-entity resolution a **default behavior** — back then, DTD was a type-system concept; nobody treated it as a fetch primitive. XXE's root cause = **the parser trusting the document's "fetch instructions" by default**: `<!ENTITY x SYSTEM "file:///etc/passwd">` has the parser issue I/O on the document's behalf. That is why the fix must be explicitly disabling features at the factory (disallow DTD / external-general-entities), not filtering keywords. XXE is natively the parser-built-in version of SSRF (an entity SYSTEM pointing at an intranet address = the parser fetching for you), and their high-value targets coincide as well (cloud metadata).

### 2.7 NoSQL/Document-Query Injection and Expression Injection (the EL Family)

- **NoSQL (Mongo etc.)**: when `db.users.find({user: req.query.user})` receives `{"$ne":1}`, the query string is parsed into a **query-operator object** — data acquires DSL grammatical standing, equivalent to SQL metacharacter crossing, except the "metacharacters" are now `$` keys and nested objects. Isomorphic root cause: **putting user input directly into the query language's object-representation layer**. PHP's `?user[]=x` auto-array parameter is this root cause's classic amplifier.
- **Expression injection (SpEL/OGNL/EL)**: the root form of the Struts2 vulnerability series — the framework parses user-controllable parameter names/values with OGNL; the contents of `%{}`/`${}` get evaluated as expressions, and `@java.lang.Runtime@getRuntime()` is direct RCE. Its difference from SSTI is only the host: the template engine is "the business deliberately renders"; the EL is "the framework implicitly evaluates" — with the latter, developers often **don't know the boundary exists**, which is why Struts2 bugs kept detonating: an invisible boundary cannot be defended.

### 2.8 Deserialization: Data as Object Graph

One-line root cause: **deserialization protocols are "instantiate a byte stream directly into an object graph" protocols, equivalent to letting the remote end choose the construction logic to execute; a gadget = a concatenatable construction chain that happens to exist on the classpath.** The Java/PHP/Python/.NET gadget ecosystems and evolution lines are in [05-web/code-audit.md](../05-web/code-audit.md) §4 (the Shiro/Fastjson evolution line); the memory-layer root cause (why "arbitrary class loading" becomes "code execution") belongs to [memory-error-root-causes.md](memory-error-root-causes.md) and is not repeated here. The unified detection-side law: **a deserialization bug's signature is not in the input (the byte stream is legal protocol data) but in "whether protocol-handling classes appear where they shouldn't"** — which is why scanners can only match known gadget signatures, while white-box review sees through it at a glance.

Wrapping up §2 from the injection-family overview: the seven injection surfaces share one verdict line —

```
SQL │ XSS │ 命令 │ 路径 │ SSTI/EL │ LDAP/XXE │ NoSQL │ 反序列化 │ 提示注入
 └── 用户字节获得「目标语言的语法地位」──┘
      修复只有两型:bind 通道(参数化/argv/textContent)或关能力(禁 DTD/禁 eval/沙箱)
```

## 3. SSRF's Root Cause: Implicitly Trusted Network Position

### 3.1 The Root-Cause Formula

```
SSRF = 服务端 fetch(url) 
     + url 含用户输入
     + 「内网默认可信」的边界模型
```

The firewall's trust model is **tight outside, loose inside** (ACL at the perimeter, everything allowed inside). SSRF makes a legitimate egress located at the boundary (image fetching/webhook/import) send requests into the intranet on the attacker's behalf, **piercing the boundary model with the application's legitimate network position**. The highest-value target is cloud metadata (169.254.169.254): IMDSv1 has no authentication and returns temporary credentials — one GET for a cloud account; this is the priciest single point of the "intranet trusted by default" assumption.

### 3.2 redirect and DNS Rebinding: TOCTOU's Network Edition

The two mechanisms of allowlist failure are both, in essence, **validation and use separated**:

- **redirect**: what was validated is the first-hop URL; with `followRedirects=true`, every 30x triggers a **re-interpretation** of Location. The URL at validation time ≠ the URL at use time.
- **DNS rebinding**: the check phase resolves `evil.com` → a public IP (passes the allowlist); the use phase (after TTL expiry) resolves again → 127.0.0.1. **The same name resolves differently twice**; the window = the TTL. This is classic TOCTOU (check-then-use) projected onto DNS resolution — between check and use, the "value" changed.

Why the radical cure must be "pinning": pin the IP (the address resolved at check time is used directly for the connection, no second resolution), disable redirects or **re-run the full validation at every hop**, schema allowlists. All of it points to the same line: **make validation act on the very resolution result that gets used** — isomorphic with §2.4's canonicalization timing and §4.5's atomic debit. Black-box playbooks and escalation chains are in the skill knowledge base's SSRF module + [05-web/code-audit.md](../05-web/code-audit.md) §9.1 (the CodeQL SSRF taint-query skeleton).

## 4. Logic-Bug Root Causes: Why Scanners Can't Find Them

Master statement: **a logic bug = code correctly implementing a wrong mental model.** It has no payload signature — the attacking request and a normal request are byte-identical; the difference lies only in "whether this state transition / this amount is permitted in business semantics", and business semantics live in no signature database. So DAST has no oracle (it doesn't know what an "abnormal response" is) and SAST has no sink (every line of code is "correct"). The only reliable oracle is **business-consistency diffing** (two accounts' visibility of the same object compared) — which is why authorization/logic bugs can only be found by "understanding the business, then hand-crafting".

### 4.1 Missing State Machines

- Developer's mental model: "users will follow the page A→page B→page C flow" (mistaking the **frontend flow** for a **backend constraint**)
- Actual semantics: every backend endpoint is an independent entrance; nothing enforces ordering between `/pay` and `/deliver`

Typical: an order state machine that only writes `UPDATE orders SET status='shipped' WHERE id=?` without checking the current `status` → ship without paying. The root cause is **the missing (from,to) transition allowlist** — the state machine exists in the developer's head, not in the code. Fix: an explicit transition table + `UPDATE ... WHERE id=? AND status='paid'` (conditional updates also solve §4.5's concurrency).

### 4.2 Why Object-Level Authorization Always Leaks (IDOR's Architectural Root Cause)

The single most important entry among logic bugs, worth a full dissection:

- Developer's mental model: "logged in = authenticated = may use every feature of the system"
- Actual semantics: **authentication answers "who are you", not "is this thing yours"** — two orthogonal questions collapsed into one check
- Structural causes at the framework layer:
  1. The granularity of auth middleware (filter/interceptor/AOP) is **URL-level** ("does this endpoint require login"), while authorization failures happen at **row level** ("does this record belong to you");
  2. The data layer has no default expression of row-level ownership — the ORM's `findById(id)` fetches by primary key, without `AND user_id=?`; unless the developer writes it by hand everywhere, which the framework **never enforces**;
  3. So "per-object checks" become a point-by-point manual duty — miss one spot and it's a hole — **IDOR is an architectural default omission, not a mis-written line of code**.

This simultaneously explains three phenomena: it sits permanently in the OWASP top three; code review keeps missing it (no suspicious sink; `findById` looks perfectly normal); the fix can only be pattern-based (a global ORM filter / Postgres RLS row-level security / forcing an ownership predicate into every query) — spot patches never finish. For the black-box object-graph playbook see the skill knowledge base's idor-supplement and the h1 IDOR-to-ATO module.

### 4.3 Missing Idempotency (Replay)

- Mental model: "one request = one user intent"
- Actual semantics: networks retry, proxies replay, attackers capture and resend — **the transport layer does not guarantee intent uniqueness**; the business must provide it itself

Without an idempotency key on coupon-claim/vote/transfer endpoints, sending the same request N times produces N effects. The root cause is **equating "arrived once" with "intended once"**. The fix uses database uniqueness as an atomic gate: first `INSERT INTO idempotency(key)` — a unique-constraint hit means rejection — then run the business logic, reducing a distributed problem to a single-point constraint.

### 4.4 Negative and Boundary Amounts: The Gap Between Type Semantics and Business Semantics

- Mental model: "quantity comes from my dropdown; it can only be 1–10"
- Actual semantics: **the client can rewrite everything**; the type system promises `int` (can be negative, can overflow), not business constraints (≥1)

In `total = price * quantity`, quantity=-1 → a negative total that offsets the bill; `int` multiplication wraps → bypasses the ceiling check; float comparison → `0.1+0.2`-style precision bypasses. Root cause: **business invariants (amount ≥ 0, positive quantity, total ceiling) are never expressed in code — they exist only in the requirements doc**. Even fuzzing struggles to cover these — you need an oracle that knows "this is money".

### 4.5 Concurrency: The Balance-Debit TOCTOU

```
read  balance = 100
check balance >= 80     ✓        ← 两个请求都在此通过
write balance = 100-80 = 20      ← 两次写,双花
```

- Mental model: "requests arrive serially"
- Actual semantics: multi-thread/multi-machine concurrency; the window between check and use gets squeezed open by parallel requests

This is the business-layer projection of the C-level TOCTOU (the kernel re-checking file ownership after `copy_from_user` is the same family). The unified radical form is **atomicizing check and use**: `UPDATE account SET balance=balance-80 WHERE id=? AND balance>=80` and judge success by rows affected — the business layer's `cmpxchg`. The black-box combo chains for business-logic bugs (negatives/replay/concurrent fund loss) are in the skill knowledge base's h1 business-logic-and-races module; the systematic overview cross-links [08-business/business-security.md](../08-business/business-security.md) §1.

### 4.6 Summary: Mental Model vs Actual Semantics

| Bug | Developer's mental model | Actual semantics | Missing mechanism |
|-----|--------------------------|------------------|-------------------|
| State skipping | frontend flow = backend constraint | every endpoint an independent entrance | a (from,to) transition allowlist |
| IDOR | authentication = authorization + ownership | authentication and ownership are orthogonal | row-level ownership forcibly injected |
| Replay | one request = one intent | the transport layer doesn't guarantee uniqueness | idempotency key + unique constraint |
| Negatives/boundaries | parameters come from my form | the client can rewrite everything | business invariants explicitly encoded |
| Concurrent debits | requests are serial | a window exists between check/use | conditional updates (atomicized) |

## 5. Permission-Model Root Causes

### 5.1 The Failure Modes of ACL / RBAC / ABAC

The three models are not advances in security but **administrative compromises under permission explosion**, each with a fixed failure mode:

- **ACL** (subject×resource×action triples): once resources scale, nobody maintains them; the fatal ambiguity is in the **default semantics** — when no entry is found, deny or allow? Default allow ("not prohibited means permitted") is a privilege-escalation bug outright.
- **RBAC** (role = permission bundle): fails at **role accumulation** — a user holding multiple roles gets the union, and the union contains combinations nobody approved (the God role is its limit form); plus "temporary grants" never reclaimed.
- **ABAC** (attribute predicates): fails at **the predicate itself being wrong and untested** — whether `tenantId` comes from the session or the request parameter is a one-word difference spanning tenants; the trustworthiness of attribute sources (in-session vs client-supplied) is the whole ballgame.

### 5.2 The Essence of Privilege Escalation: Where the Check Lives (Edge Checks vs Per-Object Checks)

Horizontal/vertical escalation share one root cause: **the granularity of the authorization check is coarser than the granularity of resource access**.

```
边缘检查(网关/interceptor):  「请求者已登录吗?」——只回答认证
每对象检查(每次 access):      「请求者对 THIS object 有 THIS 权限吗?」

垂直提权 = 管理接口只靠「菜单里不显示」隐藏(hidden route),后端不二次验角色
水平提权 = 业务接口只验登录,资源对象不验属主(§4.2)
```

Both are "check at the edge, use on the inside" structures — the same "wrong validation location" leitmotif as SSRF's first-hop validation and path traversal's premature blocklist. The fix is always pushing the check down to **every object access** (default deny + explicit grant); what frameworks can automate (annotations + ORM filters) exists to lower the point-by-point cost of per-object checks.

### 5.3 CORS/CSRF Root Causes: The Cookie Is a Credential "Relayed" by the Browser

HTTP is a stateless protocol; the cookie is state the browser attaches **automatically** on the user's behalf — hence:

- **The request initiator** (JS/img/form on an a.com page) and **the credential carrier** (the browser's cookie jar) **are not the same party**;
- CSRF = an attacking page sending a request through the browser's hand (credentials arrive automatically; the same-origin policy governs "reading" the response, not "sending");
- A loose CORS config (`Access-Control-Allow-Origin: reflecting any Origin` + `Allow-Credentials: true`) = granting "who may read the response" to origins that shouldn't, completing the last link CSRF lacks;
- SameSite patches the "relay" step (no cookie cross-site); why token-in-header is the radical cure: the initiator must **explicitly know** the token to build the request, while a cookie requires no knowledge at all — turning "implicit carriage" into "explicit presentation" is precisely the code/data separation of §1.4 projected onto the credential layer.

(Per this machine's rules: CORS is not an SRC hunting target; included here only for white-box root-cause understanding.)

## 6. The One-Line Layer: Business / AI / Blockchain / Smart Contracts

- **Prompt injection** (the LLM era's new injection family): the context window is itself an interpreter; instructions and material share one token stream with no grammatical boundary — §1's interpreter-boundary problem in its ultimate form, "natural language as the instruction language", without even quote-style metacharacters. Attack-surface expansion in [09-ai-security/ai-security.md](../09-ai-security/ai-security.md).
- **Why contracts are special** (see [10-blockchain/blockchain-security.md](../10-blockchain/blockchain-security.md) §2): three properties stack —
  1. **Unstoppable**: deployed means eternal; no kill switch (upgradable proxies are the patch, and the proxy storage layout is itself a new root cause — see its §2.9 delegatecall trap);
  2. **Balance is state**: in the EVM, balance is storage; any bug that can write storage directly equals stealing money (in the traditional world, many layers separate memory corruption from fund transfers);
  3. **Reentrancy without locks**: the EVM has no threads, but external calls **yield control flow** — a `call` sending funds to the attacker's contract invokes its fallback; the attacker re-enters the not-yet-updated function from the fallback, equivalent to signal-handler re-entrancy; `transfer/send`'s 2300-gas limit, checks-effects-interactions, and ReentrancyGuard are patches at three levels (its §2.1).
- **Cross-chain bridges/oracles** in one line: the transport step that moves "off-chain facts" into "on-chain state" inherits every validate-use separation problem of §3/§4, amplified by balance-is-state.
- **The AI×blockchain intersection** (Agents holding funds): prompt injection (§6 item one) stacked with balance-is-state — see [10-blockchain/ai-blockchain-crossover.md](../10-blockchain/ai-blockchain-crossover.md).

## 7. The Root-Cause Leitmotifs, Fully Converged (Three Sentences)

1. **Boundary leitmotif**: every interpreter entrance must answer "does user data go through the lexer or through bind" — SQL/XSS/command/SSTI/LDAP/XXE/prompt injection are all this one question.
2. **Timing leitmotif**: wherever there is a time gap or a transformation gap between validation and use, there is a window — SSRF redirect/rebinding, path canonicalization, concurrent debits, DNS TOCTOU are all this one.
3. **Model leitmotif**: wherever the mental model misaligns with actual semantics, the more "correct" the code the more hidden the bug — state machines/IDOR/idempotency/negatives/permission granularity/cookie relaying are all this one.

## 8. Cross-Links

| Destination | Content |
|-------------|---------|
| [root-cause-to-technique-map.md](root-cause-to-technique-map.md) | This piece's sister: the whole-repo 20+ root causes → failure modes/primitives/exploitation/detection/radical cures, the big table |
| [05-web/web-security.md](../05-web/web-security.md) | Vulnerability-class master table/pentest pipeline/WAF (technique layer) |
| [05-web/code-audit.md](../05-web/code-audit.md) | Taint methodology/Java deserialization evolution/CodeQL (audit layer) |
| [08-business/business-security.md](../08-business/business-security.md) | Logic-bug system/accounts & payments (business layer) |
| [10-blockchain/blockchain-security.md](../10-blockchain/blockchain-security.md) | The ten contract bug classes (reentrancy/flash loans/oracles) |
| `~/.zcode/skills/skill/知识库/` | Black-box test checklists (idor-supplement, the h1 high-severity series) |
