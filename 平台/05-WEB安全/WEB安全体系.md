# WEB安全 知识体系(树节点 1000965,43 节点,16 个二级)

> 分工原则:**具体漏洞类型测试(SQLi/XSS/CSRF/SSRF/IDOR/反序列化/上传/逻辑/竞态等)** 已被 `~/.zcode/skills/skill/知识库/`(40+ 篇)与 `~/.zcode/skills/api-pentest/` 深度覆盖,本区每类只做 1 行总表+互链;本区深挖**知识库视角**内容:渗透测试方法论、协议分析、WAF/防火墙、运维安全、应急响应、社工。
> 树外关联:CTF writeup > Web [1001262](挂在 CTF writeup 1001414 下,非 KCTF 赛事树 1001027)、Android协议分析 [1001535]、Windows解密篇>协议分析 [1000270] — 互链 `../02-Android安全/` 与 `../01-Windows安全/`。

## 1. 网站安全 [1000966] + 基础理论 [1001189]

一句话:网站安全=从「域名解析→CDN→WAF→中间件→应用→数据库」整条请求链上每一环的攻击面收敛。

- **基础理论速览**:同源策略(SOP)与 CORS 放宽边界、Cookie 属性(Secure/HttpOnly/SameSite)与会话 fixation、CSP 内容安全策略、JWT/OAuth/SAML 三种断言模型 → 细节互链 `~/.zcode/skills/skill/知识库/oauth-jwt-test.md`。
- **部署面**(渗透前先认脸):中间件(Tomcat/Nginx/IIS/Apache)历史洞——Tomcat PUT 上传(CVE-2017-12615)、Nginx 解析漏洞/别名穿越(CVE-2017-7529 越界读)、IIS 短文件名/PUT;面板(宝塔/phpMyAdmin/Adminer);网关(APISIX/Kong 的 admin 接口)→ 互链 `api-gateway-test.md`。
- 加固基线:最小版本暴露、目录权限、默认凭据清零、管理面隔离。

## 2. 渗透测试 [1000969] — 本区核心深挖

知识库该节承载完整 PTES/OSSTMM 式流程。代表帖:入门渗透测试的一条路线-WEB安全(按月/周拆学习路线,第4个月即内网渗透+代理隧道);红队课程体系见社区红队书单。

### 2.1 全流程管线(自绘 ASCII)

```
[授权/范围界定]
      │
      ▼
①信息收集 ──被动: whois/ICP备案/CT日志(crt.sh)/GitHub泄露/网盘
│            搜索语法: FOFA/Shodan/Hunter/Quake/Google Dork
│   主动: 子域(subfinder/OneForAll)→存活(httpx)→端口(nmap/masscan)
│          →目录(ffuf/dirsearch)→指纹(Wappalyzer/EHole)→JS资产(LinkFinder)
      │
      ▼
②漏洞扫描 ── xray/AWVS/W13Scan/nuclei(POC模板) + 手工验证
│            Burp 全流量代理为工作台
      │
      ▼
③漏洞利用 ── 公开EXP(CVE复现) / 弱口令 / 逻辑洞 / 社工钓鱼拿初始访问
      │
      ▼
④后渗透 ── 权限维持(webshell/内存马/计划任务) → 凭证抓取(mimikatz)
│           → 内网信息收集 → 代理隧道(frp/Neo-reGeorg/ew) → 横向移动
      │
      ▼
⑤清痕+报告(路径/证据/修复建议)
```

### 2.2 各阶段要点

- **信息收集**:信息收集质量决定后面全部效率。子域→同 C 段→旁站→JS 里的 API/密钥 → 深挖互链 `~/.zcode/skills/skill/知识库/recon-methodology.md`、`js-reverse-guide.md`、`info-leak-test.md`。
  - 被动优先(不触碰目标):证书透明度 `crt.sh`、ICP 备案反查、GitHub/Gitee 泄露(密钥/内部域名)、网盘/文库泄露;测绘语法(FOFA `domain=""`/`icon_hash=""`/`body=""`)。
  - 主动收敛:子域爆破+置换(mutations)+JS 引用提取 → 存活(httpx,过滤 CDN/泛解析)→ 端口分层(全端口 masscan 一次+ top1000 nmap 精扫)→ 目录爆破分层字典(常见+框架特有)+ 备份文件(`.svn/.git/WEB-INF/web.xml`、`.rar/.tar.gz/.bak`)。
  - 指纹决定打法:识别框架/中间件/CMS → 直接对已知 1day 面(nuclei tag),比盲测快一个量级。
- **漏洞扫描**:被动扫描(代理模式:Burp+xray 联动、W13Scan)与主动扫描(nuclei 模板)互补;扫描器结果必手工复核,防误报。
  - 手工主线:登录后全业务流挂代理走一遍,让流量被动过扫描器;再对高危面(支付/找回/上传/导出)手测。
  - API 面:swagger 暴露→对象图批量换 id(→ `~/.zcode/skills/api-pentest/知识库/鉴权与对象图.md`)。
- **利用**:公开 CVE 优先(1day 打未 patched 资产);逻辑洞靠业务流对照 → `../08-业务安全/业务安全.md`;组合链把单洞升级 → `h1-组合攻击链短表.md`。
- **后渗透**:内网本质是信息搜集(社区免费课观点);域渗透四大件(Kerberoasting/AS-REP/Golden/Silver Ticket)、NTLM Relay;隧道按协议选(ICMP/DNS/HTTP 隧道);C2 二开看代表帖 CS 4.4 二开笔记:基础篇、增强篇、CobaltStrike 分析2-beacon解析。
  - 权限维持分级:webshell(易检)→ 内存马(§7.2)→ 计划任务/服务(系统层)→ BIOS/Bootkit(硬件层,树内 Windows>Rootkit/BIOS 互链)。
  - 横向:凭证复用(密码同步率)、fscan 类一键扫网段、WSUS/SCCM/PAM 等管理通道滥用。
- **App 渗透(移动面并入 WEB 打法)**:贝壳APP渗透测试WP(JSBridge 鉴权绕过/TOKEN 落 sdcard 日志/HTTP 明文传 COOKIE)、UNI-APP渗透测试-抓包;更深的 hook/抓包对抗 → `~/.zcode/skills/re/手法/04-对抗攻防/抓包全场景.md`。
  - App 渗透与 WEB 的接口:大部分 App 业务洞最终落在 HTTP 接口层(越权/重放/逻辑),差异只在传输加密(签名/证书校验)与客户端存储;解掉对抗层后回归 WEB 打法。

### 2.3 渗透测试 vs 红队 vs SRC 漏洞挖掘(概念分层)

| 维度 | 渗透测试 | 红队演练 | SRC 挖掘 |
|---|---|---|---|
| 目标 | 已授权系统找洞 | 模拟真实 APT 全链路 | 企业公开范围收漏洞 |
| 约束 | 范围/时间窗口 | 规则书(ROE) | 平台规则+法律边界 |
| 深度 | 单系统纵深 | 初始访问→持久→横向→目标 | 单洞+组合链危害证明 |
| 报告 | 修复导向 | 战术还原+检测差距 | 平台定级 |

知识库的渗透测试节覆盖前两者视角;SRC 视角(本机主流程)→ `~/.zcode/rules/src-value-hunting.md`、`dig-scope-workflow.md`。

### 2.4 工具链矩阵

| 阶段 | 代表工具 |
|---|---|
| 信息收集 | FOFA/Shodan/Hunter/Quake、subfinder、httpx、nmap、masscan、EHole、ffuf、LinkFinder |
| 代理工作台 | Burp Suite(树内 1001520 专节)、mitmproxy、Charles |
| 扫描 | xray、AWVS、nuclei、W13Scan(树内 1001521)、Nessus |
| 利用 | sqlmap(树内 1001522 注入工具)、metasploit、各类公开 EXP |
| 后渗透 | CobaltStrike(4.4 二开帖)、frp/ew/Neo-reGeorg、mimikatz、fscan |
| 密码 | hydra、medusa、Hashcat |

### 2.5 攻击方法 [1001527] 与 ATT&CK 映射

WEB 入口对应 ATT&CK 初始访问(T1190 利用公开应用)+执行(T1505.003 Web Shell)+防御逃逸(T1027 混淆/T1562 禁用安全);Windows 树内另有 ATT&CK 节点 [1001352] 互链 `../01-Windows安全/病毒木马篇.md`。

## 3. WEB漏洞 [1000971] + 漏洞分析 [1001496] — 全类总表(每类 1 行,细节互链)

> 与 skill 知识库分工:本表只做索引;测试手法/Payload/判真全在右列。

| 树子节点 | ID | 一句话 | 互链(skill 知识库) |
|---|---|---|---|
| SQL注入 | 1000967 | 未净化的查询串拼进 SQL | `injection-test.md` |
| XSS | 1000968 | 反射/输入回显到浏览器执行 | `xss-test.md` |
| 存储型XSS | 1001517 | 落库后对所有访客触发 | `xss-test.md` |
| CSRF | 1001515 | 借用户会话发跨站请求 | `csrf-test.md` |
| SSRF | 1001511 | 服务端替攻击者发起内网请求 | `ssrf-test.md` + `h1-手法-SSRF信息泄露与配置.md` |
| 命令注入 | 1001502 | 拼接进系统命令 | `rce-面定位.md` |
| 命令执行 | 1001510 | 直接调用执行函数 | `rce-面定位.md` |
| 代码执行 | 1001514 | eval/动态代码注入 | `ssti-专题.md` |
| 文件包含 | 1001505 | LFI/RFI | `path-traversal-lfi-test.md` |
| 文件读取 | 1001508 | 路径穿越读任意文件 | `path-traversal-lfi-test.md` |
| 上传漏洞 | 1001503 | 上传可执行体 getshell | `file-upload-test.md` + `h1-高危害专项-文件上传链.md` |
| 反序列化 | 1001512 | Java/PHP 对象注入 RCE | `deserialization-test.md` + `deserialization-gadgets.md`(链分析→本文代码审计篇) |
| XXE注入 | 1001507 | XML 外部实体读文件/SSRF | `h1-高危害专项-SQLi反序列化XXE.md` |
| CORS劫持 | 1001513 | 跨域策略过宽(**本机规则:不挖**) | `cors-test.md`(仅资料) |
| JSON劫持 | 1001509 | JSON 接口被第三方页面读取 | `idor-test.md` 对象图思路复用 |
| 逻辑漏洞 | 1001506 | 业务流缺陷 | `../08-业务安全/业务安全.md` + `race-condition-test.md` |
| Java漏洞 | 1000994 | Fastjson/Shiro/Log4j 等 | [代码审计.md](代码审计.md) §4 |
| 信息泄露 | 1001504 | 源码/密钥/备份暴露 | `info-leak-test.md` |
| URL跳转 | 1001516 | 开放重定向 | `open-redirect-test.md` |
| 其他 | 1001519 | 原型污染/缓存投毒/走私等 | `prototype-pollution-test.md`、`cache-poisoning-test.md`、`http-smuggling-test.md`、`websocket-test.md`、`subdomain-takeover-test.md`、`webshell-管理.md` |

组合链视角(多洞串联升级)→ `h1-组合攻击链短表.md`(最优先)。

## 4. 协议分析 [1001395] — 本区深挖

```
应用层:  GraphQL   HTTP/2   HTTP/1.1   WebSocket
            │        Frame      报文      │Upgrade握手
            └────────┴─────────┴──────────┘
                       TLS 1.3(加密层)
                          │
                    HTTP/3 = QUIC(UDP 443,内置 TLS1.3)
```

- **HTTP/1.1**:方法/状态码语义、Keep-Alive、管线化废弃原因;经典走私根源(CL/TE 歧义)→ `http-smuggling-test.md`。
- **HTTP/2**(RFC 9113):二进制分帧+多路复用+HPACK 头压缩;h2c 升级走私、cleartext h2c 后端走私;缓存键歧义。
- **HTTP/3 / QUIC**(RFC 9114):UDP 承载、0-RTT 重放风险、连接迁移(Connection ID);抓包需 quic 解密(wireshark 支持有限)。
- **TLS 1.3**:1-RTT 握手、前向安全默认;中间人调试靠 mitmproxy/Charles 信任根证书;App 侧 SSL Pinning 绕过 → `~/.zcode/skills/re/手法/04-对抗攻防/ssl-pinning绕过.md`。
- **WebSocket**:Upgrade 握手、Origin 校验缺失=跨站 WebSocket 劫持(CSWSH)、鉴权只做一次的会话滥用 → `websocket-test.md`。
- **GraphQL**:introspection 全图泄露、batching 打频控、深度查询 DoS、字段级越权(IDOR 变体)→ `graphql-test.md` + `~/.zcode/skills/api-pentest/知识库/fuzz与业务逻辑.md`。
- **App 私有协议**:protobuf/自定义加密体抓包与还原 → `~/.zcode/skills/re/手法/04-对抗攻防/抓包全场景.md`。
- API 全景(REST/RPC 鉴权矩阵、对象图)→ `~/.zcode/skills/api-pentest/知识库/鉴权与对象图.md`。

## 5. 防火墙 [1001400] + 工具脚本>waf [1001523] — WAF 与绕过概览

### 5.1 WAF 形态与部署位置(自绘 ASCII)

```
用户 → CDN(云WAF:阿里云盾/腾讯T-Sec/创宇盾) → 反代(软件:ModSecurity/Naxsi/雷池)
     → 硬件盒子(F5 ASM/Imperva) → 应用侧 RASP(Contrast/JRASP)
                                        │
              检测引擎:正则/语义分析/机器学习/频次与声誉(树内 1001523 归类为工具)
```

### 5.2 检测原理与绕过概览

- 检测:签名正则(SQLi/XSS 特征)、语义解析(AST 级)、机器学习(异常参数分布)、行为(频次/UA/信誉)。
- 绕过大类:**语法变形**(注释/大小写/编码/等价函数)、**协议层**(分块传输/HPP/参数污染/未覆盖编码路径/多 Content-Type 歧义)、**架构层**(寻找非标端口/直连源站 IP/旧版本缓存)、**资源层**(超长参数、性能耗尽降级)。
- 完整手法与判真 → `~/.zcode/skills/skill/知识库/waf-bypass.md`(本区不重复展开);W13Scan 类插件式扫描器的 waf 检测模块见 §9。
- 防火墙(网络层)与 WAF(应用层)互补;传统防火墙规则绕过(分片/协议隧道)归运维安全视角 §6。

## 6. 运维安全 [1001383]

- **暴露面治理**:管理口(22/3389/6379/3306/9200)公网收敛、堡垒机、跳板。
- **容器与云原生**:Docker 2375 未授权、K8s API 6443 匿名/etcd 2379/dashboard、镜像投递链;互链 `../07-智能设备/` 工控面与 `~/.zcode/skills/ops-pilot/`(部署侧视角)。
- **CI/CD**:Runner 命令执行、制品投毒、secrets 泄露 → `insecure-scm-test.md`、`cloud-ide-codex-rce-chain.md`。
- **配置审计**:错误配置是头类根因(云存储桶、对象列举、密钥硬编码);基线工具(lynis/CIS-CAT)。
- 日志体系:access log 留存与告警是应急响应的燃料(§7)。

## 7. 应急响应 [1001497] — 本区深挖(溯源/取证/持久化排查)

社区代表帖:2025-2月Solar应急响应公益月赛题解(Autopsy/FTK Imager 取证)、第一届Solar杯应急响应挑战赛官方WP(Geoserver 入侵后 webshell 已删,排查残留攻击痕迹)、AI打造Linux工具之启动管理器(持久化排查场景)。

### 7.1 PDCERF 六阶段

```
准备P → 检测D → 遏制C(断网/封IP/下线) → 根除E(清后门/补洞)
                          → 恢复R(重部署/改密钥) → 跟踪F(复盘/加固)
```

### 7.2 排查树(自绘)

```
Linux:进程(ps -aux/top 异常CPU;netstat -antp 外连;lsof -p)
 ├─ 计划任务 crontab -l /etc/cron.* / systemd timer
 ├─ 自启 /etc/rc.local / init.d / systemd / ~/.ssh/authorized_keys
 ├─ 文件 find / -mtime -3 -type f;大小异常的 sh/php/jsp
 ├─ 日志 /var/log/secure·auth(爆破)、wtmp/btmp(last/lastb)、history
 └─ rootkit: chkrootkit / rkhunter
Windows:进程(wmic process get)·服务·计划任务·注册表Run键·事件日志(4624/4625登录,4720建号)·IPC$/net user
Web侧:access log 按 time+uri 聚类还原攻击路径 → 定位 webshell(时间戳/大小/特征)
 ├─ webshell 查杀:D盾/河马/CloudWalker
 └─ 内存马(Java):arthas sc *Filter / javaagent dump class 比对 web.xml 无配置的动态注册类
```

- **溯源**:从首条异常请求回放→入口(CVE/弱口令/上传)→横向路径;IP/UA/工具指纹(sqlmap 默认 UA 等)归因。
- **取证**:内存易失先行(订单:内存>网络连接>进程>磁盘);镜像 dd/dcfldd,分析 Autopsy/FTK Imager/volatility;证据链(哈希固定、时间线)。
- **持久化手法盘点**(查什么):webshell/内存马/计划任务/系统服务/SSH key/后门账户/BOOTKIT;Windows 深层(BIOS/植入)→ `../01-Windows安全/病毒木马篇.md`。

### 7.3 Web 入侵排查实战命令速查

| 目的 | Linux | Windows |
|---|---|---|
| 异常进程/外连 | `ps -aux --sort=-%cpu`、`netstat -antp`、`ls -l /proc/<pid>/exe` | `wmic process get name,commandline`、`netstat -ano` |
| 计划任务 | `crontab -l -u <user>`、`ls /etc/cron.*`、`systemctl list-timers` | `schtasks /query /fo list`、计划任务程序 |
| 自启项 | `chkconfig`/`systemctl list-unit-files`、`cat ~/.ssh/authorized_keys` | 注册表 Run/RunOnce 键、服务 `sc query` |
| 新增/改动文件 | `find / -mtime -3 -type f -size -100k`、`find /var/www -name "*.jsp"` | forfiles 按日期、Everything 按大小排序 |
| 登录痕迹 | `last`/`lastb`、`grep Accepted /var/log/secure` | 事件 4624/4625/4720,`Log Parser` |
| Web 日志取证 | `grep -E "(select|union|eval|whoami)" access.log \| sort \| uniq -c` | 同左(IIS: ex*.log) |

- **webshell 定位特征**:无引用的孤立文件、mtime 与入侵窗口吻合、异常小体积、编码混淆(gzip/base64 长串)、`ANTSWORD`/`cmd` 参数特征;查杀工具误报高时按「时间窗+目录+大小」三条件人工收敛。
- **内存马排查(Java 站)**:比对 web.xml/注解注册的 Filter/Servlet/Listener 与运行时实际类集合(arthas `sc`/`sm`、javaagent dump);Spring 型查 RequestMapping 注解表;Agent 型需 dump transform 后字节码比对。
- **数据库被脱(取证面)**:general_log/mysql-bin 时间窗分析、慢日志异常大查询、应用账号的跨库访问。

### 7.4 溯源与取证规范

- 证据链固定:第一时间 `md5sum` 镜像与关键日志;操作时间线记录(谁在何时做了什么动作);原盘只读,分析在副本。
- 入口还原:日志按攻击链回放(首个 4xx 探测→首个 200 利用成功→webshell 创建→外连),给修复组输出「时间线+攻击面+影响面」三件套。
- 依法报送:重大事件按《网络安全事件应急预案》分级报送;客户数据泄露涉个保法通报义务。

## 8. 社会工程学 [1000970]

### 8.1 攻击分类

| 类型 | 手法 | 技术交叉点 |
|---|---|---|
| 鱼叉钓鱼 | 定制邮件+宏文档/LNK/HTML 重定向 | 宏逆向 → `../01-Windows安全/病毒木马篇.md` 恶意脚本 |
| 凭证钓鱼 | 仿登录页+Adversary-in-the-Middle(Evilginx 类反向代理中继 MFA) | OAuth/会话 → `oauth-jwt-test.md` |
| 水坑攻击 | 目标常访站点植入浏览器洞 | → `../06-二进制漏洞/` 浏览器节 |
| 电话/冒充 | 冒充 IT/供应商诱导重置 MFA | 账号安全 → `../08-业务安全/业务安全.md` §2 |
| OSINT 情报 | LinkedIn/招聘/码云/网盘聚合出组织架构与密钥 | GitHub dork → `insecure-scm-test.md` |

### 8.2 检测与防

- 技术防:DMARC/SPF/DKIM 三件套、URL 沙箱 detonation、密码管理器防键盘记录、FIDO2 硬件钥(AiTM 也难 relay)。
- 流程防:转账/改密双人复核、外部验证渠道(回拨确认);红队钓鱼演练度量点击率/上报率。
- 相邻面:钓鱼攻防帖群《常用钓鱼手法》、《钓鱼文件应急溯源:方法篇》、钓鱼邮件→窃密木马全链(攻击视角正本归 `../08-业务安全/`)。

## 9. 工具脚本 [1000972] — 6 个三级深挖

| 子节点 | ID | 定位 |
|---|---|---|
| Kali | 1001518 | 攻击发行版,工具集管理(信息收集/无线/Exploit) |
| Burpsuite | 1001520 | WEB 测试工作台:Proxy/Intruder/Repeater/Scanner/插件(Turbo Intruder 竞态) |
| W13Scan | 1001521 | 开源被动式扫描器(Python,代理模式+插件式检测,国产) |
| 注入工具 | 1001522 | sqlmap(tamper 绕 WAF)/NoSQL注入工具 |
| waf | 1001523 | waf 检测/识别工具(wafw00f 类)+对抗脚本 |
| 其他 | 1001719 | nuclei/xray/ffuf 等现代链路(见 §2.4) |

Burp 生态深入(插件开发/批量自动化)与 AI 辅助 → `token-spray-ai-dast.md`。

## 10. 其余节点一句话

- **代码分析 [1001382]**:对无源码目标做静态/动态分析定位漏洞,JS 反编译还原 → `js-reverse-guide.md`;二进制面 → `../06-二进制漏洞/`。
- **经验分享 [1001498]**:散帖,已并入各节代表帖。
- **CTF Web**:树挂 CTF writeup>Web [1001262],训练场视角(ssti/反序列化/JS 库洞)互链 `../02-Android安全/恶意样本与CTF.md` §CTF。

## 11. 互链总表

- 漏洞类测试 → `~/.zcode/skills/skill/知识库/`(§3 表)
- API/鉴权 → `~/.zcode/skills/api-pentest/知识库/`
- 白盒 → 本文姊妹篇 [代码审计.md](代码审计.md) + `~/.zcode/skills/secure-code-audit/`
- 业务 → [../08-业务安全/业务安全.md](../08-业务安全/业务安全.md)
- App 侧对抗 → `~/.zcode/skills/re/手法/`
