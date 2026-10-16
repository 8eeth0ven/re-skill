# 漏洞披露与 CVE 申请(从发现到拿号实操手册)

> 定位:**拿号全流程**——发现漏洞后向谁报、怎么报、多久拿号、被拒怎么办。漏洞怎么挖(根因/利用)不归本文,→ `../平台/11-漏洞根因学/`、`../手法/`;中文 SRC 报告格式 → 全局 rules `vuln-report-format`。
> 时效:**2026-10 联网核实**。CVE 生态 2025-04 起经历资助危机与治理重组(§1.2),各渠道时间线以官方页面为准;标注【过时】的旧说法只作背景,别再照走。

---

## 0. 全景:一条漏洞的三种拿号路径

```
                    你发现了漏洞(已有可复现证据)
                              │
              ┌───────────────┼─────────────────┐
              ▼               ▼                 ▼
      路径A:厂商/CNA      路径B:GitHub SA      路径C:兜底
      (目标有 CNA 或       (开源项目,含        (无 CNA/厂商失联/
       官方 PSIRT/SRC)      第三方上报)         厂商拒收)
              │               │                 │
        官方渠道报送      草案→Request CVE     cve.org 联系表单
        (门户/邮箱/表单)  →72h 内拿号→发布     →MITRE CNA-LR 处理
              │               │                 │
              ▼               ▼                 ▼
        厂商修复+发号     GHSA+CVE 双号       CVE ID(等待期最长,
        (时间线厂商定)    (开源最快路径)       数天~数周)
              └───────────────┴─────────────────┘
                              ▼
              发布后:同步 CNVD/CNNVD(国内认可度,可选)
```

三条路径不互斥:先报厂商(拿修复),厂商不接再走兜底;开源双通道(GitHub SA 拿号 + 厂商知会)。**一个独立可修复漏洞只应有一个 CVE**(CNA Rules:同根因多产品不得拆多号)。

---

## 1. CVE 编号从哪来(2026 现状)

### 1.1 CNA 体系:谁的漏洞找谁

CVE Program 当前的编号分配结构(2026-10 核实):

| 角色 | 职能 | 2026 现状 |
|------|------|-----------|
| TL-Root(Top-Level Root) | 顶级根:CISA(美国)与 MITRE(秘密ariat)各管一棵树 | 2025-04 后结构未变 |
| Root | 中间根(如 GitHub、Red Hat、日本 JPCERT 等管理下属 CNA) | — |
| CNA(CVE Numbering Authority) | 给**自己范围内**的漏洞发号:厂商管自家产品、开源项目管自家仓库 | **500~550+ 家**(2026-04 称 500+,年末官方口径 550+);2026 全年预计发 ~9.6 万个 CVE |
| CNA-LR(CNA of Last Resort) | 兜底:没人管的漏洞归 MITRE CNA-LR | 表单流程见 §1.3 |

**查目标归谁管——只用官方列表**:`https://www.cve.org/PartnerInformation/ListofPartners`(可按名称/国家/Root 过滤)。cvedetails、CVEdetails 类第三方站只做聚合,**不权威**:厂商是否 CNA、范围划到哪条产品线,以官方 partner 页的 Scope 描述为准。找不到 CNA ≠ 拿不到号,走 CNA-LR。

速查常识(拿号前先想"它家自己发号"):
- **微软、Google、Apple、Adobe、Oracle、思科、Linux 内核(kernel.org)、GitHub、Apache、Python/PSF、红帽/SUSE/Canonical、各大云厂**都是 CNA——这些目标**不要**去 CNA-LR 要号,直接报厂商,号由厂商发。
- 国内:**华为、阿里巴巴、字节跳动、腾讯、奇虎 360、奇安信、微众银行、深信服、CNCERT/CNVD** 等均已是 CNA,自研产品漏洞报其 PSIRT/SRC 即可拿 CVE。

### 1.2 【2025-2026 重大变化】治理危机与 CVE Foundation

这段决定 2026 年流程的底层逻辑,必读:

- **2025-04**:MITRE 与 CISA 的 CVE 运营合同一度到期不续(25 年来首次),社区震动;CISA 临时续约 11 个月,2025-04-16 CVE Board 宣布成立独立非营利 **CVE Foundation** 接管长期治理。
- **2026 现状**:CVE Foundation 已实体化运行,数据/编号服务(cve.org、CVE Services API)未中断,对报送者的**操作层面无感**——渠道、表单、CNA 职责照旧。但 MITRE 秘密ariat 角色在过渡中,遇到页面跳转/新旧表单并存(见 §1.3)不要奇怪。
- 同期 NIST 在收缩 NVD 富化角色、CISA 2026-09 提出"质量优先"框架——**号在变多、审核在变严**:低质量报告(无复现、无影响面)2026 年更容易被 CNA 打回。

【过时】"MITRE 独家发 CVE""发邮件给 cve@mitre.org 要号"——2020 年前的话术,早已废弃;CVE ID 从不通过该邮箱分配。

### 1.3 MITRE/CVE Program 官方申请(无 CNA 时的兜底)

**现行入口(2026 核实)**:`https://cveform.mitre.org/` 已 302 跳转到新版 **"Contacting the CVE Program"** 页面(mitre.github.io/mitre-cve-roles),旧 cveform 表单退役中。新版为分类 web 表单,选类型提交:

| 表单类型 | 用途 |
|---------|------|
| CVE ID Requests | 向 MITRE CNA-LR 要号(供应商和漏洞发现者均开放) |
| CVE Record Updates | 更新已有记录 |
| General Support | 一般问题(原 "Other",秘密ariat 分流) |
| Report a Reserved But Public(RBP) | **_reserved 号已被公开使用但记录为空_的举报**(发现别家占坑不填时用) |
| Domain Verification / CNA Registration | 机构向:验证 DNS 域名入 CVE Services、申请成为 CNA |

流程与预期:
1. 表单提交 → 自动回执邮件带追踪号(**记下来**,后续催单/补充全靠它)。
2. CNA-LR 核查:漏洞是否真实、是否真无 CNA 接管、是否与已公开漏洞重复。
3. 通过 → **CVE ID reserved**(拿到 CVE-2026-XXXXX 占号);你补齐描述/受影响版本/参考链接后记录才转 **Published**。只 reserve 不 publish = 别人看到空号,可能被 RBP 举报。
4. 时间线:官方不再承诺固定天数;社区经验**数天到数周**不等,补件、重复疑义会拉长。CNA-LR 明确声明不与漏洞奖励、时效承诺挂钩。

**【澄清:CVE Services ≠ 公众自助拿号】**CVE Services(cve.org 的 API/Web 服务,cveawg)是给 **CNA 及其授权账号**自动化 reserve/publish 记录用的,**不对普通研究者开放注册自助拿号**。外部人拿号的官方路径仍是"目标 CNA → CNA-LR 表单"。看到"CVE Services 自助申请、注册账户拿号"的说法,要么指 CNA 内部操作,要么过时/讹传。

### 1.4 GitHub Security Advisory:开源最快拿号路径

GitHub 是 CNA(管 github.com 上的开源仓库),`仓库 → Security → Advisories` 全在线,免邮件免表单:

1. **建草案**(maintainer):New draft security advisory,填生态系统/包名/受影响版本/严重度(CVSS 在线算)/描述。第三方发现者:走仓库的 **Report a vulnerability**(仓库需配 security policy),私下转给 maintainer。
2. **Request CVE ID**:草案页一键申请。GitHub 以 CNA 身份直接发号(实走 CVE Services),**不公开草案**。官方口径通常 **72 小时内**出号;2025-2026 因提交量创纪录,社区大量反馈拖到 **3~5+ 个工作日**——超了就去 GitHub Support 开工单催(discussion 区成批这类催单帖)。
3. **私下修**:临时私有 fork 里开发修复 PR(注意:私有 fork 不跑 Actions,测试本地跑)。
4. **Publish**:发布 advisory → 同时进入 GitHub Advisory Database(GHSA 号 + CVE 号双标识),可联动 Dependabot 告警、私有 fork 自动删除。
5. 想进 bounty:GitHub Security Advisories 本身无通用赏金,但开源项目可自设 bounty;部分厂商(如 Google 对其 OSS)有 OSS VRP。

典型全程(发现→发布):**1~3 周**;纯拿号环节最快**小时级**(实测案例 §6.1)。

---

## 2. 分目标形态报送渠道对照表(2026-10 核实)

| 目标形态 | 报送入口(主链接) | 拿号方式 | 奖励量级 | 典型时间线 | 关键注意 |
|---------|------------------|---------|---------|-----------|---------|
| 开源软件 | 仓库 security policy / GitHub SA;无 policy 看 SECURITY.md/官网 | GitHub CNA 发号;或项目自身 CNA(Apache/PSF 等) | 多数无;Google OSS VRP 等例外 | 72h~数天拿号;全程 1-3 周 | 先私下报,禁直接开公开 issue |
| Android App/框架 | Android 官方漏洞表单(source.android.com → vulnerability form,归口 Issue Tracker `b/`);SRC 类 app 报各厂 SRC | Google 是 CNA,Android Security Bulletin 发布时发号 | Mobile VRP:T1 $300k/150k、T2 $150k/75k、T3 $45k/22.5k(2025 起) | 月度安全公告节奏;赏金另算 | 报告要素齐全(设备/版本/PoC);与厂商定制 ROM 漏洞走 OEM |
| Android 内核/驱动/Pixel | 同上(Google);上游 Linux 子系统漏洞另报 kernel.org | Google 或 Kernel CNA | Mobile VRP 最高档覆盖内核链 | 修复随公告 | OEM 驱动归 OEM PSIRT |
| Windows/微软全系 | MSRC 研究员门户 `https://msrc.microsoft.com`(在线提交/跟踪/赏金/Zero Day Quest) | 微软自研产品由微软(CNA)发号 | MSRC Bounty 最高 $25 万+(Defender/云上限更高) | Patch Tuesday 节奏,个案数周~数月 | 报告格式好=进 Zero Day Quest;微软对公开时间无固定承诺 |
| Linux 内核 | `security@kernel.org` + 子系统 maintainer抄送 | **kernel.org 2023 起自任 CNA**,对已修 bug 批量回溯发号 | 无赏金 | 修复即公开(不 embargo 预告);CVE 政策=报告后 90 天或补丁落地 30 天(孰先) | 见 §2.1 内核细节;**别直接发公开邮件列表** |
| Apple 全系 | `https://support.apple.com/102549`(product-security@apple.com) | Apple(CNA)随安全更新发号 | Apple Security Bounty 顶格 $100 万+(零点击内核链等) | 随 iOS/macOS 安全更新;回复慢是常态 | 赏金要求可利用 PoC;SRD 设备发现加成 |
| Chrome/浏览器 | Chrome VRP(bughunters.google.com,Chrome 规则页);Firefox:bugzilla.mozilla.org(安全组);Safari 走 Apple | 各自 CNA | Chrome 单项最高 $25 万(沙箱逃逸实付出现过 $25 万) | Chrome 双周发版节奏 | Chrome 漏洞细节随版本公开,赏金需按 VRP 规则先报先得 |
| IoT/工控/通用厂商 | 官网 PSIRT/security 页、security.txt;找不到:CERT/CC 或 CNA-LR | 厂商是 CNA 则发号;否则 CNA-LR;工控可走 ICS-CERT(美国) | 多数无;个别有赏金 | 无标准,数周~数月 | 僵尸厂商:留证据→90 天后自行公开(§5) |
| 国内渠道 CNVD | `https://www.cnvd.org.cn`(注册+实名→漏洞上报) | CNVD 号;**可同步申请 CVE**(通用型经其流程) | 无现金,发**原创漏洞证书** | 归档后每周批量发证;全程约 1-2 个月(§2.2) | 通用型证书需 ~10 个实例;要实名 |
| 国内渠道 CNNVD | `https://www.cnnvd.org.cn`(官网报送/邮件) | CNNVD 号(自有编号体系,非 CVE) | 无现金,无 CNVD 式原创证书体系 | 收录快慢不一 | 定位=国家漏洞库收录;拿 CVE 认可度不如直接走 CNA |

### 2.1 Linux 内核专项(流程最反直觉,单独说)

现行(docs.kernel.org/process/security-bugs.html,2026 核实):

1. **报给谁**:受影响子系统的 maintainer + 抄送 `security@kernel.org`。**不要**发公开邮件列表(LKML/mailing list),不要开公开 issue。
2. **embargo 模型**:内核是**有限 embargo**——修复在 maintainer 私下小圈子开发,但补丁合入公开 git 树即公开,**不再给发行版提前预告**(kernel 团队约 2024 年起退出 linux-distros 预告流程,至今如此)。
3. **CVE 谁发**:kernel.org 自己(2023-02 起自任 CNA)。已修复 bug 会被**回溯批量**编 CVE(社区对此有争议,但现行如此);政策:报告后 90 天、或补丁进入主线 30 天,孰先公开。
4. **linux-distros 列表**(`linux-distros@vs.openwall.org`):发行版互通报 embargo 列表,**会员制**(需现有成员担保 + 接受条款),个人研究者一般不走;其条款:公开后 7 天、总计 14 天孰先必须撤 embargo。上游已修的内核问题,研究员直接公开技术细节不再违规(内核侧本就不留 embargo),但**先给 90 天窗口是行业惯例**。
5. 【过时】"内核漏洞报 MITRE 拿 CVE"——2023 年前流程,现走 kernel CNA;"报 linux-distros 等协调"——对内核不再适用,对**发行版特有组件**(如某 distro 的补丁)仍适用。

### 2.2 国内双轨:CNVD 与 CNNVD

| 维度 | CNVD(cncert.org.cn 体系) | CNNVD(中国信息安全测评中心) |
|------|---------------------------|------------------------------|
| 定位 | 国家信息安全漏洞共享平台 | 国家信息安全漏洞库 |
| 报送 | 官网注册(**需实名认证**)→ 漏洞上报入口,交结构化报告(描述/复现/危害/厂商信息,通常附 doc) | 官网报送入口/邮件(vulpro 邮箱),格式要求严 |
| 漏洞分类 | 通用型(影响某通用产品/平台)vs 事件型(具体站点) | 以收录为主 |
| 证书 | **原创漏洞证书**:通用型需黑盒案例 ~10 起且文档复现 ≥3;事件型限三大运营商中高危。流程:一级→二级→复现→处置→归档,每周对上周归档发证 | 无同类证书体系(支撑单位/报送排名另算) |
| 时间线 | 提交→归档约 1 个月+,发证全程 1-2 个月(公开攻略最快 ~60 天) | 收录时间不定 |
| 与 CVE 关系 | 通用型可经 CNVD 流程申请 CVE(CNVD 是 CNA);但**拿 CVE 最快路径仍是厂商 CNA/GitHub** | 自有 CNNVD 编号,不发 CVE |
| 认可度 | 国内甲方/评奖/求职认可"CNVD 原创证书" | 政企通报语境出现,国际不通行 |
| 适合谁 | 需要国内书面凭证;挖到通用型缺陷的批量实例 | 补充通报 |

实操建议:目标在境外且是 CNA → 直接厂商渠道拿 CVE,**顺手**把公开后的 CVE 同步 CNVD/CNNVD 收录(国内可见);目标失联/无 CNA → CNA-LR 拿 CVE + CNVD 双轨;纯国内 SRC 业务漏洞 → 走 SRC,别硬凑 CVE(认证后漏洞多数不给号,§3)。

---

## 3. 判定关:什么发现才值得报、什么拿不到号

### 3.1 三要件(报前自检)

1. **安全策略被违反**:机密性(未授权读)/完整性(未授权写)/可用性(未授权拒绝服务)至少中一条,能指出被绕过的具体机制(鉴权/沙箱/类型隔离……)。"行为不符合开发者预期"≠漏洞,要有安全后果。
2. **可利用证明**:最小可复现(PoC 或逐条复现步骤)+ 攻击者前置条件说清(未认证?需内网?需本地账号?)。"理论上可以"不报,构造出实际原语再报。
3. **影响范围**:受影响产品与版本区间、默认配置是否受影响、修复版本(若已知)。影响面模糊是 CNA 打回的头号原因。

### 3.2 常见不给号清单(CNA Rules 不适用标准,2026 依旧)

以下类型申请 CVE 大概率被拒,**别浪费排队时间**:

- 需要**纯物理接触/持有设备**才能触发(拆机、Debug 口);
- **Self-XSS**(自己把 payload 打进自己的页面)——除非有额外链路升级为存储/反射;
- **理论 DoS/资源耗尽**:如靠打满包让 TCP 栈抖动、超长串打满 CPU,无结构性缺陷证据;
- **CSRF 登出、UI 点击劫持(纯 UI redressing)** 等无实质安全后果项;
- **HTTP 响应拆分**本身不构成(需接可利用下游);
- **纯暴力破解/垃圾信息/钓鱼**类,无协议层弱点;
- **设计如此(Insecure by Design)**:文档明示的行为、厂商声明 IBD 的功能;
- **未公开发布的软件**(从未可公开获取的内部/定制版)——无公开影响面;
- 仅为**配置错误**且软件默认安全(默认配置无此问题);
- 认证后、仅同租户可触达的"越权",本质是产品功能边界而非缺陷(多归 SRC 业务漏洞,不归 CVE;见下)。

**CVE 与 SRC 认证后漏洞的分野**:SRC 报的业务逻辑漏洞(改价、越权订单)很多拿不到 CVE——不满足"通用软件缺陷+技术安全边界被破坏"。两条线分开走:业务洞→SRC(要赏金),通用洞→CNA(要号)。别拿业务洞去 CNA-LR 排队。

### 3.3 重复与一洞多号

- 同一**独立可修复**漏洞跨多产品:CNA Rules 禁止拆成多个 CVE(一次修复解决=一个号);例外是不同代码库独立修复、协议层缺陷多实现分别修(Samba 与微软各自拿号属此类,Zerologon 即先例)。
- 报前查重:NVD/GHSA/厂商公告/目标 git 历史;已修未公开的 bug(kernel 批量回溯)常"撞已修"——提交前 diff 一下目标版本 fix 记录。
- 撞号处置:CNA 判重复会直接关闭,给你 referenced 到主 CVE;不服→提供"不同根因/不同修复"的证据申诉(§5.3)。

---

## 4. 报告模板(可直接抄)

### 4.1 报告正文模板

```markdown
# [组件名] [漏洞类型] 导致 [核心后果](CVE-2026-XXXXX,待分配)

## 1. 概要
一段话:什么组件、什么版本、什么缺陷、什么前置条件、什么后果、严重度。

## 2. 受影响组件与版本
- 组件:vendor/product
- 受影响:< x.y.z(含默认配置是否受影响)
- 不受影响/修复版本:x.y.z(commit <hash>)
- 平台/前置条件:如需低权限账号、需同一 NAT 内网、需特定编译选项

## 3. 严重度
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N ...(= 9.8 Critical)
(附 CVSS 3.1 备用值,兼容旧系统)

## 4. 技术细节
缺陷位置:文件/函数/行号或 API
根因:哪条安全假设被打破(边界/鉴权/生存期……)

## 5. 复现步骤
1. 环境:docker 镜像或发行版+精确版本
2. 步骤 a/b/c(每步给完整命令/请求)
3. 预期 vs 实际

## 6. PoC
见 4.2 规范;附最小化脚本/请求包

## 7. 影响面
直接危害 + 可组合的后续利用(接管/横向/数据外带);
攻击成本与稳定性(100% 触发/需竞态窗口)

## 8. 修复建议
短期缓解(配置/WAF 规则)+ 根治建议(补丁思路,可附 diff)

## 9. 时间线(随进度更新)
- YYYY-MM-DD 发现
- YYYY-MM-DD 报送 <渠道>(回执号 xxx)
- YYYY-MM-DD 厂商确认/发号/修复
- YYYY-MM-DD 计划公开(建议:报告日+90 天)

## 10. 参考
公开资料/相关 CVE/测试原始输出(附件)
```

### 4.2 PoC 规范:自包含 + 无害化 + 脱敏

**自包含**:
- 单文件可跑(脚本/单个 HTTP 请求包),依赖写明版本;环境用公开镜像或 `docker run` 一行起;
- 不依赖你本机的私有数据/内网 host/抓包文件里的会话;
- 目标读者的验收标准:复制粘贴即可看到"预期 vs 实际"差异。

**无害化(红线)**:
- 只证明到"控制流/数据流被劫持"即停:弹计算器→改 `id`/打印标记;RCE 用 `id`/`whoami`,不用反连真实 C2;
- 禁:删改真实数据、停服生产环境、横向移动、留后门、拖库;演示数据外带用自建的 1 条测试记录;
- DoS 类:在自建实例证明崩溃(带 crash dump),不对线上目标压测;
- 蠕虫化/自动化武器化不写进 PoC。

**脱敏**:
- 请求包里真实的 token/账号/手机号/内网 IP 打码;保留**你自己的**测试账号凭据可明文(注明"测试账号,仅此环境");
- 截图抹掉无关页面元素与个人身份信息;
- 厂商未公开前,PoC 不进公开仓库/网盘直链;发布时随 advisory 公开(或先留索取链接)。

### 4.3 严重度与 CVSS 版本(2026 现状)

- **CVSS 4.0 是现行标准**(FIRST 官方现行页为 v4.0,v3.1 移入存档):新指标组 CVSS-B/BT/BE/BTE,新增 Attack Requirements(AT),废弃 Scope,Temporal→Threat,补充指标组含 Safety/Automatable/Recovery,强化 OT/安全场景。
- 实务:GitHub SA、多数 CNA 已接受 4.0;不少企业风险平台仍按 3.1 计算。**报告里两个都给**(4.0 为主,3.1 括号备查),避免下游换算争议。
- 注意 CVSS ≠ 厂商最终评级:MSRC/Google 均按自家标准定级;别在 CVSS 上和厂商吵架,焦点放影响论证。

---

## 5. 时间线与博弈

### 5.1 各方时间线基准(2026)

| 主体 | 时间线 | 说明 |
|------|--------|------|
| 行业惯例 | 报告后 90 天公开 | Google/MSRC/CNVD 多数成文或默契遵守 |
| Google P0 | **90+30**:厂商 90 天修复+用户 30 天打补丁窗口;修复临近可加 **14 天宽限**;0day 在野仅 **3 天**宽限;周末/节假日到期自动顺延至下一工作日发布 | 2025 年调整后现行,见 projectzero.google 政策页 |
| MSRC | 无固定承诺,按 Patch Tuesday 分发 | 个案 2 周~6 个月;进 Zero Day Quest 可获直接对接 |
| Linux 内核 | 修复即公开;CVE 记录遵循"报告后 90 天/补丁后 30 天孰先" | 无 embargo 预告(§2.1) |
| GitHub SA | 72 小时拿号承诺,现实 3-5+ 工作日,催单走 Support | 全程 1-3 周 |
| CNVD | 归档约 1 个月+,发证全程 1-2 个月 | 通用型证书案例 ~60 天(§6.3) |

### 5.2 embargo 期间的规矩

- embargo 内:细节只留在报告通道与厂商确认的私有渠道;**不要**在会议演讲摘要/朋友圈/CTF 题/商品(卖洞)里露特征;
- 快到 90 天厂商要延期:要**书面**新期限+理由,宽限一次(≤14 天)是行业容忍上限;厂商沉默/拒修 → 按原期限公开(这是 P0 式立场,不是义务;公开前把证据链留全);
- 内核/发行版特有组件的 distro 侧 embargo:公开后 7 天、总计 14 天孰先(Openwall 条款),转发补丁前确认条款允许。

### 5.3 CNA 拒了怎么办(按序升级)

1. **要书面理由**:定位到 CNA Rules 具体条款(不适用清单 §3.2 / 范围外 / 重复);
2. **补证申诉**:同一渠道回复补充"可利用性+影响面"证据;若因"范围内有其他 CNA"被拒,按其指引改投;
3. **换渠道**:
   - 认为归错了 CNA → 官方 partner 列表重查,改投正确 CNA;
   - 无 CNA 愿接 → MITRE CNA-LR 表单(cveform 新版,§1.3),回执号追踪;
   - 开源且 maintainer 不理 → 你fork修复+自行 GitHub SA(对衍生分发的包名行得通时);或直接写公开 advisory(无号的技术披露,PSA/GHSA 社区投稿);
4. **占坑不填的号**:RBP 表单举报;
5. **最终武器**:90 天到期自行公开技术博客(带全部时间线证据)。公开后多数 CNA 会补号(公开压力下重复判定也更谨慎);这是行业常规手段,不是撕破脸。

### 5.4 公开写技术博客的时机

- **最优**:厂商修复已发布 + advisory/号已发 → 48 小时内跟进深度文(补丁 diff 分析、利用条件、检测方法),流量与口碑双收;
- **厂商超期未修**:90 天到期日发布,内容含负责任披露完整时间线(证明流程正当);标题写明"[Coordinated Disclosure]";
- **不要**:embargo 中发(哪怕"暗示性"细节)、修复未铺开就发利用链(给用户留至少一个打补丁窗口,参考 P0 +30 理念);
- 发布渠道:个人博客 + 转发厂商 advisory 链接;同步 GHSA/CNVD 收录;微信号党注意别把未公开细节截图带出去。

---

## 6. 案例:三条走通全程的路(公开记录)

### 6.1 GitHub SA 路线:SpiceDB CVE-2022-21646(开源,小时级拿号)

- **发现**:2021-12 下旬,SpiceDB(开源授权引擎)LookupResources 在交集/排除+通配符组合下权限判定缺陷,可导致越权放行(v1.3.0 受影响)。
- **动作**:repo Security → New draft advisory 建草案(生态系统/包名/版本/CVSS);开**临时私有 fork** 私下修(私有 fork 不跑 Actions,测试本地 `go test` + act);修复先部署到自家生产再公开。
- **拿号**:草案页 Request CVE ID,**1 小时内**收到 CVE-2022-21646(UI 提示最多 3 天)。
- **发布**:修复合入主干、打 release、回填 patched 版本 → publish advisory,GHSA-7p8f-8hjm-wm92 与 CVE 双号生效,v1.3.0 自动标 insecure。
- **全程**:发现到公开约 2 周多。启示:开源自研项目,GitHub SA 是拿号最短路径;但 2025-2026 提交量暴涨后,72 小时承诺已不可靠(§1.4),预留催单余量。

### 6.2 MSRC 路线:Zerologon CVE-2020-1472(微软,披露节奏教科书)

- **发现**:Secura 研究员 Tom Tervoort 分析 Netlogon 远程协议(MS-NRPC):AES-CFB8 固定全零 IV,可把域控机器账户密码置空 → 直接接管 AD 域。
- **报送**:私下报 MSRC 门户;微软归入 2020-08-11 Patch Tuesday 修复,公告以 CVE-2020-1472 发号(CVSS 10.0),初始公告细节极简。
- **公开**:2020-09-11 Secura 发技术博客(复现分析);社区跟进 PoC(9 月下旬)后业界才真正理解其严重性,催动全球紧急修补;微软原定 2020-10 强制 enforcement 推迟至 2021-02。Samba 因独立实现同一协议缺陷,由 Samba 侧另行公告(一缺陷多实现的先例)。
- **启示**:MSRC 号随补丁发,快而稳;但**公告初版几乎没细节**——想让世界重视,修复发布后由你本人发深度技术分析,补足影响论证;强制 enforcement 分阶段是微软大改动的惯用节奏。

### 6.3 CNVD 路线:个人 60 天拿原创漏洞证书(国内双轨)

- **背景**:2025-11 公开攻略(个人白帽,通用型漏洞)。
- **动作**:官网注册+**实名认证** → 漏洞上报入口按官方模板提交(漏洞描述/复现步骤/验证代码/危害等级/厂商信息,附 doc);通用型漏洞按平台口径提供**约 10 个互联网实例**并在文档中详细复现其中 3+。
- **流程**:一级审核(完整性)→ 二级审核 → 复现验证 → 处置 → 归档;归档后平台**每周**对上周满足条件的漏洞批量颁发原创漏洞证书。
- **全程**:提交→拿证约 **60 天**;被驳回常见于材料不齐/案例数不足,补件重排。
- **启示**:CNVD 证书是"国内书面凭证"逻辑(实名+案例数+周期批量),与 CVE 的"技术通用缺陷"逻辑不同;想要 CVE 认可度,同一漏洞仍应走厂商 CNA/GitHub 主线,CNVD 作同步收录。

---

## 7. 主入口速查(只给主门,细节站内搜)

| 渠道 | 入口 |
|------|------|
| CVE 官网/CNA 列表/CNA Rules | https://www.cve.org |
| CVE Program 联系表单(CNA-LR 兜底,原 cveform) | https://cveform.mitre.org |
| CVE Foundation(治理动态) | https://www.thecvefoundation.org |
| GitHub Security Advisories 文档 | https://docs.github.com(→ repository security advisories) |
| MSRC 门户 | https://msrc.microsoft.com |
| Google VRP 总入口/Chrome/Mobile 规则 | https://bughunters.google.com |
| Android 安全报告指引 | https://source.android.com(→ security → report) |
| Linux 内核安全漏洞 | https://www.kernel.org(→ doc → Security bugs);linux-distros:https://oss-security.openwall.org |
| Apple 报告/赏金 | https://support.apple.com/102549 ; https://security.apple.com/bounty |
| Project Zero 披露政策 | https://projectzero.google/vulnerability-disclosure-policy.html |
| CVSS 4.0 | https://www.first.org/cvss/v4.0 |
| CNVD | https://www.cnvd.org.cn |
| CNNVD | https://www.cnnvd.org.cn |
| Mozilla 安全报告 | https://bugzilla.mozilla.org(security 组) |

> 互链:挖洞手法 → `../手法/`;根因分析 → `../平台/11-漏洞根因学/`;Windows/内核 CVE 模式 → `../平台/01-Windows安全/win-vuln/内核池与CVE模式库.md`、`../手法/07-内核级/`;SRC 中文报告格式 → 全局 rules `vuln-report-format.md`。
