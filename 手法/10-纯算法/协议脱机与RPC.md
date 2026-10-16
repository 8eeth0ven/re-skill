# 全协议脱机挂:从 frida RPC 到纯协议重写

> 脱机 = 不跑 app 客户端,协议栈与服务端直接通信。「全协议脱机完成」= 任意业务请求可离线构造、发送、维持会话,服务端无法从协议层区分脱机客户端与真机。
> 交叉引用:算法层还原 → 同目录《纯算还原方法论.md》(本文是其 L3 层的完整展开 + 协议层补全);抓包链路 → `../04-对抗攻防/抓包全场景.md`;unidbg 基础 → 《../05-工具矩阵/模拟执行框架.md》。

## 0. 全文地图

```
目标 app
 │ ①抓包(明文化) ──→ ②参数定位(signed 参数 diff) ──→ ③算法还原(纯算方法论)
 │                                                        │
 │    ┌─────────────────── 算法在哪能跑 ──────────────────┤
 │    │                                                  │
 │  frida RPC(真机跑)   unidbg(本机模拟跑)   纯算重写(离线复算)
 │    └── 三级火箭,按成本递增、按稳定性递增选 ──┘
 │
 ├─ ④协议结构还原(header/序列化/protobuf/长连接)
 ├─ ⑤会话与状态(token/设备注册/风控字段)
 ├─ ⑥防重放对抗(nonce/timestamp/sign 校验推断)
 └─ ⑦脱机挂工程化(队列/指纹池/拟人节奏/TLS 指纹)
        ──→ ⑧验收:全参数可重放 + 会话可维持 + 风控 N 小时无异常
```

## 1. 脱机三级火箭

### 1.1 三级定义(与《纯算还原方法论.md》L1/L2/L3 对齐)

| 级 | 名称 | 算法执行位置 | app 是否需要 | 设备是否需要 | 对应纯算文档层级 |
|---|---|---|---|---|---|
| R1 | frida RPC | 真机/模拟器 app 进程内 | 要(常驻) | 要 | L3 |
| R2 | unidbg 模拟 | 本机 JVM(Unicorn 模拟 so) | 只要 so + apk 上下文 | 不要 | L2 |
| R3 | 纯算重写 | 本机 python/go 复现算法 | 不要 | 不要 | L1 |
「三级火箭」的含义:**从 R1 起步最便宜,R1→R2→R3 逐级推进,每升一级,对 Android 运行时的依赖就少一层**。R1 五分钟能通,R3 可能要两周——但 R3 才是真正意义上的「协议脱机」,前两级只是算法供给的手段。

### 1.2 选型表

| 维度 | R1 frida RPC | R2 unidbg | R3 纯算 |
|---|---|---|---|
| 开发成本 | 小时级(hook+导出) | 天级(补环境) | 天~周级(含魔改还原) |
| 部署形态 | 设备池+frida-server 常驻 | JVM 服务(unidbg-boot-server) | 任意语言进程 |
| 并发/QPS | 单设备低(app 主线程/内部锁瓶颈),靠设备数量横向堆 | 中(单实例线程安全要自己保证,不稳就单线程队列),容器横向扩 | 高(纯计算,无模拟开销) |
| 风控暴露 | **真实设备指纹长期在线,指纹被标记整池报废**;frida 本身可被检测 | 不产生真实设备行为,不污染指纹池;但若算法输入含设备强指纹则拿不到 | 同 R2;且输入含动态 challenge/TEE 时无解(纯算方法论 §1.3) |
| 稳定性 | 最差:app 崩/被杀/版本升级即断 | 中:换版本要重补环境 | 最好:密钥轮换才需重做 |
| 版本迭代维护 | hook 点偏移变了就失效,每次升级重定位 | JNI 调用序列变了要补 | 密钥换=重提 key(DFA 流程可脚本化) |
| 适用 | 摸参数/低频调用/快速验证;算法读不懂时的持久兜底 | 主流生产终点:签名服务器批量供给 | 终极形态;算法可识别(标准/魔改/白盒可攻)时首选 |
经验法则(承接《纯算还原方法论.md》):**先 R1 摸清,再 R2 固化,能 R3 就 R3;输入拿不全(强设备指纹/服务端 challenge)就地停在 R1/R2,不要硬冲 R3**。

### 1.3 何时必须保留 R1(永不下线)

- 算法输入含传感器/TEE attestation/动态下发 challenge(离线构造不出输入);
- 算法版本迭代极快,纯算折旧期小于还原期;
- 只需要低频调用(如登录一次拿 token),设备挂机成本可接受。
此时 R1 要按 §2.3「佬的 RPC」工程化,把设备故障率压到可用 SLA。

## 2. frida RPC 工程化

### 2.1 基础形态(你的 RPC)

正己《安卓逆向这档事》第十七课「你的RPC vs 佬的RPC」:
「你的 RPC」= 会跑通的最小实现:
- frida spawn 目标 app,resume 后 attach;
- 注入脚本里 `rpc.exports = { sign: function(...) { ... } }` 把加密函数导出;
- python 侧 `script.exports_sync.sign(...)` 拿返回值;
- 单设备、单实例、无并发控制,app 一崩整个服务死。
典型用途:验证算法输入输出、低频取参数。它的死穴:每次 spawn 冷启动秒级开销、无并发、无自愈。

### 2.2 进阶形态(佬的 RPC)

社区沉淀的共识:

| 能力 | 做法 |
|---|---|
| 长驻 | spawn 后不退出,进程常驻;`enable_child_gating` 处理多进程 app |
| 批量并发 | 单设备内用 JS 侧队列排队(签名函数多有内部锁,真并发会被串行化);跨设备用设备池分发 |
| 多设备负载 | 每台设备一个 worker 进程,上层按负载/健康度路由;设备指纹与账号绑定关系固定(见 §6.2) |
| 多脚本实例 | 同一进程可 create 多个 script 各自 rpc.exports,按功能拆(sign/token/设备信息各一) |
| 异常自愈 | `script.on('detached')` + 进程死亡检测 → 自动 respawn 重 attach;看门狗进程监控 frida-server 存活(Sekiro 方案核心卖点,91fans/CSDN 教程均强调 app 崩溃概率必须用看门狗兜底) |
| 心跳 | 导出 `ping` 定时调用;超时即判死,触发自愈(Sekiro 长连接自带心跳语义,frida 直连方案要自己做) |
| 网络化 | frida 默认 USB/本地;远程场景用 `frida-server -l 0.0.0.0` + `get_device_manager.add_remote_device(ip:port)`,或干脆上 Sekiro(长连接+注册中心+集群路由,官方文档明示其与 frida-rpc 的差异:frida rpc 走 USB,sekiro 基于长连接适合远程持久化) |
| 接口化 | Arida:FastAPI 包 frida-RPC,直接出 HTTP 接口;或自写 flask/fastapi 网关 |

### 2.3 性能账

- 单次 RPC 调用开销:毫秒级(本机 USB)/数十毫秒(远程)。瓶颈从来不是传输,是**签名函数在 app 内的执行串行化**与设备 CPU。
- 批量 amortize:一次调用攒一批输入,JS 侧 for 循环出参一次返回(RPC 往返次数从 N 降到 1)——批处理是 frida RPC 最大的免费提速。
- 冷启动 spawn(秒级)只做一次,之后全部长驻热调用;绝不做「一次请求 spawn 一次」的反模式。

### 2.4 完整可跑骨架:RPC 服务端(JS)+ Python 客户端(设备池/自愈/心跳)

```javascript
// agent.js —— 注入目标 app 的 RPC 服务端
// 假设已定位:com.xxx.security.SignUtil 的 native 方法 sign(Map) → String
var SIGN_CLASS = "com.xxx.security.SignUtil";

function doSign(paramsObj) {
    var Clz = Java.use(SIGN_CLASS);
    var Map = Java.use("java.util.HashMap");
    var m = Map.$new();
    for (var k in paramsObj) m.put(k, paramsObj[k]);
    return Clz.sign(m);            // 返回签名字符串
}

rpc.exports = {
    ping: function () { return Date.now(); },
    sign: function (paramsObj) {
        var out = null, err = null;
        Java.perform(function () {
            try { out = doSign(paramsObj); }
            catch (e) { err = "" + e; }
        });
        if (err) throw new Error(err);
        return out;
    },
    // 批量 amortize:一次往返出 N 个签名
    signBatch: function (list) {
        var results = [];
        Java.perform(function () {
            for (var i = 0; i < list.length; i++) {
                try { results.push(doSign(list[i])); }
                catch (e) { results.push({ "__err__": "" + e }); }
            }
        });
        return results;
    }
};
```

```python
#!/usr/bin/env python3
# rpc_client.py —— 设备池 + 长驻 + 心跳 + 异常自愈客户端骨架
# pip install frida frida-tools
import frida, time, threading, queue, pathlib, itertools

AGENT_JS = pathlib.Path(__file__).with_name("agent.js").read_text(encoding="utf-8")
PKG = "com.xxx.app"

class DeviceWorker(threading.Thread):
    """一台设备一个 worker:spawn 长驻 + 心跳 + 崩溃自愈"""
    def __init__(self, device):
        super().__init__(daemon=True)
        self.device, self.api, self.alive = device, None, False
        self.q = queue.Queue()
        self._stop = False

    def _boot(self):
        pid = self.device.spawn([PKG])          # 冷启动一次
        self.device.resume(pid)
        time.sleep(8)                           # 等 app 过闪屏/自检,按目标调
        session = self.device.attach(pid)
        session.on("detached", self._on_detached)
        script = session.create_script(AGENT_JS)
        script.load()
        self.api = script.exports_sync          # frida>=12.3;旧版用 script.exports
        self.pid, self.session = pid, session

    def _on_detached(self, reason, *a):
        self.alive = False                      # 触发主循环自愈

    def _heartbeat(self, timeout=10):
        try: return time.time() - self.api.ping() / 1000 < timeout
        except Exception: return False

    def run(self):
        while not self._stop:
            if self.api is None or not self.alive or not self._heartbeat():
                try:
                    self._boot(); self.alive = True
                except Exception as e:
                    time.sleep(5); continue     # 自愈失败退避重试
            try:
                params, result_q = self.q.get(timeout=5)
            except queue.Empty:
                continue
            try:
                result_q.put(("ok", self.api.sign(params)))
            except Exception as e:
                result_q.put(("err", str(e)))
        # stop 后清理略

    def call(self, params, timeout=30):
        rq = queue.Queue()
        self.q.put((params, rq))
        return rq.get(timeout=timeout)

class RpcPool:
    """多设备负载:round-robin 分发到健康 worker"""
    def __init__(self, serials):
        self.workers = []
        for s in serials:
            dev = frida.get_device(s) if s else frida.get_usb_device()
            w = DeviceWorker(dev); w.start(); self.workers.append(w)
        self._rr = itertools.cycle(self.workers)

    def sign(self, params):
        for _ in range(len(self.workers) * 2):
            w = next(self._rr)
            if w.alive:
                st, val = w.call(params)
                if st == "ok": return val
        raise RuntimeError("no healthy worker")

if __name__ == "__main__":
    pool = RpcPool(serials=["emulator-5554", "emulator-5556"])  # frida-ps -D 列 serial
    for _ in range(3):
        print(pool.sign({"ts": str(int(time.time() * 1000)), "path": "/api/list", "body": "{}"}))
```

骨架要点:worker 线程内串行消费(天然规避签名函数内部锁)、`detached` 回调+心跳双保险判死、boot 失败退避重试、池化 round-robin。生产上再补:worker 熔断计数、设备-指纹绑定路由(§6.2)、指标上报。

### 2.5 Sekiro:现成的持久化 RPC 基建

不想自养池子时,Sekiro 是社区主流选择:app 内 frida 注入 sekiro client → 长连接注册到 sekiro server(分组+clientId)→ 业务侧走 HTTP 调 sekiro server 转发到设备。官方文档明示定位:frida-rpc 适合 USB 短连,sekiro 基于长连接适合远程持久化。配套看门狗教程与心跳断连处理见社区帖;yint-tech/sekiro-samples 提供多语言样例。选型:设备在同一机房/USB 可达 → 自养池;设备分散异地 → sekiro。

## 3. 协议还原工作流

### 3.1 总流程

1. **抓包**:全场景链路与断点排查见《../04-对抗攻防/抓包全场景.md》(加密 body→§2.9 hook 加解密、QUIC→§2.6、私有 TCP→§2.13 r0capture 出 pcap)。产出:明文请求/响应样本集(正常流+边界流)。
2. **参数定位**:抓包样本里找「随请求变化、无法本地复算」的字段——signed 参数 diff 法:同接口固定业务参数只改时间发两次,变了的字段就是时效性签名;改 UA/设备字段发两次,观察签名是否跟着变(判断设备字段是否入参)。
3. **算法还原**:走《纯算还原方法论.md》全流程(定位生成点→指纹识别→魔改/白盒分流→DFA/unidbg/纯算)。
4. **协议重写**:本节展开。

### 3.2 请求结构还原

- **header 生成规则**:User-Agent(OkHttp 默认带 OkHttp/x.y.z,部分 app 定制 UA 拼机型)、设备头(device-id/imei/oaaid/umid,来源见 §4 设备注册)、语言/时区/渠道号(channel)。还原成模板函数:`build_headers(ctx)` 按会话上下文填。
- **参数序列化**:
 - json:`Content-Type: application/json` + body 序列化后参与签名时,注意**序列化字节序**(key 排序、空值是否丢弃、数字格式 1 vs 1.0)——签名与 body 都要逐字节一致;
 - form:URL 编码变体(`%20` vs `+`、中文编码)与参数排序(sort by key 是签名前规则,不是 body 规则,两者常不同);
 - protobuf:见 3.3。
- **签名覆盖域**:确认 sign 的输入是「body 还是 path+query+body+timestamp」,从 hook 加密函数入参 buffer 直接看(纯算方法论 §4.4),不要猜。

### 3.3 protobuf 逆向(无 .proto 文件)

工具矩阵:

| 场景 | 工具 | 说明 |
|---|---|---|
| 纯黑盒(只有二进制流量) | `protoc --decode_raw < body.bin` / protoscope 语法 | 打出字段号/wire type/值的树,无需定义 |
| 黑盒解码+重编码 | `blackboxprotobuf` | 自动推断结构 → python dict 往返解码/再编码,支持把推断结果导出成 .proto |
| 有 APK/jar | `pbtk` | 从 Java/C++ 提取 descriptor 转 .proto,GUI 编辑+重放+fuzz;**LITE_RUNTIME 编译时 descriptor 缺失,不可用** |
| LITE_RUNTIME/descriptor 被剥 | IDA 静态还原 | 社区《protobuf 还原——从 IDA 中还原 .proto 文件》 |
黑盒推断的坑:varint/int32/bool 会混淆、repeated 检测依赖样本覆盖、嵌套 message 要逐层 decode_raw。**先收足够多样本再让 blackboxprotobuf 推断,再用「改一字段回放看服务端反应」验证字段语义**——protobuf 逆向的验收在服务端,不在本地解析成功。

### 3.4 长连接协议

- **websocket**:抓包工具直接支持;重写时注意 header 里的 Sec-WebSocket-Key 随机性、鉴权 token 挂在 query 或首帧、ping/pong 间隔。
- **私有 TCP**:
 - 抓包侧:《抓包全场景.md》§2.13(r0capture 出 pcap);
 - 结构还原:帧头(魔数+版本+cmd+seq+body_len)、序列号递增规则、心跳帧间隔、断线重连后的 seq 对齐(部分协议要求 resume 时带最后 ack 的 seq);
 - 重写侧:python asyncio/tcp 或 netty,按协议状态机实现;**seq 与心跳必须严格模拟,否则连接被服务端静默丢弃**。

## 4. 会话与状态管理

协议脱机的半衰期取决于状态管理,不取决于签名算法。要维持的状态:

| 状态 | 来源 | 维护要点 |
|---|---|---|
| 登录态 token | 登录/短信/一键登录接口 | 过期前刷新(被动 401 再刷会被风控记一笔;主动按 expires_in 提前刷) |
| 设备身份 | **设备注册接口(流程先行)** | 见 §4.1,这是顺序上第一件事 |
| 风控 token(t/q/shield 类,每次请求刷新) | 响应 header/body 下发 | 每次响应都检查是否有新 token 回传,本地热替换 |
| cookie/session | Set-Cookie | requests.Session 自动管,但注意域名作用域 |
| 业务上下文(购物车/浏览轨迹) | 业务接口 | 部分风控校验行为链完整性(先 list 后 detail 的顺序) |

### 4.1 设备注册流程先行

顺序铁律:**先跑通「设备注册/激活」拿到合法设备身份,再谈业务接口**。典型流程:
1. 首启:上报设备信息(型号/系统/分辨率/安装列表特征)→ 服务端下发 device-id/device-token;
2. 部分风控要求注册前先过「设备指纹 SDK 初始化」(umid/oaid 体系),此时指纹参数本身可能是 R1 RPC 供给;
3. device-token 与后续所有请求的设备头绑定,换 token 不换设备特征会被关联。
脱机挂要做的:**为每个「虚拟身份」完整重放一次注册流程**,设备参数从一个「合法参数空间」采样(真机型库+真 UA 库),而不是随机字符串。

### 4.2 风控 token 每次刷新

t/q/anti_content 类参数常见「响应里带回新值,下一请求必须用新值」的滚动机制。实现:响应拦截器统一扫描已知 token 字段 → 写回会话上下文;发现 token 跳变(如强制下线/异地)立即停该身份并告警,继续用被标记的 token 发请求等于自杀式取证。

## 5. 重放与防重放对抗

### 5.1 服务端校验逻辑推断

nonce/timestamp/sign 三件套的服务端校验形态(推断,按常见梯度):

| 形态 | 服务端行为 | 探测法 |
|---|---|---|
| 无校验 | sign 对就收 | 固定 nonce 连发 3 次,全 200 → 签名只是摆设 |
| nonce 去重 | 同 nonce 拒绝 | 同 nonce 复用 → 第二次起 4xx「重复请求」 |
| 滑动窗口 | timestamp 偏移超窗(常见 5~10 分钟)拒绝 | 把 ts 改成 ±30min/±1h 探窗口边界 |
| nonce+身份绑定 | nonce 与 uid 绑定去重 | 换 uid 复用同 nonce |
| body 绑定 | sign 覆盖 body,body 改一字节签名失配 | 改 body 不重算 sign → 被拒则 sign 覆盖 body |
**固定 nonce 探测是第一枪**:成本最低、信息量最大。无数「签名校验」实际只校验 timestamp 甚至完全不校验。

### 5.2 绕过与合规实现

- 时钟对齐:脱机挂用 NTP 校准本地钟,timestamp 取服务器 Date 响应头校准的偏移(每身份记一个 clock_skew);
- nonce 生成:按服务端去重键(uid?设备?全局?)选生成域,uuid/计数器/随机均可,关键是**不重复**而非「看起来随机」;
- 滑动窗口内重放:授权测试中证明「窗口内可重放」即为发现,不必真做批量(见 §8 边界)。

## 6. 脱机挂工程化

### 6.1 任务队列

- 上下两层:**业务任务队列**(爬取/压测任务粒度)+ **请求速率整形**(每身份独立令牌桶);
- 幂等去重:任务级指纹(目标+参数 hash)防重发;
- 失败分类重试:网络错误可重试、风控拦截(特定业务码)立即停身份进冷却,绝不无脑 retry。

### 6.2 代理池与设备指纹绑定

铁律:**一个身份 = 一套(设备指纹 + 出口 IP)的长期绑定**。换 IP 不换指纹、换指纹不换 IP,都会被关联网络(graph)风控聚类。实现:身份对象持有 {device_profile, proxy, cookies, tokens};代理质量探测与身份冷却联动。设备指纹包括:device-id 族、UA、TLS 指纹(§6.4)、HTTP/2 settings(akamai 指纹)。

### 6.3 行为模拟:请求间隔拟人

- 间隔分布:不用固定 sleep,从真实用户节奏采样(对数正态拟合;页面停留→连发 3~5 个接口→长停),请求间存在业务因果顺序(list→detail 而非乱序打点);
- 昼夜节律:按目标用户群作息调流量曲线;秒级精准整点爆发(抢购场景除外)是机器人指纹;
- 该节是风控对抗中性价比最高的部分,纯算做得再好,节奏穿帮照样全池标记。

### 6.4 TLS 指纹保持

问题本质:OkHttp(app 原生)与 python requests 的 ClientHello 完全不同(cipher 套件/扩展/ALPN/HTTP2 settings),服务端在 HTTP 语义之前就能用 JA3/JA4/akamai 指纹区分(Scrapfly 实测多 Python 客户端指纹)。
方案(curl_cffi 官方文档+issue):
- **curl_cffi**(lexiforest/curl_cffi):基于 curl-impersonate。官方直接支持自定义指纹:设 `ja3` + `akamai` 字符串(akamai=HTTP2 settings 指纹)再用 `extra_fp` 微调——官方文档的示例就是「如何模拟 okhttp」(curl-cffi readthedocs impersonate/customize);
- 内置预设滞后时(如 chrome133a vs 最新 chrome),手动更新 ja3/akamai 即可(issue #529 有完整步骤);
- 获取目标指纹:抓真机 ClientHello(JA3/JA4)或从社区指纹库存;JA4 相比 JA3 对扩展排序更稳定(Cloudflare 官方文档),服务端越来越用 JA4,模拟时优先对齐 JA4+akamai;
- 极端一致派:直接用 OkHttp 写脱机客户端(JVM 系),TLS/HTTP2 栈与 app 天然一致——放弃 python 生态换指纹零误差,大型项目可选项。

## 7. 案例复盘

### 7.1 某易新闻(资讯类:简单签名的全流程练手)

某易新闻逆向(2024-07)。
推演路径:资讯类 app 签名通常是「路径+参数+时间戳+固定盐 → MD5/自定义 hash」,Java 层或轻量 so;流程=抓包→jadx 定位签名函数→frida hook 验证→纯算重写。教学价值在「全」:从抓包到脱机重放一次走完,适合当三级火箭的入门跑分对象。资讯接口风控弱,固定 nonce 探测(§5.1)常直接暴露「无校验」。

### 7.2 会员商店 api(电商:接口面与状态机的展开)

电商类要点:①接口清单化(商品列表/详情/库存/下单/优惠券)——先建「接口-参数-状态」矩阵再逐个还原;②会话状态重(购物车/coupon 状态影响签名外的业务校验);③下单类接口的防重放最严格(orderId 服务端生成则客户端只防重发);④积分/优惠券接口是逻辑漏洞高发区,协议脱机后便于系统化遍历测试。

### 7.3 支付扫码 URI(资金类:流程分析与安全边界)

支付扫码转账 URI 生成流程分析(2024-12,frida 形态)。
该文形态是「frida 分析生成流程」——即 R1 阶段产物:hook 定位 URI 生成函数,拆解收款方标识/金额/币种/校验段的拼接规则。**边界声明(硬性)**:此类目标仅做技术分析(协议格式/生成流程/校验逻辑),**不做任何真实资金操作、不做批量转账构造、不触碰他人账户**;资金类接口的「重放」验证止步于测试环境或拒付语义分析。《利用frida主动调用小程序云托管API》(2024-12)则是 R1 主动调用形态的直接范例——小程序云函数场景下 frida RPC 调容器内 API,属低对抗高复用样本。
另:网盘秒传(2024-12)是**协议层(不碰算法)脱机**的代表——秒传只需拿到文件哈希+分片哈希的上报协议即可构造,无需逆向任何 so;说明:能走协议语义利用就先走协议,别上来就三级火箭。

## 8. 边界声明

- 脱机技术仅用于:**授权渗透测试/SRC 挖洞(在目标方授权范围内)**、**自研产品的压测与兼容性验证**、**协议安全研究(防重放/风控有效性证明)**;
- 账号批量注册/养号、资金操作(转账/下单支付/薅羊毛)、绕过付费墙——**必须持有书面授权**;无授权即违法(《刑法》285/286 条相关),本文方法论不构成对此类用途的支持;
- 案例复盘中资金类目标(7.3)的分析深度止于「生成流程与校验逻辑」,重放验证止于测试环境;
- 验收清单(§9)中的「风控无异常」指授权测试中验证己方防护有效性,非教唆逃避风控。

## 9. 验收清单:协议脱机完成的判定

| # | 判定项 | 通过标准 |
|---|---|---|
| 1 | 全参数可重放 | 任意业务请求的**全部** header/body 参数(含签名/设备/风控 token)均可在脱离 app 的进程里生成;无「只有真机能算」的遗留参数(R1 供给的输入除外,须在文档标注) |
| 2 | 签名对拍 | 固定输入集,脱机实现 vs 真机输出 100% 一致(含时间戳冻结对拍,纯算方法论 §7.1) |
| 3 | 会话可维持 | 登录态连续保持 ≥24h:token 主动刷新无 401、风控 token 滚动无跳变、cookie 域作用域正确 |
| 4 | 长连接稳定 | (若有)心跳/seq/重连状态机实现,断网重连后服务端不静默丢弃 |
| 5 | TLS 指纹一致 | 脱机客户端 JA3/JA4/akamai 与目标 app 真机抓包一致(JA4 优先) |
| 6 | 防重放结论明确 | 三件套每项的校验形态已探测并记录(无校验/nonce 去重/窗口/body 绑定) |
| 7 | 风控无异常 N 小时 | 授权测试窗口内(建议 ≥24h)无验证码升级、无强制下线、无业务码异常、账号状态正常 |
| 8 | 版本升级预案 | 记录算法依赖点清单(hook 偏移/so 版本/密钥),升级时按《纯算还原方法论.md》§7.3 版本回归流程重跑三件套 |

## 10. 参考案例

- RPC 案例:XX 出行 APP(frida 检测对抗→frida-RPC 调用封装);秀动 APP(魔改 frida 过检测+Python 还原 getToken/Crpsign)
- 工具:unidbg-boot-server(Spring Web 封装/docker/高并发,多线程不稳改单线程队列)、blackboxprotobuf、pbtk(含 LITE_RUNTIME 限制)、protoscope/decode_raw、curl_cffi(okhttp 指纹示例/extra_fp)
