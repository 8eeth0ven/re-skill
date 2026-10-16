# Root 与环境隐藏

> 主题：Magisk/Zygisk/Shamiko/KernelSU/APatch 的隐藏原理、各自的天花板、金融级检测栈的解法顺序。

## 1. Magisk + Zygisk + Shamiko 联动原理

### 1.1 Magisk 的 systemless 基础

- Magisk 不改 /system 分区，而是**修补 boot.img**（改 ramdisk，放 init 脚本与 magiskinit），启动后：
 - `/data/adb/magisk/` 是本体，`magiskd`（daemon）常驻；
 - 用 **overlay/bind mount** 把模块文件叠加挂到 `/system` 上（systemless 修改），卸载即恢复原样；
 - `su` 请求走 `magiskd` → `magisk.db`（授权数据库）判定，弹窗在 Manager app。
- 弱点（检测侧视角）：挂载表（/proc/mounts）、`/data/adb` 路径、zygote 被替换（app_process 劫持历史）都是可扫的痕迹。

### 1.2 Zygisk：官方的注入与隐藏框架

- Zygisk = **Zygote + Magisk 注入**：magiskd 在 zygote 进程里注入一段 loader，zygote 每次 fork 出 app 进程时，loader 检查 DenyList：
 - 进程在 DenyList 里 → **不注入任何东西**，并把 Magisk 造成的挂载对该进程 **unmount（还原）**；
 - 不在 → 注入 zygisk runtime，各模块（如 Shamiko）获得在该 app 进程内运行的机会。
- DenyList 原生语义（Magisk 自带，勾「Enforce DenyList / 遵循排除列表」生效）：**只是「不注入 + unmount 系统修改」**，对 Magisk 自身的隐藏很浅——magiskd 还活着、/data/adb 还在、props 还露。

### 1.3 MagiskHide 为什么死了

- MagiskHide（v23 及以前）：对目标进程做「unmount + 环境清理」，是当年过 SafetyNet/银行检测的主力；
- v24+ 上游**整体移除**：官方理由是对抗检测（尤其是 Google Play Integrity 级别）是无止境军备竞赛、维护成本高、且部分隐藏手法与系统稳定性冲突；把「不注入」的弱化版留给 DenyList，把深度隐藏让给社区（于是有了 Shamiko）。
- 现状（2026）：**MagiskHide 已死，等价能力 = Zygisk + Shamiko**。社区开源替代 DenylistUnmount只还原挂载，效果弱于 Shamiko。

### 1.4 Shamiko：闭源的深度隐藏

- LSPosed 系出品，**闭源 Zygisk 模块**，借用 DenyList 当配置（注意：**要关掉「Enforce DenyList/遵循排除列表」**，开了反而冲突；Shamiko 状态显示笑脸才生效）；
- 两种模式：
 - **黑名单模式**（默认）：对 DenyList 里的进程做比原生 unmount 更彻底的隐藏——unmount 之外还隐藏 Zygisk 自身的存在痕迹（native bridge 状态、注入残留、部分 mount/props 信号）；
 - **白名单模式**：逻辑反转——**所有 app 默认全部隐藏 root（含系统应用）**，只有通过 su 授权的 app 能感知/使用 root。全局一刀切，不用逐个维护列表，对银行类 app（交管 12123 这类顽固户）效果最好。给白名单模式下的 app 授权：`su <应用uid> -c su` 触发授权弹窗。
- 原理层(黑盒观察 + 社区逆向，非官方文档，标「」细节)：Shamiko 在 zygote fork 目标进程的瞬间工作——切 mount namespace、umount magisk 相关树、清 props、伪装状态，让检测代码「看到的世界」是未 root 的世界；由于动作发生在 app 第一条指令执行之前，app 没有时序窗口先观察到「被还原的过程」。
- 检测 Shamiko 本身要靠**间接信号**：异常的挂载拓扑（/proc/mounts 里 tmpfs 数量/位置与官方 ROM 统计模型不符）、`/proc/self/mountinfo` 的 mount id 序列空洞、Zygisk 注入过又隐藏导致的微小时序差——Medium 上有 2025 年的「Detecting Shamiko」专题（arnavsinghinfosec），思路是 mount namespace 行为统计而非特征匹配。

## 2. KernelSU / APatch 与 Magisk 的差异

### 2.1 KernelSU：内核态 su

- 原理：**直接改内核**——内核里 hook `execve`/`syscall`（GKI 内核可用 kprobe 或直接改源码编译），su 授权判定在内核态完成：
 - app 请求 root → 触发内核里注册的钩子 → 内核查授权表（manager 写入）→ 直接以 root 凭证执行；
 - **用户态没有 su 二进制、没有 magiskd、没有 overlay 挂载**——常规 root 检测（扫文件/扫挂载/扫进程）在用户态无靶子。
- 代价：需要适配内核（GKI 2.0 设备友好，老机型/魔改内核痛苦）；root 一旦进内核无法从用户态摘除；旧内核(<4.14)支持差。
- 生态：模块系统兼容 Magisk 模块格式；配合 **ZygiskNext**（独立 zygisk 实现，不依赖 magiskd）补齐 zygisk 生态。

### 2.2 APatch：KernelPatch + 模块化

- 原理：**KernelPatch（KP）**——不重编内核，直接对内核**镜像打补丁**注入能力（像 Magisk 修 boot.img 一样「修 kernel.img」），实现内核态 root；
- 特色：APM（APatch 模块）+ **KPM（Kernel Patch Module，内核补丁模块）**——能在内核里做 hook（syscall 级），是「检测方上 svc」时对抗的钥匙；
- 使用体验向 Magisk 看齐：修 boot 即用、Manager 界面、模块生态。

### 2.3 性价比结论（2026 视角）

| 方案 | 检测面 | 上手成本 | 适用 |
|------|------|------|------|
| Magisk + Zygisk + Shamiko | 挂载/props/包名（Shamiko 兜住大半） | 低（一键刷） | 大多数金融/风控 app |
| KernelSU + ZygiskNext | 用户态几乎无 su 痕迹 | 中（找适配内核；GKI 设备低） | 检测狠、Magisk 被 meitus 判死时 |
| APatch | 同 KSU + KPM 内核 hook 加成 | 中 | 需要内核态对抗时 |
一般顺序：**先 Magisk+Shamiko（便宜），不行换 KernelSU（更静），内核级攻防再上 APatch**。

## 3. HideMyApplist / Zygisk-Assistant

### 3.1 HideMyApplist（HMA）

- 定位：**Xposed/LSPosed 模块**，hook `android.content.pm.PackageManager` 家族：
 - `getInstalledPackages` / `getInstalledApplications`（全量枚举——把 Magisk/LSManager/supersu 包名从结果里滤掉）；
 - `getPackageInfo` / `getApplicationInfo`（点名探测——直接抛 NameNotFoundException）；
 - `queryIntentActivities` / `queryServices` / `getInstalledProviders`（intent 侧信道）；
 - `getPackagesForUid`、`getPermissionGroupInfo` 等长尾 API。
- 配置粒度：按「检测方 app」配模板（对哪个 app 隐藏哪批包名，黑/白名单模板化）。
- **天花板**：只挡 Java 层 PackageManager。挡不住：
 - native 层直接扫 `/data/app` 目录列表（需要 root 才能列别人，但可以 stat 猜路径）；
 - `pm list packages` 走 `Runtime.exec` → 走的是 pm 命令（其输出最终也来自 system_server 的 PMS——LSPosed 的 hook 在 app 进程内，pm 在另一个进程，**HMA 挡不住 pm 命令**，需要配套 hook exec/或由 system 侧方案处理）；
 - `/proc/mounts`、props 等非 PMS 信号。

### 3.2 Zygisk-Assistant

- 定位：配合 Shamiko 使用的 Zygisk 模块，核心作用是**强化 DenyList 的 spawn 隔离**：
 - 处理「DenyList 进程 fork/su 起的子进程」继承痕迹问题；
 - 让 list 内进程的 unmount 更完整（部分场景 Shamiko 管不到的 secondary user / isolated process）；
- 与 Shamiko 关系：社区常见组合「Zygisk + Shamiko + Zygisk-Assistant + HMA」四件套打金融 app；Assistant 关掉自身模块特征，减少「Zygisk 模块存在」这个间接信号。
- 细节随版本变化快，以项目 README 为准（Dr-TSNG/Zygisk-Assistant）。

## 4. Shamiko 处理不了的检测与补丁

### 4.1 mount 检测（残留面）

- Shamiko 只对 DenyList 内进程还原挂载；**非 list 进程（或白名单模式下已授权进程）看到的 mounts 仍带 magisk 痕迹**；
- 更深的检测：`statfs`/`statx`（svc 化）读 `/system` 的文件系统 magic 与挂载源，overlay 特征（`overlay` fs magic 0x794c7630）与只读 tmpfs 都可作信号；
- 补丁方向：内核态方案（KSU/APatch 天然少挂载）或 KPM 改 `statfs` 返回；用户态无解（svc 不可 hook）。

### 4.2 SELinux 状态

- 检测：`security_getenforce` / 读 `/sys/fs/selinux/enforce`；更狠的看 `/proc/self/attr/current` 的上下文——magisk 起的进程上下文可能是 `u:r:magisk:s0`；
- Shamiko 不改 SELinux 策略。补丁：`setenforce 1` 保持 Enforcing + 用 `magiskpolicy` 精细放行（Magisk 新版默认就这样），别全局 permissive。

### 4.3 props 特征（resetprop / MHPC）

高危 props（检测=比对）：

```
ro.debuggable=1        → resetprop ro.debuggable 0
ro.secure=0            → resetprop ro.secure 1
ro.build.tags=test-keys → resetprop ro.build.tags release-keys
ro.boot.verifiedbootstate=orange → resetprop ro.boot.verifiedbootstate green
ro.boot.vbmeta.device_state=unlocked → locked
ro.boot.flash.locked=0 → 1
```
- 工具：`resetprop`（Magisk 内置，直接改内存中的 prop 值，比改 build.prop 干净——系统 props 存在 `__properties` 内存区，resetprop 改的是运行时视图）；
- **MagiskHide Props Config（MHPC）**：Magisk 模块形式，开机构建指纹库（按设备型号把整套 build fingerprint 换成通过认证的样本），对付「指纹黑名单」型检测（Play Integrity 设备完整性）。
- 局限：`ro.boot.*` 来自内核 cmdline/boot 阶段，部分检测直接读 `/proc/cmdline`（svc 可读），resetprop 改不到 cmdline 本体——这是已知残面。

### 4.4 签名/包名残面

- Manager 随机化包名对付点名探测；但「全量枚举后按 APK 签名/特征识别」要靠 HMA 挡枚举本身；
- `pm` 命令路径：native `Runtime.exec("pm list packages -f")` —— HMA 挡不住，需 hook `execve` 过滤参数（frida 时代）或 system 侧模块。

## 5. 常见金融 app 检测栈与解法顺序

### 5.1 典型叠加（从下到上）

```
① 加固壳（梆梆/爱加密/腾讯乐固/娜迦/Bangcle/360）——反调试+反注入+dex 抽取
② 自研/商用 SDK 环境 sweep：root+frida+xposed+模拟器+多开+hook 框架（梆梆 SecShell、娜迦 SecNeuro、网易易盾、顶象、数美、同盾）
③ SSL pinning（okhttp+native 双层，部分 mTLS）
④ 设备指纹与风控上报（即使全过了，异常指纹也会被打标）
```

### 5.2 建议解法顺序（先环境后注入，成本递增）

1. **环境层先干净**：Magisk+Zygisk+Shamiko（白名单模式）+ HMA + Zygisk-Assistant，resetprop 过 props；能装 KernelSU 更好——环境不干净，注入工具再花哨也活不过第一屏；
2. **注入层降特征**：zygisk-frida 或 gadget 内嵌（§对抗篇 3），frida-server 裸跑是最后选择；配合 strongR/自编译去特征；
3. **过壳**：壳的反调试反注入先 patch/绕（对抗篇 2.3/4.3），再做 dex dump；
4. **过 pinning**：最后处理网络层（ssl-pinning绕过.md 的分层脚本）；
5. **风控残面**：能过≠无痕，高频操作仍会被行为指纹标记，测试节奏克制。

## 6. 排障速查（配错时的症状表）

| 症状 | 常见原因 | 修法 |
|------|------|------|
| Shamiko 状态不笑（LSPosed 管理器里） | 开了「遵循排除列表/Enforce DenyList」 | 关掉该开关重启 |
| 白名单模式下 app 拿不到 root | 未走授权流程 | `su <uid> -c su` 触发弹窗 |
| 加了系统证书模块后目标 app 抓包失效 | DenyList unmount 连证书挂载一起还原 | 目标 app 移出 DenyList 或模块路径排除 |
| HMA 配了还是看到 Magisk | 检测走 pm 命令或 native 扫描 | hook execve / 换 system 侧方案 |
| 12123 类 app 仍闪退 | mounts 或 props 残面 | §4 resetprop + MHPC，仍不行换 KernelSU |

## 参考来源

- 社区《Android主流Root方案Magisk和KernelSU的对比和详解》
- Medium《Detecting Shamiko》（2025）
