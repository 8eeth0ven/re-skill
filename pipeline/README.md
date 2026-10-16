# pipeline 分支:全自动 APK 逆向执行器

**一句话**:给一个 APK 路径,零人工跑完「环境体检→信息收集→静态→动态→报告」五阶段,失败自动降级,产出固定目录结构的报告。**本分支是执行器,不是知识库**。

## 用法(agent 入口)

对 <apk> 执行全链(在 re 技能入口说「全自动逆向 / pipeline 跑一遍 / 对 <apk路径> 执行全链」)时:

1. Read 本目录 `pipeline.md`(唯一作业流程,按阶段顺序执行);
2. 对 APK 路径执行全链:`S0 体检 → S1 并行信息收集 → S2 静态 → S3 动态 → S4 报告`;
3. 产物落在 `输出/<包名>-<日期>/`(相对 APK 同级或用户指定目录);
4. 每阶段验收门(文件存在且非空)过了才进下一阶段;失败走降级路径,**不问用户、不停机**;
5. 结束把 `03-report.md` 路径回给用户,并附「未执行项及原因」清单。

命令全部是 subagent 可直接 Bash 执行的真实命令(基准环境 macOS arm64)。

## 定位与衔接

本分支 = **执行器**(固定 DAG 全自动跑出报告);跑完是**起点**:报告的「风险与下一步」「脱壳路线建议」要展开时,转 `../手法/` 对应篇(03-脱壳dump/、02-frida/java层/ 等)按 INDEX 点名开篇;查历史文章/技术佐证走 `../data/` 语料索引。

规则:不在本分支复制手法库知识。

## 文件清单

| 文件             | 用途                                 |    |     |        |
| -------------- | ---------------------------------- | -- | --- | ------ |
| `pipeline.md`  | 核心:五阶段 DAG,命令                      | 产物 | 验收门 | 降级 四列表 |
| `env_check.sh` | 可独立执行的环境体检脚本(exit 0 全绿/1 有黄/2 关键红) |    |     |        |

## 环境基线(以 env_check.sh 实测为准)

- 可用:jadx 1.5.6 / apktool 3.0.3 / adb+SDK(~/Library/Android/sdk) / radare2 / 7z / java 24 / node / uv / timeout(coreutils 9.9) / aapt2(SDK build-tools 36.0.0 内)
- 在装(动态探测,缺失即降级):frida 系与 python 库(unicorn/capstone/androguard/apkid/apkleaks)→ venv `~/.zcode/skills/re/tools-env/.venv`
- MCP:android-emulator ✓(AVD `Medium_Phone_API_36.0` 就绪)、node_repl ✓、WebSearch/WebFetch ✓、ida-pro-mcp(需 IDA 手动启动插件,未启动则跳过)、fofa(无 key 跳过)
