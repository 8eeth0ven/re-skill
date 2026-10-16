# 逆向工具雷达(持续发现→学习管线)

不断发现互联网上新的逆向相关工具,评估后流入知识库。由每日定时自动化驱动,也可随时手动让 agent 按「发现流程」跑一轮。

## 文件

| 文件 | 用途 |
|------|------|
| `基线工具清单.md` | 已知工具基线(条数见清单头部),diff 用;**入库新工具后必须追加到此清单**,否则会重复发现 |
| `发现日志.md` | 每轮发现结果增量落盘(日期/工具/链接/一句话/去向) |
| `基线工具清单.md` | 已知工具 diff 底册(**入库新工具后必须追加**) |
| `MCP测试报告.md` / `工具测试报告.md` | 本机 MCP 与工具现况(哪些能用/怎么用) |

## 发现流程(每轮)

1. **发现源**(按优先级,限流就换下一个):
   - GitHub Search API:`https://api.github.com/search/repositories?q=topic:frida+topic:android created:>N天前` / `reverse-engineering`、`android`、`ios`、`ghidra`、`unidbg`、`dynamic-analysis` 等 topic 组合;`sort=stars`
   - GitHub trending:WebFetch github.com/trending?since=weekly 过滤逆向相关
   - awesome 列表 diff:awesome-reversing / awesome-android-security / awesome-frida / awesome-ghidra 的最近 commit
   - 安全论坛工具版新帖(WebSearch site:bbs.kanxue.com 工具)
   - Hex-Rays/Google Project Zero/开发者博客新工具
2. **diff**:新工具名 grep `基线工具清单.md`,只留基线没有的
3. **评估**:每个新工具看 README/GitHub 判断——star 数与增速/是否解决现有库未覆盖的问题/是否活跃。值得入库的打 ★
4. **学习入库**(★ 项):按归类 Edit 进 wiki——Android 逆向工具→`re/手法/05-工具矩阵/工具总表.md` 对应分类(+必要时专项篇);跨平台/其他→`re/平台/` 对应区;同时把工具名**追加进基线清单**
5. **本地冒烟(能装的必须测)**:python 系→`UV_CACHE_DIR=/tmp/uv-cache uv pip install -p ~/.zcode/skills/re/tools-env/.venv/bin/python <包>` 后 import/version 验证;CLI 系(brew/直接下载)→装后跑 --version 或小样本;测完记入日志「冒烟:✓/✗原因」。测试规范与已知坑(venv 无 pip 须用 uv、MCP /tmp 沙箱限制、keystone 不兼容 py3.13)见 `工具测试报告.md`
6. **落盘**:发现日志追加 `## YYYY-MM-DD | 发现 N 项,入库 M 项` + 表格(工具|链接|一句话|归类|入库✓/✗|冒烟);全部轮结果写完结束

## 规则

- 只收逆向/安全分析工具(不收漏洞 PoC 集合、不收教程仓库)
- 信息不足(打不开/空仓)只记日志不入库
- 入库写法遵守库规范:不放作者名/精确 star 数,状态用「可用/新/停更」
