<p align="center">
  <h1 align="center">VCD Analyzer</h1>
  <p align="center">
    一个单文件命令行工具，用于快速检查 Verilog <b>VCD</b> 波形。
    为 RTL 调试、AI Agent 工作流和所有不想打开波形查看器的人设计。
  </p>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/版本-1.6.0-3366cc?style=flat-square">
  <img alt="Python" src="https://img.shields.io/badge/python-3.8+-3366cc?style=flat-square&logo=python&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-3366cc?style=flat-square">
</p>

---

## 为什么需要这个工具？

仿真跑完了一个巨大的 `.vcd` 文件，你想知道 `state[3:0]` 在 17.3 us 到 17.6 us 之间发生了什么。
打开 GTKWave 意味着等 GUI 加载、点层级树、缩放波形、眯眼看数值。这个工具一条命令搞定。

它从设计之初就面向 **AI Agent 辅助调试**：每个命令都有 `--json` 模式，输出紧凑的机器可读结构，
LLM Agent 可以直接读取波形信息，无需图形界面。

面对 GB 级巨型 dump，完整版还提供**索引 sidecar**：一次 `index` 构建（约为源文件的
0.2%）把原本要全文件扫描数分钟的点查询变成亚秒级——而且可以在后台自动完成。

```bash
python vcd_analyzer.py search sim.vcd --condition "state=5" --show data,valid --begin 17us
```

## 快速开始

```bash
# 文件里有什么？
python vcd_analyzer.py info sim.vcd

# 只看时钟和复位
python vcd_analyzer.py list sim.vcd --filter clk,rst

# 100ns 到 200ns 之间发生了什么？
python vcd_analyzer.py dump sim.vcd --begin 100ns --end 200ns --filter state

# valid=1 且 ready=1 同时成立的时刻？
python vcd_analyzer.py search sim.vcd --condition "valid=1,ready=1" --show data

# ready 为低的时候 req 在哪些时刻跳变？
python vcd_analyzer.py search sim.vcd --condition "changed(req),ready=0" --show state

# 多个通道里任意一个握手的时刻？（重复 --condition 即 OR）
python vcd_analyzer.py search sim.vcd --condition "ch0_valid=1,ch0_ready=1" \
                                      --condition "ch1_valid=1,ch1_ready=1"

# 17.55us 时刻所有信号的快照
python vcd_analyzer.py snapshot sim.vcd --at 17.55us --filter state,init_done

# 统计信号翻转次数，哪些是静态的？
python vcd_analyzer.py summary sim.vcd --filter dll_*

# 10GB dump 建一次索引，之后所有查询秒回（完整版）
python vcd_analyzer.py index sim.vcd
```

## 安装：完整版或精简版

两个单文件，零依赖，Python 3.8+。

| | **完整版** `vcd_analyzer.py`（默认） | **精简版** `vcd_analyzer_lite.py` |
|:--|:--|:--|
| 七个查询命令、输出与语义 | 完全一致 | 完全一致 |
| 巨型文件的索引加速 | ✅ 自动构建、自动使用 | ❌ `index` 命令明确提示改用完整版 |
| 多核原生索引构建器 | ✅ 内嵌（arm64/x86-64 Linux、arm64 macOS、x86-64 Windows） | 纯 Python |
| 文件大小 | 约 1.6 MB | 约 180 KB |
| 环境要求 | Python 3.8+（Linux 需 glibc ≥ 2.17） | Python 3.8+ |

```bash
# 最新版（完整版）
curl -fsSL https://raw.githubusercontent.com/neveltyc/VcdAnalyzer/main/vcd_analyzer.py -o vcd_analyzer.py

# 锁定已发布版本（推荐，避免 main 分支更新破坏兼容性）
curl -fsSL https://raw.githubusercontent.com/neveltyc/VcdAnalyzer/v1.6.0/vcd_analyzer.py -o vcd_analyzer.py

# 精简版（纯 Python，无索引功能）
curl -fsSL https://raw.githubusercontent.com/neveltyc/VcdAnalyzer/v1.6.0/vcd_analyzer_lite.py -o vcd_analyzer_lite.py

python vcd_analyzer.py --version
```

无需 pip、无需虚拟环境、无需 PyPI。只要有 curl 和 Python 3.8+ 就能用——适合 CI 容器、EDA 服务器、Docker 构建、Agent 工具链。

## 命令一览

| 命令 | 功能 |
|:------|:-----|
| `info` | 文件概览：时间精度、信号数量、时间跨度、层次结构 |
| `list` | 列出信号路径、位宽和类型 |
| `dump` | 按时间顺序输出时间窗口内的所有值变化 |
| `summary` | 逐信号统计：活跃/静态、变化次数、上升/下降沿 |
| `snapshot` | 指定时刻所有已知信号的瞬时值 |
| `compare` | 两个时刻之间哪些信号变了？ |
| `search` | 条件搜索：找出条件成立的区间，可选观察关联信号 |
| `index` | 构建可选的 `.vcidx` 索引，让巨型文件的点查询瞬间完成（完整版） |

所有命令支持 `--begin` / `--end` 时间窗口（带单位：`fs`/`ps`/`ns`/`us`/`ms`/`s`），
`--filter` 子串或通配符过滤，以及 `--json` 结构化输出。

运行 `python vcd_analyzer.py --help` 查看完整参考。

## JSON 输出

每个命令在 `--json` 下输出紧凑的结构化 JSON。Agent 和脚本可以同时获取
原始 tick 数（`_ticks`）和人类可读时间（`_h`）。

```bash
python vcd_analyzer.py --json info sim.vcd
python vcd_analyzer.py --json search sim.vcd --condition "state=5" --show data
```

## 索引 sidecar（完整版）

- **显式或自动。** `vcd_analyzer.py index sim.vcd` 生成 `sim.vcd.vcidx`
  （约为源文件的百分之一都不到；10GB 级 dump 只需几秒）。也可以什么都不做：
  对 10 MiB 及以上、尚未索引的文件，第一次查询会自动在后台构建，下一次查询
  就快了。更小的文件不会被自动处理（纯扫描几秒内就能回答）；需要时可用
  `index` 对任意大小的文件显式构建。
  `--output PATH` 可存到别处（PATH 必须以 `.vcidx` 结尾）并软链接回
  `<file>.vcidx`；绝不删除已存在的普通文件，链接/构建失败只报告不致命。
- **查询自动使用**新鲜的索引；输出完全一致，只是更快（分钟级点查询变亚秒级）。
- **块大小自动选择。** 点查询要重新解析它所在的索引块，块越小查询越快（1 MiB
  块约 0.1–0.2 秒）；而索引大小随"在块内有变化的（信号, 块）对"增长。构建从
  1 MiB 开始，只有索引超过 dump 的 2% 时才合并相邻块——常见 dump 保持 1 MiB
  （索引约 0.2%）；成千上万个信号处处活跃的宽设计会逐级放大块直到满足预算。
  `index --block-mib N` 可强制指定。
- **新鲜度 = `(文件大小, 纳秒级 mtime)` + 内容指纹**：头部记录大小与 mtime，
  尾部对源文件均匀分布的 8 个 4 KiB 采样（含文件头与文件尾）做哈希，因此
  大小相同、mtime 被保留的另一份 dump（`cp -p`、`rsync -t`、tar 解包）也能
  识别。每条查询只多几次小读取，与文件大小无关。索引陈旧时警告一次并由纯
  解析器回答；源文件疑似仍在被写入时（mtime < 5 秒、lsof 显示被持有、
  Windows 共享冲突）自动重建被跳过并给出提示。1.6.0 生成的索引没有指纹，
  会被视为陈旧并重建。
- **dump 旁边的文件。** 除 `<file>.vcidx` 外，后台构建会保留一个几字节的
  `<file>.vcidx.lock`（单例锁）；只有构建失败时才写 `<file>.vcidx.log`，
  之后构建成功会将其删除。
- 无内嵌原生库的平台上，后台自动构建默认关闭（只会跑慢得多的纯
  Python 路径）——`index` 命令仍可用，并会说明所用机制。
- 环境变量：`VCD_ANALYZER_AUTO_INDEX=0` 关闭后台构建，
  `VCD_ANALYZER_NO_INDEX=1` 完全禁用索引，
  `VCD_ANALYZER_INDEX_THREADS=N` 限制原生构建线程数（默认 min(4, 核数)）。
- 精简版没有这些功能，遇到会明确报错说明。

## 语义说明

- **保留同一时间戳内的多次值变化。** IEEE 1364 允许同一时间戳内对同一信号写多次
  value change（delta-cycle 风格的仿真器）；`dump` 按顺序全部输出，`summary`
  逐次计数。仅仅重复断言信号当前值的记录——连续的重复值，或
  `$dumpall`/`$dumpon` 检查点重发当前值——属于 no-op，不产生变化事件
  （`summary` 的 static/active 统计保持精确）。
- **位拆分总线每个时刻只变化一次。** 重组总线的多个位在同一时间戳变化时，
  `dump`、`summary` 和 `changed()` 只看到一次组装后的值，不会出现跨位的中间值；
  同一位在一个时刻内被写两次仍视为 delta-cycle 变化并保留。
- **向量值按完整位宽比较。** 4 位信号上的 `b11` 与 `b0011` 是同一个值
  （IEEE 1364 左扩展规则），换一种写法不算变化。
- **`summary` 与 `changed()` 计数一致。** 信号的首次出现不算变化：窗口内首次
  出现的信号以该值作为 `init`，并给出 `defined_at`。event 变量每次触发都计数。
- **时间是精确的。** 文本输出保留每一位 tick（`17.534712ms`）；时间参数不是
  tick 的整数倍时会四舍五入并在 stderr 给出警告。缺少或无法解析 `$timescale`
  时按 1ps 处理，并在 stderr 警告。
- **`search` 的条件是 AND 子句，重复 `--condition` 即 OR。** 一个 `--condition`
  是逗号分隔的 AND 项列表，每项是 `SIG=VAL`、`SIG!=VAL` 或 `changed(SIG)`。
  重复该标志后，任一子句成立的时刻即成立（OR-of-ANDs）——每个通道写一个子句，
  就能找出"任意通道握手"的时刻。**不支持串内 OR**：条件字符串里的 `|` 和 `OR`
  是普通文本并会被拒绝，所以误写的布尔表达式会报错，而不是给出一个看似确定的空结果。
- **`changed(SIG)` 是边沿谓词**，在 SIG 跳变的那些时刻为真，并把 `search` 切换到
  event 模式（报告时刻而非区间）。此时要么每个子句都带一个，要么都不带。
  子句里的 level 项读取该 tick 的**结算态**，所以结果不依赖同刻记录的书写顺序；
  而正在跳变的那个信号读取它**在该边沿上取到的值**，因此 `"changed(s),s=1"`
  仍然表示"s 的上升沿"。`changed(a),changed(b)` 要求两者在同一 tick 跳变。
- **条件匹配依据信号的声明类型。** real/realtime 信号按数值比较
  （`dac=3.14`、`dac=100`），绝不按位串——否则它的 `%g` 文本会被读成二进制，
  使 `dac=4` 匹配上一个值为 100.0 的 real。event 变量没有电平，
  `ev=1` 会被拒绝并指向 `changed(ev)`。
- **搜索时间窗口。** 不给 `--end` 时，有效终点是文件最后一个时间戳，
  超出的 `--begin` 会报错。显式 `--end` 超过最后时间戳时，最后已知状态
  会延续到该窗口（与 `snapshot`/`compare` 的 last-known-value 语义一致）。

## 单文件，零依赖

两个版本都是单文件、零第三方 Python 依赖。完整版额外内嵌压缩的原生构建库，
运行时经 C ABI 加载，平台不匹配时自动回退纯 Python。不需要 `pip install`，
不需要虚拟环境——随便放到 Python 3.8+ 环境里就能跑。

## 项目结构

```
src/                  源码模块（在此编辑，Parts 1-9，见 _make.py）
_make.py              打包器：从 src/ 生成两个发行文件（--check 校验）
vcd_analyzer.py       发行物：完整版（生成文件，勿手改）
vcd_analyzer_lite.py  发行物：精简版，纯 Python（生成文件）
native/               Rust 索引构建器 crate + 交叉编译脚本
verify/               pytest + unittest 测试套件
verify/fixtures/      脱敏 VCD 测试波形（不含任何私有路径）
verify/samples/       真实 GitHub VCD 样本，用于冒烟测试
.github/workflows/    CI：发行文件与 src/ 一致、原生库与重新构建结果一致、3.8-3.13 测试
CHANGELOG.md          简洁变更日志，含详细发行说明链接
```

## 开发

两个发行文件都是生成物。在 `src/` 下编辑模块（`_preamble.py` 存放
docstring、版本与全部 import；其余按 `_make.py` 中的 Part 编号），
提交前重新生成：

```bash
python _make.py        # 重建 vcd_analyzer.py 与 vcd_analyzer_lite.py
```

CI 会拒绝发行文件与 `src/` 不一致的提交，并在每次 push 时跑全量测试
（Linux/macOS/Windows，Python 3.8-3.13）；本地先跑测试是可选的。
只有 `_preamble.py` 可以包含模块级 import——各部分共享同一个命名空间。

没有 `native/dist/` 时，`_make.py` 会复用 `vcd_analyzer.py` 中已内嵌的库，
因此只改 Python 不需要 Rust 工具链。原生库用锁定的工具链可复现地构建
（Rust 1.96.0 见 `native/rust-toolchain.toml`，zig 0.16.0，cargo-zigbuild 0.24.0）：

```bash
pip install ziglang==0.16.0 cargo-zigbuild==0.24.0
sh native/build_all.sh                        # -> native/dist/
python _make.py                               # 嵌入
python _make.py --check-native native/dist    # 内嵌库是否等于本次构建？
```

CI 的 `native` 任务每次 push 都做同样的构建，内嵌库与之不一致即失败；
修改 `native/` 后，以它上传的 `native-dist` 产物为准嵌入。

## 测试

```bash
# 完整 pytest 套件（需安装 pytest；pytest-xdist 的 -n auto 可并行）
python -m pytest verify/ -q -n auto

# 仅 unittest（标准库，无需额外安装）
python -m unittest discover -s verify -p "test_cli.py"
```

覆盖 helpers、parser 内部、命令函数、文本/JSON 输出模式、CLI subprocess、
以及三个真实外部 VCD 样本。


## Agent 技能

仓库内置了 [skill/SKILL.md](skill/SKILL.md)，专为 AI 编程 Agent 设计（Codex、Claude Code 等）。
直接从仓库安装即可 — Agent 会自动掌握全部七个命令的用法、根据任务选择正确的命令、
解析 JSON 输出，并遵循成熟的调试工作流。

技能涵盖完整命令参考、决策树、五个工作流模式、条件语法、错误恢复和环境变量调优。

各版本详细变更见 [CHANGELOG.md](CHANGELOG.md) 与
[GitHub Releases](https://github.com/neveltyc/VcdAnalyzer/releases) 页面。

## 许可证

MIT —— 详见 [LICENSE](LICENSE)。&copy; 2026 neveltyc

[English](README.md)
