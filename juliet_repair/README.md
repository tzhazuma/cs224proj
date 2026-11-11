# Juliet CWE-401 修复评测（编译 / LSan / 行为闭环）

本目录负责 Juliet CWE-401 冻结 test 集的**真实修复评测**：让 DeepSeek V4.1 Flash 与
MiMo V2.6 Flash 分别修复 70 个 test bad 单元，然后在本机 WSL 中真实编译、运行
AddressSanitizer/LeakSanitizer，并与原始 bad 程序的可观测输出做差分。所有产物都写在
`juliet_repair/` 内，不修改 `juliet/` 的冻结数据，也不覆盖 `runner/`、`splits/`、
`traditional/`、`benchmark/`、`mimo/` 中的旧结果。

> 结论先行：修复成功不等于“模型说修好了”。只有同时满足
> **编译通过、LSan 不再报泄漏、可观测行为逐行一致、baseline 确实观察到泄漏**，
> 才计入 `strict_pass`。不可观测的单元单独列出，绝不默认算通过。

## 0. 结果摘要（2026-11-12）

正式运行：`runs/deepseek_test70_final`、`runs/mimo_test70_final`。

| 指标 | DeepSeek V4.1 Flash | MiMo V2.6 Flash |
| --- | ---: | ---: |
| 编译通过 / 70 | 70 | 70 |
| LSan 干净 / 70 | 70 | 70 |
| 行为保持 / 70 | 70 | 70 |
| **strict pass / 58 个可观测单元** | **58** | **58** |
| 首次回答即 strict pass / 58 | 58 | 57 |
| 反馈迭代次数 | 0 | 2（1 次真实 double-free，1 次 schema 路径错误） |
| 真实 API 调用 | 70 | 72 |
| 成本（USD） | 0.026990 | 0.005841 |
| prompt / completion tokens | 30,405 / 16,835 | 30,826 / 15,733 |

12 个 LSan 不可观测单元（7 个 `malloc_realloc` latent + 5 个 `..._68` 全局
reachable）不计入 strict 分母；它们仍全部编译通过且行为保持，但不能证明泄漏被移除。
两个模型在 58 个可观测单元上都达到 58/58；差异主要体现在首次通过率、反馈使用和成本。
详见 `report/comparison.md` 与各单模型报告。

> 成本透明：两个 headline run 合计 **$0.032831**（headline 保持不变）；加上解析器
> 开发/冒烟运行的全部真实 API 成本为 **$0.082550**（按 manifest 的 configured 价格、
> provider 返回的 usage 与 cached-token 计算；含 `parser_dev/mimo_test70_v1` 的 $0.005034）。
> 没有用 token 数估算代替账单；每个 run 的 `summary.json` 和 `requests.jsonl` 保存逐次
> usage 与 cost。provider-list 归一化口径（DeepSeek 峰谷价、allowance 独立）见
> `../analysis/cost_normalization.md`；该口径不改变本节 headline 数字。

`runs/parser_dev/deepseek_test70_v1`、`runs/parser_dev/mimo_test70_v2` 是解析器
收紧/放宽过程中的开发运行（不作为 headline）；`runs/*_final` 使用最终解析器，迭代只在
真实编译/LSan/行为失败或路径/schema 错误时发生。`scripts/reevaluate.py` 可对已保存响应
离线复评，不发起新请求。

## 1. 数据与选择

| 项目 | 值 |
| --- | --- |
| 数据集 | NIST Juliet Test Suite for C/C++ v1.3，CWE-401 Memory Leak |
| 冻结子集 | `juliet-cwe401-v1.3-subset-v1`（`juliet/FREEZE.json`） |
| 本次选择 | `split=test, label=bad`，70 个组 / 70 个 bad 单元 |
| 语言 | C 29、C++ 41 |
| 输入冻结 | `inputs/units.jsonl` + `inputs/manifest.json` + `inputs/SHA256SUMS` + `inputs/FREEZE.json` |

冻结输入的 SHA-256 记录在 `inputs/FREEZE.json`，并绑定
`juliet/subset_units.jsonl`、`juliet/FREEZE.json`、`juliet/manifest.json` 的哈希。
`prepare_inputs.py` 默认拒绝覆盖已有输入，必须显式 `--force`。

## 2. 防标签泄漏的输入构造

模型看到的不是原始 Juliet 文件，而是评测端净化后的“bad-only”源码：

1. 删除全部 `/* ... */` 与 `//` 注释（包括 `POTENTIAL FLAW`、`FIX`、`BadSink` 等提示）。
2. 用预处理器求值删除 `OMITGOOD` 区域，只保留 bad 构建实际参与编译的代码。
3. 删除 `INCLUDEMAIN` 区域，模型输入中不含 harness 的 `main()`。
4. 删除只属于 good 路径的全局声明（如 `..._goodG2BData`、`..._goodB2GData`）。
5. 评测端另写一个 probe `main()`，只调用 bad 入口；模型永远看不到 good 实现，
   也看不到“哪个文件是 good 参考”。

自动审计（`inputs/manifest.json` 的 `leak_audit`）检查 `FIX`、`POTENTIAL FLAW`、
`GoodSink`、`BadSink`、`good*` 标识符、`good()` 调用、块注释和行注释。
**70/70 单元审计干净，0 条命中。**

`check_baselines.py` 另外证明净化没有改变程序语义：对每个单元，净化后的输入重新编译、
运行，其泄漏观测与行为行必须和原始 bad 单元完全一致。**70/70 一致。**
原始 bad 源码与 good 源码只存在于评测端，不进入任何模型请求。

## 3. 模型请求

- 入口：`scripts/run_repair.py --model {deepseek,mimo}`。
- 端点：OpenCode Go `https://opencode.ai/zen/go/v1`。
- 模型：`deepseek-v4.1-flash`、`mimo-v2.6-flash`；temperature 0，非推理模式。
- 凭证：从 `/mnt/c/Users/tzh03/.kimi-code/config.toml` 的 `opencode-go` provider
  读入进程内存；脚本不打印、不落盘密钥，所有产物记录
  `"api_key_value_stored": false`。
- 输出 schema：

```json
{"files": [{"path": "<输入文件之一>", "content": "<完整替换文件>"}], "explanation": "<可选>"}
```

`explanation` 允许缺省（MiMo 常省略），但记录 `schema_strict` 与
`explanation_present`；`files` 必须非空、路径必须是输入文件之一、内容不能与输入完全相同。
正式运行中严格 top-level schema 的比例为 DeepSeek 69/70、MiMo 66/70；其余仅返回
`files`（或把 explanation 放在每个 file 对象里），仍可应用为补丁，故不按格式失败处理。
路径白名单防止模型凭空新增文件或覆盖评测端 probe。

每个单元先请求一次；若编译、LSan 或行为失败，再发送**最多一次**反馈请求。反馈只包含
编译器 stderr 尾部、LSan summary、以及可观测输出行的期望/实际值，不包含 good 源码。
所有请求/响应、usage、成本和延迟逐次保存在 run 目录。

## 4. 编译、LSan 与行为判定

编译器与参数（与 `juliet/scripts/build_lib.py` 的冻结方式一致）：

```text
gcc   -std=gnu11   -O0 -g -fsanitize=address -fno-omit-frame-pointer -w -DOMITGOOD
g++   -std=gnu++11 -O0 -g -fsanitize=address -fno-omit-frame-pointer -w -DOMITGOOD
-I <workdir> -I juliet/raw/testcasesupport
<fixed sources> <probe main> build/support/io.o build/support/std_thread.o -lpthread -lm
```

运行时：

```text
ASAN_OPTIONS=detect_leaks=1:abort_on_error=0:exitcode=23
LSAN_OPTIONS=exitcode=23:use_stacks=0:use_registers=0
```

`use_stacks=0:use_registers=0` 是刻意的评测配置：不把栈/寄存器里的悬垂指针当作
LSan 根，避免“修完但栈上残留指针”被误判为无泄漏。全局变量仍作为 LSan 根保留，
因为 `..._68` 变体的唯一指针在全局变量里；关闭全局扫描会把 good 单元里进程生命周期
的支撑分配也误报。

行为判定：probe `main()` 只调用 bad 入口。stdout 通过 pty 捕获（泄漏进程被 LSan
`_exit` 时管道缓冲会丢失输出），去掉空行后逐行比较：

- `behavior_observable`：原始 bad 单元的数据行非空；70/70 可观测。
- `behavior_preserved`：修复程序 stdout 数据行与原始 bad **完全相等**，且 exit code 为 0，
  且没有其他 ASan 错误/超时。
- `leak_removed`：编译成功、LSan 不报泄漏、无其他 ASan 错误、未超时。
- `strict_pass`：`compile_pass && leak_removed && behavior_preserved &&
  baseline_leak_observed`。baseline 未观察到泄漏的单元一律不计 strict pass。

## 5. 指标口径

| 指标 | 含义 |
| --- | --- |
| `compile_pass` | 模型给出的完整文件能编译并链接出可执行文件 |
| `leak_removed` | 编译通过且 LSan 运行干净（无泄漏、无其他 ASan 错误、无超时） |
| `behavior_preserved` | 数据行与原始 bad 完全一致，且退出码 0 |
| `strict_pass` | 以上三项 + baseline 确实可观测泄漏 |
| `strict_evaluable` | baseline 泄漏可观测，因而 strict 判定有意义 |

报告同时给出 **全 70** 与 **58 个 LSan 可观测单元** 两个分母，避免把 12 个不可观测
单元算成“白捡的通过”。

## 6. 已知限制

1. **12 个单元 baseline 在 LSan 下不报泄漏**：7 个 `malloc_realloc` 变体只有在
   `realloc` 失败时才会泄漏初始块，而默认执行路径 `realloc` 成功并随后 `free`；
   5 个 `..._68` 变体把唯一指针放进全局变量，LSan 视为 reachable。它们可以评编译与
   行为，但不能据此声称“泄漏已修复”。
2. **没有故障注入**：没有用 `ulimit`/分配器故障注入强制 `realloc` 失败，因为 ASan
   需要巨大的虚拟地址空间，`RLIMIT_AS` 不可用；`hard_rss_limit_mb` 也不能可靠地让
   `realloc` 返回 NULL。因此这 7 个 latent 单元保持不可观测。
3. **行为只覆盖 stdout 数据行**：没有覆盖文件、网络、全局状态或 API 契约；Juliet
   用例本身以打印值作为可观测语义，这已是该数据集能提供的真实 differential oracle。
4. **Wide-character 输出**：原始 harness 先调用 `printf` 再调用 `wprintf`，stdout 已
   被定向为窄字符流，`wprintf` 静默失败，导致 wchar 用例没有数据输出。评测端的
   probe `main()` 直接调用 bad 入口，使 `printWLine` 成为第一次输出，从而恢复可观测性；
   baseline 与修复程序使用完全相同的 probe，因此差分公平。
5. **一次反馈迭代**：只做一次基于编译器/LSan/行为反馈的修复，不进行多轮搜索；成本与
   调用次数逐单元记录，不用估算值代替真实 usage。
6. **非推理模式**：MiMo 关闭 reasoning（`reasoning_effort=none`），DeepSeek 使用其默认
   非 thinking 配置；两者输出预算均为 8192。

## 7. 目录与命令

```bash
# 1) 冻结 70 个净化输入
python3 juliet_repair/scripts/prepare_inputs.py --force

# 2) 编译/运行原始 bad、good 与净化输入，验证输入未改变语义
python3 juliet_repair/scripts/check_baselines.py --jobs 8 --force

# 3) 真实模型修复（每个模型最多 1 次反馈迭代）
python3 juliet_repair/scripts/run_repair.py --model deepseek --concurrency 8 \
  --out-dir juliet_repair/runs/deepseek_test70_final
python3 juliet_repair/scripts/run_repair.py --model mimo --concurrency 8 \
  --out-dir juliet_repair/runs/mimo_test70_final

# 4) 汇总单模型报告或跨模型对比
python3 juliet_repair/scripts/report.py --run juliet_repair/runs/deepseek_test70_final
python3 juliet_repair/scripts/report.py --run juliet_repair/runs/deepseek_test70_final \
  --run juliet_repair/runs/mimo_test70_final --out juliet_repair/report/comparison.md
```

产物：

| 路径 | 内容 |
| --- | --- |
| `inputs/` | 冻结的净化输入、manifest、SHA256、FREEZE |
| `build/baselines/<unit_key>/` | 原始 bad/good 的编译产物、运行日志、baseline.json |
| `build/sanitized/<unit_key>/` | 净化输入的复编译/复运行核验 |
| `runs/<run_id>/manifest.json` | 模型/端点/价格/输入哈希（不含密钥） |
| `runs/<run_id>/units/<unit_key>/attemptN/` | request、response、patch.diff、eval.json、src |
| `runs/<run_id>/requests.jsonl` | 每次调用的 usage、成本、延迟、响应哈希 |
| `runs/<run_id>/results.jsonl` | 每单元最终四项指标 |
| `runs/<run_id>/summary.json` | 汇总指标与成本 |
| `report/` | 单模型与对比 Markdown/JSON |

## 7.1 自检与审计

```bash
# 手工构造 4 个 control：正确 free、行为改变、不修复、double free
python3 juliet_repair/scripts/selftest.py
# -> PASS，4/4 与预期一致

# 冻结输入哈希、逐单元产物、密钥扫描、strict 口径
python3 juliet_repair/scripts/audit.py \
  --run juliet_repair/runs/deepseek_test70_final \
  --run juliet_repair/runs/mimo_test70_final
# -> status=PASS, problems=[]
```

`selftest.py` 的 control 证明 harness 不是“只要编译过就算过”：删掉 `printLine(data)` 会
被行为差分抓到；不 free 会被 LSan 抓到；double free 会被其他 ASan 错误抓到。
`audit.py` 会重算 70 个输入哈希、检查冻结 Juliet 文件未被改动、核对每个 run 的
70 个 result / request 行数、并扫描 `sk-...`/`Bearer ...` 形式的疑似密钥。

## 8. 复现边界

- 所有 Python 与编译器命令均在 WSL Ubuntu 中执行；Windows 侧只读写同一份文件。
- 没有修改 `juliet/` 下的任何冻结文件；`build/baselines` 与 `build/sanitized`
  都是本目录自己的复编译产物。
- `juliet/build/` 的旧结果未被覆盖；本目录的编译全部写入 `juliet_repair/build/`。
- 模型返回的 `fixed files`、`patch.diff`、编译 stderr、LSan stderr、stdout 均为真实
  运行产物；没有手工编造或修补模型输出。
