# CWE-401 传统静态检测适配器（`traditional/static/`）

本目录只负责**传统静态分析**这一条线：把带标签的 C/C++ 翻译单元交给 Clang Static Analyzer 和/或 Cppcheck，归一化 CWE-401（Memory Leak）诊断，输出统一的 JSONL 与指标。它不调用模型、不联网、不修改输入文件，也不覆盖其他工作流的结果。

**当前状态**：适配器、冒烟验证和**正式 Juliet CWE-401 200 单元双工具静态基线**已完成（2026-11-12）。`juliet/subset_units.jsonl` / `juliet/manifest.json` 已冻结（200 单元：100 bad / 100 good，dev 60 / test 140）；正式结果在 `runs/juliet_formal_20261112_clang_cppcheck_gnu/`，未覆盖任何既有 LLM/其他工作流结果。正式数字见 §7，冒烟数字仅用于链路验证，不作为结论。

---

## 1. WSL 工具核验（2026-11-12，未使用 sudo）

| 工具 | 路径 | 版本/状态 | 用途 |
| --- | --- | --- | --- |
| `clang` | `/usr/bin/clang` | `Ubuntu clang version 22.1.8 (1ubuntu1)` | **主工具**：`clang --analyze` 直接调用 Clang Static Analyzer |
| `clang++` | `/usr/bin/clang++` | 同上 | 用 `-x c++` 分析 C++ 翻译单元 |
| `scan-build` | `/usr/bin/scan-build` | 存在（LLVM 22.1.8 工具链；`--version` 不是其支持的参数） | 未使用；单文件适配不需要构建系统包装 |
| `clang-tidy` | `/usr/bin/clang-tidy` | `Ubuntu LLVM version 22.1.8` | 未使用（不是本任务的泄漏规则来源） |
| `cppcheck` | 未安装 | `apt-cache policy` 候选 `2.21.0-1`；已用无 sudo 方式解包验证 | **次工具**，通过 `--cppcheck-bin` 指向可执行文件 |
| `infer` | 未找到 | 不可用 | 未实现/未运行；没有用其他工具冒充 |

Cppcheck 在 Debian/Ubuntu 包里把 `FILESDIR` 编译为 `/usr/lib/x86_64-linux-gnu/cppcheck`，直接解包到 `/tmp` 会找不到 `std.cfg`。本次验证的做法是：`apt-get download cppcheck libtinyxml2-11`、`dpkg-deb -x` 到 `/tmp`，把二进制中的绝对 `FILESDIR` 补丁到 `/tmp/cppcc`，再把 `cfg/` 与 `std.cfg` 放到该目录，最后用一个导出 `LD_LIBRARY_PATH` 的 wrapper 调用。该做法只用于本机验证，**没有把二进制提交进仓库**；正式复现时应优先使用系统已安装的 `cppcheck`，或用同样方式准备后通过 `--cppcheck-bin` 指定。

快速核验命令：

```bash
wsl bash -lc 'clang --version | head -1; clang++ --version | head -1; command -v scan-build; command -v cppcheck; command -v infer'
```

---

## 2. 快速开始

在项目根目录执行（WSL）：

```bash
# 单工具：Clang
python3 traditional/static/static_adapter.py \
  --input traditional/static/fixtures/manifest.jsonl \
  --out traditional/static/runs/my_clang_run \
  --tool clang

# 两个工具写进同一份 predictions.jsonl / metrics.json
python3 traditional/static/static_adapter.py \
  --input traditional/static/fixtures/juliet_smoke_manifest.jsonl \
  --out traditional/static/runs/my_both_run \
  --tool both \
  --cppcheck-bin /path/to/cppcheck \
  --include-dir juliet/raw/testcasesupport \
  --jobs 4
```

输出目录必须不存在或为空；适配器拒绝覆盖已有结果。`--dry-run` 只校验输入和工具可用性，不创建结果。

常用参数：

| 参数 | 说明 |
| --- | --- |
| `--tool clang\|cppcheck\|both` | 可重复；`both` 等价于两个都跑 |
| `--clang-bin` / `--cppcheck-bin` | 二进制路径；也读 `CLANG_BIN` / `CPPCHECK_BIN` |
| `--include-dir` | 传给两个工具的 `-I`；可重复 |
| `--define` | 传给两个工具的 `-D`；可重复 |
| `--clang-arg` / `--cppcheck-arg` | 额外参数；可重复 |
| `--std-c` / `--std-cxx` | 默认 `c11` / `c++17` |
| `--timeout` | 每个（样本，工具）调用的秒数，默认 120 |
| `--jobs` | 并行样本数，默认 1；结果顺序仍按输入顺序 |
| `--filter-cwe` | 只保留 CWE 列表包含该值的样本，例如 `CWE-401` |
| `--assume-cwe` | 给没有 `cwe` 字段的记录补上该 CWE；Juliet manifest 没有 `cwe` 时必需 |
| `--only-label` | `vulnerable` 或 `non_vulnerable` |
| `--limit` | 只跑前 N 条（调试用） |
| `--include-external` | 把头文件等非目标文件中的 CWE-401 也计入预测 |
| `--cppcheck-force` | 给 Cppcheck 加 `--force` |
| `--allow-missing-tools` | 某个工具缺失时继续跑可用工具；默认缺失即报错退出 2 |

---

## 3. 输入格式

### 3.1 单文件记录

JSONL 一行一条；也接受 JSON 数组、`{"samples": [...]}`、`{"units": [...]}`、`{"records": [...]}`、`{"testcases": [...]}`、`{"functions": [...]}`。`{"pairs": [...]}` 会展开为 `vulnerable`/`fixed` 两个成员。

```json
{"sample_id":"leak_malloc","path":"leak_malloc.c","language":"c","label":true,"cwe":["CWE-401"],"split":"dev"}
{"sample_id":"clean_malloc","path":"clean_malloc.c","language":"c","label":false,"cwe":["CWE-401"],"split":"dev"}
```

字段：

| 字段 | 必需 | 说明 |
| --- | --- | --- |
| `sample_id` / `id` / `idx` / `pair_id` | 否 | 样本 ID；缺失时生成 `sample-00001`；重复时追加 `#2` |
| `path` / `file` / `source_path` | 二选一 | 相对路径先按 manifest 所在目录解析，再按当前目录解析 |
| `code` / `func_body` / `source` / `body` | 二选一 | 内联代码；写入 `<out>/work/` 后分析 |
| `sources` / `source_files` / `files` / `paths` | 否 | 多文件单元；字符串列表或 `{"path": ...}` 对象列表；见 §3.3 |
| `language` / `lang` | 否 | `c` 或 `cpp`；否则按扩展名推断 |
| `label` / `is_vulnerable` / `vulnerable` | 强烈建议 | 布尔值；也接受 `true/false`、`1/0`、`vulnerable/non_vulnerable`、`bad/good` 等 |
| `cwe` / `cwe_list` / `cwes` | 否 | 字符串、整数或列表；`CWE-415CWE-401` 连写会拆成 `CWE-415`、`CWE-401` |
| `defines` / `macro_defines` | 否 | 该样本额外的 `-D`，字符串列表；自动去掉前导 `-D` |
| `include_dirs` / `include_paths` | 否 | 该样本额外的 `-I`，字符串列表；按 manifest 目录/当前目录解析 |
| `split` / `subset` | 否 | 只用于分组指标 |
| `project` / `function` / `pair_id` | 否 | 只用于报告/追溯 |
| `line_start` / `line_end` | 否 | 只统计目标行区间内的诊断；用于函数级或区域级标签 |
| `preamble` | 否 | 在代码前插入的文本；Juliet 用 `#define OMITGOOD 1` / `#define OMITBAD 1` |
| `notes` | 否 | 原样保留在输入中，不进入输出 |

也直接兼容 `datasets/independent_200.json` 和 `splits/*.json` 的 SecVulEval 记录：`func_body` 会作为内联代码，`filepath` 只用于推断扩展名，`is_vulnerable` 作为标签，`cwe_list` 作为 CWE 列表。注意：SecVulEval 的函数是**抽取片段**，不是可编译翻译单元，Clang 会大量编译失败；这是真实限制，不是适配器静默丢弃。

### 3.2 相对路径

`path`/`sources` 先按 manifest 文件所在目录解析；若该路径不存在，再按当前工作目录解析。这样既能处理“manifest 放在数据旁边”的常规布局，也能直接消费 Juliet 工作流生成的 `juliet/...` 项目相对路径（manifest 位于 `juliet/` 时不会重复前缀）。`include_dirs` 同样按这两级解析。

### 3.3 多文件单元（`sources`）

`sources` 非空时，元素可以是路径字符串，也可以是 `{"path": "..."}` 对象（Juliet `manifest.json` 的 units 使用后者；`subset_units.jsonl` 使用前者）。适配器在 `<out>/work/` 生成一个包装翻译单元：

```c
#define OMITGOOD 1
#define INCLUDEMAIN 1
#include "/abs/path/..._54a.c"
#include "/abs/path/..._54b.c"
...
```

Clang 会额外加 `-Xclang -analyzer-opt-analyze-headers`，并对所有被包含的源文件做路径敏感分析；诊断归属到 `sources` 中任意文件都算命中。这适合 Juliet 的 flow-variant 组（例如 `_54` 的 a–e 五个文件）。它是“整组近似为一个 TU”，不是跨 TU 的链接时分析；Cppcheck 仍可能漏报。若一个组的所有函数都在一个文件里，直接用 `path` 即可。

Juliet 的 bad/good 由宏控制，`preamble` 必须按标签设置，例如：

```json
{"sample_id":"juliet_54_bad","sources":["...54a.c","...54b.c","...54c.c","...54d.c","...54e.c"],"language":"c","label":true,"cwe":["CWE-401"],"preamble":"#define OMITGOOD 1\n#define INCLUDEMAIN 1\n"}
{"sample_id":"juliet_54_good","sources":["...54a.c","...54b.c","...54c.c","...54d.c","...54e.c"],"language":"c","label":false,"cwe":["CWE-401"],"preamble":"#define OMITBAD 1\n#define INCLUDEMAIN 1\n#include <alloca.h>\n"}
```

`#include <alloca.h>` 是 Linux 上 Juliet `ALLOCA` 宏需要的；不是所有用例都需要，但加上无害。也可以不用 `preamble`，而在记录的 `defines` 里写 `["INCLUDEMAIN", "OMITGOOD"]`（坏单元）或 `["INCLUDEMAIN", "OMITBAD"]`（好单元），适配器会作为命令行 `-D` 传入。

**C++ 多文件组的注意点**：如果组内多个 `.cpp` 共享一个没有 include guard 的头（例如 `_81.h`），把它们合成一个 TU 会触发 `redefinition`，适配器会如实记为 `compile_error`。这类组应按单文件/单 TU 拆分，或只选择兼容的源文件；不要为了跑通而修改 Juliet 源码。

### 3.4 行区间归属

同一文件可以出现多条记录，用 `line_start`/`line_end` 区分函数或区域。诊断的 `line` 落在区间内才计入该记录；否则只保留在 `diagnostics` 中并标记 `counts_as_finding=false`。这只做行号过滤，不做函数边界推断；需要严格函数级时，应让数据清单给出精确区间，或把函数拆成独立翻译单元。

---

## 4. 输出格式

```text
<out>/
  predictions.jsonl     # 一行一个（样本，工具）
  metrics.json          # 混淆矩阵、P/R/F1、macro-F1、MCC、Wilson 区间、分组、计时
  metrics_verified.json # 可选：verified_subset.py 生成的运行时支持标签子群指标
  metrics.md            # 中文摘要表
  manifest.json         # 输入/输出 SHA-256、适配器哈希、工具版本、命令、设置
  raw/                  # 每次调用的 stdout/stderr/命令行，逐字保留
  work/                 # 内联代码、preamble 包装、多文件包装 TU
```

### 4.1 `predictions.jsonl` 一行

```json
{
  "schema_version": "static-cwe401-v1",
  "method": "clang-static-analyzer",
  "tool": "clang",
  "sample_id": "juliet_char_calloc_54_bad",
  "sample": {"source_paths": ["..."], "language": "c", "label": true, "cwe": ["CWE-401"], "line_start": null, "line_end": null, "defines": ["INCLUDEMAIN", "OMITGOOD"], "include_dirs": ["..."]},
  "source": {"analyzed_path": "<out>/work/00009_....c", "origin_path": null, "origin_paths": ["..."], "analyzed_sha256": "...", "origin_sha256": "...", "generated": true, "combined": true},
  "label": true,
  "prediction": {"is_vulnerable": true, "cwe": "CWE-401", "finding_count": 1},
  "diagnostics": [
    {
      "tool": "clang", "checker": "unix.Malloc",
      "severity": "warning", "message": "Potential leak of memory pointed to by 'data'",
      "file": "/abs/..._54a.c", "line": 38, "column": 1,
      "trace": [{"file": "...", "line": 101, "column": 5, "message": "Calling '...'"}],
      "cwe": ["CWE-401"], "is_cwe401": true,
      "in_target_file": true, "in_target_region": true, "counts_as_finding": true
    }
  ],
  "diagnostic_counts": {"total": 1, "cwe401": 1, "target_file": 1},
  "status": "ok",
  "runtime": {"started_at": "...", "ended_at": "...", "duration_seconds": 0.12, "exit_code": 0, "timed_out": false},
  "errors": [],
  "command": ["clang", "--analyze", "..."],
  "cwd": "/abs/source/dir",
  "raw": {"stdout": {"path": "raw/...stdout.txt", "sha256": "...", "bytes": 0}, "stderr": {"path": "...", "sha256": "...", "bytes": 123}, "command": {"path": "...", "sha256": "..."}},
  "report": null
}
```

`status`：

| 值 | 含义 |
| --- | --- |
| `ok` | 工具正常完成，诊断可用 |
| `compile_error` | 编译器/解析器报错（Clang `error:`/`fatal error:`，Cppcheck `syntaxError`/`cppcheckError`）；原始错误保留 |
| `timeout` | 超过 `--timeout` |
| `tool_error` | 工具非零退出、未产出 XML 等，诊断不可信 |
| `unavailable` | 只在 `--allow-missing-tools` 的指标中标记，不产生预测行 |

Cppcheck 的 `raw/` 还有 `report.xml`，`report` 字段记录其路径与哈希。

### 4.2 `metrics.json`

顶层：

```
schema_version, generated_at, started_at, wall_seconds,
dataset {path, sha256, bytes, name, n_input, n_selected, n_labelled,
         label_counts, language_counts, filter_counts, filter_cwe},
settings {tools, missing_tools, std_c, std_cxx, timeout_seconds, jobs,
          include_dirs, defines, clang_args, cppcheck_args,
          cppcheck_force, include_external, filter_cwe, assume_cwe, only_label, limit},
tool_info {clang|cppcheck {available, binary, version, environment_errors}},
tools {clang|cppcheck {
  runs, labelled, evaluable, coverage_labelled, status_counts,
  confusion_evaluable, metrics_evaluable,
  confusion_end_to_end, metrics_end_to_end,
  by_language, by_split, diagnostics {total, cwe401, samples_with_cwe401, by_rule, by_cwe401_rule},
  timing {n, total_seconds, mean_seconds, median_seconds, p95_seconds, max_seconds},
  error_examples, environment_errors
}},
target_cwe, rule_mapping, environment, limitations, errors
```

指标口径：

- **可评估（evaluable）**：只含 `status=ok` 且有标签的样本。编译失败、超时、工具错误不计入。
- **端到端（end_to_end）**：把 `compile_error` 和 `timeout` 按“未报泄漏”计入混淆矩阵；`tool_error`/`unavailable` 仍排除。这是部署成本视角，会惩罚无法解析的输入。
- **macro-F1**：漏洞类与非漏洞类 F1 的宏平均。某类在标签集中不存在时记 `null`，不强行记 0；某类存在但从未被预测时该类 F1 记 0。
- **Wilson 95%**：用于 precision/recall/specificity/accuracy 的比例区间；F1/macro-F1/MCC 不套 Wilson。
- `MCC` 分母为 0 时为 `null`。
- 计时是子进程墙钟时间之和；`wall_seconds` 是整次运行墙钟。

---

## 5. CWE-401 规则映射

| 工具 | 原始标识 | 判定 |
| --- | --- | --- |
| Clang | `unix.Malloc` 且 message 含 `potential leak of memory` | CWE-401 |
| Clang | `cplusplus.NewDeleteLeaks` 且 message 含 `leak of memory` | CWE-401 |
| Clang | `unix.Malloc` 的 double free / use-after-free / free non-heap 等 | **不计入**（保留原始诊断） |
| Cppcheck | `id=memleak` | CWE-401 |
| Cppcheck | `id=memleakOnRealloc` | CWE-401 |
| Cppcheck | XML `cwe` 属性含 `401` | CWE-401 |
| Cppcheck | `doubleFree`（CWE-415）等 | **不计入**（保留原始诊断） |

因此 `double_free.c` 这类负控制会出现在 `diagnostics` 中，但 `prediction.is_vulnerable=false`。所有未映射诊断仍逐条保留，方便审计误报/漏报和工具差异。

---

## 6. 小规模冒烟验证（不是正式结果）

所有运行都在 WSL 完成，输出在 `traditional/static/runs/`。这些目录包含真实命令、原始 stdout/stderr、运行时和标签，可直接复核；因为样本量很小，**不能据此做统计推断或论文结论**。

### 6.1 合成夹具：7 条 × 2 工具

输入 `fixtures/manifest.jsonl`：3 个真泄漏（C 的 `malloc`、C++ 的 `new[]`、同一文件另一个函数区域的泄漏）、4 个负例（全路径释放、`double free`、clean region 等）。多区域用例专门验证 `line_start`/`line_end`：同一文件中 `leak_region` 的泄漏不会算到 `clean_region` 记录上。

| 工具 | 状态 | TP | FP | TN | FN | Precision | Recall | Macro-F1 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Clang | 7/7 ok | 3 | 0 | 4 | 0 | 1.0 | 1.0 | 1.0 |
| Cppcheck | 7/7 ok | 3 | 0 | 4 | 0 | 1.0 | 1.0 | 1.0 |

产物：`runs/smoke_fixtures_both/`。这只证明适配器、映射、区间过滤和原始日志链路正常，**不是**工具能力的估计。

### 6.2 真实 Juliet v1.3 CWE-401：10 个单元 × 2 工具

从 `juliet/raw/testcases/CWE401_Memory_Leak/` 选取 5 个真实测试用例/组，按 `OMITBAD`/`OMITGOOD` 拆成 bad/good 单元：

- `CWE401_Memory_Leak__char_malloc_01.c`（C）
- `CWE401_Memory_Leak__int_malloc_01.c`（C）
- `CWE401_Memory_Leak__char_calloc_01.c`（C）
- `CWE401_Memory_Leak__new_array_int_01.cpp`（C++）
- `CWE401_Memory_Leak__char_calloc_54{a..e}.c`（C，多文件 flow variant，包装成一个 TU）

| 工具 | 状态 | TP | FP | TN | FN | Precision | Recall | F1(V) | Macro-F1 | Accuracy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Clang | 10/10 ok | 5 | 0 | 5 | 0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| Cppcheck | 10/10 ok | 2 | 0 | 5 | 3 | 1.0 | 0.4 | 0.5714 | 0.6703 | 0.7 |

Cppcheck 的 3 个漏报是真实工具行为：`char_malloc_01`、`char_calloc_01`、`char_calloc_54` 的 bad 单元没有报 `memleak`；其中前两个在源码里把指针传给 `printLine`，Cppcheck 保守地认为指针可能逃逸。Clang 在 `char_malloc_01`/`char_calloc_01` 上能报，但在把指针传给外部函数时也可能漏；`_54` 组只有把 5 个文件合成一个 TU 并启用 `-analyzer-opt-analyze-headers` 后才报出。

产物：`runs/juliet_smoke_both/`。清单 `fixtures/juliet_smoke_manifest.jsonl` 记录每条 `sources`/`preamble`/标签。

### 6.3 SecVulEval 的 CWE-401 函数片段：3 条 × 2 工具

输入 `datasets/independent_200.json`，`--filter-cwe CWE-401` 得到 3 条（其中 2 条 `is_vulnerable=true`）。这些是**孤立函数片段**，不是可编译 TU：

| 工具 | 状态 | 可评估 | 结果 |
| --- | --- | --- | --- |
| Clang | 3/3 `compile_error` | 0 | 全部缺少类型/头文件，无法进入路径敏感分析；端到端按未报泄漏计 |
| Cppcheck | 1 `compile_error` + 2 `ok` | 2 | 2 条可解析但均未报 `memleak`；端到端 recall 0 |

具体错误（原样保留在 `runs/secvuleval_cwe401_snippets_both/raw/`）：

- `17743`（DCMTK，`dcmnet/libsrc/dulfsm.cc`）：Cppcheck `syntaxError`；Clang 缺 `DcmItem` 等类型。
- `17507`（SDL，`src/render/opengles/SDL_render_gles.c`）：Clang 缺 `SDL_Renderer`/`SDL_Texture` 等类型；Cppcheck 可解析但未报泄漏（该条标签为 false）。
- `5896`（Linux，`drivers/spi/spi-fsl-lpspi.c`）：Clang 缺 `struct platform_device` 等；Cppcheck 可解析但未报泄漏（该条标签为 true）。

这与 `research/evaluation_protocol.md` §4 记录的“20 条函数 `clang -fsyntax-only` 0/20 通过”一致：**不能把 SecVulEval 片段直接当作静态分析的可编译输入**。正式 CWE-401 静态基准应使用 Juliet 这类自包含测试用例，或由数据工作流提供可编译的函数级 TU。

产物：`runs/secvuleval_cwe401_snippets_both/`。这是限制演示，不是 SecVulEval 检测结果。

---

## 7. 正式 Juliet 静态基线（200 单元）

### 7.1 数据与冻结状态

Juliet 工作流已生成并冻结以下文件（本目录只读消费，不修改）：

- `juliet/cache/juliet-c-cplusplus-v1.3.zip`：NIST SARD `2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip`，SHA-256 `ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb`。
- `juliet/raw/testcases/CWE401_Memory_Leak/`：2,827 个 CWE-401 文件；`juliet/raw/testcasesupport/` 为支持库；`juliet/provenance.json` 记录逐文件哈希。
- `juliet/subset_units.jsonl`：200 个冻结单元（100 bad / 100 good），SHA-256 `4827d1da6a1966759d66989dfb16678bc3e14d8f0588f9fe59d92a08ae4aac24`；`juliet/manifest.json`：同一批单元加划分、运行时验证、编译命令和哈希（其元数据会随冻结流程更新，正式运行以 `subset_units.jsonl` 的稳定哈希为输入锚点）；`juliet/FREEZE.json` 记录当前的 `subset_units_sha256` 与 `manifest_sha256`。
- 划分：dev 60（30 bad/30 good），test 140（70 bad/70 good）；语言 88 C / 112 C++；42 个 filename family。
- 标签与运行时：100 个 good 单元均无 ASan/LSan 泄漏；100 个 bad 单元中 **78 个**有 ASan 观测泄漏，22 个没有。`verification.runtime_supports_label=178`。因此正式表同时给出 **all 200（冻结标签）** 和 **runtime-supported 178（78 bad + 100 good）** 两个口径，不把 22 个“bad 但未观测到泄漏”的单元悄悄删掉。

### 7.2 运行

正式主结果命令（`_GNU_SOURCE` 对齐 Juliet 的 GNU 构建；`-include alloca.h` 解决 `ALLOCA`）：

```bash
python3 traditional/static/static_adapter.py \
  --input juliet/subset_units.jsonl \
  --out traditional/static/runs/juliet_formal_20261112_clang_cppcheck_gnu \
  --tool both \
  --cppcheck-bin /path/to/cppcheck \
  --include-dir juliet/raw/testcasesupport \
  --assume-cwe CWE-401 \
  --define _GNU_SOURCE \
  --clang-arg=-include \
  --clang-arg=alloca.h \
  --timeout 120 --jobs 8 \
  --dataset-name juliet-cwe401-v1.3-subset-v1
```

上面的 `--out` 是已存在的本次运行目录；复跑时请改成新目录，适配器拒绝覆盖非空目录。

- 输出：`runs/juliet_formal_20261112_clang_cppcheck_gnu/`（`predictions.jsonl` 400 行 = 200 单元 × 2 工具，另有 `metrics.json`、`metrics_verified.json`、`metrics.md`、`manifest.json`、`raw/`、`work/`）。
- 输入：`juliet/subset_units.jsonl`（SHA-256 `4827d1da…`，200 单元）；`juliet/manifest.json` 只用于 §7.4 的运行时子群 join，不改变预测行。
- 工具：Clang 22.1.8 / Cppcheck 2.21.0；整次 wall 9.0 s；Clang 子进程总计 23.6 s（均值 0.118 s/单元），Cppcheck 9.0 s（均值 0.045 s/单元）。计时随缓存/负载波动，表内数字来自本次运行。
- 对照：`runs/juliet_formal_20261112_clang_cppcheck_strict_c11/` 是不加 `_GNU_SOURCE` 的严格 `c11` 运行；Clang 12 个编译失败（`strdup`/`wcsdup` 未声明 + `_82` 头重定义），因此只作配置敏感性对照，不作主结果。

### 7.3 主结果（all 200，端到端）

正类 = “存在 CWE-401 诊断”；`compile_error`/`timeout` 按未报泄漏计入端到端混淆矩阵。

| 工具 | 可评估 | TP | FP | TN | FN | Precision | Recall | F1(V) | Macro-F1 | Accuracy | MCC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Clang | 194/200 | 73 | 0 | 100 | 27 | 1.000 | 0.730 | 0.844 | 0.862 | 0.865 | 0.758 |
| Cppcheck | 200/200 | 30 | 4 | 96 | 70 | 0.882 | 0.300 | 0.448 | 0.585 | 0.630 | 0.346 |

只看可评估样本（Clang 194、Cppcheck 200）：

| 工具 | TP | FP | TN | FN | Precision | Recall | Macro-F1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Clang | 73 | 0 | 97 | 24 | 1.000 | 0.753 | 0.874 |
| Cppcheck | 30 | 4 | 96 | 70 | 0.882 | 0.300 | 0.585 |

Clang 的 6 个 `compile_error` 全部是 C++ `_82` 组（`new_array_TwoIntsClass_82`、`new_twoIntsStruct_82`、`new_wchar_t_82` 的 bad/good）：这些组共享无 include guard 的 `_82.h`，`sources` 合成一个 TU 时头文件被重复包含，触发 `redefinition`；适配器如实记录，不修改 Juliet 源码。端到端因此把 3 个 bad 记为 FN、3 个 good 记为 TN。

### 7.4 运行时支持标签的 178 子群

只保留“bad 且 ASan 观测到泄漏”或“good 且未观测到泄漏”的单元（78 bad + 100 good）：

| 工具 | 视图 | TP | FP | TN | FN | Precision | Recall | F1(V) | Macro-F1 | Accuracy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Clang | 端到端 178 | 58 | 0 | 100 | 20 | 1.000 | 0.744 | 0.853 | 0.881 | 0.888 |
| Clang | 可评估 172 | 58 | 0 | 97 | 17 | 1.000 | 0.773 | 0.872 | 0.896 | 0.901 |
| Cppcheck | 端到端/可评估 178 | 15 | 4 | 96 | 63 | 0.789 | 0.192 | 0.309 | 0.525 | 0.624 |

这组数字更严格：在 78 个运行时确实泄漏的 bad 单元中，Clang 找到 58 个（74.4%），Cppcheck 找到 15 个（19.2%）。22 个“bad 标签但 ASan 未观测到泄漏”的单元没有被删除，而是保留在主结果中并单列此子群，避免把标签噪声误当成工具漏报。该子群的机器可读结果由 `verified_subset.py` 从 `juliet/manifest.json` 的 `runtime_check` 连接生成：`runs/juliet_formal_20261112_clang_cppcheck_gnu/metrics_verified.json`（178 个支持单元，Clang 可评估 172，Cppcheck 178）。

```bash
python3 traditional/static/verified_subset.py \
  --manifest juliet/manifest.json \
  --predictions traditional/static/runs/juliet_formal_20261112_clang_cppcheck_gnu/predictions.jsonl \
  --out traditional/static/runs/juliet_formal_20261112_clang_cppcheck_gnu/metrics_verified.json
```

### 7.5 分语言与分 split

可评估样本内：

| 工具 | 语言 | N | TP | FP | TN | FN | Precision | Recall |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Clang | C | 88 | 39 | 0 | 44 | 5 | 1.000 | 0.886 |
| Clang | C++ | 106 | 34 | 0 | 53 | 19 | 1.000 | 0.642 |
| Cppcheck | C | 88 | 19 | 0 | 44 | 25 | 1.000 | 0.432 |
| Cppcheck | C++ | 112 | 11 | 4 | 52 | 45 | 0.733 | 0.196 |

| 工具 | split | N | TP | FP | TN | FN | Recall |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Clang | dev | 58 | 20 | 0 | 29 | 9 | 0.690 |
| Clang | test | 136 | 53 | 0 | 68 | 15 | 0.779 |
| Cppcheck | dev | 60 | 8 | 0 | 30 | 22 | 0.267 |
| Cppcheck | test | 140 | 22 | 4 | 66 | 48 | 0.314 |

C++ 明显更难：Clang C++ recall 0.642，Cppcheck C++ recall 0.196，且 Cppcheck 的 4 个 FP 全在 C++ `_33` good 单元（`int64_t_calloc_33`、`int64_t_malloc_33`、`int_calloc_33`、`int_malloc_33`），原因是 `alloca`/作用域遮蔽导致的 `memleak` 误报。test 与 dev 的差异只是描述性的，不能据此做显著性结论。

### 7.6 原始诊断与错误

Clang：152 条原始诊断，其中 `unix.Malloc` 59、`cplusplus.NewDeleteLeaks` 14、`deadcode.DeadStores` 72、`core.StackAddressEscape` 7；只有 73 条被映射为 CWE-401。Cppcheck：111 条原始诊断，其中 `memleak` 19、`memleakOnRealloc` 15、`allocaCalled` 49、`passedByValue` 12、`virtualDestructor` 10 等；34 条被映射为 CWE-401，4 条为上述 FP。所有未映射诊断、原始 stdout/stderr 和错误文本均在 `raw/` 与 `predictions.jsonl` 中保留。

### 7.7 解释边界

- 这是**传统静态方法的真实基线**，不是 LLM 结果，也不是动态 ASan 结果；不能把本表与 DeepSeek 的 2484 请求结果直接放在同一张“模型对比”表里而不注明方法/输入/标签口径不同。
- 静态工具只做“可能泄漏”的路径敏感/值流分析，不执行程序；22 个 bad 单元没有 ASan 泄漏，说明 Juliet 标签本身包含运行时未触发的路径，主表与 178 子群必须同时报告。
- Cppcheck 的 4 个 FP 和 Clang 的 6 个 C++ 编译失败都是真实工具行为；没有为了提升数字而调规则、删样本或改 Juliet 源码。
- Wilson 95% 区间、每语言/每 split 的混淆矩阵、每次调用的运行时和原始诊断都在 `metrics.json` / `predictions.jsonl` 中；上表只摘点估计。

---

## 8. 已知限制

1. **片段不可编译**：SecVulEval 的函数是抽取片段，Clang 需要完整类型/头文件；失败会记 `compile_error`，不会被静默当成负例。端到端指标会惩罚这类样本，可评估指标则排除。
2. **逐 TU 分析**：Clang Static Analyzer 和 Cppcheck 都不是链接时/全程序分析。多文件 Juliet 组用 `sources` 合成一个 TU 只是近似；跨 TU 的数据流仍可能丢。Cppcheck 对 `_54` 组没有报出泄漏就是例子。C++ 组若共享无 include guard 的头，合成 TU 会 `redefinition`，适配器记为 `compile_error`，不会静默修改源码。
3. **指针逃逸导致漏报**：把指针传给外部函数（如 Juliet 的 `printLine`）时，工具可能保守地认为指针被保存/释放，从而不报泄漏；Cppcheck 在 `char_malloc_01`/`char_calloc_01` 上就是这样。
4. **静态结果不自己执行程序**：静态工具报的是“可能泄漏”；本目录不运行 ASan/LSan。正式表的 178 子群引用 Juliet 工作流 `manifest.json` 里的 ASan/LSan `runtime_check`，不是本适配器产生的动态证据；动态内存泄漏是另一条工作流。
5. **标签粒度**：文件级标签会把文件中任意位置的泄漏算作命中；`line_start`/`line_end` 只是行号过滤，不做函数边界推断。正式函数级结论需要精确区间或独立 TU。
6. **配置影响结果**：Cppcheck 的 `--enable`、`--inconclusive`、`--force`，Clang 的 checker 集合和 `-analyzer-opt-analyze-headers` 都会改变召回。每次运行都在 `manifest.json` 记录命令和版本；不要跨版本直接比较。主结果用 `_GNU_SOURCE` 对齐 Juliet 的 GNU 构建；严格 `c11` 对照的 12 个编译失败说明了该选择的影响。
7. **CWE-401 在 SecVulEval 中很少**：独立集 200 条中只有 3 条 CWE-401（其中 2 条漏洞），不足以做 CWE-401 专项统计；本目录的 3 条片段运行只是限制演示。
8. **冒烟与正式样本量**：10 个 Juliet 单元、7 个夹具、3 个片段只是链路验证；正式 200 单元是单数据集、单次配置的描述性基线，不能外推到真实项目、其他 CWE 或其他静态工具版本。
9. **22 个 bad 未被 ASan 观测到泄漏**：主表按冻结标签全部计入，178 子群只保留运行时支持标签的单元；两者不可混用。Clang 主表的 27 个 FN = 3 个编译失败 + 17 个运行时确有泄漏但漏报 + 7 个运行时未观测到泄漏；Cppcheck 的 70 个 FN = 63 个运行时确有泄漏但漏报 + 7 个未观测到泄漏。不要把 22 个未观测泄漏的 bad 全部解释成工具漏报。

---

## 9. 文件清单

| 路径 | 内容 |
| --- | --- |
| `static_adapter.py` | 适配器主程序（仅标准库） |
| `verified_subset.py` | 从 `runtime_check` 生成 178 子群指标的只读脚本 |
| `fixtures/manifest.jsonl` | 7 条合成夹具清单（含区域/负控制） |
| `fixtures/juliet_smoke_manifest.jsonl` | 10 条真实 Juliet 冒烟清单（单文件 + 多文件组） |
| `fixtures/leak_malloc.c`、`leak_new.cpp`、`clean_malloc.c`、`clean_new.cpp`、`double_free.c`、`multi_region.c` | 冒烟输入 |
| `runs/smoke_fixtures_both/` | 7 条夹具 × 2 工具的真实输出 |
| `runs/juliet_smoke_both/` | 10 个真实 Juliet 单元 × 2 工具的真实输出（冒烟，非正式） |
| `runs/juliet_formal_20261112_clang_cppcheck_gnu/` | **正式主结果**：200 个冻结 Juliet 单元 × 2 工具，输入为 `subset_units.jsonl`，`_GNU_SOURCE` 配置 |
| `runs/juliet_formal_20261112_clang_cppcheck_strict_c11/` | 严格 `c11` 对照运行；Clang 12 个编译失败，不作为主结果 |
| `runs/secvuleval_cwe401_snippets_both/` | SecVulEval 3 条 CWE-401 片段的限制演示 |
| `README.md` | 本文 |

所有 `runs/` 下的输出都由对应 `manifest.json` 记录输入/输出哈希、命令、工具版本；`raw/` 保留逐字 stdout/stderr，`work/` 保留实际分析的代码（含 `preamble` 包装）。复跑时请使用新目录，不要覆盖已有结果。
