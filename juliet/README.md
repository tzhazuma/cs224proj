# Juliet CWE-401（Memory Leak）冻结评估子集

本目录只做一件事：从 NIST SARD 官方发布获取 C/C++ Juliet Test Suite v1.3 的 CWE-401 用例，构建一个**可复现、标签可核验、dev/test 近重复隔离**的 200 单元评估子集。这里不包含任何模型调用、静态分析器结论或传统动态工具结论；那些属于其他工作流。

> 本目录的数据**不是**从项目根目录的 `SecVulEval.xlsx` 读取的，也没有改写 `datasets/`、`splits/`、`runner/`、`report/` 中的任何旧结果。所有代码执行都在 WSL Ubuntu 中完成。

## 1. 结论摘要

| 项目 | 值 |
| --- | --- |
| 数据集 | Juliet Test Suite for C/C++ **v1.3**，CWE-401 |
| 官方来源 | NIST SARD Test Suites 页面 |
| 归档 SHA-256 | `ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb` |
| 归档大小 | 152,957,342 bytes |
| 提取的 CWE-401 源码 | 1,228 个 `.c`、1,482 个 `.cpp`、111 个 `.h`，合计 2,827 个文件（另有 3 个 Makefile / 3 个 `.bat`） |
| 保留的依赖 | `raw/testcasesupport/`（`std_testcase.h`、`io.c`、`std_thread.c` 等）、`raw/doc/`、`raw/Makefile` |
| 候选测试用例组 | 1,658 个（每个组含一个 bad/good 测试用例，可能跨多个源文件） |
| 功能家族 | 42 个（文件名 `__` 与流变体编号之间的 token） |
| 冻结评估集 | **100 个测试用例组 = 200 个编译/运行单元** |
| bad / good | 100 / 100 |
| dev / test | 60 / 140 单元（30 / 70 组） |
| C / C++ 单元 | 88 / 112 |
| 编译与运行核验 | 200/200 编译通过；200/200 宏门控 + 符号门控通过；good 100/100 无泄漏；bad 78/100 默认运行观察到泄漏 |
| 跨 split 近重复 | 阈值 0.85，违规 **0** 对；实测最大 Jaccard **0.8231** |
| 清单 | `manifest.json`、`subset_units.jsonl`、`SHA256SUMS`、`FREEZE.json` |

## 2. 来源、版本与完整性

### 2.1 下载地址

- 官方归档：
  `https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip`
- 发布入口：
  `https://samate.nist.gov/SARD/test-suites`
- 归档顶层目录：`C/`
- 归档内版本证据：`raw/doc/changelog_Juliet_C_Cpp.txt` 第 3 行 `Sep 2017 - v1.3`

### 2.2 HTTP 元数据

抓取时服务器返回：

| 字段 | 值 |
| --- | --- |
| `Content-Type` | `application/zip` |
| `Content-Length` | `152957342` |
| `Last-Modified` | `Wed, 07 Jan 2026 14:08:03 GMT` |
| `ETag` | `"91df19e-647ccd20cfb0c"` |

`Last-Modified` 是 SARD 在 2026 年重新打包服务器文件的时间，不代表 Juliet 版本变化；版本仍以归档内 changelog 的 v1.3 为准。

### 2.3 SHA-256 与逐文件核验

- 归档 SHA-256：`ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb`
- `provenance.json` 记录归档 URL、HTTP 头、大小、SHA-256、提取时间、成员前缀，以及 `raw/` 下 **2,839 个文件的逐个 SHA-256 与字节数**。
- `SHA256SUMS` 使用标准 `sha256sum` 格式覆盖 `raw/`、`scripts/`、`provenance.json`、`verification.json`、`manifest.json`、`subset_units.jsonl`、`README.md`。
- `build/` 是可再生的编译产物，不进入 `SHA256SUMS`；`cache/` 中的 146 MB 归档也不进入，但其哈希固定在 `manifest.json` 与 `provenance.json`。

## 3. 目录结构

```text
juliet/
├── README.md                     # 本文件
├── manifest.json                 # 权威清单：来源、选择、split、200 单元、逐文件哈希、核验结果
├── subset_units.jsonl            # 一行一个单元，便于 benchmark/runner 直接消费
├── SHA256SUMS                    # 标准 sha256sum 清单
├── FREEZE.json                   # manifest / units / SHA256SUMS 的冻结哈希
├── verification.json             # 两次独立校验的实际结果
├── provenance.json               # 归档与 raw/ 的逐文件溯源
├── cache/
│   └── juliet-c-cplusplus-v1.3.zip
├── raw/
│   ├── Makefile
│   ├── doc/                      # v1.2 用户指南、1.3 变更说明、changelog
│   ├── testcasesupport/          # 编译必需：std_testcase.h、io.c、std_thread.c 等
│   └── testcases/CWE401_Memory_Leak/
│       ├── s01/ s02/ s03/        # 全部 1,228 C + 1,482 C++ + 111 头文件
│       └── ...
├── scripts/
│   ├── fetch_juliet.py           # 下载/复用归档，提取 CWE-401 + 依赖
│   ├── lib_juliet.py             # 文件名解析、宏保护解析、标签证据、相似度
│   ├── select_lib.py             # 42 家族、100 组、变体选择
│   ├── split_clusters.py         # 近重复连通分量 + dev/test 整簇分配
│   ├── build_lib.py              # ASan 编译、符号检查、LSan 运行
│   ├── build_subset.py           # 一键构建/回填/写清单
│   ├── verify.py                 # 独立校验；--build 重新编译全部单元
│   ├── check_structure.py        # 1,658 组的宏结构预检
│   └── audit_similarity.py       # 跨 split 近重复审计
└── build/                        # ASan 可执行文件（可再生产物）
    ├── support/                  # io.o、std_thread.o
    ├── units/bad|good/           # 200 个可执行文件
    ├── results/                  # 每个单元的历史检查 JSON
    └── verify/                   # verify.py --build 的独立重编译产物
```

`raw/testcases/CWE401_Memory_Leak/` 保留的是**完整 CWE-401 目录**，不是只保留被选中的 100 组。这样可以审计未选样本，也方便以后重新抽样；评估时请只使用 `manifest.json` / `subset_units.jsonl` 中列出的单元。

## 4. 子集设计

### 4.1 功能家族

家族取文件名中 `CWE401_Memory_Leak__` 之后、两位流编号之前的 token，例如：

- `CWE401_Memory_Leak__char_calloc_01.c` → 家族 `char_calloc`
- `CWE401_Memory_Leak__new_array_TwoIntsClass_82a.cpp` → 家族 `new_array_TwoIntsClass`
- `CWE401_Memory_Leak__malloc_realloc_int_18.c` → 家族 `malloc_realloc_int`

共 42 个家族：21 个同时有 C/C++，6 个只有 C（`malloc_realloc_*`），15 个只有 C++（`new_*`、`destructor`、`virtual_destructor`）。

### 4.2 选择规则

- 42 个家族全部至少选 1 组；大多数家族 2 组，18 个家族 3 组。
- 双语家族：优先 1 个 C + 1 个 C++；若选 3 组，第 3 组补 C。
- 每个 C 家族以 `_01` 为基线锚点，再从 `_22`（全局变量控制流）、`_54`（递归）、`_68`（跨文件全局数据流）等交错选择，避免只覆盖 `_01`。
- C++ 家族使用 `_33`/`_43`/`_82` 等类/引用流变体，以及 `_31`、`_54`、`_68` 等；具体分布见 `manifest.json.selection.variant_distribution`。
- 选择完全确定，种子字符串为 `juliet-cwe401-subset-v1`；不依赖运行时随机数。

最终 100 组的变体分布：

```text
01: 42   09: 3   18: 6   22: 5   31: 5
33: 20   54: 5   68: 7   72: 4   82: 3
```

### 4.3 编译单元

一个“单元”是一个**带标签的构建目标**：

- 大多数 C 用例：单个 `.c` 文件 → 1 个源文件。
- 多文件 C 流变体（`_22`、`_51`–`_54` 等）：同一测试用例的 `a/b/c/...` 源文件一起编译 → 1 个构建目标。
- 多文件 C++ 流变体（`_62`、`_72`、`_81`–`_84`）：`a` 文件 + `_bad`/`_good*` 实现文件 + 头文件一起编译 → 1 个构建目标。
- `destructor` / `virtual_destructor`：`_bad.cpp` 与 `_good1.cpp` 各自带 `main`，按标签只编译其中一个；这两个家族的单元 `sources` 只列该标签实际编译的文件，而 `guard_evidence` 仍记录组内 bad/good 两个入口（另一入口来自未编译的兄弟文件）。

200 个单元中 152 个是单源文件，48 个是多源文件（24 组，最多 5 个源文件），合计 **290 个源文件编译实例**。这里的“单元”是带标签的构建目标，不是源文件个数；如果下游工具只接受“一个文件 = 一个输入”，请过滤 `len(sources) == 1`，得到 152 个单元。

## 5. 标签如何核验

### 5.1 宏门控是标签的唯一依据

Juliet 原始结构：

```c
#ifndef OMITBAD
void ..._bad() { ... }
#endif /* OMITBAD */

#ifndef OMITGOOD
void ..._good() { ... }
#endif /* OMITGOOD */

#ifdef INCLUDEMAIN
int main(...) { ... }
#endif
```

因此：

| 单元标签 | 编译宏 | 语义 |
| --- | --- | --- |
| `bad` | `-DINCLUDEMAIN -DOMITGOOD` | 只保留原始 `bad` 路径；`label_semantics = memory_leak_present` |
| `good` | `-DINCLUDEMAIN -DOMITBAD` | 只保留原始 `good` 路径；`label_semantics = memory_leak_absent` |

`manifest.json` 的每个单元都保存 `guard_evidence`：

- `bad_entry` / `good_entry` 的源文件、行号、完整 `#if/#ifndef` 保护栈；
- `included_when`：在 bad build / good build 中是否被包含；
- 构建时的 `defines`。

`verify.py` 会重新解析源文件，确认：

1. `bad_entry` 在 `OMITGOOD` 下被包含、在 `OMITBAD` 下被排除；
2. `good_entry` 相反；
3. 该单元的构建中恰好包含 1 个 bad 入口、0 个 good 入口（或反之）。

### 5.2 符号门控

编译后用 `nm -C --defined-only` 检查：

- `bad` 单元必须定义 bad 入口符号，且不定义 good 入口；
- `good` 单元必须定义 good 入口符号，且不定义 bad 入口。

这排除了“宏写错但源码碰巧还能编过”的情况。

### 5.3 ASan/LSan 运行佐证

每个单元用 `gcc/g++ -O0 -g -fsanitize=address -fno-omit-frame-pointer` 编译，运行 `ASAN_OPTIONS=detect_leaks=1`：

- **good**：100/100 默认运行无泄漏；任何 good 泄漏都会被拒绝并回填。
- **bad**：78/100 默认运行由 LeakSanitizer 报告泄漏；22/100 默认运行未观察到泄漏。

22 个未观察到泄漏的 bad 单元不是标签错误，而是 CWE-401 的“条件性/可达性”情形：

- 15 个 `malloc_realloc_*`：只有 `realloc()` 失败时旧块才泄漏；默认 `main` 中 130 KB 的 `realloc` 成功，随后 `free()`，所以看不到泄漏。
- 7 个 `_68`（跨文件全局变量）单元：指针在程序退出时仍被全局变量引用，LeakSanitizer 将其归为 **still reachable**，而不是 leaked；按 Juliet 的 bad 定义它仍然没有在生命周期内释放。

这些单元保留 `runtime_check.leak_detected = false`，`verification.runtime_label_ok = false`，但 `macro_gate_ok`、`compiled_ok`、`symbol_gate_ok` 均为 true。**没有因为运行观察不到泄漏而改标签**。完整的 22 个单元 ID 可从 `manifest.json` 用 `label == "bad" and not runtime_check.leak_detected` 过滤得到；`verification.bad_units_without_observed_leak` 记录总数。

## 6. dev/test 划分与近重复控制

### 6.1 为什么要按簇划分

Juliet 是模板生成的，不同家族（例如 `char_malloc` 与 `int_malloc`）在相同流变体下只差类型/分配函数，结构 Jaccard 可以接近 1.0。如果只按家族随机分，dev/test 之间会出现大量近重复，导致测试集泄漏。

本子集的做法：

1. 对每个选中组，去掉注释、预处理行，把标识符统一为 `<id>`、字符串/数字统一为 `<str>`/`<num>`；
2. 取 5-token shingle，计算组间 Jaccard；
3. 以 **0.85** 为阈值建图，取连通分量（18 个簇）；
4. **整个簇**只能进入 dev 或 test；同一家族天然不会被拆开；
5. 在满足 60 个 dev 单元、C/C++ 各 30、且覆盖 8 类分配机制（malloc/calloc/realloc/malloc_realloc/new/new_array/strdup/destructor）的前提下，选择确定性的 dev 簇集合。

### 6.2 结果

| split | 单元 | 组 | 家族 | C 单元 | C++ 单元 | 簇 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| dev | 60 | 30 | 13 | 30 | 30 | 9 |
| test | 140 | 70 | 29 | 58 | 82 | 9 |

- dev 家族：`destructor, malloc_realloc_char, malloc_realloc_struct_twoIntsStruct, malloc_realloc_wchar_t, new_array_TwoIntsClass, new_array_struct_twoIntsStruct, new_struct_twoIntsStruct, strdup_char, strdup_wchar_t, struct_twoIntsStruct_calloc, struct_twoIntsStruct_malloc, struct_twoIntsStruct_realloc, virtual_destructor`
- test 家族：其余 29 个，包括 `char_*`、`int_*`、`int64_t_*`、`wchar_t_*`、`new_*`、`new_array_*`、`malloc_realloc_*` 等。
- 跨 split 共 2,100 对，最大 Jaccard **0.8231**；≥0.85 的对数 **0**；≥0.80 的对数 **2**。完整 top-10 见 `manifest.json.near_duplicate_audit.top_cross_split`。
- dev/test 的家族、组、源文件完全不相交；同一组不会同时出现在两侧。

注意：这是**按近重复簇的分布隔离**，不是 i.i.d. 随机划分。dev 和 test 的家族/类型分布有意不同（dev 13 个家族，test 29 个），因此适合“在 dev 上调参、在 test 上测泛化”，不适合把两侧当成同分布样本做显著性检验。

## 7. `manifest.json` 结构

顶层字段：

| 字段 | 内容 |
| --- | --- |
| `dataset_id` | `juliet-cwe401-v1.3-subset-v1` |
| `source` | URL、版本、归档 SHA-256/大小/HTTP 头、changelog 证据、逐文件核验数 |
| `selection` | 种子、家族数、候选组数、选择规则、变体分布、回填记录、18 个近重复簇 |
| `near_duplicate_audit` | 阈值、度量、跨 split 最大/计数、top-10 对 |
| `splits` | dev/test 的单元/组/家族/C/C++/簇统计 |
| `verification` | 200 个单元的宏/编译/符号/运行统计 |
| `per_file_sha256` | 选中单元源文件、头文件、support 文件的逐文件 SHA-256 |
| `units` | 200 个单元的完整记录 |

单个单元示例（截断）：

```json
{
  "unit_id": "CWE401_Memory_Leak__char_calloc_01__bad",
  "group_id": "CWE401_Memory_Leak__char_calloc_01",
  "family": "char_calloc",
  "variant": "01",
  "language": "c",
  "split": "test",
  "label": "bad",
  "label_semantics": "memory_leak_present",
  "sources": [{"path": "raw/testcases/.../....c", "sha256": "...", "bytes": 1234}],
  "defines": ["INCLUDEMAIN", "OMITGOOD"],
  "guard_evidence": {
    "bad_entry": {"name": "..._bad", "source": "...", "line": 24, "guards": [...]},
    "good_entry": {"name": "..._good", "source": "...", "line": 71, "guards": [...]}
  },
  "compile": {"compiler": "gcc", "ok": true, "command": ["gcc", "..."]},
  "symbol_check": {"ok": true, "bad_symbols": ["..."], "good_symbols": []},
  "runtime_check": {"tool": "AddressSanitizer + LeakSanitizer", "leak_detected": true}
}
```

`subset_units.jsonl` 是同一批单元的轻量索引，每行包含 `unit_id / group_id / family / variant / language / split / label / sources / defines`，适合直接 `grep` 或喂给 runner。

## 8. 复现命令（全部在 WSL 中执行）

```bash
# 1) 校验归档与 raw/ 逐文件哈希（不会重新下载）
cd /mnt/c/Users/tzh03/Downloads/cs224proj
python3 juliet/scripts/fetch_juliet.py

# 2) 结构预检：1,658 组、42 家族、宏标签问题 0
python3 juliet/scripts/check_structure.py

# 3) 重新构建 100 组 / 200 单元（会重写 juliet/manifest.json 等本目录产物）
python3 juliet/scripts/build_subset.py --jobs 6

# 4) 独立校验；--build 会重新编译并运行全部 200 单元
python3 juliet/scripts/verify.py --build --jobs 6

# 5) 近重复审计
python3 juliet/scripts/audit_similarity.py
```

`build_subset.py` 只写 `juliet/` 下的文件，不会触碰 `datasets/`、`splits/`、`runner/`、`report/` 或根目录的 Excel。首次下载如归档不存在，`fetch_juliet.py` 会自动下载；已有归档时默认复用并通过 HEAD/哈希核验，`--redownload` 可强制重下，`--force` 可重新解压。

### 8.1 手工编译一个单元

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj/juliet
gcc -std=gnu11 -O0 -g -fsanitize=address -fno-omit-frame-pointer \
  -DINCLUDEMAIN -DOMITGOOD \
  -I raw/testcasesupport \
  -o /tmp/unit_bad \
  raw/testcases/CWE401_Memory_Leak/s01/CWE401_Memory_Leak__char_calloc_01.c \
  build/support/io.o build/support/std_thread.o -lpthread -lm
ASAN_OPTIONS=detect_leaks=1 /tmp/unit_bad
```

C++ 单元把 `gcc` 换成 `g++ -std=gnu++11`，并把单元的所有 `sources` 一起传入。更稳妥的方式是直接读 `manifest.json` 的 `compile.command`，或调用 `scripts/build_lib.py:evaluate()`。

## 9. 已验证的内容

- 官方归档 SHA-256 与 2,839 个 raw 文件逐个哈希：通过。
- 1,658 个候选组的宏结构：0 个结构问题；每个组都能定位唯一的 bad/good 入口与 `INCLUDEMAIN`。
- 200 个选中单元：200 编译通过、200 符号门控通过、200 宏门控通过。
- good 单元：100/100 默认运行无泄漏。
- bad 单元：78/100 默认运行观察到泄漏；22/100 为条件性/可达性情形，未观察到泄漏，但宏与符号门控均正确。
- dev/test：家族、组、源文件完全隔离；跨 split 近重复 ≥0.85 为 0 对，最大 0.8231。
- `SHA256SUMS` 列出的全部文件：逐行重新哈希通过。
- `verify.py --build` 独立重编译/重运行：通过；实际输出与统计见 `verification.json`。

## 10. 限制与边界

1. **只覆盖 CWE-401**，不是完整 Juliet。其他 CWE 的用例仍在 `raw/` 归档中，但未提取、未进入评估集。
2. **标签以原始宏结构为准**，不是以 ASan 是否观察到泄漏为准。22 个 bad 单元在默认 `main` 下不泄漏（`realloc` 成功或全局指针仍可达），动态工具可能将其判为 false negative；这是 CWE-401 数据本身的属性，不是标签错误。若下游需要“运行必现”的 bad，请按 `runtime_check.leak_detected == true` 过滤，得到 78 个 bad 单元（并相应只取同组 good，保持配对）。
3. **ASan/LSan 只是标签佐证**，不是传统动态内存泄漏工具的正式结果；本目录没有 Valgrind、静态分析器或 LLM 的任何输出。
4. **近重复度量是词法/结构性的**（标识符与字面量掩码后的 5-gram Jaccard），阈值 0.85。它能保证“跨 split 没有 ≥0.85 的模板级近重复”，但不能保证语义上完全无相似；同 split 内仍有 1.0 的重复（同一簇），这是按簇划分的预期结果。
5. **dev/test 不是同分布**：test 包含 29 个家族，dev 只包含 13 个；dev 覆盖全部 8 类分配机制，但类型/家族分布与 test 不同。报告结果时应写成“家族/簇隔离的泛化划分”，不要写成随机 i.i.d. 划分。
6. **多文件单元**：200 个单元中 48 个由 2–5 个源文件组成。若下游按单文件输入，需过滤 `len(sources) == 1`（152 个单元），或自行把多文件目标展开。
7. **`raw/` 不是评估集**：它保留全部 1,658 组、2,827 个 CWE-401 文件，仅用于审计与再抽样；评估请使用 `manifest.json` 的 100 组。
8. **`cache/` 归档 146 MB**：保留它是为了可复核 SHA-256 与重新提取；如果空间紧张，可在记录哈希后删除，`fetch_juliet.py --redownload` 可恢复。
9. **构建产物不可移植**：`build/` 中的 ASan 可执行文件含本机绝对路径和 WSL 运行时依赖；跨机器请重新编译，不要直接搬运。
10. **未读取 Excel**：本目录没有读取或依赖 `SecVulEval.xlsx`，也没有改写项目其他工作流的任何结果文件。

## 11. 文件哈希与冻结

- `FREEZE.json` 记录 `manifest.json`、`subset_units.jsonl`、`SHA256SUMS` 的 SHA-256 与构建耗时。
- `SHA256SUMS` 覆盖 `raw/`、`scripts/`、`provenance.json`、`verification.json`、`manifest.json`、`subset_units.jsonl`、`README.md`；可用 `sha256sum -c SHA256SUMS` 在 `juliet/` 下校验。
- 归档本身的 SHA-256 固定在 `manifest.json.source.archive_sha256` 与 `provenance.json.archive.sha256`，不依赖 `SHA256SUMS` 中的 146 MB 大文件。

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj/juliet
sha256sum -c SHA256SUMS
```
