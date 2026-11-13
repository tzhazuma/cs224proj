# CodeQL 扩展静态基线（`static_extended/`）

本目录只做一件事：在 Juliet CWE-401 冻结子集上运行**新的**传统静态分析工具 CodeQL，规范化为与 `traditional/static/` 相同的预测/指标口径，并在同一批 140 个 test 单元上与 Clang Static Analyzer、Cppcheck 对比。不调用模型、不修改 `juliet/` 输入、不覆盖既有结果、不执行 git。

**状态**：CodeQL CLI **2.27.4** + `codeql/cpp-queries` **1.10.0** 已在 200 个冻结单元（test 140）上完成真实运行。194 单元正常分析，6 单元编译失败（与 Clang 基线相同的 `_82` 头文件重定义）。140 test 上端到端 **Macro-F1 0.8173（项目主指标）**、正类 F1(V) 0.8447，Precision 0.747 / Recall 0.971 / MCC 0.674；Clang 为 Macro-F1 0.8768、F1(V) 0.8618、P 1.000 / R 0.757 / MCC 0.781，Cppcheck 为 Macro-F1 0.5879、F1(V) 0.4583、P 0.846 / R 0.314 / MCC 0.331。

---

## 1. 结论摘要

| 项目 | 值 |
| --- | --- |
| 数据集 | `juliet/subset_units.jsonl`，`juliet-cwe401-v1.3-subset-v1`，SHA-256 `4827d1da…aac24` |
| 单元 | 200（bad 100 / good 100；C 88 / C++ 112；dev 60 / test 140） |
| 工具 | CodeQL CLI 2.27.4（Linux x86_64 bundle） |
| 查询包 | `codeql/cpp-queries` 1.10.0 + `codeql/cpp-all` 12.4.0 |
| 查询 | `cpp/memory-never-freed`、`cpp/memory-may-not-be-freed`（均标记 `external/cwe/cwe-401`） |
| 编译覆盖 | 194/200 可分析（97.0%）；test 136/140；6 个 `_82` 单元编译失败 |
| 140 test（端到端） | TP 68 / FP 23 / TN 47 / FN 2；P 0.7473 / R 0.9714 / F1(V) 0.8447 / Macro-F1 0.8173 / MCC 0.6739 |
| 140 test（可评估） | TP 68 / FP 23 / TN 45 / FN 0；P 0.7473 / R 1.0000 / F1(V) 0.8553 / Macro-F1 0.8259 / MCC 0.7032 |
| 主指标对比（端到端） | CodeQL **Macro-F1 0.8173** vs Clang **0.8768**（差 0.0595）；正类 F1(V) 0.8447 vs 0.8618，仅作参考 |
| 运行时间 | 200 单元墙钟 1434.7 s（6 并发）；单单元均值 42.5 s（建库 22.5 s + 查询 20.6 s） |
| 结论 | CodeQL 在 test 上补回 Clang 漏掉的 15 个 bad 单元、未漏掉任何 Clang 检出的单元；代价是 23 个 C++ good 单元误报 |

---

## 2. 工具安装与版本（无 sudo）

### 2.1 网络限制与真实下载路径

WSL 内 GitHub 直连被阻断（`github.com:443` 超时/重置，release 资产无法直接下载）；PyPI 与 GitHub API 可用。最终通过镜像 `https://gh-proxy.com/https://github.com/...` 以单连接、断点续传方式下载：

- `codeql-linux64.zip`，418,431,999 bytes
- 官方 SHA-256：`393bf92b66596141ec93baf9b483f4a350f3749916c922fed0dd63c67706047d`（来自 GitHub API asset `digest` 与 `codeql-linux64.zip.checksum.txt`，两者一致）
- 实测校验通过；此前一次 aria2c 多连接下载得到错误哈希且 `unzip -t` 报错，已丢弃，未用于任何结果

安装位置（用户目录，不进入仓库）：

| 路径 | 内容 | 大小 |
| --- | --- | --- |
| `~/tools/downloads/codeql-linux64-v2.27.4.zip` | 官方 bundle（已校验） | 418 MB |
| `~/tools/codeql-2.27.4/codeql/codeql` | CodeQL CLI 2.27.4 | 747 MB（解包） |
| `~/.codeql/packages/codeql/cpp-queries/1.10.0/` | 查询包 | 55 MB |
| `~/.codeql/packages/codeql/cpp-all/12.4.0/` | QL 标准库 | 26 MB |

查询包与依赖通过 `codeql pack download` 从 GHCR 获取（`ghcr.io` 可访问，无需登录）：

```bash
env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
  ~/tools/codeql-2.27.4/codeql/codeql pack download \
  codeql/cpp-queries codeql/cpp-all@12.4.0 codeql/suite-helpers@1.0.61 codeql/util@2.0.48
```

### 2.2 其他候选工具（未产出结果，不冒充）

| 工具 | 状态 | 结论 |
| --- | --- | --- |
| Semgrep | 已安装 1.185.0（用户 venv，PyPI 阿里云镜像） | 对 `semgrep/semgrep-rules` 的 2,194 条规则路径做路径级检索，未找到 C/C++ 的 CWE-401/`leak` 规则（0 命中）；未逐条审计规则内容，也未用自写模式规则冒充工具能力，因此不报告 Semgrep 指标 |
| Infer | 未安装 | 官方 release 资产 275,901,768 bytes；本轮以 CodeQL 为主，未下载/运行 Infer，不报告任何 Infer 数字 |

---

## 3. 查询

| 查询 ID | 文件（`cpp-queries/1.10.0`） | 语义 | 标签 |
| --- | --- | --- | --- |
| `cpp/memory-never-freed` | `Critical/MemoryNeverFreed.ql` | 函数在**所有**返回路径上都没有释放本次分配的内存 | `security`, `external/cwe/cwe-401` |
| `cpp/memory-may-not-be-freed` | `Critical/MemoryMayNotBeFreed.ql` | 函数**存在**某条返回路径未释放内存（近似、可能误报） | `security`, `external/cwe/cwe-401` |

两者都只匹配 `requiresDealloc()` 的分配表达式（`malloc`/`calloc`/`realloc`/`new`/`new[]` 等）。本目录把任一查询在目标源文件中产生结果视为预测为漏洞；同时保留分查询指标。

---

## 4. 方法

### 4.1 单元准备与编译

- 每个单元单独建一个 CodeQL 数据库，`--source-root=juliet`，编译命令只编译该单元。
- 单文件单元直接编译原文件；多文件单元（48/200，`_54`/`_68` 等 flow variant）在 `work/` 生成一个 `#include` 包装 TU，与 `traditional/static/` 基线相同。
- 编译命令（C 用 `gcc`，C++ 用 `g++`，版本 15.3.0）：

```text
gcc|g++ -std=c11|c++17 -D_GNU_SOURCE -DINCLUDEMAIN -D<OMITGOOD|OMITBAD> \
  -I juliet/raw/testcasesupport -include alloca.h -c <unit源文件> -o <obj>
```

- `-D_GNU_SOURCE`、`-include alloca.h` 与 Clang/Cppcheck 正式基线一致，用于对齐 Juliet 的 GNU 构建。
- 多文件 C++ `_82` 组共享无 include guard 的 `_82.h`，合成 TU 时 `g++` 报 `redefinition`，与基线 Clang 的 6 个 `compile_error` 完全对应；适配器如实记录，不修改 Juliet 源码。
- 编译失败判定：CodeQL `database create` 输出含 `Build command failed` / `Exit status`，或数据库未生成。原始 g++ stderr 保留在 `raw/*.create.stderr.txt`。

### 4.2 结果归一化

- `codeql database analyze --format=sarif-latest`，解析每条结果的 `ruleId`、文件 URI、起止行、message、code flow 数量。
- 只有落在该单元自身源文件（多文件单元为 `sources` 列表）中的结果才计入；头文件结果不计入（与基线 `--include-external` 关闭一致）。200 个单元共 132 条原始结果，全部落在目标文件。
- SARIF 以 gzip 保存（每单元约 47 KB），原始 stdout/stderr/命令行逐字保留。

### 4.3 指标口径

- **可评估**：仅 `status=ok` 且有标签的单元。
- **端到端**：把 `compile_error`/`timeout` 按“未报泄漏”计入混淆矩阵；`tool_error` 排除。
- 正类 = 目标文件中存在 CWE-401 结果；Precision/Recall/Specificity 为点估计；Macro-F1 为漏洞类与非漏洞类 F1 的宏平均；MCC 分母为 0 时记 `null`。
- 本目录不改动 `juliet/`、`traditional/`、`report/` 的任何文件；基线预测只读。

---

## 5. 运行

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj
python3 static_extended/codeql_adapter.py \
  --units juliet/subset_units.jsonl \
  --juliet-root juliet \
  --out static_extended/runs/codeql_20261114_cwe401_full \
  --codeql ~/tools/codeql-2.27.4/codeql/codeql \
  --jobs 6 --timeout 600

python3 static_extended/compare_test140.py \
  --units juliet/subset_units.jsonl \
  --baseline traditional/static/runs/juliet_formal_20261112_clang_cppcheck_gnu/predictions.jsonl \
  --codeql-run static_extended/runs/codeql_20261114_cwe401_full \
  --out static_extended/runs/codeql_20261114_cwe401_full/comparison_test140.json
```

或直接 `bash static_extended/run_codeql.sh`（自动选择新目录，不覆盖旧运行）。

- 实际墙钟 **1434.7 s**（约 24 min），6 并发，16 核 / 30 GB 内存的 WSL Ubuntu 26.10。
- 每单元：建库均值 22.5 s（中位 22.3），查询均值 20.6 s（中位 20.8）；单单元端到端均值 42.5 s，P95 51.7 s，最大 60.5 s。
- 说明：首轮正式运行因 `--out` 用了相对路径，编译对象路径按 `juliet/` 解析导致 200/200 误判 `compile_error`。该运行已整体移到 `/tmp/codeql_run_invalid_relativepath`，**不报告其指标**；适配器随后把输出目录解析为绝对路径并重跑，本文件所有数字来自重跑结果。

---

## 6. 结果

### 6.1 覆盖与状态

| 范围 | ok | compile_error | timeout | tool_error | 覆盖率 |
| --- | --- | --- | --- | --- | --- |
| 全部 200 | 194 | 6 | 0 | 0 | 0.9700 |
| test 140 | 136 | 4 | 0 | 0 | 0.9714 |
| dev 60 | 58 | 2 | 0 | 0 | 0.9667 |

6 个 `compile_error`（全部为 C++ `_82` 组，`redefinition`，与 Clang 基线一致）：

| 单元 | split | 错误 |
| --- | --- | --- |
| `new_array_TwoIntsClass_82__bad` | dev | `CWE401_Memory_Leak__new_array_TwoIntsClass_82.h:27: error: redefinition of '..._base'` |
| `new_array_TwoIntsClass_82__good` | dev | 同上 + `goodG2B`/`goodB2G` 重定义 |
| `new_twoIntsStruct_82__bad` | test | `CWE401_Memory_Leak__new_twoIntsStruct_82.h:27: error: redefinition of '..._base'` |
| `new_twoIntsStruct_82__good` | test | 同上 |
| `new_wchar_t_82__bad` | test | `CWE401_Memory_Leak__new_wchar_t_82.h:27: error: redefinition of '..._base'` |
| `new_wchar_t_82__good` | test | 同上 |

这是 Juliet 多文件 `_82` 组共享无 guard 头文件的真实编译问题，不是 CodeQL 提取器故障；适配器没有为了提升覆盖而改源码或拆样本。

### 6.2 全部 200 单元

| 视图 | TP | FP | TN | FN | Precision | Recall | Specificity | F1(V) | Macro-F1 | Accuracy | MCC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 可评估 194 | 96 | 30 | 67 | 1 | 0.7619 | 0.9897 | 0.6907 | 0.8610 | 0.8366 | 0.8402 | 0.7130 |
| 端到端 200 | 96 | 30 | 70 | 4 | 0.7619 | 0.9600 | 0.7000 | 0.8496 | 0.8271 | 0.8300 | 0.6835 |

分语言（可评估）：

| 语言 | N | TP | FP | TN | FN | Precision | Recall | F1(V) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| C | 88 | 44 | 0 | 44 | 0 | 1.0000 | 1.0000 | 1.0000 |
| C++ | 106 | 52 | 30 | 23 | 1 | 0.6341 | 0.9811 | 0.7704 |

C 单元 88/88 全部分析成功且全部判对；全部 30 个误报都在 C++ good 单元。

### 6.3 140 test：与 Clang / Cppcheck 同集对比

正类 = 存在 CWE-401 诊断；端到端视图把 4 个 `_82` 编译失败按未报泄漏计。下表同时列出正类 F1(V) 与 Macro-F1：**项目汇总主指标是 Macro-F1**（漏洞类与非漏洞类 F1 的宏平均），F1(V) 只描述漏洞类，两者不可混用或互相替代。

| 工具 | 可评估/总数 | TP | FP | TN | FN | Precision | Recall | F1(V) | Macro-F1 | Accuracy | MCC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Clang 22.1.8 | 136/140 | 53 | 0 | 70 | 17 | 1.0000 | 0.7571 | 0.8618 | 0.8768 | 0.8786 | 0.7805 |
| **CodeQL 2.27.4** | 136/140 | 68 | 23 | 47 | 2 | 0.7473 | 0.9714 | 0.8447 | 0.8173 | 0.8214 | 0.6739 |
| Cppcheck 2.21.0 | 140/140 | 22 | 4 | 66 | 48 | 0.8462 | 0.3143 | 0.4583 | 0.5879 | 0.6286 | 0.3306 |

只看可评估单元：

| 工具 | N | TP | FP | TN | FN | Precision | Recall | F1(V) | Macro-F1 | MCC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Clang | 136 | 53 | 0 | 68 | 15 | 1.0000 | 0.7794 | 0.8760 | 0.8883 | 0.7991 |
| CodeQL | 136 | 68 | 23 | 45 | 0 | 0.7473 | 1.0000 | 0.8553 | 0.8259 | 0.7032 |
| Cppcheck | 140 | 22 | 4 | 66 | 48 | 0.8462 | 0.3143 | 0.4583 | 0.5879 | 0.3306 |

**互补性**（70 个 test bad 单元，按工具原始预测）：

| 组合 | 数量 |
| --- | --- |
| CodeQL 与 Clang 都报 | 53 |
| 仅 CodeQL 报（Clang 漏） | 15 |
| 仅 Clang 报（CodeQL 漏） | 0 |
| 两者都不报 | 2（均为 `_82` 编译失败） |
| CodeQL 与 Cppcheck 都报 | 22 |
| 仅 CodeQL 报（Cppcheck 漏） | 46 |

CodeQL 在 test bad 上的可评估召回为 100%（68/68），Clang 为 78%；代价是 23 个 good 单元误报，MCC 因此低于 Clang。**按项目主指标 Macro-F1，CodeQL 0.8173 低于 Clang 0.8768（差 0.0595）**；正类 F1(V) 0.8447 与 Clang 0.8618 看似接近，但 F1(V) 只覆盖漏洞类，不能据此认为两者整体相当。15 个“仅 CodeQL 检出”的 bad 中 12 个是 C++（`_68` 5、`_01` 4、`_72` 3，`_22`/`_31`/`_54` 各 1），3 个是 C。

test 内的语言拆分：C 单元 58/58 全部分析成功且全部判对（29 TP / 29 TN / 0 FP / 0 FN）；C++ 78 个可评估单元为 39 TP / 23 FP / 16 TN / 0 FN，另有 4 个 `_82` 编译失败。

### 6.4 分查询

140 test（端到端）：

| 查询 | TP | FP | TN | FN | Precision | Recall | F1(V) | Macro-F1 | MCC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `cpp/memory-never-freed` | 46 | 0 | 70 | 24 | 1.0000 | 0.6571 | 0.7931 | 0.8084 | 0.6995 |
| `cpp/memory-may-not-be-freed` | 22 | 23 | 47 | 48 | 0.4889 | 0.3143 | 0.3826 | 0.4978 | -0.0153 |
| 并集（预测口径） | 68 | 23 | 47 | 2 | 0.7473 | 0.9714 | 0.8447 | 0.8173 | 0.6739 |

全部 200（可评估）：

| 查询 | TP | FP | TN | FN | Precision | Recall | F1(V) | Macro-F1 | MCC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `cpp/memory-never-freed` | 63 | 0 | 97 | 34 | 1.0000 | 0.6495 | 0.7875 | 0.8192 | 0.6935 |
| `cpp/memory-may-not-be-freed` | 33 | 30 | 67 | 64 | 0.5238 | 0.3402 | 0.4125 | 0.5001 | 0.0330 |
| 并集（预测口径） | 96 | 30 | 67 | 1 | 0.7619 | 0.9897 | 0.8610 | 0.8366 | 0.7130 |

上表同时列出正类 F1(V) 与 Macro-F1；比较不同工具或不同查询时应使用 Macro-F1，F1(V) 只描述漏洞类。

两个查询在真正例上完全互补（test 46 + 22 = 68；全部 63 + 33 = 96），`never-freed` 零误报，全部 23/30 个误报来自 `may-not-be-freed`。因此若要低误报配置，可只启用 `memory-never-freed`（test P 1.0 / R 0.657）；本目录主结果仍按两个查询的并集报告，以覆盖 CodeQL 的完整 CWE-401 查询面。

### 6.5 分 split（可评估）

| split | N | TP | FP | TN | FN | Precision | Recall | F1(V) | Macro-F1 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| dev | 58 | 28 | 7 | 22 | 1 | 0.8000 | 0.9655 | 0.8750 | 0.8606 |
| test | 136 | 68 | 23 | 45 | 0 | 0.7473 | 1.0000 | 0.8553 | 0.8259 |

test 与 dev 的差异只是描述性的，不做显著性推断；两列分别是正类 F1(V) 与 Macro-F1，跨表比较应使用 Macro-F1。

### 6.6 计时

| 指标 | 值 |
| --- | --- |
| 整次运行墙钟 | 1434.7 s |
| 建库总时长（200 次） | 4500.6 s，均值 22.5 s，中位 22.3 s |
| 查询总时长（194 次） | 4003.5 s，均值 20.6 s，中位 20.8 s |
| 单单元总时长（200） | 均值 42.5 s，中位 43.0 s，P95 51.7 s，最大 60.5 s |
| test 单元（136 ok） | 均值 44.1 s，中位 44.0 s，最大 60.5 s |
| 对比 Clang / Cppcheck | 0.118 s / 0.045 s 每单元（基线，单进程串行口径），CodeQL 约 360× / 940× |

CodeQL 的时间主要花在为每个单元单独建库（TRAP 导入、source archive）；查询本身在 6 并发下约 20 s/单元。该开销是“每单元一个数据库”的代价，换来了干净的编译失败归因；若改为单库多 TU 可显著降低总时间，但会失去单元级隔离，本目录没有这样做。

---

## 7. 误报与漏报分析

### 7.1 误报：30 个 good 单元，全部 C++

| 变体 | 数量 | 典型机制 |
| --- | --- | --- |
| `_33` | 20 | `char * &dataRef = data;` 后在块内 `char * data = dataRef; free(data);`；CodeQL 不追踪“通过引用别名/同名遮蔽变量释放”，认为原分配未释放 |
| `_72` | 4 | 分配发生在 source 函数，释放发生在另一个 sink 函数（或经 `vector` 元素传递）；跨函数所有权转移未被识别 |
| `_54` | 3 | 多文件 flow variant，分配与释放分布在不同 TU/函数，包装成单 TU 后仍按函数内可达性判断 |
| `_22` | 3 | 分配在 source，释放由全局标志控制的分支执行；CodeQL 保留“标志为真时不释放”的可行路径 |

23 个 test 误报的构成为 `_33` 15、`_22` 3、`_72` 3、`_54` 2；dev 为 7 个（`_33` 5、`_72` 1、`_54` 1）。全部来自 `cpp/memory-may-not-be-freed`，没有 C 误报。

示例（`char_calloc_33__good`，第 74 行）：

```cpp
data = (char *)calloc(100, sizeof(char));
...
{
    char * data = dataRef;   // dataRef 是 data 的引用别名
    free(data);              // 通过别名副本释放
}
```

`never-freed` 不报该单元；`may-not-be-freed` 报“may not be released at this exit point”。这是工具的值流/别名建模限制，不是 Juliet 标签错误（good 单元 ASan/LSan 未观察到泄漏）。

### 7.2 漏报

- test 的 2 个 FN 都是 `_82` 编译失败（`new_twoIntsStruct_82__bad`、`new_wchar_t_82__bad`），不是查询漏报；端到端口径计入，可评估口径排除。
- 可评估范围内唯一 FN：`CWE401_Memory_Leak__virtual_destructor_01__bad`（C++，dev）。`BadDerivedClass` 构造函数 `new char[]`，`~BadDerivedClass()` 中 `delete[]`，但基类析构函数非虚，`delete baseClassObject` 不会调用派生类析构；CodeQL 看到析构函数里有 `delete[]` 就认为已释放，未建模非虚析构的派发语义。
- 其余 bad 单元全部被至少一个查询命中（可评估 test 68/68）。

### 7.3 与 Clang / Cppcheck 的差异解释

- Clang 的 `unix.Malloc`/`cplusplus.NewDeleteLeaks` 是路径敏感的过程内检查，误报极低（test FP 0），但对 `_54` 多文件、指针逃逸到 `printLine`、部分 C++ 模式漏报较多（test 15 个可评估 FN）。
- Cppcheck 的 `memleak` 规则最保守，test 只报 22 个 bad，漏 48 个；4 个 FP 在 `_33` good（与 CodeQL 的 `_33` 误报同源）。
- CodeQL 的 `memory-never-freed` 与 `memory-may-not-be-freed` 组合把 test 可评估召回推到 100%，其中 15 个是 Clang 未报的 bad；误报集中在 C++ 间接释放模式，MCC 0.674 低于 Clang 0.781。
- 三者输入、编译器和查询语义不同（Clang/Cppcheck 用 clang 22.1.8 编译并分析；CodeQL 用 gcc/g++ 15.3 建库），数字只能作为同一数据集上的方法对比，不能当作工具排名。

---

## 8. 限制

1. **过程内/单 TU**：每单元一个数据库、一个编译命令；跨 TU 链接时分析没有做。多文件单元用 `#include` 包装近似，和基线一致，但跨函数所有权转移仍会误报（§7.1）。
2. **查询版本固定**：结果只对 CodeQL 2.27.4 + `cpp-queries` 1.10.0 成立；升级查询包会改变召回/误报，不能跨版本直接比较。
3. **编译器不同**：CodeQL 用 gcc/g++ 15.3 建库，Clang/Cppcheck 基线用 clang 22.1.8；`_82` 的 6 个编译失败在两边一致，但其他边界语法可能不同。曾用 `-std=c11/c++17` + `_GNU_SOURCE` 对齐基线，未做多编译器敏感性实验。
4. **标签口径**：按冻结标签计分；Juliet 有 22 个 bad 单元在 ASan/LSan 下未观察到泄漏，本目录没有另做 178 运行时支持子群，主表包含这 22 个。因此 CodeQL 的 96 个 TP 中包含“静态认为泄漏、运行时未触发”的单元。
5. **时间口径**：42.5 s/单元包含建库、TRAP 导入、查询加载与 6 并发争用，不是查询内核的纯计算时间；也没有做缓存/增量优化。
6. **Semgrep / Infer 未产出结果**：Semgrep CE 无官方 C/C++ CWE-401 规则；Infer 未安装。文中没有把它们当作对比工具，也没有用自写规则冒充工具能力。
7. **网络与许可**：CodeQL bundle 经第三方 GitHub 镜像下载，已用官方 SHA-256 校验；CodeQL CLI 的使用受 GitHub 许可条款约束，本目录只保存结果与脚本，不再分发二进制。
8. **单次运行**：每个单元只跑一次，没有重复测量方差；计时受 WSL/文件系统缓存影响。

---

## 9. 文件清单

| 路径 | 内容 |
| --- | --- |
| `codeql_adapter.py` | 主适配器：建库、查询、SARIF 解析、指标、manifest（仅标准库） |
| `compare_test140.py` | 从既有 Clang/Cppcheck 预测与 CodeQL 预测生成 140 test 对比 |
| `run_codeql.sh` | 一键复现脚本（新目录，不覆盖） |
| `scripts/download_codeql_direct.sh` | 单连接断点续传下载 + 官方 SHA-256 校验 |
| `scripts/download_codeql.sh`、`scripts/probe_net.sh`、`scripts/probe_mirrors.sh`、`scripts/speedtest.sh`、`scripts/par_speed.sh` | 网络/镜像探测与下载尝试记录（失败路径保留，便于复核） |
| `runs/codeql_20261114_cwe401_full/predictions.jsonl` | 200 行逐单元预测（含每条诊断、查询、状态、计时、命令） |
| `runs/codeql_20261114_cwe401_full/metrics.json` / `metrics.md` | 混淆矩阵、P/R/F1(V)/Macro-F1/MCC、分语言/split/查询、计时 |
| `runs/codeql_20261114_cwe401_full/comparison_test140.json` / `.md` | 与 Clang/Cppcheck 的同 140 test 对比 |
| `runs/codeql_20261114_cwe401_full/manifest.json` | 输入/输出 SHA-256、工具版本、查询哈希、设置、墙钟 |
| `runs/codeql_20261114_cwe401_full/raw/` | 每单元 `*.create.*`、`*.analyze.*`、`*.compile.cmd.txt`、`*.sarif.gz`；逐字保留 |
| `runs/codeql_20261114_cwe401_full/work/` | 多文件包装 TU 与目标文件（`obj/` 为编译产物） |

所有结果目录均由 `manifest.json` 记录输入与输出哈希；复跑请用新目录，适配器拒绝覆盖非空目录。
