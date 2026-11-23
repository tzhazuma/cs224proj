# 动态覆盖率证据：Juliet CWE-401 冻结 test 140

本目录只做一件事：给冻结的 `split=test` 140 个 Juliet CWE-401 单元补上**逐行/逐分支执行覆盖**，把原路径（default ASan/LSan）与 `dynamic_enhanced` 的两条故障路径（`realloc_fail`、`nogobal`）的 clean/leak 判定和“这段代码到底执行了多少”对齐。

结论先行（全部来自本目录已落盘的真实运行，`runs/test140_coverage_v1`）：

| 指标 | 值 |
| --- | ---: |
| 单元 | 140（bad 70 / good 70），70 组 |
| 覆盖率采集成功 | 140 / 140；`compile_error` 0，`coverage_error` 0 |
| 入口已执行 | 140 / 140 |
| 有效行覆盖（剔除 CWE-561 声明死代码） | 140 / 140 单元 100% |
| 原始行覆盖 | 99.9%（6 个 good 单元各有 1 行声明死代码未走） |
| 分支覆盖（单元自身文件） | 52.7%；`branch_complete` 21 / 140 |
| 原路径判定 | 58 TP / 0 FP / 70 TN / 12 FN |
| 三模式并集判定 | 70 TP / 0 FP / 70 TN / 0 FN |
| 与归档判定一致 | default 140/140；并集 140/140 |
| `realloc_fail` 新增覆盖 | 14 个单元各新增 1 个分支，0 行 |
| `nogobal` 新增覆盖 | 0 行 / 0 分支 |
| 分配/释放调用点执行 | 167/167、89/89（default 与并集相同） |

读法：

- **行覆盖不能证明 clean。** 原路径 82 个 clean（70 good + 12 实际 bad）在剔除声明死代码后**全部 100% 行覆盖**；其中 12 个是漏报的 bad。行覆盖只能排除“入口没执行/代码没走到”，不能区分“执行了但没泄漏”和“执行了但泄漏没被观测到”。
- **分支覆盖能解释 7 个，但不能解释另外 5 个。** 7 个 `malloc_realloc_*` bad 的默认路径所有行都执行，但 `realloc` 返回 NULL 的分支没走；`realloc_fail` 恰好新增这 14 个分支（7 bad + 7 good）。5 个 `_68` 全局指针单元的 `nogobal` 新增 0 行/0 分支，问题在 LSan 把全局当根，不在执行不足。
- **覆盖率门控不能自动修正错误负例。** 用 effective line gate 门控原路径，12 个漏报仍然全部被当作“有覆盖支持的 clean”（`supported_clean_but_bad = 12`）；只有把增强模式并集接上，才变成 70 TP / 0 FN。branch gate 更严，但 70 个 good 没有一个是 `branch_complete`（分配失败守卫不可达），会把全部 good 弃权。
- **动态 `clean` 的正确说法**：在本数据上，`executed_clean` 是“该次执行走完了单元自身所有可达行”，不是“无泄漏”；`covered_clean / unsupported_clean` 只能作为证据强度标签，不能替代泄漏判定。
- **逐单元三分类**：`coverage_class ∈ {covered_clean, uncovered, compile_error, leak}`。原路径：covered_clean 82（good 70 + bad 12）、uncovered 0、compile_error 0、leak 58；增强并集：covered_clean 70（全 good）、uncovered 0、compile_error 0、leak 70。`uncovered` 不写成负例，`compile_error` 单独计数。

---

## 1. 问题与定位

项目已有的动态结果是 ASan/LSan 的单路径观测。`README.md` §3.2 已明确：动态 clean 不是 TN，因为旧 run 没有行/分支覆盖率，clean 只表示“执行路径上未观察到 definite/indirect leak”。`dynamic_enhanced` 用 `realloc_fail` 与 `nogobal` 把 12 个旧不可观测 bad 变成可观测，但仍没有回答：

1. 一个 clean 单元到底执行了多少？是“执行了但没泄漏”，还是“关键代码没走到”？
2. 12 个漏报里，哪些可以用“分支没走”解释，哪些是工具语义（LSan 根集）限制？
3. 如果用覆盖率给 clean 做门控，能不能减少错误负例？会弃权多少 good？

本目录用 gcov 回答这三个问题。覆盖率只作为**证据强度**，不改标签、不改泄漏判定、不把 `coverage_error` 写成负例。

---

## 2. 方法

### 2.1 单元与构建

- 单元来自 `juliet/subset_units.jsonl` 的冻结 `split=test`：140 个，70 bad / 70 good，70 组；启动时校验 `juliet/FREEZE.json` 的 `subset_units_sha256`，不一致直接退出。
- 直接编译**原始未修改**的 Juliet 源文件；评测端只额外提供一个 probe `main()`，调用该单元自己的 `bad` 或 `good` 入口。bad 用 `-DOMITGOOD`，good 用 `-DOMITBAD`。
- 编译参数：`gcc/g++ -O0 -g -fsanitize=address -fno-omit-frame-pointer --coverage -w`；链接 `--coverage`、`juliet/raw/testcasesupport/io.o`、`std_thread.o`、`-lpthread -lm`。和 `dynamic_enhanced/dyne/build.py` 的编译器、sanitizer、probe 完全一致，只加了 `--coverage`。
- 每个单元只编译一次，链接两个二进制：plain（default/nogobal）和 wrap（`-Wl,--wrap=realloc` + `dynamic_enhanced/dyne/assets/inject_realloc.c`）。
- 三种模式逐次运行，运行前删除旧 `.gcda`，运行后 `gcov -j -b -c` 读取 JSON。三个模式共享同一份 `.gcno` 块编号，因此分支并集不会因重复编译而错位。

### 2.2 三种模式

| 模式 | 二进制 | 环境 | 回答的问题 |
| --- | --- | --- | --- |
| `default` | plain | `ASAN_OPTIONS=detect_leaks=1:abort_on_error=0:exitcode=23`；`LSAN_OPTIONS=exitcode=23:use_stacks=0:use_registers=0` | 原路径：标准根集下是否观察到泄漏 |
| `realloc_fail` | wrap | 同上，另加 `DYNENH_REALLOC_FAIL_NONNULL=1` | 第一次非 NULL `realloc` 真实失败时，初始块是否泄漏 |
| `nogobal` | plain | 同上，`LSAN_OPTIONS=...:use_globals=0` | 去掉全局根后，全局持有的块是否不可达 |

`realloc_fail` 只对真正执行到非 NULL `realloc` 的单元适用；本次 14 个（7 bad + 7 good），与归档 run 一致。其余 126 个记为 `applicable=false`，不参与该模式的判定；它们的覆盖率仍被采集，但与 default 路径相同。

### 2.3 覆盖率的归属与口径

- **只统计单元自身文件**：`unit.sources` 中的 `.c/.cpp`，以及同组 `group_id*.h`。`testcasesupport`、STL 头、probe main 不计入单元覆盖率。
- `gcov` 的逐对象汇总会把 STL 模板头也算进 “Lines executed: X% of N”；本目录不采用这个总数，而是解析 JSON 后按文件归属过滤。`verify` 另行用“JSON 原始行记录数 vs gcov 最后一行汇总”做一致性检查（`_72` 单元的 STL 头会被 gcov 重复计数，因此比较的是原始记录数而不是去重后的行数）。
- **tier 定义是精确的，不是百分比阈值**：
  - `branch_complete`：单元自身每个可执行行都执行，且每个记录到的分支都至少走一次；
  - `line_complete`：每个可执行行都执行，但至少一个分支未走；
  - `partial`：有可执行行未执行；
  - `not_executed`：单元自身一行都没执行；
  - `no_coverage` / `coverage_error`：gcov 没有记录或运行失败，不当作 clean。
- **CWE-561 声明死代码**：6 个 good 单元各有 1 行位于 `if (GLOBAL_CONST_FALSE)` / `if (goodB2G1Global)` 的不可达分支，源码明确标注 `INCIDENTAL: CWE 561 Dead Code`。本目录同时保留原始行覆盖与 effective 行覆盖：effective 把这些声明死代码从分母剔除，并逐行列明；这不是把未执行行算成已执行。原始 `partial` 6 个，effective `partial` 0 个。
- **并集**：三模式执行到的行/分支的并集；只在有 coverage 的模式上合并。
- **逐单元三分类**：`coverage_class` 取 `covered_clean`（clean + effective 行完整 + 入口执行）、`uncovered`（clean 但覆盖不足，或 harness/coverage 不可用）、`compile_error`（构建失败）、`leak`。`covered_clean` 不是正确性标签，原路径下 82 个里有 12 个实际是 bad。

### 2.4 泄漏判定

沿用 `dynamic_enhanced` 的规则：解析 LSan 的每个 `Direct/Indirect leak` 块，跳过工具链/运行时帧、probe 帧和 `__wrap_realloc` 帧，取第一个带源码位置的帧；只有该帧属于本单元自己的源文件或同组头文件时，才把这块算作本单元的泄漏。任一适用模式出现归因泄漏 → `leak`；所有适用模式都没有 → `clean`。覆盖率不参与这个判定。

### 2.5 为什么用 GCC gcov 而不是 clang/llvm-cov

任务允许 llvm-cov 或 gcov。选择 GCC gcov 的原因是**可比性**：`dynamic_enhanced` 的归档结果就是 GCC 15.3.0 + ASan/LSan；同编译器、同 sanitizer、同 probe 才能把覆盖率执行与归档判定逐单元对齐（本次 default/并集均 140/140 一致）。

实现过程中也实测过 clang 22.1.8 + `-fprofile-instr-generate -fcoverage-mapping`：普通的 ASan+coverage 泄漏运行可以写出 `.profraw` 并导出 LCOV；但 **clang + `-Wl,--wrap=realloc` + LSan 在注入泄漏后会挂起**（不注入或 `detect_leaks=0` 时不挂），无法可靠复现 `realloc_fail`。因此最终采用 GCC gcov，并在 README 中保留这一失败记录，避免把工具限制写成“没有尝试”。

---

## 3. 结果

完整表格在 `runs/test140_coverage_v1/metrics.md`，机器可读版本是同目录 `metrics.json`。本节只摘主数字。

### 3.1 覆盖率采集

| 模式 | 单元 | 适用 | bad leak | good leak | 有效行覆盖均值 | 分支覆盖均值 | branch_complete | line_complete | partial |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `default` | 140 | 140 | 58 | 0 | 100.0% | 50.0% | 21 | 119 | 0 |
| `realloc_fail` | 140 | 14 | 7 | 0 | 97.8% | 50.0% | 21 | 105 | 14 |
| `nogobal` | 140 | 140 | 63 | 0 | 100.0% | 50.0% | 21 | 119 | 0 |

- 并集：有效行覆盖 100.0%，原始行覆盖 99.9%，分支覆盖 52.7%，入口 140/140。
- `realloc_fail` 的 14 个 `partial` 就是 14 个 realloc 单元：注入失败后走 `if (data != NULL)` 的 false 分支，跳过了成功路径的 `free/print` 行。这不是采集失败，而是故障路径本身的控制流。
- `branch_complete` 只有 21 个，且 **0 个 good**；这 21 个全部是 bad。原因是 good 单元普遍有 `if (allocation == NULL) exit(-1)` 守卫和 `GLOBAL_CONST_FALSE` 死代码分支，错误处理越多，未走分支越多。**通用分支覆盖在本数据上不是 clean 的充分证据，甚至不是质量信号：它把代码形状（守卫多少）当成了覆盖高低。**

### 3.2 原路径 82 个 clean 的执行证据

| 分层 | 原始 | effective（剔除声明死代码） |
| --- | ---: | ---: |
| `branch_complete` | 2 | 2 |
| `line_complete` | 74 | 80 |
| `partial` | 6 | 0 |
| `not_executed` | 0 | 0 |
| 合计 | 82 | 82 |

- 82 = 70 good + 12 实际 bad。
- `executed_clean = 82/82`：所有 clean 判定的单元自身可执行行都执行了。
- 其中真 good 70，实际 bad 12；**12 个漏报全部是 `executed_clean`**。
- `branch_complete` 的 good = 0；因此 branch gate 会把 70 个 good 全部弃权（见 §3.4）。
- 6 个原始 `partial` 的未覆盖行全部是 CWE-561 声明死代码（6 行）；逐行清单在 `metrics.json` 的 `clean_evidence` / `latent_units` 和 `cases/*/run_*/coverage.json`。

### 3.3 12 个漏报：7 个由分支解释，5 个由根集解释

| 组 | 数量 | 默认 tier | 默认未走分支 | 增强模式新增 | 结论 |
| --- | ---: | --- | --- | --- | --- |
| `malloc_realloc_*` | 7 | `line_complete` | `if (data != NULL)` 的 false 分支（`realloc` 返回 NULL） | +1 分支/单元，0 行 | 执行不足（分支级） |
| `*_68` 全局指针 | 5 | 2 个 `branch_complete`，3 个 `line_complete` | 只有分配失败守卫；与泄漏无关 | 0 行 / 0 分支 | LSan 根集语义，不是执行不足 |

具体例子（完整表在 `metrics.md` §3）：

- `malloc_realloc_int_01__bad`：默认 11/11 行、2/4 分支；未走分支是 `28: if (data == NULL)` 和 `34: if (data != NULL)`。`realloc_fail` 让第 34 行走 false 分支，归因泄漏 400 字节，分配点 `..._malloc_realloc_int_01.c:27`。
- `new_TwoIntsClass_68__bad`：默认 13/13 行、0/0 分支（`branch_complete`），`nogobal` 下 8 字节泄漏，分配点 `..._68a.cpp:41`。`nogobal` 不新增任何行/分支，因为代码路径完全相同，变的只是 LSan 的根集。

### 3.4 覆盖率门控视图

只对负例门控：clean 且覆盖不足 → `abstain`，从分母移除；leak 判定不因覆盖率被撤销。

| 视图 | TP | FP | TN | FN | abstain | macro-F1 | MCC | supported clean 但 bad |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| default operational | 58 | 0 | 70 | 12 | 0 | 0.914 | 0.841 | 12 |
| default line-gated（raw） | 58 | 0 | 64 | 12 | 6 | 0.910 | 0.835 | 12 |
| default line-gated（effective） | 58 | 0 | 70 | 12 | 0 | 0.914 | 0.841 | 12 |
| default branch-gated | 58 | 0 | 0 | 12 | 70 | — | — | 2 |
| enhanced operational | 70 | 0 | 70 | 0 | 0 | 1.000 | 1.000 | 0 |
| enhanced line-gated（effective） | 70 | 0 | 70 | 0 | 0 | 1.000 | 1.000 | 0 |
| enhanced branch-gated | 70 | 0 | 0 | 0 | 70 | — | — | 0 |

关键读法：

- **line gate 对原路径没有任何纠错作用**：12 个漏报全部 line-complete，所以既不被弃权，也不被改判；它只把 6 个死代码单元从 raw 视图里弃权。
- **branch gate 过于严格**：70 个 good 全部弃权（0 TN），同时仍有 2 个 `_68` bad 被当作有覆盖支持的 clean。它不能作为 clean 证书。
- **增强并集 + line gate**：70 TP / 0 FN / 70 TN / 0 abstain / 0 supported_clean_bad。这个 1.000 的前提是三种模式都跑；缺任何一种，12 个漏报会回来。
- `supported_clean_but_bad` 是覆盖率证据最危险的失败模式：覆盖看起来充分，判定却是错的。原路径 12 个，增强并集 0 个。

### 3.5 每个模式新增了什么

| 模式 | 相对 default 有新覆盖的单元 | 新增行 | 新增分支 |
| --- | ---: | ---: | ---: |
| `default` | 0 | 0 | 0 |
| `realloc_fail` | 14 | 0 | 14 |
| `nogobal` | 0 | 0 | 0 |

- `realloc_fail` 新增的 14 个分支正好对应 14 个 realloc 单元（7 bad + 7 good）；7 个 bad 全部因此从 clean 变 leak，7 个 good 仍 clean。没有新增行，因为失败路径跳过的是已有的 `free/print` 行。
- `nogobal` 新增 0 行/0 分支，是“5 个 `_68` 的修复不是靠执行更多代码”的直接证据。
- `default` 与 `nogobal` 的覆盖率逐单元完全相同；差异只在 LSan 报告。

### 3.6 分配/释放调用点覆盖

| 视图 | 分配调用点执行 | 释放调用点执行 |
| --- | ---: | ---: |
| default | 167/167 | 89/89 |
| union | 167/167 | 89/89 |

所有分配/释放调用点都执行了，包括 12 个漏报 bad。**调用点覆盖也不能区分“执行了分配/释放”与“该块被泄漏”**；泄漏取决于指针是否被覆盖、是否还有根、以及失败路径是否释放，而不是调用点是否出现。

### 3.7 与归档结果的一致性

| 对比 | 一致 |
| --- | ---: |
| 覆盖率运行 default vs `dynamic_enhanced` 归档 default | 140/140 |
| 覆盖率运行并集 vs 归档并集 | 140/140 |
| 归档 default vs 旧 ASan（`traditional/dynamic/...`） | 140/140 |
| 归档并集 vs 旧 ASan/Valgrind 任一 | 128/140（差异恰好 12 个 bad） |

`runs/test140_coverage_v1/verify.json` 为 `PASS`：140 单元、70/70、三模式、逐模式行/分支总数一致、gcov 原始行计数一致、归档一致、selftest PASS。`compile_error` 0，`coverage_error` 0。

---

## 4. 文献与定位

覆盖率作为测试充分性准则的经典讨论见 Zhu, Hall & May, *Software unit test coverage and adequacy*, ACM Computing Surveys 29(4), 1997（DOI 10.1145/267580.267590）。本文的实验正好给出一个具体反例：**100% 行覆盖（以及 100% 可达行覆盖）不等于无泄漏**，因为泄漏是分配/释放/根可达性的语义性质，不是行是否出现。

工具与数据：

- LLVM Source-based Code Coverage：<https://clang.llvm.org/docs/SourceBasedCodeCoverage.html>（本文在选型时实测，但因 clang + `--wrap=realloc` + LSan 挂起而未采用）。
- GCC gcov：<https://gcc.gnu.org/onlinedocs/gcc/Gcov.html>，`gcov -j -b -c` 的 JSON 中间格式是本文逐行/逐分支数据的来源。
- LeakSanitizer：<https://clang.llvm.org/docs/LeakSanitizer.html>；`use_globals=0` 的行为是 5 个 `_68` 单元的解释基础。
- AddressSanitizer：Serebryany et al., *AddressSanitizer: A Fast Address Sanity Checker*, USENIX ATC 2012。
- NIST Juliet Test Suite / SARD：<https://samate.nist.gov/SARD/testsuite.php>；CWE-401 用例的 `GLOBAL_CONST_FALSE`、`_68`、`_72`、`_82` 等变体是本文分层的主要来源。

定位：本文不是提出新的覆盖率准则，而是把**已有覆盖率工具**接到**已冻结的泄漏判定**上，量化“执行覆盖”与“泄漏证据”之间的缺口。结论对使用动态 clean 作为负例的任何 pipeline 都成立：必须同时报告覆盖层，且不能用行覆盖单独给 clean 背书。

---

## 5. 改进 idea 与下一步实验

以下均为**尚未运行**的后续工作，不是本目录的结果；每条给出可执行设计和要看的指标。

1. **泄漏相关分支覆盖（Leak-Relevant Branch Coverage, LBC）**
   当前通用分支覆盖被 `if (malloc == NULL) exit()` 守卫主导（good 的 `branch_complete` 为 0）。可以按源码/模板标注“分支结果控制分配、释放、指针覆盖或逃逸”的分支，只对这些分支计覆盖。预期能把 7 个 realloc 漏报从 119 个 line-complete 中单独分离出来，而不把分配失败守卫算成缺口。指标：LBC 默认 vs 三模式并集、LBC 与漏报的交叉表。

2. **第 k 次分配失败调度**
   现在只让第一次非 NULL `realloc` 失败。可以对每个分配点（167 个）和每个 realloc 调用序号 k=1..N 做确定性失败注入，执行 `malloc/calloc/realloc` 的失败守卫。预期提高 `branch_complete`，并检验“good 在分配失败路径上是否仍 clean”。指标：新增分支数、新增泄漏数、good 误报数、每单元运行时间。

3. **逐全局变量根消融**
   `nogobal` 是进程级总开关。可以在每个单元里逐个把全局指针置空/`__lsan_ignore_object`，观察块是否变成不可达，从而把 5 个 `_68` 的“哪个全局持有它”定位到变量级。指标：根敏感单元数、每变量消融后的泄漏字节、good 对照。

4. **覆盖率引导的故障搜索**
   用 LBC/新分支作为反馈，选择下一个失败注入点或输入变异，直到没有新的泄漏相关分支。相比固定三模式，能发现“第二次 realloc 失败才泄漏”“多级错误处理”等当前看不到的路径。指标：达到 LBC=100% 所需注入次数、发现的新 leak、成本。

5. **覆盖率门控接入 hybrid/LLM**
   把 `executed_clean`、`line_complete`、`branch_complete`、LBC 作为证据强度字段传给 hybrid；只在 LBC 充分时接受 clean，否则弃权或要求更多证据。当前 line gate 对 12 个漏报无效，说明门控必须用 LBC，不能用通用行/分支覆盖。指标：弃权率、decided accuracy、macro-F1、token/请求成本。

6. **gcov vs llvm-cov 交叉验证**
   在无 LSan 的构建上对同一批单元同时跑 GCC gcov 与 clang source-based coverage，比较行/区域/分支计数。两者对模板、宏、异常边的定义不同；交叉验证能区分“覆盖率差异”与“工具定义差异”。指标：逐单元行/分支计数的一致率、分歧最大的文件。

7. **MC/DC 与复合条件**
   对 `if (data != NULL && ...)` 这类复合条件，分支覆盖不保证每个条件都取真/假。可以对 140 个单元的复合条件做 MC/DC 或条件覆盖，检验是否存在“分支走了但某个子条件从未取假”的 clean。指标：复合条件数、MC/DC 对子、新增可区分单元。

---

## 6. 复现

环境：WSL Ubuntu，GCC/G++ 15.3.0，gcov 15.3.0，Python 3；不需要网络和任何 API key。

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj/dynamic_coverage

# 1) 合成 control：一个二路分支，两次运行各走一边，并集必须 branch_complete
python3 run_dynamic_coverage.py selftest
# -> selftest/selftest.json: PASS

# 2) 全量 140 单元 × 3 模式（新 run id；已存在目录会被拒绝）
python3 run_dynamic_coverage.py run --run-id test140_coverage_v2 --jobs 8

# 3) 只重算指标/报告/CSV（不重跑）
python3 run_dynamic_coverage.py report --run-dir runs/test140_coverage_v1

# 4) 完整性校验
python3 run_dynamic_coverage.py verify --run-dir runs/test140_coverage_v1
# -> {"status": "PASS", "problems": []}
```

正式 run 是 `runs/test140_coverage_v1`（2026-11-22，93.30 s，8 workers；每单元 mean 5.14 s / p95 15.22 s / max 19.44 s）。任何重跑都必须使用新的 `--run-id`；`run` 拒绝写入已存在目录。

---

## 7. 限制与不能声称的事

1. **单次执行路径，不是输入空间覆盖。** 每个模式只执行 probe 调用的一次运行；没有 fuzzing、输入生成或多输入调度。`line_complete` 只说明这次执行走完了可达行，不说明任意输入下都无泄漏。
2. **`realloc_fail` 只让第一次非 NULL `realloc` 失败。** 如果某个单元只在第二次失败时泄漏，本实验看不到；本 test 集的 7 个单元都只有一次非 NULL `realloc`。
3. **`nogobal` 是进程级开关，不是逐变量根映射。** 它证明“去掉全局根后该块不可达”，不能指出是哪一个全局变量持有它；5 个 `_68` bad 各只有一个全局指针，配对 good 在同样设置下干净。
4. **`executed_clean` 不是无泄漏证明。** 默认路径 82 个 clean 在剔除 6 行声明死代码后全部行覆盖，其中 12 个实际是 bad；2 个 `_68` 甚至 `branch_complete`，另外 3 个 `_68` 是 `line_complete`。覆盖充分不能替代根集/泄漏判定语义。
5. **CWE-561 死代码剔除是文本规则，不是执行事实。** 只有源码明确标注 `INCIDENTAL: CWE 561 Dead Code` 的未覆盖行才从 effective 分母剔除；原始行覆盖和具体行号都保留在记录里。换数据/换注释后需要重新核对。
6. **覆盖率只属于单元自身文件。** STL 头、`testcasesupport`、probe main 不计入；`_72` 单元的 `std::vector` 模板代码不在单元覆盖率里。这是有意的归属，不是遗漏。
7. **通用分支覆盖不是 clean 的充分证据。** 0 个 good 达到 `branch_complete`，branch gate 会把 70 个 good 全部弃权；本数据上通用分支覆盖被分配失败守卫主导。需要 LBC 或分配失败注入（§5）才有机会把“分支充分”变成可用判据。
8. **没有重跑 Valgrind。** 当前 WSL 没有 valgrind；旧 Valgrind 的对比只来自归档，没有被冒充成本次测量。
9. **只限 `split=test` 的 140 个冻结单元。** 不外推到 dev、其他 CWE、其他编译器或优化级别；`-O0 -g` 是分配栈归因和行号的前提。
10. **不能把 70/70 写成“动态检测 100%”。** 正确说法是：在冻结 test 140 上，`default + realloc_fail + nogobal` 的并集对 70 bad / 70 good 达到 70/0/70/0，且 12 个旧不可观测 bad 全部有可复核证据；这不是对所有 CWE-401 变体的保证。

---

## 8. 目录

```text
dynamic_coverage/
├── README.md
├── run_dynamic_coverage.py          # CLI: selftest / run / report / verify
├── dyncov/
│   ├── config.py                    # 路径、模式、环境、tier 定义
│   ├── units.py                     # 冻结 test 140、哈希校验、dyne 复用
│   ├── build.py                     # gcov+ASan 编译、plain/wrap 链接
│   ├── execute.py                   # 固定 ASan/LSan 环境、超时/进程组
│   ├── gcov.py                      # gcov -j JSON 解析、归属、死代码、tier
│   ├── pipeline.py                  # 140 × 3 调度与逐单元证据
│   ├── link.py                      # 关联 dynamic_enhanced / 旧 ASan 归档
│   ├── metrics.py                   # 分层混淆、门控视图、模式增益、调用点
│   ├── report.py                    # metrics.md / metrics.json / CSV
│   ├── selftest.py                  # 合成 control：二分分支 + 并集
│   └── verify.py                    # 计数、totals、gcov、归档一致性
├── selftest/selftest.json           # PASS
└── runs/test140_coverage_v1/
    ├── manifest.json                # 冻结哈希、工具版本、时间
    ├── results_units.jsonl          # 140 行，逐单元判定 + 覆盖率
    ├── results_raw.jsonl            # 420 行，逐单元 × 模式
    ├── metrics.json / metrics.md    # 分层指标与报告
    ├── verify.json                  # PASS
    ├── exports/
    │   ├── coverage_units.csv       # 140 × 3 行/分支/tier
    │   ├── clean_evidence.csv       # 82 个 clean 的执行证据
    │   ├── latent_units.csv         # 12 个漏报的覆盖解释
    │   └── strata.csv               # 分层混淆矩阵
    └── cases/<unit_key>_<label>/
        ├── build.json
        ├── unit.json
        ├── coverage_union.json
        └── run_<mode>/{run.json,coverage.json,stdout.txt,stderr.txt}
```

所有 Python、编译和运行都在 WSL Ubuntu 内完成；本目录不读取、不打印、不保存任何 API key，也没有发起任何网络请求。
