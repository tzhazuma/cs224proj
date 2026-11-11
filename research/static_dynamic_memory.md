# 传统内存泄漏检测：静态与动态方法系统调研（CWE-401 重点）

> 调研日期：2026-11-12。范围：C/C++ 堆内存泄漏（CWE-401）为主，兼顾资源泄漏（CWE-772）的边界；覆盖 Clang Static Analyzer、Cppcheck、Infer、CodeQL、SVF/Saber/SMOKE、符号执行，以及 Valgrind/Memcheck、ASan/LSan、Dr. Memory、libFuzzer/AFL++/OSS-Fuzz。
>
> 证据级别：**A** = 同行评审论文/标准（DOI 可核验）；**B** = 预印本/技术报告（arXiv、NIST TN）；**C** = 工具官方文档/项目页（行为描述可信；性能数字按项目自述处理）。所有数字均给出处；未核验的内容不写成事实。
>
> 本文件只做文献与工具调研，不运行本项目数据，不修改 `references.bib` 或其他文件。

---

## 0. 结论摘要

1. **静态与动态回答的不是同一个问题。** 静态泄漏检测器通常回答“是否存在一条可行的、分配后未释放且指针未逃逸的路径”（may-leak）；Valgrind/LSan/Dr. Memory 回答“在这次执行的退出点，这个堆块是否已经不可达”（definitely lost / leak）。两者不能直接放在同一张 accuracy 表里比较。
2. **CWE-401 的标签是程序属性，动态报告只是某次执行的证据。** 动态工具没报泄漏，不等于程序没有泄漏；静态工具报了泄漏，也不等于存在可执行到的泄漏路径。统一 benchmark 必须把“未执行到”与“真阴性”分开。
3. **Clang Static Analyzer 是开源工具中路径敏感符号执行的典型代表：** 默认以单个翻译单元（TU）为边界，跨 TU 需要 CTU 配置；自定义分配/释放函数需要 `ownership_returns/takes/holds` 注解，否则无法建模；路径深度和节点数限制会造成漏报。
4. **Cppcheck 以低误报为设计目标、通常是最快的第一遍，但泄漏检查是路径不敏感的简单控制流分析。** 它适合作为快速第一遍/CI 门禁，不适合承担深度跨过程、错误路径泄漏的证明责任；LeakGuard 的实测中它只找到 129 个真实泄漏中的 1 个，但平均耗时仅 378 秒/项目。
5. **Infer 用分离逻辑/双向归纳（bi-abduction）做组合式分析，扩展性好，但抽象会丢精度。** 官方明确说未知函数会被“乐观”处理，可能同时造成漏报和误报；Pulse 只在错误路径条件充分确定时报告，输入相关的泄漏可能变成 latent。
6. **SVF/Saber/SMOKE 代表稀疏值流与路径敏感的分层路线。** Saber 自报 18.5% 误报率，SMOKE 在自身基准上测到 Saber 66.7% 误报率；同一工具在不同基准/配置下差异巨大，引用时必须带基准与配置。
7. **Valgrind/Memcheck 的泄漏语义最细：** still reachable、definitely lost、indirectly lost、possibly lost 四类；默认 `--leak-check=summary`，且只有 `--leak-check=full` 才把泄漏计为 error；20–30× slowdown；无需重编译。
8. **ASan/LSan 是“编译期插桩 + 退出时扫描”：** ASan 典型 2× slowdown（原论文 SPEC CPU2006 平均 73% slowdown，约 1.73×；3.37× 内存）；LSan 在退出前几乎零开销，只报告不可达堆块；需要重编译，LSan 不支持 Windows。
9. **Dr. Memory 是 Windows 场景的重要补充：** 10–20× slowdown，平均比 Memcheck 快 2×（部分基准 4×）；无需重编译；区分 leak / possible leak / still reachable；对未对齐指针、加密指针、自定义分配器有已知误报来源。
10. **模糊测试的泄漏 oracle 继承自 LSan：** libFuzzer 默认 `-detect_leaks=1`，通过 malloc/free 计数 + LSan 复验来报告 `leak-<sha1>`；AFL++ 用 `AFL_USE_LSAN=1` 和 `__AFL_LEAK_CHECK()`。它擅长输入驱动的解析器/协议代码，但 harness、语料和退出时机是瓶颈。
11. **近年最强的一组 CWE-401 对比数字来自 LeakGuard（2025 预印本）：** Juliet CWE-401 上 CSA F1=0.479、Infer=0.331、SVF=0.395、LeakGuard=0.990；真实项目 129 个泄漏中 CSA/Infer/Cppcheck 分别找到 44/25/1 个。但这是作者自建基准，不能当作无偏排行榜。
12. **对“AI + 传统统一 benchmark”的直接建议：** 静态、动态、模糊测试、AI 分 track 记录；共享 case id 与标签；动态主指标用 definitely lost，possibly lost 单列，still reachable 按 CERT MEM31-C 的终止期例外处理；所有工具记录版本、配置、超时、构建失败与输入覆盖。

---

## 1. CWE-401 的可检测语义

### 1.1 定义与边界

MITRE 对 CWE-401 的定义是：*“The product does not sufficiently track and release allocated memory after it has been used, making the memory unavailable for reallocation and reuse.”* 它是一个 **Variant** 级弱点：在完整弱点层次中 ChildOf CWE-772（Missing Release of Resource after Effective Lifetime），在简化映射视图中也 ChildOf CWE-404（Improper Resource Shutdown or Release）。CWE-772 是 **Base** 级，范围更广，除了内存还包括文件描述符、句柄等资源；CWE-401 只覆盖内存。[CWE-401](https://cwe.mitre.org/data/definitions/401.html) [CWE-772](https://cwe.mitre.org/data/definitions/772.html)

这意味着：

- **CWE-401 不是“所有未 free 的分配”。** 如果内存被赋给一个生命周期覆盖程序终止的指针（典型是静态/全局缓存），CERT MEM31-C 明确把它列为例外（MEM31-C-EX1），不要求释放。[MEM31-C](https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/rules/memory-management-mem/mem31-c/)
- **CWE-401 也不等于 double free / use-after-free。** 后两者分别是 CWE-415/CWE-416；很多工具把 leak、double free、UAF 放在同一个 checker 里（如 Clang `unix.Malloc`），做 CWE-401 评测时必须按报告类型过滤。
- **CWE-401 与 CWE-772 的映射要写清楚。** 文件描述符/句柄泄漏应归 CWE-772（如 CWE-775），不能算 CWE-401；Infer 的 `PULSE_RESOURCE_LEAK`、CodeQL 的 `cpp/descriptor-never-freed` 属于资源泄漏，不应混入内存泄漏主指标。
- **CWE-401 的后果主要是可用性。** MITRE 列出的影响是 DoS（崩溃、退出、重启、不稳定、CPU/内存资源消耗）和性能下降；它不一定直接给出代码执行。[CWE-401](https://cwe.mitre.org/data/definitions/401.html)

CERT MEM31-C 的风险表给该规则 **Severity=Medium、Likelihood=Probable**；同一页的 “Automated Detection” 表列出了 Cppcheck 2.15 的 `memleak`、`leakReturnValNotUsed`、`leakUnsafeArgAlloc`、`memleakOnRealloc`，以及 Coverity 的 `RESOURCE_LEAK`、CodeSonar 的 `ALLOC.LEAK` 等 checker。[MEM31-C](https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/rules/memory-management-mem/mem31-c/) 该页的 “Detectable: No” 是 CERT 规则层面的自动可判定性评级，不应解读为“所有工具都检测不到”；同页明确列出了多种工具的 checker。

**把工具输出映射到 CWE-401 时，建议按下表过滤，而不是“有 warning 就算”：**

| 工具 | 可计入 CWE-401 的输出 | 需要排除/注意 |
|---|---|---|
| Clang SA | `unix.Malloc` 的 leak 警告；`cplusplus.NewDeleteLeaks` 的 leak 警告 | 同一 checker 的 double-free/UAF 警告；`ownership_holds/takes` 相关的非 leak 语义 |
| Cppcheck | `memleak`、`leakReturnValNotUsed`、`leakUnsafeArgAlloc`、`memleakOnRealloc` | 资源泄漏/分配 API 误用；按 message 确认是内存块未释放 |
| Infer | `MEMORY_LEAK_C`、`MEMORY_LEAK_CPP` | `PULSE_RESOURCE_LEAK` 属于 CWE-772；latent issue 单列 |
| CodeQL | `cpp/memory-may-not-be-freed`、`cpp/memory-never-freed`、`cpp/catch-missing-free`、`cpp/memory-leak-on-failed-call-to-realloc` | `cpp/descriptor-never-freed` 等资源泄漏；may/never 分开统计 |
| Valgrind | definitely lost、indirectly lost | possibly lost 单列；still reachable 按 CERT 例外不计正例 |
| LSan | direct leak、indirect leak | still reachable 不报告；suppression 命中数要记录 |
| Dr. Memory | leak | possible leak 单列；still reachable 不计正例 |

### 1.2 三种 oracle：may-leak、must-leak、definitely lost

| 方法类 | 它回答的问题 | 正例定义 | 负例定义 | 典型误报 | 典型漏报 |
|---|---|---|---|---|---|
| 静态分析 | 是否存在一条**可行路径**，分配后未释放且指针未逃逸？ | 至少一条可行路径在函数/程序退出前失去最后一个指向该对象的指针，且没有 free | 所有可行路径都 free，或指针逃逸到调用者/全局/容器 | 不可行路径被当成可行；自定义分配器/所有权转移未建模；全局缓存被误判；容器/RAII 析构未建模 | 路径深度/节点限制；跨 TU 未开启；未知库/函数指针；自定义 MAD 函数未识别；抽象合并路径 |
| 动态分析（Valgrind/LSan/Dr. Memory） | 在**这次执行**的退出点，这个堆块是否不可达？ | 退出时堆块没有任何根可达的指针（definitely lost / leak） | 退出时仍可从根到达（still reachable），或已被 free | `possibly lost` 被当成 definitely lost；自定义池/分配器；未对齐/加密指针；全局缓存被误报 | 输入没走到泄漏路径；错误路径未执行；进程未正常退出；泄漏被 suppression；LSan 只按对齐指针扫描 |
| 模糊测试 | 在**生成的输入**上，是否触发 sanitizer 泄漏报告？ | 某个输入使 LSan/ASan 在退出或显式检查点报告泄漏，并留下 reproducer | 所有生成输入都未触发泄漏报告 | 同上；持久模式下的累积泄漏；全局缓存；工具误报 | harness 没覆盖 API；语料不足；`-detect_leaks=0`；泄漏发生在进程退出前但未被检查 |
| 静态+动态验证（如 DVSML） | 静态警告在具体执行下是 MUST-LEAK、LIKELY-NOT-LEAK、BLOAT 还是 MAY-LEAK？ | 动态执行确认对象在警告点后不可达 | 动态执行证明对象仍可达/被释放 | 动态路径覆盖不足导致分类保守 | 静态警告本身缺失；测试生成无法覆盖 |

关键区别：

- **may-leak** 是“存在一条路径”的存在量化；**must-leak** 是“所有路径”的全称量化。Clang SA/LeakGuard 倾向报 may-leak；Infer/Pulse 倾向只在错误条件“regardless of input”成立时报告，接近 must-leak；CodeQL 同时提供 `cpp/memory-may-not-be-freed` 与 `cpp/memory-never-freed` 两类查询，正好对应两种 oracle。[CodeQL CWE coverage](https://codeql.github.com/codeql-query-help/cpp-cwe/)
- **definitely lost** 是动态工具对“退出时不可达”的分类；它不等于静态的 may-leak，也不等于“所有输入都会漏”。Valgrind 手册明确说，它只能告诉你退出时哪些块丢了，不能告诉你指针是何时/如何丢的。[Memcheck manual](https://valgrind.org/docs/manual/mc-manual.html)
- **still reachable** 在 Valgrind/Dr. Memory 中默认不算泄漏；LSan 也不报告仍可达的块。这与 CERT MEM31-C-EX1 的终止期例外一致，但在静态工具中常被报成 leak。因此，做统一 benchmark 时，静态的“全局缓存 leak”与动态的“still reachable”不能直接算成同一类错误。

### 1.3 Juliet CWE-401：合成基准的结构与局限

Juliet C/C++ 1.3 包含 64,099 个可编译测试用例、118 个 CWE；每个 CWE 的测试单元通常由一个 vulnerable（bad）程序和一个 non-vulnerable（good）程序组成。[NIST SARD Juliet C/C++ 1.3](https://samate.nist.gov/SARD/test-suites/112) [NIST TN 1995](https://doi.org/10.6028/NIST.TN.1995)

LeakGuard 的评测使用的是 Juliet CWE-401 目录：**1,364 个独立测试单元，每个单元一个 positive + 一个 negative**；其混淆矩阵中 TP+FN=1,364、TN+FP=1,364，正好对应 2,728 个程序。[LeakGuard §4.3/Table 2](https://arxiv.org/html/2504.04422v1)

| 事实 | 数值 | 出处 |
|---|---|---|
| Juliet 总测试用例 | 64,099 | NIST SARD / TN 1995 |
| CWE 数 | 118 | NIST SARD |
| CWE-401 测试单元 | 1,364（positive+negative 各一） | LeakGuard §4.3 |
| CWE-401 程序数 | 2,728（1,364×2） | 由 LeakGuard 混淆矩阵反推 |

Juliet 的价值是**标签干净、可重复、可对比**；局限是**小型合成程序、路径短、分配/释放模式固定**。在 Juliet 上接近满分，不代表在真实项目的深调用链、自定义分配器、错误路径上同样有效。LeakGuard 自己在 Juliet 上 F1=0.990，但在真实项目上仍需逐个报告给开发者确认；这两个数字不能互相替代。

---

## 2. 静态方法

静态泄漏检测的共同思路是 **source-sink 可达性**：每个 allocation 是 source，free 是 sink；如果存在一条从 source 到程序出口的路径，期间没有到达 sink，且指针没有逃逸，就报告 leak。不同工具的差别在于：路径敏感度、跨过程/跨 TU 能力、指针/堆抽象、自定义分配器建模、以及为 scalability 做的截断。

### 2.1 Clang Static Analyzer（CSA）

**机制。** 官方定义是“path-sensitive, inter-procedural analysis based on symbolic execution”。[Clang Static Analyzer](https://clang.llvm.org/docs/ClangStaticAnalyzer.html) 它在符号执行中维护 `(ProgramState, ProgramPoint)` 的 ExplodedGraph，沿分支累积路径约束；跨过程主要通过内联（inlining）实现。默认分析边界是**单个翻译单元（TU）**；跨 TU 需要 CTU 模式，额外生成 PCH/AST dump 和 `clang-extdef-mapping` 索引。[CTU analysis](https://clang.llvm.org/docs/analyzer/user-docs/CrossTranslationUnit.html)

**泄漏 checker。**

- C：`unix.Malloc`，检查 memory leak、double free、use-after-free，跟踪 `malloc()/free()`；自定义分配/释放函数可用 ownership 属性标注。[Available checkers: unix.Malloc](https://clang.llvm.org/docs/analyzer/checkers.html#unix-malloc)
- C++：`cplusplus.NewDeleteLeaks`，跟踪 `new/delete` 的泄漏；同样支持 ownership 属性。[Available checkers: cplusplus.NewDeleteLeaks](https://clang.llvm.org/docs/analyzer/checkers.html#cplusplus-newdeleteleaks)
- 自定义分配器：如果 analyzer 看不到函数定义，必须用 `ownership_returns`、`ownership_takes`、`ownership_holds` 注解声明，否则无法知道 `my_free()` 等价于 `free()`。官方原文：*“Otherwise the analyzer cannot know that the opaque `my_free()` is basically equivalent to a standard `free()` call.”* [Source annotations](https://clang.llvm.org/docs/analyzer/user-docs/Annotations.html)

**输入要求。**

- 最常用 `scan-build` 包裹真实构建：`scan-build --use-analyzer=clang make`（或 CMake/Ninja）；也可用 `CodeChecker`。
- 需要可编译的源码、头文件、宏定义、include 路径；最好有 `compile_commands.json`。
- CTU 需要每个 TU 的 PCH/AST dump、`externalDefMap.txt`、编译数据库；配置成本明显高于单 TU。
- 对自定义分配器，注解会改变分析能力；不注解就按“未知函数”处理，通常导致漏报或误报。

**Oracle 与误报/漏报。**

- Oracle：may-leak；报告通常形如 “Potential leak of memory pointed to by 'p'”，并给出路径注释。
- 误报来源：不可行路径（约束求解/循环展开限制）、未知函数、所有权转移未建模、全局/静态生命周期、C++ 析构/容器/RAII 未被充分建模、宏/模板展开。
- 漏报来源：默认单 TU、路径深度/节点预算、函数指针/虚调用、复杂调用链、自定义 MAD 函数在深层调用中、CTU 未开启、分析超时。
- `unix.Malloc` 把 leak/double-free/UAF 放在一起，评测 CWE-401 时必须只取 leak 类报告。

**成本。** 在 LeakGuard 的 18 个真实项目（70,992 KLoC，32 核/128 GB，32 小时上限，3 次平均）上，CSA 总耗时 190,793 秒，平均 10,600 秒/项目；同一基准上 Cppcheck 平均 378 秒、Infer 4,748 秒、LeakGuard 7,466 秒。[LeakGuard Table 4](https://arxiv.org/html/2504.04422v1) 这些数字不是通用常数，但说明 CSA 属于“分钟到小时”级的重分析。

**边界。** 适合中小型、可编译、带注解的代码；适合在 CI 中对改动文件做增量分析；不适合没有构建系统、重度宏/模板、超大单体、或完全无法注解的自定义分配器代码。

| 维度 | 结论 | 出处 |
|---|---|---|
| 分析类型 | 路径敏感、符号执行、跨过程（内联） | 官方文档 |
| 默认范围 | 单 TU；CTU 可选 | CTU 文档 |
| 泄漏 checker | `unix.Malloc` / `cplusplus.NewDeleteLeaks` | checker 文档 |
| 自定义分配器 | 需要 ownership 注解 | annotations 文档 |
| Oracle | may-leak | checker 语义 |
| 主要成本 | 路径爆炸、CTU 配置、小时级 | LeakGuard 计时 |
| 主要风险 | 深路径/跨 TU/未注解导致的漏报；不可行路径误报 | 官方 FAQ + LeakGuard 分析 |

### 2.2 Cppcheck

**机制。** Cppcheck 的目标是“只报真实错误、尽量少误报”，并明确说检查并不完美、会漏掉应该发现的 bug。[Cppcheck manual](https://cppcheck.sourceforge.io/manual.html) 它的泄漏检查基于简单的控制流/值流分析；官方设计文档 A.5 明确写道：*“The check uses simple control-flow analysis. The control flow analysis assumes that all conditions can always be true or false. It is assumed that all statements are reachable.”* 它不判断执行如何到达 `return`，只看到“如果到达 return，则存在 leak”。[A Cppcheck Design, A.5](https://www.cs.kent.edu/~rothstei/fall_14/sec_notes/cppcheck-design.pdf)

**Checker。** CERT MEM31-C 页面列出 Cppcheck 2.15 的相关 checker：`memleak`、`leakReturnValNotUsed`、`leakUnsafeArgAlloc`、`memleakOnRealloc`。[MEM31-C](https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/rules/memory-management-mem/mem31-c/)

**输入要求。**

- 可以直接扫源文件/目录，不要求完整构建；这对嵌入式、非标准语法、宏较多的代码很实用。
- 也可以导入 `compile_commands.json`：`cppcheck --project=compile_commands.json`；`--cppcheck-build-dir` 支持增量/whole-program 分析；`--check-level=exhaustive` 用于更彻底但更慢的检查。[Cppcheck manual](https://cppcheck.sourceforge.io/manual.html)
- 需要 `-I`/`-D`/`--include` 等配置来近似编译环境；配置不同会显著改变结果。

**Oracle 与误报/漏报。**

- Oracle：may-leak，但基于语法/控制流模式，不做路径可行性证明；它把条件都当成可真可假，因此会报告“某条路径可能 leak”，也会因为不追踪复杂跨过程而漏报。
- 误报：相对低（设计目标），但仍会因全局/静态生命周期、容器/RAII、所有权转移、宏展开而误报。
- 漏报：跨 TU、深调用链、自定义分配器、函数指针、复杂错误路径；LeakGuard 的作者将其描述为 path-insensitive 且主要限于单 TU，并报告在 129 个真实泄漏中只找到 1 个。[LeakGuard §4.4](https://arxiv.org/html/2504.04422v1)
- 注意：Cppcheck 官方提供 whole-program/build-dir 能力，但这不等同于 leak checker 的完整跨 TU 路径敏感分析；引用“Cppcheck 不支持跨 TU”时应限定为“其泄漏检查在特定版本/配置下对跨 TU 复杂数据流覆盖有限”。

**成本。** LeakGuard 基准上平均 378 秒/项目，总计 6,795 秒，是四个工具中最快的；比 LeakGuard 快约 20×。[LeakGuard Table 4](https://arxiv.org/html/2504.04422v1) 对单文件/小项目通常是秒级。

**边界。** 最适合“快速第一遍”、CI 门禁、嵌入式/非标准代码、以及作为其他工具的预筛选；不适合承担“证明没有泄漏”或“覆盖深错误路径”的责任。

| 维度 | 结论 | 出处 |
|---|---|---|
| 分析类型 | 路径不敏感的简单控制流/值流 | Cppcheck Design A.5 |
| 输入 | 源码或 compile_commands；不要求完整构建 | manual |
| 泄漏 checker | `memleak` 等 | CERT 页面 |
| Oracle | may-leak（模式级） | design doc |
| 成本 | 秒到分钟；基准平均 378 秒/项目 | LeakGuard |
| 主要风险 | 跨过程/自定义分配器/深路径漏报 | LeakGuard + design doc |

### 2.3 Infer（Pulse）

**机制。** Infer 是 Meta 的静态分析器，支持 Java/C/C++/ObjC/Erlang，部署在 CI 中分析跨文件/跨函数的深层问题。[About Infer](https://fbinfer.com/docs/about-Infer/) 其内存安全引擎 Pulse 是 **interprocedural memory safety analysis**，基于分离逻辑和双向归纳（bi-abduction）：先为函数生成前后条件摘要，再在调用点组合；不需要从 `main` 开始遍历整个程序。[Pulse](https://fbinfer.com/docs/checker-pulse/) [Compositional Shape Analysis by Means of Bi-Abduction](https://doi.org/10.1145/2049697.2049700) [Moving Fast with Software Verification](https://doi.org/10.1007/978-3-319-17524-9_1)

**泄漏 checker。** Pulse 报告 `MEMORY_LEAK_C`、`MEMORY_LEAK_CPP`；资源泄漏另有 `PULSE_RESOURCE_LEAK`。[Pulse issue types](https://fbinfer.com/docs/checker-pulse/)

**Oracle 与语义。**

- 官方原文：*“Errors are only reported when all conditions on the erroneous path are true regardless of input.”* 这意味着它倾向于只报告“条件充分确定”的错误，减少误报，但输入相关的泄漏可能先以 **latent issue** 存在，只有在调用点条件满足时才变成 manifest。[Pulse](https://fbinfer.com/docs/checker-pulse/)
- 未知函数（第三方库、函数指针无法解析）会被**乐观**处理：Pulse 会“scramble”与参数可达的状态，假设未知函数不会破坏关键事实。官方明确说这既可能造成漏报，也可能造成误报，并给出一个 memory leak 漏报例子。[Pulse: Unknown Functions](https://fbinfer.com/docs/checker-pulse/)
- 因此 Infer 的 oracle 更接近“在抽象语义下可证明的 must-leak”，而不是“某条具体路径可能漏”。

**输入要求。**

- 需要可构建的项目和编译命令：`infer run --pulse --compilation-database compile_commands.json`，或 `infer run --pulse -- make`；它通过 capture 阶段记录编译命令。Pulse 用 `--pulse` 激活。
- 需要为第三方/自定义分配器提供模型或注解；否则按未知函数处理。
- 对 C++ 模板、虚调用、函数指针、复杂容器，抽象会损失精度。

**误报/漏报证据。**

- LeakGuard 的 Juliet CWE-401 结果：Infer TP=320、FP=250、TN=1,114、FN=1,044、F1=0.331。[LeakGuard Table 2](https://arxiv.org/html/2504.04422v1)
- LeakGuard 的真实项目：129 个泄漏中找到 25 个；平均 4,748 秒/项目，比 CSA 快。[LeakGuard Table 1/4](https://arxiv.org/html/2504.04422v1)
- MemHint 的报告：在 8 个真实项目、3.6M LoC 上，vanilla Infer 只找到 3 个泄漏，vanilla CodeQL 19 个；作者认为主要缺口是项目自定义的分配/释放函数。[MemHint](https://arxiv.org/abs/2603.27224)

**边界。** 适合大规模、可构建、CI 化的代码库；对“错误路径上的泄漏”和“自定义 allocator”需要额外建模；不适合把它的低误报当成高召回。

| 维度 | 结论 | 出处 |
|---|---|---|
| 分析类型 | 分离逻辑/双向归纳，组合式过程摘要 | JACM 2011 / NFM 2015 |
| 输入 | 可构建项目 + 编译命令 | Infer docs |
| Oracle | 条件充分确定时报告；latent issue | Pulse docs |
| 未知函数 | 乐观处理，可致 FP/FN | Pulse docs |
| 成本 | 基准平均 4,748 秒/项目 | LeakGuard |
| 主要风险 | 抽象丢精度、自定义 allocator 未建模 | Pulse docs + MemHint |

### 2.4 SVF、Saber、SMOKE：稀疏值流与路径敏感的分层路线

**SVF。** SVF 是 LLVM 上的过程间静态值流分析框架：它接受指针分析结果，构造过程间内存 SSA，显式表示 top-level 与 address-taken 变量的 def-use/value-flow；值流构造与指针分析可以迭代进行，以提高精度。[SVF: Interprocedural Static Value-Flow Analysis in LLVM](https://doi.org/10.1145/2892208.2892235) SVF 本身是**研究框架**，不是开箱即用的泄漏产品。Saber 是更早的 full-sparse value-flow 泄漏检测器（2012 年，Open64 实现），与 SVF 同属稀疏值流路线，但**不是 SVF 的客户端**；两者不要混为同一实现。[Saber](https://doi.org/10.1145/2338965.2336784)

**Saber。** Saber 使用 full-sparse value-flow graph（SVFG），把泄漏检测转化为图可达性问题；在不同阶段利用 field-/flow-/context-sensitivity。论文报告：在 15 个 SPEC2000 C 程序 + 5 个应用上检测到 211 个泄漏，误报率 18.5%，速度 10,220 LOC/s；比 Sparrow 快 14.2×，比 Fastcheck 多报 40.7% 的 bug 但只慢 3.7×。其 Table 1 中 Clang（2012 年的静态分析器）为 400 LOC/s、27 个 bug、25% 误报率。[Saber](https://doi.org/10.1145/2338965.2336784)

**SMOKE。** SMOKE 采用两阶段：先用可扩展但粗糙的分析生成候选泄漏路径（use-flow graph，UFG），再用 SMT（Z3）验证路径可行性。论文报告：可在 40 分钟内检查最多 8 MLoC 的工业项目，平均误报率 24.4%，比对比技术/工业工具快 5.2×–22.8×；在 29 个成熟项目中新发现 30 个泄漏（1 个获得 CVE）。同一篇论文还报告：**在其评测中 Saber 的误报率为 66.7%**，而 CSA/Infer 在 2 小时内无法分析超过 2 MLoC 的项目。[SMOKE](https://doi.org/10.1109/ICSE.2019.00025)

**这两个数字的冲突很重要。** Saber 自报 18.5%，SMOKE 测到 66.7%：基准不同（SPEC2000 vs SMOKE 的项目集）、版本/配置不同、对“误报”的判定口径不同。引用任何单一 FP 数字时，必须同时写“在哪个基准、哪个版本、什么配置下”。这也是本调研对统一 benchmark 的核心建议之一。

**成本与边界。** SVF 需要 LLVM bitcode、编译数据库和指针分析配置；Saber 基于 Open64；SMOKE 需要构建项目和 SMT 求解。它们适合研究/工业深度审计，不适合作为轻量 CI 门禁；对自定义分配器、函数指针、复杂 C++ 仍依赖建模。

| 工具/方法 | 核心 | 报告数字 | 边界 |
|---|---|---|---|
| SVF | LLVM 过程间稀疏值流/内存 SSA | 框架；无统一 leak 精度 | 需 LLVM IR；研究框架 |
| Saber | full-sparse SVFG + 图可达性 | 211 leaks，FP 18.5%，10,220 LOC/s（SPEC2000） | 2012 年实现；配置/基准敏感 |
| SMOKE | UFG 候选 + SMT 验证 | 8 MLoC/40 min，FP 24.4%，5.2–22.8× | 需构建/SMT；工业级 |
| LeakGuard | under-constrained symbolic execution + MAD 摘要 | Juliet F1 0.990；129 真实 leaks | 作者自建基准；预印本 |

### 2.5 符号执行：能力与代价

符号执行把输入符号化，沿路径累积约束，用 SMT 求解可行性；它可以在不运行程序的情况下探索错误路径，是 Clang SA、LeakGuard、SMOKE 等工具的底层引擎之一。经典 KLEE 用 LLVM bitcode + 符号输入 + 环境模型生成高覆盖率测试，展示了符号执行在复杂系统程序上的能力，也暴露了路径爆炸、环境建模、外部调用/系统调用模拟等瓶颈。[KLEE](https://www.usenix.org/legacy/event/osdi08/tech/full_papers/cadar/cadar.pdf) [Symbolic Execution for Software Testing: Three Decades Later](https://doi.org/10.1145/2408776.2408795)

对泄漏检测而言，符号执行的优势是**路径可行性**：它可以说“这条泄漏路径是可行的”，从而减少不可行路径误报；代价是**路径数指数增长**。LeakGuard 用 under-constrained symbolic execution（从感兴趣的函数开始，而不是从 `main` 开始）+ 自定义 MAD 函数摘要 + 指针逃逸分析来缓解路径爆炸；这也是它能在 18 个项目、70,992 KLoC 上运行的原因。[LeakGuard §3](https://arxiv.org/html/2504.04422v1)

**边界：**

- 需要 harness/入口函数、外部函数模型、循环/递归边界；对 GUI、网络、文件系统、多线程环境不友好。
- 路径爆炸导致超时/漏报；对不透明库调用只能保守/乐观近似。
- 符号执行本身不是泄漏 oracle；必须再加“分配-释放-逃逸”的检查器（Clang `unix.Malloc`、LeakGuard 的 leak checker 等）。

### 2.6 CodeQL（补充）

CodeQL 把源码转成关系数据库，用 QL 查询做数据流/控制流分析；它不是传统的“跑一个 checker”，而是“写/复用查询”。官方 CWE 覆盖页为 CWE-401 列出四个查询：`cpp/catch-missing-free`（Leaky catch）、`cpp/memory-may-not-be-freed`（Memory may not be freed）、`cpp/memory-never-freed`（Memory is never freed）、`cpp/memory-leak-on-failed-call-to-realloc`（Memory leak on failed call to realloc）。[CodeQL CWE coverage](https://codeql.github.com/codeql-query-help/cpp-cwe/)

这个设计对 benchmark 很有启发：**`memory-may-not-be-freed` 与 `memory-never-freed` 对应 may/must 两种 oracle**，评测时应分开统计。CodeQL 的扩展性较好，但对项目自定义分配器/释放器需要自定义模型；MemHint 的报告正是把“vanilla CodeQL 只找到 19 个、vanilla Infer 只找到 3 个”归因于自定义 MAD 函数识别不足。[MemHint](https://arxiv.org/abs/2603.27224)

### 2.7 静态方法对比表

| 工具/方法 | 分析精度 | 输入要求 | 泄漏 oracle | 主要误报来源 | 主要漏报来源 | 成本量级 | 最适合 |
|---|---|---|---|---|---|---|---|
| Clang SA | 路径敏感符号执行；默认单 TU | 可编译源码 + 构建命令；CTU 需 PCH/extdef；自定义分配器需注解 | may-leak | 不可行路径、未注解 allocator、全局生命周期、RAII/容器 | 路径深度、跨 TU、函数指针、深调用链 | 分钟–小时/项目 | 中小项目、CI 增量、可注解代码 |
| Cppcheck | 路径不敏感简单控制流 | 源码或 compile_commands；不要求完整构建 | may-leak（模式级） | 全局/静态、容器/RAII、所有权转移 | 跨过程、自定义 allocator、深错误路径 | 秒–分钟/项目 | 快速第一遍、嵌入式/非标准代码、CI 门禁 |
| Infer/Pulse | 组合式分离逻辑；抽象解释 | 可构建项目 + 编译命令；未知函数需模型 | 条件充分确定的 must-leak；latent | 未知函数乐观、抽象丢精度 | 自定义 allocator、复杂路径、输入相关泄漏 | 分钟–小时/项目 | 大规模 CI、跨文件分析 |
| CodeQL | 数据库查询/数据流 | 可构建数据库；查询/模型 | may 与 never 两类查询 | 查询/模型不完整、路径不敏感 | 自定义 allocator、复杂数据流 | 分钟–小时/项目 | 可定制查询、大规模代码 |
| SVF/Saber | 稀疏值流；图可达性 | LLVM bitcode + 指针分析配置 | may-leak | 指针/堆抽象、配置 | 复杂路径、自定义 allocator | 小时级/大项目 | 研究、深度值流分析 |
| SMOKE | 两阶段：UFG + SMT | 构建项目 + SMT | may-leak（候选验证） | 候选生成/约束建模 | 路径/约束复杂、超时 | 40 min/8 MLoC（作者报告） | 工业级大项目 |
| 符号执行（KLEE 等） | 路径级符号执行 | bitcode + harness + 环境模型 | 取决于 checker | 环境模型、不可行路径 | 路径爆炸、外部调用 | 取决于路径数 | 小模块、协议/解析器 |

---

## 3. 动态方法

动态方法在真实执行中观察堆状态；泄漏 oracle 通常是“进程退出时，堆块是否仍可从根集合到达”。不同工具的差别在于：插桩方式（DBI vs 编译期 CTI）、泄漏分类、退出时机、平台支持、以及是否需要在测试中显式触发检查。

### 3.1 Valgrind / Memcheck

**机制。** Valgrind 是动态二进制插桩（DBI）框架；Memcheck 用 shadow memory 跟踪每个字节的 addressability/definedness，并在程序退出时扫描仍分配的堆块，判断它们是否可从根集合（寄存器、栈、全局等）到达。[Valgrind: A Framework for Heavyweight Dynamic Binary Instrumentation](https://doi.org/10.1145/1250734.1250746) [Memcheck manual](https://valgrind.org/docs/manual/mc-manual.html)

**四类泄漏。** Memcheck 把退出时仍分配的块分为：

| 类别 | 含义 | 默认是否报告/计为 error |
|---|---|---|
| Still reachable | 仍有 start-pointer 或 pointer chain 指向该块；程序“本可以”在退出前 free | 默认不单独报告；不算 error |
| Definitely lost | 没有任何指针指向该块；程序已不可能 free | 默认报告概要；`--leak-check=full` 时计为 error（默认 error kinds 含 definite/possible） |
| Indirectly lost | 块本身被指向，但指向它的块已经 lost | 默认不单独报告；随直接泄漏一起说明 |
| Possibly lost | 存在指向块内部的 interior pointer，但是否为真指针不确定 | 默认报告概要；`--leak-check=full` 时计为 error |

官方原文：*“Still reachable blocks are very common and arguably not a problem. So, by default, Memcheck won't report such blocks individually.”* 以及 *“In general, you should attempt to ensure your programs do not have any definitely lost or possibly lost blocks at exit.”* [Memcheck manual](https://valgrind.org/docs/manual/mc-manual.html)

**关键默认值。** `--leak-check` 默认是 `summary`；只有 `--leak-check=full` 才会给出每个 lost block 的详细栈，并且**只有 full 才把泄漏计为真正的 error**。`--show-leak-kinds` 默认 `definite,possible`；`--errors-for-leak-kinds` 默认 `definite,possible`。因此 CI 中只写 `valgrind ./prog` 不会因为泄漏而失败；需要类似：

```bash
valgrind --leak-check=full \
         --show-leak-kinds=definite,possible \
         --errors-for-leak-kinds=definite,possible \
         --error-exitcode=1 ./prog
```

**输入与成本。** 直接运行可执行文件，不需要重编译；建议 `-g` 保留行号，`-O0`/`-O1` 减少优化干扰。程序通常慢 20–30×，并使用更多内存。[Valgrind Quick Start](https://valgrind.org/docs/manual/quick-start.html) [Memcheck 2005](https://www.usenix.org/legacy/events/usenix05/tech/general/seward.html) 平台覆盖 Linux、OS X、Solaris、Android 等，x86/ARM/PPC/MIPS/S390X/TILEGX。[Google memory tools comparison](https://github.com/google/sanitizers/wiki/AddressSanitizerComparisonOfMemoryTools)

**误报/漏报。**

- 误报：`possibly lost` 的 interior pointer 可能是随机值/合法内部指针；全局缓存/静态对象可能被报为 still reachable（默认不报）；自定义分配器/内存池可能让 Memcheck 误判。
- 漏报：只观察执行到的路径；进程不退出/长期运行的服务没有退出扫描；泄漏被 suppression；自定义 allocator 的块可能不在 malloc/free 跟踪范围内。
- Memcheck 不能告诉你指针何时/如何丢失，只能告诉你退出时丢了什么。[Memcheck manual](https://valgrind.org/docs/manual/mc-manual.html)

| 维度 | 结论 | 出处 |
|---|---|---|
| 插桩 | DBI，无需重编译 | PLDI 2007 |
| 泄漏 oracle | 退出时 reachability；四类 | manual |
| 默认行为 | `--leak-check=summary`；泄漏默认不计 error | manual |
| 成本 | 20–30× slowdown，更高内存 | manual/paper |
| 平台 | Linux/OS X/Solaris/Android 等 | Google comparison |
| 主要风险 | 只覆盖执行路径；possibly lost 歧义；长驻进程无退出扫描 | manual |

### 3.2 AddressSanitizer（ASan）与 LeakSanitizer（LSan）

**ASan。** ASan 是编译期插桩（CTI）+ 运行时库：在堆/栈/全局对象周围放 redzone，用 shadow memory 记录可寻址性，检测 heap/stack/global OOB、use-after-free、use-after-return、double-free/invalid free；泄漏检测在 ASan 文档中仍标为 “experimental”。[AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html) 官方文档说典型 slowdown 是 2×；原论文在 SPEC CPU2006 上报告平均 **73% slowdown**（约 1.73×）、**3.37× memory**（不同版本/平台会有差异）。[ASan paper](https://www.usenix.org/conference/atc12/technical-sessions/presentation/serebryany)

**LSan。** LSan 是运行时泄漏检测器，可单独使用（`-fsanitize=leak`）或集成在 ASan 中（支持的平台默认开启）。它“在进程最后阶段之前几乎不增加开销，然后在退出时做一次泄漏检测”。[LeakSanitizer](https://clang.llvm.org/docs/LeakSanitizer.html) 支持平台：Android、Fuchsia、Linux、macOS、NetBSD；**不支持 Windows**。`LSAN_OPTIONS=exitcode=23` 是默认泄漏退出码；`use_unaligned=0` 默认只按对齐的 8 字节模式找指针；`__lsan_do_leak_check()` 可立即检查；`__lsan_disable()` 可局部关闭。[LeakSanitizer](https://clang.llvm.org/docs/LeakSanitizer.html)

**Oracle。** LSan 在退出时报告不可达的堆块（direct leak / indirect leak）；仍可从根到达的块不报告。它不报告 still reachable，因此与 CERT 的终止期例外天然一致；但也意味着“全局缓存一直不 free”不会被 LSan 报成泄漏。

**输入与命令。**

```bash
# ASan + LSan
clang -g -O1 -fsanitize=address -fno-omit-frame-pointer prog.c -o prog
ASAN_OPTIONS=detect_leaks=1 ./prog

# 只做泄漏检测（无 ASan 插桩）
clang -g -O1 -fsanitize=leak prog.c -o prog
./prog
```

需要重编译并链接 sanitizer runtime；`-g`/`-fno-omit-frame-pointer` 改善栈；ASan 在第一个错误处退出（设计如此），因此一次运行可能只暴露一个内存错误；LSan 在退出时集中报告泄漏。[AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html) [LeakSanitizer](https://clang.llvm.org/docs/LeakSanitizer.html)

**误报/漏报。**

- 误报：LSan 可能把自定义池/分配器、未对齐指针、全局注册表等误判；可用 suppressions、`__lsan_disable`、`use_unaligned=1` 调整。ASan 官方声称“不产生 false alarms”（针对内存破坏），但这不意味着泄漏报告没有歧义。
- 漏报：只覆盖执行路径；进程不退出/异常退出；泄漏被 suppression；`detect_leaks=0`；LSan 只扫描对齐指针（默认）；第三方库/自定义 allocator 未跟踪。
- ASan 的 “leaks (experimental)” 与 LSan 的成熟度要分开表述：泄漏检测主要由 LSan 完成，ASan 只是集成入口。

| 维度 | 结论 | 出处 |
|---|---|---|
| 插桩 | 编译期 CTI | ASan docs |
| 泄漏组件 | LSan（单独或集成） | LSan docs |
| Oracle | 退出时不可达堆块；不报 still reachable | LSan docs |
| 成本 | ASan 典型 2×（论文 73%）；LSan 退出前近零 | ASan docs/paper |
| 平台 | ASan 多平台；LSan 不含 Windows | LSan docs |
| 主要风险 | 重编译；只覆盖执行路径；长驻进程；suppression 掩盖 | docs |

### 3.3 Dr. Memory

**机制。** Dr. Memory 基于 DynamoRIO 动态插桩，支持 Windows/Linux（官方首页也列 macOS），可直接运行未重编译的二进制；它做泄漏扫描时把仍分配的内存分为三类：still reachable（不算 leak）、definitely not reachable（leak）、reachable only via mid-allocation pointers（possible leak）。[Dr. Memory: Memory Leaks](https://drmemory.org/page_leaks.html) 论文报告：平均比 Valgrind Memcheck 快 2×，部分基准快 4×；工具本身处于 10–20× slowdown 量级。[Dr. Memory](https://doi.org/10.1109/CGO.2011.5764689)

**Oracle 与退出时机。** 默认在应用退出时做泄漏扫描；对不退出的应用，可用 `-nudge` 在运行中触发一次完整扫描。它报告 leak / possible leak / still-reachable 的数量与字节数；indirect leak 会归到 direct leak 下，不单独给完整栈。[Dr. Memory: Memory Leaks](https://drmemory.org/page_leaks.html)

**误报来源。** 官方列出：只存储了未按 4 字节对齐的指针、指针被加密、存在不通过直接存储指针的自定义可达机制；另外 glib 分配器需要 `G_SLICE=always-malloc`、`G_DEBUG=gc-friendly` 来避免误报。Windows 上 `HeapDestroy` 时仍存活的分配会被报 possible leak，可用 `-no_check_leaks_on_destroy` 关闭。[Dr. Memory: Memory Leaks](https://drmemory.org/page_leaks.html)

**成本与边界。** 无需重编译，适合 Windows 二进制/第三方库；10–20× slowdown；对自定义分配器、加密指针、未对齐指针有已知误报；只覆盖执行路径；长驻进程需要 nudge。它是 Windows 场景下 Valgrind 的重要替代。

| 维度 | 结论 | 出处 |
|---|---|---|
| 插桩 | DynamoRIO DBI；无需重编译 | CGO 2011 |
| 泄漏 oracle | 退出/nudge 时 reachability；leak/possible/still reachable | docs |
| 成本 | 10–20×；平均比 Memcheck 快 2× | paper |
| 平台 | Windows/Linux（首页列 macOS） | docs/paper |
| 主要风险 | 未对齐/加密指针、自定义可达机制、glib | docs |

### 3.4 模糊测试：libFuzzer、AFL++、OSS-Fuzz

**定义。** 模糊测试是“自动生成输入 + 执行程序 + 用 oracle 判定失败”的循环；覆盖率引导的 fuzzer 用代码覆盖率反馈来变异语料。[The Art, Science, and Engineering of Fuzzing](https://doi.org/10.1109/TSE.2019.2946563) 对内存泄漏，oracle 通常是 ASan/LSan 的退出报告；因此 fuzzing 的泄漏检测能力继承 LSan 的语义和局限。

**libFuzzer。** 进程内、覆盖率引导；需要实现 `LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)`，用 `-fsanitize=fuzzer,address` 编译。默认 `-detect_leaks=1`：它统计每次 mutation 的 malloc/free 次数，若数量不匹配（本身不一定是泄漏），会重新执行该输入并调用更昂贵的 LSan 检查；确认泄漏后报告 reproducer 并以 `leak-<sha1>` 形式落盘。[libFuzzer](https://llvm.org/docs/LibFuzzer.html) libFuzzer 的原作者已转向 Centipede，但 libFuzzer 仍处于维护支持状态。[libFuzzer](https://llvm.org/docs/LibFuzzer.html)

**AFL++。** 用 `AFL_USE_ASAN=1` / `AFL_USE_LSAN=1` 编译；LSan 通常在程序退出时运行，AFL++ 提供 `__AFL_LEAK_CHECK()` 宏在循环/持久模式中显式检查，发现泄漏时让 afl-fuzz 记一次 crash；可用 `LSAN_OPTIONS` + suppression 文件，但需保持 `exitcode=23`。注意 ASan 在 64 位下会预留约 17.5–20 TB 虚拟地址空间，AFL++ 建议 32 位模式（约 600–800 MB）或 cgroups 限制；sanitizer 与 QEMU 模式不兼容。[AFL++ ASan notes](https://aflplus.plus/docs/notes_for_asan/)

**OSS-Fuzz 的实证。** Ding & Le Goues 分析 23,907 个 bug、316 个项目：timeout、OOM、null deref、stack overflow、memory leak、signal abort 六类合计占 52%（12,316/23,907）；memory leak 是 fuzz blocker 中最常见的类型（15%，261/1,773），占所有泄漏的 19%（261/1,376）。[An Empirical Study of OSS-Fuzz Bugs](https://doi.org/10.1109/MSR52588.2021.00026) 这说明泄漏不仅影响退出，还会**阻塞 fuzzing**（泄漏累积导致 OOM/误判），因此 fuzzing 配置中常需要 `detect_leaks=0` 或定期重启；这本身会降低泄漏发现率。

**误报/漏报。**

- 误报：LSan 对全局缓存/自定义池/未对齐指针的误判；persistent mode 中累积泄漏被当成单次输入泄漏；suppression 配置不一致。
- 漏报：harness 没暴露会泄漏的 API；语料不足；泄漏只在错误路径/特定输入下发生；`-detect_leaks=0`；进程不退出；泄漏被 suppression；fuzzing 时间预算不足。
- Fuzzing 的“no leak”只说明“在测试过的输入和时间预算内没有观察到泄漏”，不是证明。

| 维度 | 结论 | 出处 |
|---|---|---|
| Oracle | sanitizer 报告 + reproducer | libFuzzer/AFL++ docs |
| 输入 | harness + 语料 + 插桩构建 | docs |
| 成本 | 取决于 harness/覆盖率；sanitizer 显著降吞吐 | docs |
| 强项 | 输入驱动的解析器/协议/文件格式；错误路径 | OSS-Fuzz 实证 |
| 弱项 | GUI/长驻服务/环境依赖；harness 覆盖不足 | 通用边界 |

### 3.5 动态方法对比表

| 工具 | 插桩/输入 | 泄漏 oracle | 误报来源 | 漏报来源 | 成本 | 平台 | 最适合 |
|---|---|---|---|---|---|---|---|
| Valgrind/Memcheck | DBI；直接运行二进制 | 退出时 reachability；4 类 | possibly lost、全局缓存、自定义池 | 未执行路径、长驻进程、suppression | 20–30× | Linux/OS X/Solaris/Android 等 | Linux 深度调试、二进制 |
| ASan/LSan | CTI；重编译 | LSan 退出时不可达 | 自定义池、未对齐指针、全局注册表 | 未执行路径、不退出、suppression | ASan 2×；LSan 近零 | Android/Fuchsia/Linux/macOS/NetBSD | CI、单元测试、fuzzing |
| Dr. Memory | DBI；直接运行二进制 | 退出/nudge 时 reachability；leak/possible/still reachable | 未对齐/加密指针、自定义可达、glib | 未执行路径、长驻进程 | 10–20× | Windows/Linux（macOS） | Windows 二进制、第三方库 |
| libFuzzer/AFL++ | 编译期插桩 + harness | sanitizer 报告 + reproducer | 同 LSan/AFL 配置 | harness/语料/时间不足 | harness 相关 | 跨平台（LSan 限制） | 输入驱动代码、协议/解析器 |

---

## 4. 静态 vs 动态 vs 模糊测试：统一比较

### 4.1 总表

| 维度 | 静态分析 | 动态分析 | 模糊测试 |
|---|---|---|---|
| 输入 | 源码 + 构建配置（+ 注解/模型） | 可执行文件 + 输入/参数（+ 符号） | harness + 语料 + 插桩构建 |
| 执行 | 不运行 | 运行一次/多次 | 运行大量生成输入 |
| Oracle | 存在可行泄漏路径（may-leak） | 本次退出时不可达（definitely lost） | sanitizer 报告 + reproducer |
| 覆盖 | 所有路径（受抽象/预算限制） | 仅执行路径 | 仅生成输入覆盖的路径 |
| 误报主因 | 不可行路径、未建模 allocator/所有权、全局生命周期 | possibly lost、自定义池、全局缓存 | 同 LSan + harness/persistent mode |
| 漏报主因 | 路径爆炸、跨 TU、未知函数、超时 | 输入未覆盖、错误路径未执行、不退出、suppression | harness/语料不足、时间预算、`detect_leaks=0` |
| 成本 | 秒–小时/项目；路径敏感更贵 | 2×–30× 运行时间 | harness 开发 + CPU 时间；吞吐受 sanitizer 影响 |
| 最适合 | 不可执行代码、嵌入式、错误路径、全量审计 | 真实执行、二进制、第三方库、快速确认 | 输入驱动代码、协议/解析器、持续 fuzzing |
| 最不适合 | 超大单体、无构建、重度模板/宏 | 无输入/无 harness、长驻服务 | GUI/环境依赖、无明确输入边界 |

### 4.2 为什么不能直接比 accuracy

1. **Oracle 不同。** 静态的 may-leak 允许“存在一条路径”；动态的 definitely lost 只说明“这次执行退出时丢了”。一个静态工具报告 100 个 may-leak，其中 60 个路径不可行，它的 precision 低，但不代表它的 may-leak 语义错；一个动态工具在 100 次运行中没报泄漏，也不代表程序没有泄漏。
2. **输入不同。** 动态工具需要 harness/输入；Nong et al. 明确指出，他们的动态工具召回率低主要是因为只用了有限的运行输入，而不是动态分析本身弱。[Nong et al. 2021](https://doi.org/10.1016/j.infsof.2021.106614) 把静态和动态放在同一 recall 表里，而不控制输入覆盖，是不公平的。
3. **标签单位不同。** 静态报告可能定位到 allocation site/函数；动态报告定位到调用栈；Juliet 的标签是“这个程序是 bad/good”；真实项目标签可能是“这个 commit 修了 CWE-401”。单位不同，TP 的判定就不同。
4. **配置不同。** 同一工具在不同 checker 集、路径深度、CTU、注解、超时下结果差异巨大。Saber 自报 18.5% FP，SMOKE 测到 66.7% FP，就是最直接的例子。
5. **误报/漏报的成本不对称。** 静态误报的代价是人工 triage；动态漏报的代价是漏掉真实泄漏。两者不能用同一个 F1 权重。

### 4.3 成本数量级（只用于规划，不是基准）

| 方法 | 典型成本 | 备注 |
|---|---|---|
| Cppcheck | 秒–分钟/项目；LeakGuard 基准平均 378 秒 | 最快，但覆盖浅 |
| Clang SA | 分钟–小时/项目；基准平均 10,600 秒 | 路径敏感；CTU 更贵 |
| Infer | 分钟–小时/项目；基准平均 4,748 秒 | 组合式；大项目更稳 |
| SMOKE | 40 分钟/8 MLoC（作者报告） | 硬件/项目相关 |
| Valgrind | 20–30× 运行时间 | 无重编译 |
| Dr. Memory | 10–20× 运行时间 | 无重编译 |
| ASan | 典型 2×；论文 73% | 3.37× 内存 |
| LSan | 退出前近零，退出扫描 | 需重编译/链接 |
| Fuzzing | harness + CPU 时间；吞吐取决于 sanitizer | 不能用一个倍数概括 |

这些数字来自不同硬件、项目、版本和配置，**不能横向排序**；只能用来判断“这个 track 是否需要 GPU/小时级预算”。

### 4.4 适用边界（按场景）

| 场景 | 首选 | 备选 | 理由/注意 |
|---|---|---|---|
| 每次提交的快速门禁 | Cppcheck + 编译器警告 | Clang SA 增量 | 快、低 FP；不要期待深度 |
| 夜间深度审计 | Clang SA（CTU）/Infer/SMOKE | Valgrind（有测试） | 深度 vs 成本 |
| 嵌入式/交叉编译 | Cppcheck/Clang SA | 静态注解 + 手工审查 | 动态工具难跑目标环境 |
| 二进制/第三方库 | Valgrind/Dr. Memory | fuzzing（若有 harness） | 无需源码/重编译 |
| 错误路径泄漏 | Clang SA/Infer/SMOKE | LeakGuard（研究） | 动态很难覆盖所有错误路径 |
| 输入驱动解析器/协议 | libFuzzer/AFL++ + LSan | Valgrind（复现） | harness 是关键 |
| 长驻服务/守护进程 | 静态 + 定期 nudge/显式检查 | LSan `__lsan_do_leak_check` | 退出扫描不适用 |
| C++ RAII/容器 | Infer/Clang SA（C++ checker） | ASan/LSan | 需要析构/所有权建模 |
| 自定义 allocator/池 | 注解/模型 + 静态 | Dr. Memory/Valgrind（可能误报） | 没有模型就没有精度 |
| 超大单体（>2 MLoC） | SMOKE/Infer/Cppcheck | Clang SA（可能超时） | CSA/Infer 在 2h 内可能失败（SMOKE 报告） |
| 安全关键/合规 | 多工具交叉 + 人工 triage | 动态确认 | 单一工具不足以证明 |

---

## 5. 近年评估与可引用数字

> 这一节只记录“论文/报告实际写了什么”，不把它们当作本项目的结果。每一条都给出基准、版本/配置（若已知）和偏差。

### 5.1 LeakGuard 的 Juliet CWE-401 对比（2025 预印本）

LeakGuard 在 Juliet CWE-401（1,364 positive + 1,364 negative）上报告：

| 工具 | TP | FP | TN | FN | F1 |
|---|---:|---:|---:|---:|---:|
| LeakGuard | 1,336 | 0 | 1,364 | 28 | 0.990 |
| Clang Static Analyzer | 490 | 192 | 1,172 | 874 | 0.479 |
| Infer | 320 | 250 | 1,114 | 1,044 | 0.331 |
| SVF | 520 | 750 | 614 | 844 | 0.395 |

出处：LeakGuard Table 2。[LeakGuard](https://arxiv.org/html/2504.04422v1)

**能支持：** 在 Juliet 这种小型合成程序上，路径敏感/自定义摘要方法可以显著优于默认配置的 CSA/Infer/SVF；SVF 的默认 leak 客户端在该基准上误报很高。
**不能支持：** “LeakGuard 在真实项目上也 0.990”；“CSA/Infer 在所有 CWE-401 任务上都只有 0.3–0.5 F1”；“SVF 本身很差”。Juliet 的路径短、分配模式固定，且 LeakGuard 是作者实现/调参的。

### 5.2 LeakGuard 的真实项目 129 个泄漏

LeakGuard 在 18 个真实项目（70,992 KLoC，OpenSSL、MySQL、Linux Kernel、FFmpeg 等）上报告 129 个此前未知、经开发者确认的泄漏；对比工具找到的数量：

| 工具 | 找到的泄漏数（共 129） |
|---|---:|
| LeakGuard | 129 |
| Clang Static Analyzer | 44 |
| Infer | 25 |
| Cppcheck | 1 |

耗时（18 个项目，32 核/128 GB，32 小时上限，3 次平均）：

| 工具 | 总耗时（秒） | 平均（秒/项目） |
|---|---:|---:|
| Cppcheck | 6,795 | 378 |
| Infer | 85,461 | 4,748 |
| LeakGuard | 134,386 | 7,466 |
| Clang SA | 190,793 | 10,600 |

出处：LeakGuard Table 1/Table 4。[LeakGuard](https://arxiv.org/html/2504.04422v1)

**能支持：** 默认配置下，快速工具（Cppcheck）在深调用链/自定义 MAD 函数的真实泄漏上召回很低；CSA/Infer 也会漏掉大量作者找到的 bug；路径敏感+摘要的方法可以找回更多。
**不能支持：** “Cppcheck 无用”；“LeakGuard 比所有工具都好”；“这些数字代表平均工业水平”。129 个 bug 是 LeakGuard 找到的集合，存在选择偏差；工具版本/配置未完整给出；作者是 LeakGuard 的实现者。

### 5.3 SMOKE 与 Saber： scalability 与 FP 的基准依赖性

- **Saber（2012）：** 15 个 SPEC2000 C 程序 + 5 个应用，211 个泄漏，FP 18.5%，10,220 LOC/s；比 Sparrow 快 14.2×；比 Fastcheck 多 40.7% bug、只慢 3.7×。[Saber](https://doi.org/10.1145/2338965.2336784)
- **SMOKE（2019）：** 最多 8 MLoC、40 分钟、平均 FP 24.4%、5.2–22.8× 加速；29 个成熟项目新发现 30 个泄漏（1 个 CVE）。同一论文报告：在其评测中 Saber 的 FP 为 66.7%；CSA/Infer 在 2 小时内无法分析超过 2 MLoC 的项目。[SMOKE](https://doi.org/10.1109/ICSE.2019.00025)

**解释：** 18.5% 与 66.7% 不是“谁撒谎”，而是**基准/配置/判定口径不同**。Saber 的数字来自 SPEC2000 的较简单程序；SMOKE 的项目更大、更复杂，且 Saber 的客户端/版本可能不同。引用时必须带上下文。这也说明：单一 FP 数字不能跨基准迁移。

### 5.4 DVSML：静态警告的动态验证

Li et al. 用 concolic testing 对 Fortify 的静态泄漏警告做动态分类：在 11 个程序、246 条警告中，分类为 112 条 MUST-LEAK、38 条 LIKELY-NOT-LEAK、38 条 BLOAT、58 条 MAY-LEAK；需要人工验证的警告从 246 降到 58；人工检查的 38 条 LIKELY-NOT-LEAK 中没有发现真泄漏。[DVSML](https://doi.org/10.1145/2483760.2483778)

**能支持：** 静态泄漏警告中存在大量可由动态执行排除的误报；静态+动态的混合可以显著降低 triage 成本。
**不能支持：** “动态验证可以证明没有泄漏”；“所有静态警告都能被分类”；“MUST-LEAK 一定可复现”。动态验证仍受测试生成/路径覆盖限制，MAY-LEAK 仍需人工。

### 5.5 Nong et al. 2021：五种内存错误检测器的系统比较

Nong et al. 在两个数据集（520 和 474 个 C/C++ 程序）上比较五种检测器：CBMC（静态 bounded model checker）、Valgrind、Dr. Memory、AddressSanitizer、MemorySanitizer。结论包括：

- 各工具在不同漏洞类别上的 accuracy 变化很大（0%–100% precision/recall/F1）；
- 动态工具召回率普遍低于静态 CBMC，主要因为只覆盖有限运行输入；
- 在他们的实验中，纯动态工具报告的都是 true positive（没有 FP），但这与输入/基准有关；
- 没有单一最有效的工具；混合分析并不总是优于纯静态/纯动态；
- 复杂代码（深循环/递归）和深层数据结构是主要障碍。[Nong et al. 2021](https://doi.org/10.1016/j.infsof.2021.106614)

**注意：** 这篇论文覆盖的是 memory error vulnerabilities（缓冲区溢出、UAF、未初始化等），不是专门的 CWE-401；但它对“静态 vs 动态”的方法论结论（输入覆盖、基准选择、无单一最优）直接适用。

### 5.6 MemHint（2026 预印本）：CodeQL/Infer 的自定义分配器缺口

MemHint 在 8 个真实 C/C++ 项目、3.6M LoC 上报告：检测到 54 个唯一泄漏（全部确认/修复），而 vanilla CodeQL 19 个、vanilla Infer 3 个；平均约 $1.76/个检测到的 bug（含 LLM/Z3 流水线成本）。作者把差距主要归因于项目自定义的分配/释放函数识别与路径敏感控制流建模。[MemHint](https://arxiv.org/abs/2603.27224)

**能支持：** 现代静态分析器在真实项目上的泄漏召回仍受“自定义 MAD 函数/所有权模型”限制；LLM 可以辅助生成函数摘要。
**不能支持：** “CodeQL 只能找到 19 个泄漏”；“MemHint 的方法普遍适用”；“$1.76 是纯工具成本”。这是预印本、作者自评、项目集有限；成本包含 LLM 调用。

### 5.7 OSS-Fuzz：泄漏是 fuzzing 的常见故障类型

Ding & Le Goues 分析 23,907 个 bug、316 个项目：六类故障（timeout、OOM、null deref、stack overflow、memory leak、signal abort）合计 52%（12,316/23,907）；memory leak 是 fuzz blocker 中最常见的类型（15%，261/1,773），占所有泄漏的 19%（261/1,376）。[OSS-Fuzz Bugs](https://doi.org/10.1109/MSR52588.2021.00026)

**能支持：** 泄漏不仅是“退出时资源浪费”，还会阻塞 fuzzing（泄漏累积导致 OOM/状态污染）；fuzzing 配置需要在“发现泄漏”和“继续 fuzz”之间取舍。
**不能支持：** “fuzzing 能发现所有泄漏”；“OSS-Fuzz 的 leak 比例适用于所有项目”。这是 OSS-Fuzz 的项目集和 sanitizer 配置。

### 5.8 真实项目 SAST 的警告质量（补充证据）

Charoenwet et al. 用 319 个真实漏洞、815 个 vulnerability-contributing commits、92 个 C/C++ 项目评估 SAST：单一 SAST 能在 52% 的 VCC 的 vulnerable function 中产生警告；但 vulnerable function 中至少 76% 的警告与本次 VCC 无关；22% 的 VCC 因规则限制未被发现。[Charoenwet et al. 2024](https://doi.org/10.1145/3650212.3680313)

这不是 CWE-401 专项，但说明**真实代码上的 SAST 警告 precision 通常远低于合成基准**；做统一 benchmark 时，不能把 Juliet 的高分直接外推到真实项目。

### 5.9 证据强度与偏差

| 研究/来源 | 范围 | 关键数字 | 能支持 | 主要偏差/限制 |
|---|---|---|---|---|
| Saber 2012 | SPEC2000 + 5 应用 | 211 leaks，FP 18.5%，10,220 LOC/s | 稀疏值流的可行性与精度 | 2012 年工具/基准；自评 |
| DVSML 2013 | 11 程序，Fortify 警告 | 246→58 人工验证；112 MUST-LEAK | 静态+动态 triage 有效 | 商业工具；测试生成覆盖有限 |
| SMOKE 2019 | 29 项目，8 MLoC | FP 24.4%，40 min，30 新 leaks | 分层路径敏感可扩展 | 作者工具；基准/配置 |
| Nong 2021 | 520+474 程序，5 工具 | 0–100% 精度；动态低召回 | 输入覆盖决定动态表现 | 非 CWE-401 专项；有限输入 |
| LeakGuard 2025 | Juliet + 18 项目 | Juliet F1 0.990；129 leaks；44/25/1 | 路径敏感+摘要有优势 | 预印本；作者自建基准；配置未全披露 |
| MemHint 2026 | 8 项目，3.6M LoC | 54 leaks；CodeQL 19；Infer 3 | 自定义 allocator 是瓶颈 | 预印本；LLM 成本/项目集 |
| OSS-Fuzz 2021 | 23,907 bugs，316 项目 | 52% 六类；leaks 15% fuzz blockers | 泄漏在 fuzzing 中常见 | OSS-Fuzz 项目集 |
| Charoenwet 2024 | 319 vulns，815 VCCs | 52% VCC 有警告；≥76% 无关；22% 未检出 | 真实 SAST 警告质量低 | 非泄漏专项；commit 级标签 |

---

## 6. 对 AI + 传统统一 benchmark 的设计建议

> 目标：让 LLM、静态工具、动态工具、fuzzing 在同一批 CWE-401 case 上产生**可解释、可复现、不可互相冒充**的结果。不是做一个“谁第一”的排行榜。

### 6.1 两条 track，一套 case id

建议至少分两条 track：

- **Static track：** 输入是函数/文件/项目源码 + 构建配置；允许 CTU/whole-program；不要求可执行；输出 leak 报告（位置、路径、类型）。
- **Dynamic track：** 输入是**可运行的程序 + harness + 输入**；输出 definitely lost/possibly lost/still reachable 报告。
- **Fuzzing track：** 输入是 harness + 语料 + 时间预算；输出 reproducer + sanitizer 报告。
- **AI track：** 输入是函数级代码（与 static track 同粒度）；输出 leak/not leak + 位置/理由；可与 static/dynamic 结果对照，但不共享 oracle。

所有 track 共享 `case_id`、项目、CWE 标签、ground truth（allocation site / leak site / fix commit）。不要用一个总分把不同 track 混在一起。

### 6.2 标签与 oracle 对齐

1. **只保留 CWE-401。** 排除 CWE-415（double free）、CWE-416（UAF）、CWE-772/CWE-775（资源/文件描述符）。如果工具报告混合类型，按 checker/message 过滤。
2. **正例/负例定义写清楚。** 正例：存在至少一条 feasible path 在对象生命周期结束后未释放，且指针未逃逸（静态）；或退出时 definitely lost（动态）。负例：所有路径都释放/逃逸（静态）；或退出时仍 reachable/已释放（动态）。
3. **may 与 must 分开。** 如果使用 CodeQL，分别统计 `memory-may-not-be-freed` 与 `memory-never-freed`；如果使用 Infer，记录 latent issue；如果使用 CSA，记录 may-leak。不要把 may 报告和 must 报告混在一个 precision 里。
4. **CERT 终止期例外。** 静态工具报的全局/静态缓存泄漏，若其生命周期覆盖程序终止，按 CERT MEM31-C-EX1 视为负例（或单列 “still reachable/global” 类别），不要直接算 FP。动态工具默认不把 still reachable 计为泄漏（Valgrind/Dr. Memory 可显式打开显示），这样两条 track 的标签才对齐。
5. **Juliet 只作为 sanity check。** 不要把 Juliet 分数当作真实项目性能；真实项目 case 应来自有 fix commit/开发者确认的 CVE 或 issue，并记录版本。

### 6.3 Static track 协议

- 固定编译器/工具版本、checker 集、路径深度/节点预算、超时（如 10 min/文件、2 h/项目）。
- 分别跑 **default** 与 **tuned** 配置：default 反映“开箱即用”，tuned 反映“专家配置”；两者都报告，不要只报最好的。
- 分别跑 **single-TU** 与 **CTU/whole-program**（若工具支持）；记录构建失败、缺失头文件、宏配置。
- 自定义分配器：先跑“无注解”，再跑“有注解/模型”；把注解成本单独报告。注解会改变任务难度，不能混为一谈。
- 报告归一化：把工具输出映射到 `(case_id, allocation_site, leak_site, leak_type)`；如果工具只给函数名，不能算“定位到 leak site”。
- 记录误报类型：infeasible path、global lifetime、unknown function、ownership transfer、container/RAII、macro/template、other。
- 记录漏报类型：timeout、parse/build failure、path limit、cross-TU、unknown function、custom allocator、no report。

### 6.4 Dynamic track 协议

- **Harness 是前提。** 对函数级 case，必须提供 driver（构造输入、调用函数、处理返回值）；没有 harness 的 case 标记 `not_runnable`，不能算动态 FN。
- 输入：至少一个“正常路径”和一个“错误/边界路径”；记录每个 case 的输入覆盖（函数/行/分支）。如果只有一个输入，动态召回不可与静态直接比较。
- 工具：
  - Valgrind：`--leak-check=full --show-leak-kinds=definite,possible --errors-for-leak-kinds=definite,possible --error-exitcode=1`；记录 `definitely lost` / `indirectly lost` / `possibly lost` / `still reachable`。
  - ASan/LSan：`-fsanitize=address`（或 `-fsanitize=leak`），`ASAN_OPTIONS=detect_leaks=1`；记录 `Direct leak` / `Indirect leak`；LSan 不支持 Windows。
  - Dr. Memory：`-batch`、`-nudge`（长驻）、`-show_reachable`（可选）；记录 leak/possible/still reachable。
- **主指标：definitely lost。** `possibly lost` 作为 secondary；`still reachable` 不计入 CWE-401 正例（按 CERT 例外），但单独报告，便于解释静态 FP。
- 统一 suppression：libc/第三方库的已知泄漏使用同一份 suppression 文件；记录 suppression 命中数；不要用 suppression 掩盖目标 case 的泄漏。
- 退出码/崩溃：区分“正常退出后报告泄漏”“ASan 在第一个错误处退出”“进程崩溃/超时”。崩溃不算 leak negative。
- 多输入/多运行：至少 3 次，记录稳定性；对非确定性程序，报告 flaky。

### 6.5 Fuzzing track

- 每个 case 提供 harness（libFuzzer `LLVMFuzzerTestOneInput` 或 AFL++ persistent harness）；固定语料/字典/时间预算（如 24 CPU-hours）。
- 构建：`-fsanitize=fuzzer,address`（libFuzzer）或 `AFL_USE_ASAN=1`/`AFL_USE_LSAN=1`（AFL++）；记录 sanitizer 组合。
- 泄漏判定：LSan 报告 + reproducer；libFuzzer 的 `leak-<sha1>`；AFL++ 的 `__AFL_LEAK_CHECK()` crash。去重按 allocation stack + leak kind。
- 报告：unique leaks、reproducer 数、time-to-first-leak、bugs/CPU-hour；不要只报“找到/没找到”。
- 多次运行/多 seed：fuzzing 有随机性；至少 5–10 次或固定 seed 集；参考 Klees et al. 的评估建议（多 trial、真实 bug、合理时间预算）。[Evaluating Fuzz Testing](https://doi.org/10.1145/3243734.3243804)
- 不要把 fuzzing 的 “no leak” 当作 negative label；它只是“预算内未发现”。

### 6.6 AI track

- 输入：与 static track 相同的函数/文件片段；prompt 中明确 CWE-401、C/C++、输出 schema（leak/no-leak、位置、理由、置信度）。
- 对照：分别与 static oracle、dynamic oracle 比较；不要用 dynamic 的 FN 当作 AI 的 TN。
- 数据泄漏：检查模型是否见过 CVE/commit；对公开数据集，记录时间切分/项目切分。
- 成本：记录 token、USD、延迟、重试、解析失败；与工具的时间/CPU 成本分开。
- 失败模式：JSON 解析失败、截断、拒答、幻觉位置；不要静默当作 negative。

### 6.7 指标与统计

| 指标 | 定义 | 备注 |
|---|---|---|
| TP/FP/TN/FN | 以 case 为单位，按 ground truth | 必须说明单位（case/函数/项目） |
| Precision / Recall / F1 | 标准定义 | 分开 may/must、static/dynamic |
| Leak-site recall | 报告位置与标注 leak site 的重合 | 比“函数级命中”更严格 |
| FPR | FP / (FP+TN) | 负例数量要写 |
| Cost | wall-clock、CPU、峰值内存、USD | 分 track |
| Timeout/build failure | 单独计数 | 不能算 FN 或 TN |
| Stability | 多次运行的方差/flaky 率 | 动态/fuzzing 必报 |
| 统计检验 | McNemar（配对）、bootstrap CI | 同一 case 上的配对比较 |
| 聚类 | 按项目/仓库 cluster | 避免同一项目大量 case 主导 |

### 6.8 报告模板（建议）

| 字段 | 说明 |
|---|---|
| `case_id` | 唯一 ID |
| `project` / `version` | 项目与版本/commit |
| `label_cwe401` | positive/negative/excluded |
| `label_site` | allocation/leak site（若已知） |
| `static_tool` / `version` / `config` | 工具、版本、checker、CTU/注解 |
| `static_result` | leak/no-leak/timeout/build-fail |
| `static_report_site` | 报告位置 |
| `dynamic_tool` / `version` | Valgrind/LSan/Dr. Memory |
| `dynamic_result` | definitely/possibly/still reachable/no-leak/crash/timeout |
| `dynamic_input` / `coverage` | 输入与覆盖 |
| `fuzz_budget` / `fuzz_result` | 时间、unique leaks、reproducer |
| `ai_model` / `prompt` / `result` | 模型、prompt 版本、解析状态 |
| `cost` | 时间/CPU/USD |
| `notes` | 失败模式、suppression、人工确认 |

### 6.9 不能支持的表述

- “某静态工具在 CWE-401 上准确率 99%” —— 除非给出基准、配置、负例、置信区间；Juliet 分数不能外推到真实项目。
- “动态工具没报泄漏，所以代码没有泄漏” —— 动态只覆盖执行路径；长驻进程/未触发错误路径不报。
- “Cppcheck 只找到 1/129，所以它没有价值” —— 它快、低 FP，适合第一遍；129 是 LeakGuard 的选择集。
- “ASan 检测泄漏” —— 精确说是 LSan；ASan 文档仍把 leaks 标为 experimental。
- “LSan 在 Windows 上可用” —— 官方支持平台不含 Windows。
- “Valgrind 的 definitely lost 等于 CWE-401 正例” —— 它只说明退出时不可达；CWE-401 是程序属性，且 still reachable 可能符合 CERT 例外。
- “模糊测试能找到所有泄漏” —— 只覆盖 harness/语料/时间预算内的输入。
- “工具 A 比工具 B 强” —— 除非同基准、同配置、同 oracle、同输入覆盖，并有统计检验。

---

## 7. 引用清单（含 DOI/URL 与建议 BibTeX key）

> 级别说明：A = 同行评审论文/标准；B = 预印本/技术报告；C = 官方文档/项目页。所有 URL 均在 2026-11-12 核对；DOI 通过 Crossref/出版商页面核验。

### 7.1 标准、CWE 与测试集

| # | 引用 | 级别 | DOI/URL | 建议 key |
|---|---|---|---|---|
| [1] | MITRE. *CWE-401: Missing Release of Memory after Effective Lifetime.* CWE 5.0, 2026. | A | https://cwe.mitre.org/data/definitions/401.html | `cwe401` |
| [2] | MITRE. *CWE-772: Missing Release of Resource after Effective Lifetime.* CWE 5.0, 2026. | A | https://cwe.mitre.org/data/definitions/772.html | `cwe772` |
| [3] | SEI CERT. *MEM31-C: Free dynamically allocated memory when no longer needed.* 2026. | A | https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/rules/memory-management-mem/mem31-c/ | `cert_mem31c` |
| [4] | NIST. *Juliet C/C++ 1.3 Test Suite.* SARD, 2017. | A | https://samate.nist.gov/SARD/test-suites/112 | `nist_juliet13` |
| [5] | P. E. Black. *Juliet 1.3 Test Suite: Changes From 1.2.* NIST TN 1995, 2018. | B | https://doi.org/10.6028/NIST.TN.1995 | `black2018juliet` |

### 7.2 静态分析

| # | 引用 | 级别 | DOI/URL | 建议 key |
|---|---|---|---|---|
| [6] | Z. Xu, T. Kremenek, J. Zhang. *A Memory Model for Static Analysis of C Programs.* ISoLA 2010, LNCS 6415, pp. 535–548. | A | https://doi.org/10.1007/978-3-642-16558-0_44 | `xu2010memory` |
| [7] | Y. Sui, D. Ye, J. Xue. *Static Memory Leak Detection Using Full-Sparse Value-Flow Analysis.* ISSTA 2012, pp. 254–264. | A | https://doi.org/10.1145/2338965.2336784 | `sui2012saber` |
| [8] | Y. Sui, J. Xue. *SVF: Interprocedural Static Value-Flow Analysis in LLVM.* CC 2016, pp. 265–266. | A | https://doi.org/10.1145/2892208.2892235 | `sui2016svf` |
| [9] | G. Fan, R. Wu, Q. Shi, X. Xiao, J. Zhou, C. Zhang. *SMOKE: Scalable Path-Sensitive Memory Leak Detection for Millions of Lines of Code.* ICSE 2019, pp. 72–82. | A | https://doi.org/10.1109/ICSE.2019.00025 | `fan2019smoke` |
| [10] | C. Calcagno, D. Distefano, P. W. O'Hearn, H. Yang. *Compositional Shape Analysis by Means of Bi-Abduction.* JACM 58(6):26, 2011. | A | https://doi.org/10.1145/2049697.2049700 | `calcagno2011biabduction` |
| [11] | C. Calcagno, D. Distefano, J. Dubreil, et al. *Moving Fast with Software Verification.* NFM 2015, LNCS 9058, pp. 3–11. | A | https://doi.org/10.1007/978-3-319-17524-9_1 | `calcagno2015movingfast` |
| [12] | D. Distefano, M. Fähndrich, F. Logozzo, P. W. O'Hearn. *Scaling static analyses at Facebook.* CACM 62(8):62–70, 2019. | A | https://doi.org/10.1145/3338112 | `distefano2019scaling` |
| [13] | A. Bessey, K. Block, B. Chelf, et al. *A Few Billion Lines of Code Later: Using Static Analysis to Find Bugs in the Real World.* CACM 53(2):66–75, 2010. | A | https://doi.org/10.1145/1646353.1646374 | `bessey2010fewbillion` |
| [14] | Clang Team. *Clang Static Analyzer.* Accessed 2026-11-12. | C | https://clang.llvm.org/docs/ClangStaticAnalyzer.html | `clangsa_docs` |
| [15] | Clang Team. *Cross Translation Unit (CTU) Analysis.* Accessed 2026-11-12. | C | https://clang.llvm.org/docs/analyzer/user-docs/CrossTranslationUnit.html | `clang_ctu_docs` |
| [16] | Clang Team. *Source Annotations.* Accessed 2026-11-12. | C | https://clang.llvm.org/docs/analyzer/user-docs/Annotations.html | `clang_annotations_docs` |
| [17] | Clang Team. *Available Checkers*（`unix.Malloc`, `cplusplus.NewDeleteLeaks`）. Accessed 2026-11-12. | C | https://clang.llvm.org/docs/analyzer/checkers.html | `clang_checkers_docs` |
| [18] | Cppcheck project. *Cppcheck Manual.* Accessed 2026-11-12. | C | https://cppcheck.sourceforge.io/manual.html | `cppcheck_manual` |
| [19] | Cppcheck project. *A Cppcheck Design.* Accessed 2026-11-12. | C | https://www.cs.kent.edu/~rothstei/fall_14/sec_notes/cppcheck-design.pdf | `cppcheck_design` |
| [20] | Meta. *Infer: Pulse.* Docs v1.3.0, accessed 2026-11-12. | C | https://fbinfer.com/docs/checker-pulse/ | `infer_pulse_docs` |
| [21] | Meta. *About Infer.* Docs v1.3.0, accessed 2026-11-12. | C | https://fbinfer.com/docs/about-Infer/ | `infer_about_docs` |
| [22] | GitHub. *CodeQL CWE coverage for C and C++.* Accessed 2026-11-12. | C | https://codeql.github.com/codeql-query-help/cpp-cwe/ | `codeql_cwe_docs` |
| [23] | C. Cadar, K. Sen. *Symbolic Execution for Software Testing: Three Decades Later.* CACM 56(2):82–90, 2013. | A | https://doi.org/10.1145/2408776.2408795 | `cadar2013symbolic` |
| [24] | C. Cadar, D. Dunbar, D. Engler. *KLEE: Unassisted and Automatic Generation of High-Coverage Tests for Complex Systems Programs.* OSDI 2008, pp. 209–224. | A | https://www.usenix.org/legacy/event/osdi08/tech/full_papers/cadar/cadar.pdf | `cadar2008klee` |

### 7.3 动态分析与模糊测试

| # | 引用 | 级别 | DOI/URL | 建议 key |
|---|---|---|---|---|
| [25] | N. Nethercote, J. Seward. *Valgrind: A Framework for Heavyweight Dynamic Binary Instrumentation.* PLDI 2007, pp. 89–100. | A | https://doi.org/10.1145/1250734.1250746 | `nethercote2007valgrind` |
| [26] | J. Seward, N. Nethercote. *Using Valgrind to Detect Undefined Value Errors with Bit-Precision.* USENIX ATC 2005, pp. 17–30. | A | https://www.usenix.org/legacy/events/usenix05/tech/general/seward.html | `seward2005memcheck` |
| [27] | Valgrind Developers. *Memcheck: a memory error detector.* Accessed 2026-11-12. | C | https://valgrind.org/docs/manual/mc-manual.html | `valgrind_manual` |
| [28] | K. Serebryany, D. Bruening, A. Potapenko, D. Vyukov. *AddressSanitizer: A Fast Address Sanity Checker.* USENIX ATC 2012, pp. 309–318. | A | https://www.usenix.org/conference/atc12/technical-sessions/presentation/serebryany | `serebryany2012asan` |
| [29] | LLVM Project. *AddressSanitizer.* Accessed 2026-11-12. | C | https://clang.llvm.org/docs/AddressSanitizer.html | `asan_docs` |
| [30] | LLVM Project. *LeakSanitizer.* Accessed 2026-11-12. | C | https://clang.llvm.org/docs/LeakSanitizer.html | `lsan_docs` |
| [31] | D. Bruening, Q. Zhao. *Practical Memory Checking with Dr. Memory.* CGO 2011, pp. 213–223. | A | https://doi.org/10.1109/CGO.2011.5764689 | `bruening2011drmemory` |
| [32] | Dr. Memory project. *Memory Leaks.* Version 2.3.20434, accessed 2026-11-12. | C | https://drmemory.org/page_leaks.html | `drmemory_leaks_docs` |
| [33] | Google Sanitizers project. *AddressSanitizerComparisonOfMemoryTools.* Accessed 2026-11-12. | C | https://github.com/google/sanitizers/wiki/AddressSanitizerComparisonOfMemoryTools | `google_memory_tools_comparison` |
| [34] | V. J. M. Manès, H. Han, C. Han, S. K. Cha, M. Egele, E. J. Schwartz, M. Woo. *The Art, Science, and Engineering of Fuzzing: A Survey.* IEEE TSE 47(11):2312–2331, 2021. | A | https://doi.org/10.1109/TSE.2019.2946563 | `manes2021fuzzing` |
| [35] | LLVM Project. *libFuzzer – a library for coverage-guided fuzz testing.* Accessed 2026-11-12. | C | https://llvm.org/docs/LibFuzzer.html | `libfuzzer_docs` |
| [36] | AFL++ project. *Notes for using ASAN with afl-fuzz.* Accessed 2026-11-12. | C | https://aflplus.plus/docs/notes_for_asan/ | `aflpp_asan_docs` |
| [37] | Z. Y. Ding, C. Le Goues. *An Empirical Study of OSS-Fuzz Bugs.* MSR 2021, pp. 131–142. | A | https://doi.org/10.1109/MSR52588.2021.00026 | `ding2021ossfuzz` |
| [38] | G. Klees, A. Ruef, B. Cooper, S. Wei, M. Hicks. *Evaluating Fuzz Testing.* CCS 2018, pp. 2123–2138. | A | https://doi.org/10.1145/3243734.3243804 | `klees2018evaluating` |

### 7.4 近年泄漏检测评估

| # | 引用 | 级别 | DOI/URL | 建议 key |
|---|---|---|---|---|
| [39] | M. Li, Y. Chen, L. Wang, G. Xu. *Dynamically Validating Static Memory Leak Warnings.* ISSTA 2013, pp. 112–122. | A | https://doi.org/10.1145/2483760.2483778 | `li2013dvsml` |
| [40] | Y. Nong, H. Cai, P. Ye, L. Li, F. Chen. *Evaluating and Comparing Memory Error Vulnerability Detectors.* IST 137:106614, 2021. | A | https://doi.org/10.1016/j.infsof.2021.106614 | `nong2021evaluating` |
| [41] | H. Liang, L. Yin, G. Wu, Y. Li, Q. Yi, L. Wang. *LeakGuard: Detecting Memory Leaks Accurately and Scalably.* arXiv:2504.04422, 2025. | B | https://doi.org/10.48550/arXiv.2504.04422 | `liang2025leakguard` |
| [42] | H. Huang, J. Shi, B. Wang, Z. Yang, D. Lo. *Finding Memory Leaks in C/C++ Programs via Neuro-Symbolic Augmented Static Analysis.* arXiv:2603.27224, 2026. | B | https://doi.org/10.48550/arXiv.2603.27224 | `huang2026memhint` |
| [43] | E. Shemetova, I. Shenbin, I. Smirnov, et al. *LAMeD: LLM-generated Annotations for Memory Leak Detection.* arXiv:2505.02376, 2025. | B | https://doi.org/10.48550/arXiv.2505.02376 | `shemetova2025lamed` |
| [44] | W. Charoenwet, P. Thongtanunam, V.-T. Pham, C. Treude. *An Empirical Study of Static Analysis Tools for Secure Code Review.* ISSTA 2024, pp. 691–703. | A | https://doi.org/10.1145/3650212.3680313 | `charoenwet2024sast` |

### 7.5 建议在正文中使用的引用组合

- **CWE-401 定义/边界：** [1], [2], [3], [4].
- **静态工具与机制：** [6]–[24]。
- **动态工具与机制：** [25]–[33]。
- **模糊测试：** [34]–[38]。
- **近年评估/数字：** [39]–[44]。
- **不建议单独引用：** 二手博客、工具排行榜截图、没有版本/配置的“某工具准确率 X%”。

---

## 8. BibTeX 建议

> 以下仅作为建议条目，**未写入** `proposal/references.bib` 或任何共享 bib 文件。合并前请按项目现有风格统一 `key`、`pages`、`note` 字段；arXiv 条目建议保留 `eprint` 与 `doi` 以便核验。

```bibtex
@misc{cwe401,
  author       = {{MITRE}},
  title        = {{CWE-401}: Missing Release of Memory after Effective Lifetime},
  year         = {2026},
  howpublished = {Common Weakness Enumeration (CWE) 5.0},
  url          = {https://cwe.mitre.org/data/definitions/401.html},
  note         = {Accessed 2026-11-12}
}

@misc{cwe772,
  author       = {{MITRE}},
  title        = {{CWE-772}: Missing Release of Resource after Effective Lifetime},
  year         = {2026},
  howpublished = {Common Weakness Enumeration (CWE) 5.0},
  url          = {https://cwe.mitre.org/data/definitions/772.html},
  note         = {Accessed 2026-11-12}
}

@misc{cert_mem31c,
  author       = {{SEI CERT}},
  title        = {{MEM31-C}: Free Dynamically Allocated Memory When No Longer Needed},
  year         = {2026},
  howpublished = {SEI CERT C Coding Standard},
  url          = {https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/rules/memory-management-mem/mem31-c/},
  note         = {Accessed 2026-11-12}
}

@misc{nist_juliet13,
  author       = {{NIST}},
  title        = {Juliet {C/C++} 1.3 Test Suite},
  year         = {2017},
  howpublished = {NIST Software Assurance Reference Dataset (SARD)},
  url          = {https://samate.nist.gov/SARD/test-suites/112},
  note         = {Accessed 2026-11-12}
}

@techreport{black2018juliet,
  author      = {Black, Paul E.},
  title       = {Juliet 1.3 Test Suite: Changes From 1.2},
  institution = {National Institute of Standards and Technology},
  number      = {NIST Technical Note 1995},
  year        = {2018},
  doi         = {10.6028/NIST.TN.1995},
  url         = {https://doi.org/10.6028/NIST.TN.1995}
}

@inproceedings{xu2010memory,
  author    = {Xu, Zhongxing and Kremenek, Ted and Zhang, Jian},
  title     = {A Memory Model for Static Analysis of {C} Programs},
  booktitle = {Leveraging Applications of Formal Methods, Verification, and Validation (ISoLA)},
  series    = {LNCS},
  volume    = {6415},
  pages     = {535--548},
  year      = {2010},
  doi       = {10.1007/978-3-642-16558-0_44}
}

@inproceedings{sui2012saber,
  author    = {Sui, Yulei and Ye, Ding and Xue, Jingling},
  title     = {Static Memory Leak Detection Using Full-Sparse Value-Flow Analysis},
  booktitle = {Proceedings of the 2012 International Symposium on Software Testing and Analysis (ISSTA)},
  pages     = {254--264},
  year      = {2012},
  doi       = {10.1145/2338965.2336784}
}

@inproceedings{sui2016svf,
  author    = {Sui, Yulei and Xue, Jingling},
  title     = {{SVF}: Interprocedural Static Value-Flow Analysis in {LLVM}},
  booktitle = {Proceedings of the 25th International Conference on Compiler Construction (CC)},
  pages     = {265--266},
  year      = {2016},
  doi       = {10.1145/2892208.2892235}
}

@inproceedings{fan2019smoke,
  author    = {Fan, Gang and Wu, Rongxin and Shi, Qingkai and Xiao, Xiao and Zhou, Jinguo and Zhang, Charles},
  title     = {{SMOKE}: Scalable Path-Sensitive Memory Leak Detection for Millions of Lines of Code},
  booktitle = {Proceedings of the 41st International Conference on Software Engineering (ICSE)},
  pages     = {72--82},
  year      = {2019},
  doi       = {10.1109/ICSE.2019.00025}
}

@article{calcagno2011biabduction,
  author  = {Calcagno, Cristiano and Distefano, Dino and O'Hearn, Peter W. and Yang, Hongseok},
  title   = {Compositional Shape Analysis by Means of Bi-Abduction},
  journal = {Journal of the ACM},
  volume  = {58},
  number  = {6},
  pages   = {26:1--26:66},
  year    = {2011},
  doi     = {10.1145/2049697.2049700}
}

@inproceedings{calcagno2015movingfast,
  author    = {Calcagno, Cristiano and Distefano, Dino and Dubreil, J{\'e}r{\'e}my and Gabi, Dominik and Hooimeijer, Pieter and Luca, Martino and O'Hearn, Peter and Papakonstantinou, Irene and Purbrick, Jim and Rodriguez, Dulma},
  title     = {Moving Fast with Software Verification},
  booktitle = {NASA Formal Methods (NFM)},
  series    = {LNCS},
  volume    = {9058},
  pages     = {3--11},
  year      = {2015},
  doi       = {10.1007/978-3-319-17524-9_1}
}

@article{distefano2019scaling,
  author  = {Distefano, Dino and F{\"a}hndrich, Manuel and Logozzo, Francesco and O'Hearn, Peter W.},
  title   = {Scaling Static Analyses at {Facebook}},
  journal = {Communications of the ACM},
  volume  = {62},
  number  = {8},
  pages   = {62--70},
  year    = {2019},
  doi     = {10.1145/3338112}
}

@article{bessey2010fewbillion,
  author  = {Bessey, Al and Block, Ken and Chelf, Ben and Chou, Andy and Fulton, Bryan and Hallem, Seth and Henri-Gros, Charles and Kamsky, Asya and McPeak, Scott and Engler, Dawson},
  title   = {A Few Billion Lines of Code Later: Using Static Analysis to Find Bugs in the Real World},
  journal = {Communications of the ACM},
  volume  = {53},
  number  = {2},
  pages   = {66--75},
  year    = {2010},
  doi     = {10.1145/1646353.1646374}
}

@misc{clangsa_docs,
  author       = {{Clang Team}},
  title        = {Clang Static Analyzer},
  year         = {2026},
  howpublished = {Clang Documentation},
  url          = {https://clang.llvm.org/docs/ClangStaticAnalyzer.html},
  note         = {Accessed 2026-11-12}
}

@misc{clang_ctu_docs,
  author       = {{Clang Team}},
  title        = {Cross Translation Unit ({CTU}) Analysis},
  year         = {2026},
  howpublished = {Clang Static Analyzer Documentation},
  url          = {https://clang.llvm.org/docs/analyzer/user-docs/CrossTranslationUnit.html},
  note         = {Accessed 2026-11-12}
}

@misc{clang_annotations_docs,
  author       = {{Clang Team}},
  title        = {Source Annotations},
  year         = {2026},
  howpublished = {Clang Static Analyzer Documentation},
  url          = {https://clang.llvm.org/docs/analyzer/user-docs/Annotations.html},
  note         = {Accessed 2026-11-12}
}

@misc{clang_checkers_docs,
  author       = {{Clang Team}},
  title        = {Available Checkers},
  year         = {2026},
  howpublished = {Clang Static Analyzer Documentation},
  url          = {https://clang.llvm.org/docs/analyzer/checkers.html},
  note         = {Accessed 2026-11-12}
}

@misc{cppcheck_manual,
  author       = {{Cppcheck project}},
  title        = {Cppcheck Manual},
  year         = {2026},
  howpublished = {Cppcheck Documentation},
  url          = {https://cppcheck.sourceforge.io/manual.html},
  note         = {Accessed 2026-11-12}
}

@misc{cppcheck_design,
  author       = {{Cppcheck project}},
  title        = {A Cppcheck Design},
  year         = {2026},
  howpublished = {Cppcheck Documentation},
  url          = {https://www.cs.kent.edu/~rothstei/fall_14/sec_notes/cppcheck-design.pdf},
  note         = {Accessed 2026-11-12}
}

@misc{infer_pulse_docs,
  author       = {{Meta}},
  title        = {Infer: Pulse},
  year         = {2026},
  howpublished = {Infer Documentation, version 1.3.0},
  url          = {https://fbinfer.com/docs/checker-pulse/},
  note         = {Accessed 2026-11-12}
}

@misc{infer_about_docs,
  author       = {{Meta}},
  title        = {About Infer},
  year         = {2026},
  howpublished = {Infer Documentation, version 1.3.0},
  url          = {https://fbinfer.com/docs/about-Infer/},
  note         = {Accessed 2026-11-12}
}

@misc{codeql_cwe_docs,
  author       = {{GitHub}},
  title        = {{CodeQL} {CWE} Coverage for {C} and {C++}},
  year         = {2026},
  howpublished = {CodeQL Query Help},
  url          = {https://codeql.github.com/codeql-query-help/cpp-cwe/},
  note         = {Accessed 2026-11-12}
}

@article{cadar2013symbolic,
  author  = {Cadar, Cristian and Sen, Koushik},
  title   = {Symbolic Execution for Software Testing: Three Decades Later},
  journal = {Communications of the ACM},
  volume  = {56},
  number  = {2},
  pages   = {82--90},
  year    = {2013},
  doi     = {10.1145/2408776.2408795}
}

@inproceedings{cadar2008klee,
  author    = {Cadar, Cristian and Dunbar, Daniel and Engler, Dawson},
  title     = {{KLEE}: Unassisted and Automatic Generation of High-Coverage Tests for Complex Systems Programs},
  booktitle = {Proceedings of the 8th USENIX Symposium on Operating Systems Design and Implementation (OSDI)},
  pages     = {209--224},
  year      = {2008},
  url       = {https://www.usenix.org/legacy/event/osdi08/tech/full_papers/cadar/cadar.pdf}
}

@inproceedings{nethercote2007valgrind,
  author    = {Nethercote, Nicholas and Seward, Julian},
  title     = {Valgrind: A Framework for Heavyweight Dynamic Binary Instrumentation},
  booktitle = {Proceedings of the 28th ACM SIGPLAN Conference on Programming Language Design and Implementation (PLDI)},
  pages     = {89--100},
  year      = {2007},
  doi       = {10.1145/1250734.1250746}
}

@inproceedings{seward2005memcheck,
  author    = {Seward, Julian and Nethercote, Nicholas},
  title     = {Using Valgrind to Detect Undefined Value Errors with Bit-Precision},
  booktitle = {Proceedings of the 2005 USENIX Annual Technical Conference (USENIX ATC)},
  pages     = {17--30},
  year      = {2005},
  url       = {https://www.usenix.org/legacy/events/usenix05/tech/general/seward.html}
}

@misc{valgrind_manual,
  author       = {{Valgrind Developers}},
  title        = {Memcheck: A Memory Error Detector},
  year         = {2026},
  howpublished = {Valgrind Documentation},
  url          = {https://valgrind.org/docs/manual/mc-manual.html},
  note         = {Accessed 2026-11-12}
}

@inproceedings{serebryany2012asan,
  author    = {Serebryany, Konstantin and Bruening, Derek and Potapenko, Alexander and Vyukov, Dmitry},
  title     = {{AddressSanitizer}: A Fast Address Sanity Checker},
  booktitle = {Proceedings of the 2012 USENIX Annual Technical Conference (USENIX ATC)},
  pages     = {309--318},
  year      = {2012},
  url       = {https://www.usenix.org/conference/atc12/technical-sessions/presentation/serebryany}
}

@misc{asan_docs,
  author       = {{LLVM Project}},
  title        = {{AddressSanitizer}},
  year         = {2026},
  howpublished = {Clang Documentation},
  url          = {https://clang.llvm.org/docs/AddressSanitizer.html},
  note         = {Accessed 2026-11-12}
}

@misc{lsan_docs,
  author       = {{LLVM Project}},
  title        = {{LeakSanitizer}},
  year         = {2026},
  howpublished = {Clang Documentation},
  url          = {https://clang.llvm.org/docs/LeakSanitizer.html},
  note         = {Accessed 2026-11-12}
}

@inproceedings{bruening2011drmemory,
  author    = {Bruening, Derek and Zhao, Qin},
  title     = {Practical Memory Checking with {Dr. Memory}},
  booktitle = {Proceedings of the 9th International Symposium on Code Generation and Optimization (CGO)},
  pages     = {213--223},
  year      = {2011},
  doi       = {10.1109/CGO.2011.5764689}
}

@misc{drmemory_leaks_docs,
  author       = {{Dr. Memory project}},
  title        = {Memory Leaks},
  year         = {2026},
  howpublished = {Dr. Memory Documentation, version 2.3.20434},
  url          = {https://drmemory.org/page_leaks.html},
  note         = {Accessed 2026-11-12}
}

@misc{google_memory_tools_comparison,
  author       = {{Google Sanitizers project}},
  title        = {{AddressSanitizer} Comparison of Memory Tools},
  year         = {2020},
  howpublished = {GitHub Wiki},
  url          = {https://github.com/google/sanitizers/wiki/AddressSanitizerComparisonOfMemoryTools},
  note         = {Accessed 2026-11-12}
}

@article{manes2021fuzzing,
  author  = {Man{\`e}s, Valentin J. M. and Han, HyungSeok and Han, Choongwoo and Cha, Sang Kil and Egele, Manuel and Schwartz, Edward J. and Woo, Maverick},
  title   = {The Art, Science, and Engineering of Fuzzing: A Survey},
  journal = {IEEE Transactions on Software Engineering},
  volume  = {47},
  number  = {11},
  pages   = {2312--2331},
  year    = {2021},
  doi     = {10.1109/TSE.2019.2946563}
}

@misc{libfuzzer_docs,
  author       = {{LLVM Project}},
  title        = {{libFuzzer}: A Library for Coverage-Guided Fuzz Testing},
  year         = {2026},
  howpublished = {LLVM Documentation},
  url          = {https://llvm.org/docs/LibFuzzer.html},
  note         = {Accessed 2026-11-12}
}

@misc{aflpp_asan_docs,
  author       = {{AFL++ project}},
  title        = {Notes for Using {ASAN} with afl-fuzz},
  year         = {2026},
  howpublished = {AFL++ Documentation},
  url          = {https://aflplus.plus/docs/notes_for_asan/},
  note         = {Accessed 2026-11-12}
}

@inproceedings{ding2021ossfuzz,
  author    = {Ding, Zhen Yu and Le Goues, Claire},
  title     = {An Empirical Study of {OSS-Fuzz} Bugs},
  booktitle = {Proceedings of the 18th IEEE/ACM International Conference on Mining Software Repositories (MSR)},
  pages     = {131--142},
  year      = {2021},
  doi       = {10.1109/MSR52588.2021.00026}
}

@inproceedings{klees2018evaluating,
  author    = {Klees, George and Ruef, Andrew and Cooper, Benji and Wei, Shiyi and Hicks, Michael},
  title     = {Evaluating Fuzz Testing},
  booktitle = {Proceedings of the 2018 ACM SIGSAC Conference on Computer and Communications Security (CCS)},
  pages     = {2123--2138},
  year      = {2018},
  doi       = {10.1145/3243734.3243804}
}

@inproceedings{li2013dvsml,
  author    = {Li, Mengchen and Chen, Yuanjun and Wang, Linzhang and Xu, Guoqing},
  title     = {Dynamically Validating Static Memory Leak Warnings},
  booktitle = {Proceedings of the 2013 International Symposium on Software Testing and Analysis (ISSTA)},
  pages     = {112--122},
  year      = {2013},
  doi       = {10.1145/2483760.2483778}
}

@article{nong2021evaluating,
  author  = {Nong, Yu and Cai, Haipeng and Ye, Pengfei and Li, Li and Chen, Feng},
  title   = {Evaluating and Comparing Memory Error Vulnerability Detectors},
  journal = {Information and Software Technology},
  volume  = {137},
  pages   = {106614},
  year    = {2021},
  doi     = {10.1016/j.infsof.2021.106614}
}

@misc{liang2025leakguard,
  author       = {Liang, Hongliang and Yin, Luming and Wu, Guohao and Li, Yuxiang and Yi, Qiuping and Wang, Lei},
  title        = {{LeakGuard}: Detecting Memory Leaks Accurately and Scalably},
  year         = {2025},
  eprint       = {2504.04422},
  archivePrefix = {arXiv},
  primaryClass = {cs.CR},
  doi          = {10.48550/arXiv.2504.04422},
  url          = {https://arxiv.org/abs/2504.04422}
}

@misc{huang2026memhint,
  author       = {Huang, Huihui and Shi, Jieke and Wang, Bo and Yang, Zhou and Lo, David},
  title        = {Finding Memory Leaks in {C/C++} Programs via Neuro-Symbolic Augmented Static Analysis},
  year         = {2026},
  eprint       = {2603.27224},
  archivePrefix = {arXiv},
  primaryClass = {cs.SE},
  doi          = {10.48550/arXiv.2603.27224},
  url          = {https://arxiv.org/abs/2603.27224}
}

@misc{shemetova2025lamed,
  author       = {Shemetova, Ekaterina and Shenbin, Ilya and Smirnov, Ivan and Alekseev, Anton and Rukhovich, Alexey and Nikolenko, Sergey and Lomshakov, Vadim and Piontkovskaya, Irina},
  title        = {{LAMeD}: {LLM}-Generated Annotations for Memory Leak Detection},
  year         = {2025},
  eprint       = {2505.02376},
  archivePrefix = {arXiv},
  primaryClass = {cs.SE},
  doi          = {10.48550/arXiv.2505.02376},
  url          = {https://arxiv.org/abs/2505.02376}
}

@inproceedings{charoenwet2024sast,
  author    = {Charoenwet, Wachiraphan and Thongtanunam, Patanamon and Pham, Van-Thuan and Treude, Christoph},
  title     = {An Empirical Study of Static Analysis Tools for Secure Code Review},
  booktitle = {Proceedings of the 33rd ACM SIGSOFT International Symposium on Software Testing and Analysis (ISSTA)},
  pages     = {691--703},
  year      = {2024},
  doi       = {10.1145/3650212.3680313}
}
```

---

## 9. 核验记录

### 9.1 主要检索来源

- **标准/CWE：** MITRE CWE-401、CWE-772 页面；SEI CERT MEM31-C 页面；NIST SARD Juliet 1.3 页面；NIST TN 1995。
- **工具官方文档：** Clang Static Analyzer（主文档、checkers、CTU、source annotations）；Cppcheck manual 与设计文档；Infer About/Pulse；CodeQL CWE coverage；Valgrind Memcheck manual/quick start；ASan/LSan libFuzzer 文档；AFL++ ASan notes；Dr. Memory leaks 文档；Google sanitizers memory-tool comparison。
- **论文 DOI：** Crossref API 核验 DOI、卷期、页码；USENIX 论文核验会议/页码。
- **arXiv：** LeakGuard 2504.04422；MemHint 2603.27224；LAMeD 2505.02376；Charoenwet 2407.12241。

### 9.2 关键数字二次核对

| 数字 | 来源 | 核对结果 |
|---|---|---|
| CWE-401 = Variant；ChildOf 772/404（不同视图） | MITRE 页面 | 一致 |
| CWE-772 = Base；子类含 401/775/1091 | MITRE 页面 | 一致 |
| MEM31-C 精确映射 CWE-401 | CERT 页面 “CWE 2.11 CWE-401 … Exact” | 一致 |
| MEM31-C Severity=Medium, Likelihood=Probable | CERT 风险表 | 一致 |
| Juliet 64,099 cases / 118 CWEs | NIST SARD/TN 1995 | 一致 |
| Juliet CWE-401 = 1,364 units | LeakGuard §4.3；TN=1,364 | 一致 |
| LeakGuard Juliet: 1336/0/1364/28, F1 0.990 | LeakGuard Table 2 | 一致 |
| CSA Juliet: 490/192/1172/874, F1 0.479 | LeakGuard Table 2 | 一致 |
| Infer Juliet: 320/250/1114/1044, F1 0.331 | LeakGuard Table 2 | 一致 |
| SVF Juliet: 520/750/614/844, F1 0.395 | LeakGuard Table 2 | 一致 |
| LeakGuard 129 real leaks；CSA 44/Infer 25/Cppcheck 1 | LeakGuard Table 1 | 一致 |
| LeakGuard timing 190,793/85,461/6,795/134,386 s | LeakGuard Table 4 | 一致 |
| Saber 211 leaks/FP 18.5%/10,220 LOC/s | Saber abstract/Table 1 | 一致 |
| SMOKE 8 MLoC/40 min/FP 24.4%/5.2–22.8× | SMOKE abstract | 一致 |
| SMOKE 测 Saber FP 66.7% | SMOKE §I | 一致 |
| DVSML 246 warnings→112/38/38/58, 58 manual | DVSML abstract/intro | 一致 |
| Nong 2021 520+474 programs, 5 detectors | Nong abstract | 一致 |
| MemHint 54 leaks/CodeQL 19/Infer 3/$1.76 | MemHint abstract | 一致 |
| OSS-Fuzz 23,907 bugs/316 projects/52% six types | OSS-Fuzz abstract/§ | 一致 |
| OSS-Fuzz leaks 15% fuzz blockers, 19% all leaks | OSS-Fuzz § | 一致 |
| ASan paper 73% slowdown/3.37× memory | ASan paper §3 | 一致 |
| Valgrind 20–30× slowdown | Memcheck 2005/quick start | 一致 |
| Dr. Memory 10–20×；比 Memcheck 快 2× | Dr. Memory paper | 一致 |
| LSan platforms: Android/Fuchsia/Linux/macOS/NetBSD | LSan docs | 一致 |

### 9.3 不确定/需要后续确认

1. **LeakGuard 的正式发表状态。** arXiv 2504.04422 的 Comments 写 “conference paper on memory leak detection”，但本次未核验到正式 DOI/会议页码；引用时按预印本（B）处理，不要写成已正式发表。
2. **MemHint 的正式发表状态。** arXiv 2603.27224 v6（2026-10-20），未核验正式 venue；按预印本处理。
3. **Cppcheck 的版本/配置。** LeakGuard 没有在正文中给出 Cppcheck 的具体版本和完整参数；CERT 页面列的是 2.15。引用 “Cppcheck 1/129” 时必须注明“在 LeakGuard 的配置/版本下”，不能当作 Cppcheck 的普遍性能。
4. **SVF 的“泄漏检测”结果。** SVF 是值流框架，不是开箱即用的泄漏产品；LeakGuard 的 SVF 结果取决于其 leak client/配置。不要把 SVF 的 Juliet 数字等同于“SVF 工具本身”的普遍能力。
5. **SMOKE 与 Saber 的 FP 冲突。** 18.5% vs 66.7% 已确认分别来自两篇论文的不同基准/配置；具体差异原因（项目集、版本、误报判定）未逐项复现。
6. **Juliet CWE-401 的 1,364 单元数。** 来自 LeakGuard 的 Table 2 反推（TN=1,364）与其 §4.3 文字；本次未直接下载 Juliet 目录逐文件计数。NIST 总数 64,099 已核验。
7. **CERT “Detectable: No”。** 这是 CERT 规则表的评级；同一页列出多种工具 checker。本文不把它解释为“工具不能检测”，但也没有找到 CERT 对该字段的详细定义。
8. **Dr. Memory 的 macOS 支持。** 官方首页写 “Windows, Linux, and Mac”，论文主要验证 Windows/Linux；本文写作 “Windows/Linux（首页列 macOS）”。
9. **ASan “leaks (experimental)” 与 LSan 成熟度。** ASan 文档仍把 leaks 标为 experimental；LSan 文档更完整。本文把泄漏检测归因于 LSan，避免说“ASan 本身成熟地检测泄漏”。
10. **Fuzzing 的成本数字。** 没有引用单一 slowdown 倍数；不同 harness/sanitizer/目标差异太大。AFL++ 文档给出的 ASan 虚拟内存占用（17.5–20 TB）是地址空间预留，不是实际 RSS，引用时不要混淆。

### 9.4 本调研没有做的事

- 没有运行 Clang SA、Cppcheck、Infer、SVF、Valgrind、ASan/LSan、Dr. Memory、libFuzzer/AFL++ 中的任何一个；本文所有性能/精度数字都来自论文或官方文档。
- 没有复现 LeakGuard/SMOKE/Saber/DVSML/Nong/MemHint 的实验。
- 没有对 Juliet 或本项目数据做逐文件计数/标注。
- 没有做 PRISMA 式系统综述；这是定向文献与工具调研，不是系统综述。
- 没有修改 `proposal/references.bib`、数据、脚本、实验输出或任何其他共享文件；只新增/修改 `research/static_dynamic_memory.md`。

---

## 10. 一句话总结

静态方法回答“是否存在一条可能泄漏的路径”，动态方法回答“这次执行是否真的漏了”；统一 benchmark 的关键不是把两者塞进同一张 accuracy 表，而是把 oracle、输入覆盖、工具配置和成本分开记录，并让 CWE-401 的 may/must、definitely/possibly/still reachable 各有明确归属。
