# 2024–2026 内存泄漏静态/动态工具最新进展：条件分配失败、still reachable、路径覆盖与真实项目迁移

> **调研日期**：2026-11-13。**检索范围**：2024-01 至 2026-11 的正式论文、预印本、工具发布说明与官方文档；Saber/SMOKE 等更早的奠基工作只作为背景引用。
>
> **证据分级**：**A** = 同行评审论文、标准或规范（DOI/正式出版页可核验）；**B** = 预印本或技术报告（arXiv、机构报告；数字按作者自报处理）；**C** = 工具官方文档、发布说明、源码（行为描述可信；厂商自报性能单独标注）；**D** = 博客/二手解读（不用于事实性断言）。
>
> **写作边界**：本文件只做文献与工具调研，不运行本项目正式数据，不修改其他文件，不调用任何模型，不读取或输出任何 API key。第 5 节有一个在 WSL `/tmp` 下完成的**最小语义验证**，只用于确认 `still reachable` 与 `realloc` 失败路径的工具行为，不是 benchmark，也不写入项目结果目录。
>
> **一句话结论**：2024–2026 年没有出现能同时解决“自定义分配器、条件分配失败、still reachable、路径覆盖”四个问题的单一工具；真正有效的路线是**把静态的 may-leak、动态的 definite-lost、覆盖率与故障注入分开记录，再用所有权模型和路径可行性把三者接起来**。
>
> **检索方法**：优先使用工具官方 changelog、官方文档、源码和 DOI/arXiv 元数据；版本号与发布日期逐条交叉核验；论文中的性能/召回数字只按作者自报口径引用，并标注基准与配置。无法核验的内容放在 §6.2，不写成事实。

---

## 0. 结论摘要

1. **工具演进的主线是工程化与建模，不是新 oracle。** 截至 2026-11，CodeQL 2.27.4 的 CWE-401 仍由 `cpp/memory-may-not-be-freed`、`cpp/memory-never-freed`、`cpp/memory-leak-on-failed-call-to-realloc`、`cpp/catch-missing-free` 四个查询覆盖；Semgrep 增强了 C/C++ 跨文件数据流，但仍不是堆生命周期证明；Infer 1.3.0 把 Pulse 变成默认引擎；SVF 3.3 仍是值流/源汇路线；Clang 22 仍是路径敏感符号执行；LSan/Valgrind 的泄漏分类语义没有根本变化。[R5][R10][R13][R17][R20][R25][R28]
2. **条件分配失败是静态/动态分工的核心缺口。** 静态工具可以回答“是否存在一条失败后未释放的可行路径”；动态工具只能回答“这次执行有没有走到失败路径”。Juliet CWE-401 的 `malloc_realloc` 坏例正是 `data = realloc(data, n)` 后仅在成功分支 `free`；默认运行 `realloc` 成功，所以 LSan/Valgrind 看不到泄漏。[R3][R33][R47]
3. **`p = realloc(p, n)` 是独立反模式，不应混在普通 malloc/free 里。** C 标准规定失败时原块不被释放并返回空指针；把返回值直接写回 `p` 会丢失原块。CodeQL 为此提供专用查询；Clang SA 在标准 Juliet 模式上会报 “Potential leak … Reallocation failed”；LSan 默认不报，只有强制失败才报。[R3][R5][R20]
4. **still reachable 不是 leak，但也不能当 TN。** LSan 的根集默认包含全局变量、线程栈、寄存器和 TLS，只报告“从根不可达”的块；Valgrind 默认只单列 definite/possible，still reachable 需要 `--show-leak-kinds=all` 才显示。CERT MEM31-C-EX1 明确允许“指针生命周期覆盖程序终止”的分配不释放。[R2][R26][R27][R28]
5. **still reachable 对长生命周期服务/库仍可能是真问题。** 进程退出时的全局缓存可以合法地不释放；但库被反复调用、服务长期运行、缓存无上限增长时，“仍可达”不等于“无泄漏”。需要用检查点泄漏检查、堆增长分析或显式生命周期策略，而不是只看退出时的 LSan 报告。
6. **路径覆盖是动态结论的边界。** 本项目全量动态 run 的 190 个 FN 中，108 个是 `malloc_realloc` 失败路径未触发，68 个是全局指针 still reachable，14 个是随机分支未覆盖；该 run 没有行/分支覆盖率 instrumentation，所以 `clean` 只能表示“执行到的路径上未观察到 definite/indirect leak”，不能表示“该单元无泄漏”。[R47]
7. **真实项目迁移的瓶颈是构建、所有权和告警治理，不是查询写法。** LeakGuard 在 18 个真实项目、超过 70 MLoC 上报告 129 个经开发者确认的泄漏；MemHint 在 8 个项目、超过 3.6M LOC 上报告 54 个；两者的 baseline 计数都是“能否找回已知 bug”，不是全量 precision/recall。[R33][R34]
8. **就本次检索的证据看，LLM 最可靠的角色是“注释/摘要生成 + 告警分流 + 修复”，不是独立 oracle。** MemHint 用 LLM 生成 allocator/deallocator 摘要、Z3 验证可达性，再注入 CodeQL/Infer；LAMeD 用 LLM 生成函数级注解，在 cJSON 上 annotation precision 0.933、recall 约 0.60，但告警量显著上升；两者都是预印本。[R34][R35]
9. **不要跨基准比较原始 bug 数。** LeakGuard 的 “CSA 44 / Infer 25 / Cppcheck 1” 是在它自己找到的 129 个 bug 上的回收数；MemHint 的 “CodeQL 19 / Infer 3 / Semgrep 2 / LeakGuard 20” 是在它自己确认的 54 个 bug 上的回收数。它们不是同一张排行榜，不能写成“某工具只有 3% 召回”。[R33][R34]
10. **对本项目最紧急的修复不是再换模型，而是把动态标签改对。** 先把 `clean` 拆成 `covered_clean` / `uncovered`，把 still reachable 单列，再对 108 个 `malloc_realloc` 加确定性失败注入；这三件事会让现有结论更可信，成本远低于再跑一轮 LLM。

---

## 1. 语义与评估口径

### 1.1 CWE-401 的边界

MITRE 对 CWE-401 的定义是：*“The product does not sufficiently track and release allocated memory after it has been used, making the memory unavailable for reallocation and reuse.”* 它是 **Variant** 级弱点，在完整层次中 ChildOf CWE-772（Missing Release of Resource after Effective Lifetime），在简化映射视图中也 ChildOf CWE-404（Improper Resource Shutdown or Release）。CWE-401 不等于 double free / use-after-free（CWE-415/416）；很多 checker（如 Clang `unix.Malloc`）同时报三类，评测时必须按报告类型过滤。[R1][R20]

CWE-401 的 “Modes of Introduction” 明确把两类原因放在首位：**错误条件/异常情况**（malformed data、意外中断的会话）和**所有权混淆**（不知道谁负责释放）。这正好对应本文的两个重点：条件分配失败和 still reachable/全局所有权。[R1]

CERT MEM31-C 要求“不再需要时释放动态分配的内存”，但其例外 MEM31-C-EX1 明确写道：如果分配的内存被赋给一个生命周期覆盖程序终止的指针（典型是 `static` 变量），则不需要释放。该规则页还把 CWE-401 标为 Exact 映射。[R2]

因此，做 CWE-401 评测时必须先决定：**是按 CERT 的终止期例外，还是按 Juliet 的标签？** 两者在全局指针用例上会给出不同答案。本文的建议是：主表按 Juliet 标签保留“FN”，同时单独给出“按 CERT 例外排除”的第二视图，不能静默丢掉这 68 个用例。

### 1.2 四种 oracle

| 方法类 | 它回答的问题 | 正例 | 负例 | 典型误报 | 典型漏报 |
|---|---|---|---|---|---|
| 静态 may-leak | 是否存在一条**可行路径**，分配后未释放且指针未逃逸？ | 至少一条可行路径在函数/程序退出前失去最后一个指针，且没有 free | 所有可行路径都 free，或指针逃逸到调用者/全局/容器 | 不可行路径被当成可行；自定义分配器/所有权转移未建模；全局缓存被误判 | 路径深度/节点预算；跨 TU 未开启；未知库/函数指针；自定义 MAD 函数未识别；抽象合并路径 |
| 静态 must-leak | 是否**所有**路径都泄漏？ | 所有可行路径都不 free | 存在一条 free 路径 | 抽象过粗导致把“有时 free”当成“从不 free” | 同上，且更容易漏掉错误路径泄漏 |
| 动态 definite/indirect lost | 在**这次执行**的退出点，这个堆块是否不可达？ | 退出时没有任何根可达指针（definitely lost）；或只被已泄漏块指向（indirectly lost） | 退出时仍可从根到达（still reachable），或已被 free | `possibly lost` 被当成 definitely lost；自定义池/分配器；未对齐/加密指针；全局缓存被误报 | 输入没走到泄漏路径；错误路径未执行；进程未正常退出；泄漏被 suppression；LSan 只按对齐指针扫描 |
| 模糊测试 | 在**生成的输入**上，是否触发 sanitizer 泄漏报告？ | 某个输入使 LSan/ASan 在退出或检查点报告泄漏，并留下 reproducer | 所有生成输入都未触发泄漏报告 | 同动态分析；持久模式下的累积泄漏；全局缓存 | harness 没覆盖 API；语料不足；`-detect_leaks=0`；泄漏发生在检查点之前但未被检查 |

关键区别：

- **may-leak** 是存在量化；**must-leak** 是全称量化。CodeQL 的 `memory-may-not-be-freed` 与 `memory-never-freed` 正好对应两种不同的问法；Infer/Pulse 的 “errors are only reported when all conditions … are true regardless of input” 更接近 must-leak，条件依赖的泄漏会变成 latent。[R6][R7][R14]
- **definitely lost** 是动态工具对“退出时不可达”的分类，不等于静态 may-leak，也不等于“所有输入都会漏”。Valgrind 手册明确说它不能告诉你指针是何时/如何丢的。[R28]
- **still reachable** 在 Valgrind/Dr. Memory 中默认不算泄漏；LSan 也不报告仍可达的块。这与 CERT MEM31-C-EX1 一致，但在静态工具中常被报成 leak。因此，静态的“全局缓存 leak”与动态的“still reachable”不能直接算成同一类错误。

### 1.3 条件分配失败：为什么必须单独建 track

C 标准对 `realloc` 的失败语义很明确：**如果内存不足，旧内存块不会被释放，返回空指针；原指针仍然有效，可能需要用 `free` 或 `realloc` 释放。** 成功时返回新指针，原指针失效；即使原地扩展，访问旧指针也是未定义行为。[R3]

这带来两个经典反模式：

```c
/* 反模式 1：失败时丢失原块 */
p = realloc(p, new_size);
if (p == NULL) return;   /* 原块已经无法被程序引用 */

/* 反模式 2：只在成功分支 free */
p = realloc(p, new_size);
if (p != NULL) {
    ...
    free(p);
}                        /* 失败分支没有 free 原块 */
```

Juliet CWE-401 的 `malloc_realloc` 坏例就是反模式 2 的变体：`data = realloc(data, 130000)` 之后，只在 `data != NULL` 分支里 `free(data)`。默认运行 `realloc` 成功，所以动态工具看不到泄漏；只有让 `realloc` 失败，才会暴露。[R33][R47]

还有一个容易忽略的边界：`realloc(p, 0)` 在 C17 及以前是 implementation-defined（可能返回空指针并释放原块，也可能返回不可用的非空指针）；**C23 起是未定义行为**。CodeQL 的 `MemoryMayNotBeFreed.ql` 源码里把 `realloc(ptr, 0)` 当作“总是成功并释放”，这是对 glibc 行为的建模，不应被当成可移植语义。[R3][R6]

| 代码模式 | 静态工具能看到什么 | 动态工具需要什么 | 建议 |
|---|---|---|---|
| `q = realloc(p, n); if (!q) { free(p); return; }` | 通常能证明失败路径，也通常能证明 `free(p)` 修复 | 需要让 `realloc` 失败；否则只走成功路径 | 作为正确写法；故障注入只用于验证分支，不用于找泄漏 |
| `q = realloc(p, n); if (!q) return;`（`p` 仍在作用域） | Clang SA 等路径敏感工具可报 may-leak；CodeQL 需要专用查询/模型 | 需要失败注入；LSan/Valgrind 在失败执行后报 definite lost | 推荐用 CodeQL `memory-leak-on-failed-call-to-realloc` + Clang SA 双查 |
| `p = realloc(p, n); if (!p) return;`（原块丢失） | 需要工具能区分“赋值前旧值”和“赋值后新值”；普通 may-leak 查询容易漏 | 需要失败注入；LSan/Valgrind 在失败执行后报 definite lost | 把它作为独立规则/独立 track，不要依赖通用 leak 查询 |
| `p = realloc(p, 0)` | 语义依实现而定；C23 为 UB | 取决于 libc；不建议作为泄漏测试用例 | 代码审查直接禁止；不要用它验证工具 |

同样的逻辑适用于 `malloc`/`calloc`/`new` 失败：错误分支可能没有释放已经获取的其他资源，或者没有检查返回值导致后续崩溃；`calloc` 还要注意乘法溢出。故障注入的目标不是“让程序崩溃”，而是“让失败分支可执行，再用泄漏 oracle 判断该分支是否漏释放”。

**结论**：条件分配失败不是“动态工具不够灵敏”这么简单，而是**执行路径与 oracle 的联合缺口**。静态工具必须证明失败路径可行；动态工具必须实际制造失败。两者缺一不可。

### 1.4 still reachable：工具语义与工程语义

LSan 的设计是：进程结束时暂停执行，扫描根集（全局变量、线程栈、通用寄存器、TLS/POSIX thread-specific data），把从根集可达的块标记为 live，然后报告不可达块。它先把 interior pointer 当成指向块起始的指针，再传递闭包。[R26]

LSan 的运行时 flag 源码明确显示：

- `use_globals = true`：全局变量（`.data`/`.bss`）属于根集；
- `use_stacks = true`：线程栈属于根集；
- `use_registers = true`：线程寄存器属于根集；
- `use_tls = true`：TLS 和 thread-specific storage 属于根集；
- `use_unaligned = false`：默认只考虑对齐的指针模式；
- `use_poisoned = false`：默认不考虑 poisoned memory 中的指针。[R27]

因此，**一个只被全局指针指向的块，LSan 默认不会报告**。这不是 bug，而是“退出时仍可达”的定义。把 `use_globals=0` 可以强制让这类块变成“不可达”从而被报告，但那是诊断手段，不是 CWE-401 的默认语义；它会把合法的进程生命周期缓存也报出来。

Valgrind 的分类更细：

- **Still reachable**：存在 start-pointer 或 start-pointer 链指向块；程序员原则上可以在退出前释放它；非常常见，**默认不单独报告**。
- **Definitely lost**：没有任何指针指向块；应当在退出前修复。
- **Indirectly lost**：块本身不是没有指针，而是所有指向它的块都 lost；默认不单独报告。
- **Possibly lost**：存在指针链，但至少有一个 interior-pointer；除非你确认存在 interior pointer，否则不应视为 OK。[R28]

Valgrind 的默认值是 `--leak-check=summary`，只有 `--leak-check=full` 才把泄漏计为 error；`--show-leak-kinds` 默认 `definite,possible`；`--errors-for-leak-kinds` 默认 `definite,possible`。要把 still reachable 显示出来，需要 `--show-leak-kinds=all`；要把 reachable 计为 error，需要显式把它加入 `--errors-for-leak-kinds`。[R28]

**工程判断**：

- 对**短生命周期进程/测试程序**，still reachable 通常不是 CWE-401 正例，符合 CERT MEM31-C-EX1。
- 对**库、插件、长生命周期服务**，全局缓存可能无界增长；“退出时仍可达”不能证明“没有泄漏”。这时需要检查点泄漏检查、堆增长分析（如 Valgrind `--xtree-memory`/Massif）或显式的缓存上限/淘汰策略。
- 对**benchmark**，still reachable 应单列，既不算 TP，也不算 TN；如果按 CERT 例外排除，要同时给出“Juliet-label view”和“CERT-exception view”。

### 1.5 路径覆盖：动态结论的最小报告字段

动态工具只对执行到的路径负责。要把“没报”与“没走到”分开，至少需要以下状态：

| 状态 | 定义 | 是否可当 TN | 备注 |
|---|---|---|---|
| `covered_leak` | 泄漏点/错误返回分支被执行，工具报告 definite/indirect leak | 否（TP） | 需要 reproducer/输入 |
| `covered_clean` | 泄漏点/错误返回分支被执行，工具未报告 leak | 是（在 oracle 正确的前提下） | 仍需确认没有 still reachable/possible 被排除 |
| `uncovered` | 泄漏点/错误返回分支未被任何输入执行 | **否** | 不能算 TN；应报“未定” |
| `build_failed` | 编译/链接失败 | 否 | 单独报告，不能写成 `y_pred=0` |
| `timeout` | 分析/执行超时 | 否 | 单独报告 |
| `suppressed` | 被 suppression 命中 | 否 | 记录 suppression id/owner/expiry |

实现上，用 Clang source-based coverage：

```bash
clang -fprofile-instr-generate -fcoverage-mapping -g -O0 case.c -o case
LLVM_PROFILE_FILE=case.profraw ./case < input
llvm-profdata merge -sparse case.profraw -o case.profdata
llvm-cov report ./case -instr-profile=case.profdata
llvm-cov export ./case -instr-profile=case.profdata -format=json > coverage.json
```

`llvm-cov report` 同时给出 function/line/region/branch 覆盖；`llvm-cov export` 的 JSON 可以按 case id 与工具报告 join。[R30]

对静态工具，路径覆盖不是“执行覆盖率”，而是“报告路径是否可行”：

- Clang SA 的路径是符号执行产生的；报告里带路径注释，但仍可能因路径预算/建模缺失而不完整。
- CodeQL 的 `MemoryMayNotBeFreed` 用 `StackVariableReachability` 在 CFG 上做可达性，不做 SMT 可行性判定；语法可达但条件不可满足的路径仍可能被报。[R6]
- Infer/Pulse 只在错误条件“与输入无关地成立”时报告；条件依赖的泄漏是 latent，不会在函数内报告，可能在调用点变成 manifest。[R14]
- MemHint 用 Z3 对每条警告做路径可行性过滤，报告在 CodeQL 上消除 86.5%、Infer 上消除 83.7% 的警告；这说明“静态报告≠可行路径”是普遍问题，不是某个工具的孤例。[R34]

---

## 2. 工具与文献更新（2024–2026）

### 2.1 CodeQL

**版本与覆盖**：CodeQL 2.27.4 发布于 2026-11-02，Default suite 共 498 个安全查询，覆盖 169 个 CWE。[R4] C/C++ 的 CWE-401 映射下可见四个查询：[R5]

| 查询 | 它问的问题 | 对条件失败/ still reachable 的含义 |
|---|---|---|
| `cpp/memory-may-not-be-freed` | 函数是否可能在释放前返回？ | 函数局部 may-leak；把赋给字段/全局视为 escape/barrier，因此“只被全局指针指向”的块通常不报。[R6] |
| `cpp/memory-never-freed` | 分配是否从未被释放？ | 全程序“never freed”；其 `allocMayBeFreed` 采用较乐观的 points-to/调用参数建模，不能当作 still reachable 的精确 oracle。[R7] |
| `cpp/memory-leak-on-failed-call-to-realloc` | `realloc` 失败时是否丢失原块？ | 专用查询，正好覆盖 `p = realloc(p, n)`/只在成功分支 free 的模式；是否命中取决于数据库与路径可行性。[R5] |
| `cpp/catch-missing-free` | 异常/catch 路径是否漏 free？ | C++ 异常路径的 may-leak；与 C 的 `goto cleanup` 模式不同，需要单独看。 |

**机制**：`MemoryMayNotBeFreed.ql` 的核心是 `StackVariableReachabilityWithReassignment`：从分配定义出发，沿 CFG 看是否到达 return，期间没有被 free、没有被 NULL 检查、没有赋给字段/全局。它不是 SMT 路径可行性分析，因此“语法可达但条件不可满足”的路径仍可能被报告。[R6] MemHint 的作者也明确指出 CodeQL 的默认内存泄漏查询“largely path-insensitive”，并额外写了按分支、错误处理路径、条件 guard 的扩展查询；这属于作者对工具的补强，不是 CodeQL 默认行为。[R34]

**2024–2026 的直接变化**：本次检索到的 CWE-401 相关变更是 CodeQL 2.18.2（2024-08-13）修复 `cpp/memory-may-not-be-freed` 在“类方法返回已分配字段”场景的误报；未把“没有看到”写成“没有发生”。本次抽查的 2.27.x C/C++ 更新主要是数据流模型、其他查询和提取器，不是 CWE-401 语义重写。[R4][R8]

**真实项目接入**：CodeQL 需要可构建的数据库；官方推荐 `codeql database create <db> --language=c-cpp --command='<build>'`，C/C++ 可用 `--build-mode=none` 作为无构建降级，但应单独报告，不要与正常构建结果混算。[R9] 对自定义分配器，CodeQL 提供 `allocationFunctionModel`/`deallocationFunctionModel` 扩展点；MemHint 用它注入 LLM 生成并 Z3 验证的摘要。[R34]

**优点**：声明式查询、跨过程数据流、可解释路径、容易做基线/抑制、SARIF 集成好。
**边界**：默认查询路径不敏感；自定义分配器需要模型；全局/字段 escape 会掩盖 still reachable；`never-freed` 与 `may-not-be-freed` 语义不同，不能混用。

### 2.2 Semgrep

**版本与能力**：Semgrep CE 最新发布为 1.185.0（2026-11-10）。[R12] 官方语言表把 C/C++ 列为 Generally Available，支持跨文件数据流和 150+ Pro rules；CE 只有单文件、跨函数常量传播和单函数 taint，Pro 才有跨文件、跨函数 taint。[R10][R11]

**它不是什么**：Semgrep 的强项是模式匹配、taint、规则可读性和无构建接入；它没有通用的堆对象生命周期/所有权模型，不能证明“这个 malloc 一定没有 free”。MemHint 用 Semgrep 1.156.0 + Pro engine 作为 baseline，在它确认的 54 个 bug 上只回收 2 个；作者明确说这是因为“purely syntactic analysis lacks data-flow and path-sensitive reasoning required for interprocedural leaks involving custom allocators”。[R34] 这个数字只说明“在该已知 bug 集上回收少”，不是 Semgrep 的总体召回。

**适用位置**：

- 作为**廉价预过滤**：抓 `p = realloc(p, ...)`、`malloc` 后直接 return、`goto` 跳过 cleanup 等语法模式；
- 作为**注解一致性检查**：确认自定义 alloc/free 包装器的调用点符合团队规则；
- 作为**CI 第一道门**：无构建、适合 diff-aware；
- 不适合作为 CWE-401 的唯一 oracle，也不适合证明“无泄漏”。

**条件失败/still reachable**：Semgrep 可以写规则匹配 `realloc` 赋值模式，但它不知道 `realloc` 是否会失败，也不知道全局指针在退出时是否可达；它只能提示“这里需要人工确认”。

### 2.3 Infer / Pulse

**版本与机制**：Infer 1.3.0 发布于 2026-05-12；Pulse 已成为默认的内存/值分析引擎，Biabduction 被移除；Clang/C++/ObjC 前端升级到 LLVM 21。[R13] Pulse 是过程间内存安全分析，官方描述是“Errors are only reported when all conditions on the erroneous path are true regardless of input”；如果错误只在某些参数值下成立，就是 **latent issue**，不会在函数内报告，除非调用点让条件变成 manifest。[R14]

**这对条件分配失败意味着什么**：`realloc` 失败依赖返回值/输入条件，按 Pulse 的 latent 语义，函数内的“失败才泄漏”很可能不被报告；它可能在某个调用点、当失败条件成为 manifest 时才报。Pulse 对未知函数采取“乐观”假设：会 scramble 参数可达状态，官方明确说这既可能造成漏报也可能造成误报。[R14] 因此，**Pulse 的沉默不是“无泄漏”的证明**，尤其当分配/释放包装器在第三方库或函数指针后面时。

**自定义分配器**：Infer 提供 `--pulse-model-alloc-pattern`、`--pulse-model-free-pattern`、`--pulse-model-realloc-pattern` 等选项，用正则把项目自定义函数建模为 alloc/free/realloc 包装器；MemHint 就是把验证过的摘要翻译成这些 pattern 注入 Pulse。[R13][R34]

**真实项目证据**：LeakGuard 在 129 个已知 bug 上，vanilla Infer 回收 25 个；MemHint 在 54 个已知 bug 上，vanilla Infer 回收 3 个，注入摘要后 Infer 贡献 31 个（与 CodeQL 有 21 个重叠）。这些数字都受“已知 bug 集”限制，不能当总体召回。[R33][R34]

**适用位置**：适合已经有 `compile_commands.json`、想用增量/差异分析、需要 Java/C++/ObjC 统一平台的团队；对 C 的纯源码、无构建项目不如 Semgrep 方便；对条件失败需要额外的失败注入或摘要。

### 2.4 SVF / Saber / SMOKE

**版本与机制**：SVF 3.3 发布于 2026-05-20（发布页在 2026-11-02 仍有更新）。[R18] SVF 以 LLVM IR 为输入，提供指针分析、内存 SSA、值流图、抽象执行，以及 source-sink 型缺陷检测；官方明确列出“memory leaks and incorrect file-open close errors”。[R17] 泄漏检测通常走 Saber 组件：把 allocation 当 source、free 当 sink，检查是否每条执行路径都能到达 sink；SVF-SVC 在 SV-COMP 2025 的 MemSafety 类别就是用 `-leak` 调用 Saber。[R19]

**路线特点**：SVF 的强项是**全程序稀疏值流 + 指针分析**，比纯语法工具更能处理别名和跨过程；弱点也在这里：指针分析是 over-approximate，路径敏感度/上下文敏感度取决于配置；对自定义分配器、函数指针、间接调用、循环复杂条件的建模仍有折中。SVF-SVC 的作者在 TACAS 2025 报告里也明确说，SVF 对复杂循环条件的 widening/narrowing 仍不完善，导致 reachability/memory safety 类别有错误结果。[R19]

**真实项目证据**：LeakGuard 在 Juliet CWE-401 上报告 SVF 520 TP / 750 FP（同一篇论文的实验设置下）；这是 LeakGuard 作者自报的 baseline，不是独立复现，不能当作 SVF 的通用性能。[R33] SMOKE（ICSE 2019）是更早的路径敏感、面向百万行代码的泄漏检测工作，适合作为“路径敏感 vs 可扩展性”的背景，不是 2024–2026 的新工具。

**适用位置**：适合研究/实验基线、需要值流图或自定义分析的场景；不适合作为没有 LLVM IR 构建经验的团队的第一道 CI 门；对 C++ 模板/异常/虚调用的精度取决于前端和指针分析配置。

### 2.5 Clang Static Analyzer

**版本与机制**：本项目使用 Clang 22.1.8；官方 22.1.0 发布说明中，Static Analyzer 的泄漏相关变化主要是崩溃修复（`unix.Malloc` 在罕见报告构造下断言、`[[assume]]` 括号崩溃等），没有改变泄漏 oracle。[R22] 分析器本身是 path-sensitive、inter-procedural、基于符号执行；默认边界是单个翻译单元（TU），跨 TU 需要 CTU 配置。[R20]

**泄漏 checker**：

- C：`unix.Malloc`，检查 memory leak、double free、use-after-free，跟踪 `malloc()/free()`；自定义分配/释放函数可用 ownership 属性标注。[R20]
- C++：`cplusplus.NewDeleteLeaks`，跟踪 `new/delete` 的泄漏；同样支持 ownership 属性。[R20]
- 自定义分配器：`ownership_returns(class, sizeArg)`、`ownership_takes(class, arg)`、`ownership_holds(class, arg)`；官方原文说，否则分析器“cannot know that the opaque `my_free()` is basically equivalent to a standard `free()` call”。[R24]
- Clang 20 让 `unix.Malloc` 对 ownership 属性的处理更一致，并修复了一批误报；这说明“注解质量”直接影响泄漏结果。[R21]

**条件失败**：在标准 Juliet 模式 `data = realloc(data, 130000); if (data != NULL) free(data);` 上，Clang 22.1.8 的 `unix.Malloc` 会报 “Potential leak … Reallocation failed”，路径注释明确指出失败分支。这是它的强项：路径敏感符号执行能看到 `realloc` 失败的那条路径（见第 5 节最小验证）。[R20]

**still reachable**：在最小例“全局指针 malloc 后不 free”上，`unix.Malloc` 没有报告；这与“赋给全局/字段视为 escape”的建模一致。不能把 Clang 的沉默当作“全局缓存无泄漏”。（这是第 5 节的实测，不是官方文档的通用承诺。）

**真实项目**：LeakGuard 在 129 个已知 bug 上，CSA 回收 44 个；MemHint 没有把 CSA 作为 baseline。LeakGuard 作者分析 CSA 漏报的主要原因是函数调用链深度限制，很多泄漏触发条件在深层调用链中。[R33]

**适用位置**：适合可编译、单 TU/可 CTU 的 C/C++，尤其是错误路径/资源释放路径；对宏/模板/自定义分配器需要注解；CTU 推荐用 CodeChecker 驱动（官方明确说 `scan-build-py` 的 CTU 不活跃、只适合非常简单的项目）。[R23]

### 2.6 LSan / Valgrind

**LSan**：

- 运行时几乎零开销，直到进程结束才做泄漏检查；可与 ASan 合用，也可 `-fsanitize=leak` 独立使用；独立模式“less well tested”。[R25]
- 根集包含 globals、stacks、registers、TLS；只报告不可达块；区分 direct/indirect leak。[R26]
- 支持 `__lsan_do_recoverable_leak_check()` 在任意检查点做可恢复检查；`__lsan_do_leak_check()` 检查后若发现泄漏则按 `exitcode` 退出；`__lsan_ignore_object()`、`__lsan_disable()/enable()`、`__lsan_register_root_region()` 用于抑制/自定义根。[R25]
- 常用 flag：`exitcode=23`、`max_leaks=0`、`report_objects=0`、`use_unaligned=0`；根集 flag 见上。[R25][R27]
- 平台：Android、Fuchsia、Linux、macOS、NetBSD；**不支持 Windows**。[R25]

**Valgrind**：

- 默认 `--leak-check=summary`；只有 `--leak-check=full` 才把泄漏计为 error；默认 `--show-leak-kinds=definite,possible`、`--errors-for-leak-kinds=definite,possible`。[R28]
- 要看 still reachable/indirect，必须 `--show-leak-kinds=all` 或 `indirect,reachable`；要让 reachable 影响 exit code，必须显式加入 `--errors-for-leak-kinds`。[R28]
- 支持 `VALGRIND_DO_LEAK_CHECK`、`VALGRIND_DO_NEW_LEAK_CHECK`、`VALGRIND_DO_ADDED_LEAK_CHECK`、`VALGRIND_DO_CHANGED_LEAK_CHECK` 在程序内部做检查点/增量泄漏检查；`VALGRIND_COUNT_LEAKS` 可取回四类字节数。[R28]
- 上游 3.28.0 已于 2026-10-23 发布；本项目固定 3.27.1。升级需要重跑基线，不能把两个版本的泄漏计数直接比较。[R29][R46]

**条件失败**：LSan/Valgrind 都只观测执行到的路径。默认运行 `realloc` 成功时，Juliet 的 108 个 `malloc_realloc` 坏例不会泄漏；只有故障注入让 `realloc` 返回 NULL，才会在退出点看到原块不可达。第 5 节用 `ASAN_OPTIONS=allocator_may_return_null=1` 强制 `realloc` 失败，LSan 报出 64 字节 direct leak；同一程序在“保存旧指针、失败时 free”的版本上不报。[R25][R28]

**still reachable**：LSan 默认不会报；Valgrind 默认不单列；两者都不是“看不到就等于没有”。对长生命周期服务，应该用检查点泄漏检查 + 堆增长分析，而不是只等进程退出。

### 2.7 新学习方法（2024–2026）

先给结论：**就本次检索范围而言，尚未发现一篇同行评审论文证明“LLM 单独做 C/C++ 内存泄漏检测”在真实项目上优于 LeakGuard/MemHint 这类专用工具。** 现有工作大致分五类：

| 类别 | 代表工作 | 年份/出处 | 在 CWE-401 中的角色 | 关键证据/限制 |
|---|---|---|---|---|
| LLM 生成分配器/释放器注解 | LAMeD | 2025 arXiv 预印本 | 给 CodeQL/Cooddy 等提供函数级 annotation | cJSON 上 precision 0.933、recall 约 0.60；真实项目上“几乎都提升”，但告警量显著上升；预印本。[R35] |
| LLM 摘要 + 符号验证 + 注入分析器 | MemHint | 2026 arXiv v6 预印本 | 识别自定义 MM 函数、Z3 验证可达性、注入 CodeQL/Infer | 8 项目/3.6M LOC，54 个 bug，$1.76/bug；Z3 过滤 86.5% CodeQL、83.7% Infer 警告；预印本，依赖 Gemini 3，Z3 编码不含循环。[R34] |
| LLM 推断调用者/被调用者内存管理意图 | IMMI | USENIX Security 2024 | 内核错误处理路径的所有权不一致 | Linux 内核 80 个新 bug（57 泄漏 + 23 破坏），35% FPR；LLM 用于解释隐式内核机制。[R36] |
| LLM 做数据流/告警分流 | LLMDFA、LLM4SA、LLMSAN | NeurIPS 2024 / TOSEM 2024 / EMNLP Findings 2024 | 把数据流分解为 source/sink、函数摘要、路径可行性；或对静态告警做解释/验证 | LLMDFA 是编译无关的数据流框架；LLM4SA 是静态告警分流；LLMSAN 在 Java 上做 data-flow path sanitization。都不是 CWE-401 专用。[R37][R38][R45] |
| LLM 合成 checker / 修复 | KNighter、TLR | SOSP 2025 / FSE 2026 | 从历史补丁合成 Clang SA checker；或按 typestate 上下文修复内存错误 | KNighter：Linux 内核 92 个新 bug、77 确认、57 修复、30 CVE；TLR：14 项目/1.57M LOC，修复 37/49，需要 PoC + 测试 + fuzzing。都不是“检测器”。[R40][R41] |

**MemHint 的关键数字（v6，作者自报）**：

- 8 个真实 C/C++ 项目、>3.6M LOC；54 个 unique leak，全部 confirmed/fixed；约 $1.76/bug。
- vanilla CodeQL 19、Infer 3、Semgrep 1.156.0 Pro 2、LeakGuard 20（在 MemHint 确认的 54 个 bug 上回收）。
- 1,532 个函数的标注样本：LLM 单独 92.0% MM precision / 100% recall；Z3 验证后 100% precision / 100% recall（“Validated MM”口径）。
- Z3 路径可行性过滤消除 86.5%（CodeQL）/83.7%（Infer）的警告；最终人工确认 44 个 CodeQL true bug、31 个 Infer true bug，precision 50.6%/46.3%。
- 静态分析阶段约 32 分钟/项目（CodeQL）、37 分钟/项目（Infer），比 LeakGuard 的 182 分钟/项目快 4.9–5.7×；摘要生成是一次性成本（总计 $87.01，约 $10.9/项目、2.1 小时/项目）。[R34]

**怎么读这些数字**：

- 它们不是“LLM 检测器”的端到端指标：MemHint 的检测仍由 CodeQL/Infer 完成，LLM 只负责摘要和最终告警确认；Z3 负责可行性。
- “54 个 bug 全部 confirmed/fixed”是作者与维护者交互的结果，不是独立第三方复现；预印本，未经同行评审。
- “Semgrep 2 / LeakGuard 20”是“能否找回 MemHint 已知 bug”的计数，不是这些工具的总体召回；MemHint 作者也明确说没有穷尽 baseline 的额外告警。
- MemHint 的实验版本是 CodeQL 2.25.1、Infer 1.2.0、Z3 4.15.4，不是本文列的 CodeQL 2.27.4/Infer 1.3.0；跨版本不能直接比较。[R34]
- Z3 编码是**无环 CFG**，不建模循环；循环携带的泄漏不在当前范围。作者在限制中明确承认这一点。[R34]

**LAMeD 的关键数字**：

- 在人工标注的 cJSON 上，Codestral 的 annotation precision 0.933、recall 约 0.60；context/post-filter 对不同模型效果不一致。
- 在真实 leak 数据集上，LLM annotation 让 CodeQL 和 Cooddy 在“几乎所有的项目”上找到更多已知 bug，但**告警数量显著增加**；作者明确说“for some projects the number of analyzer warnings significantly grows”。[R35]
- 这说明 LLM annotation 的收益是“提高已知 bug 的召回”，代价是“更多告警需要 triage”；不能直接写成“精度提升”。

**其他工作的一句话定位**：

- **IMMI**（USENIX Sec 2024）：把“调用者/被调用者内存管理意图不一致”作为 bug 信号，专门覆盖错误处理路径；35% FPR 说明它适合作为候选生成器，不是最终 oracle。[R36]
- **LLMDFA**（NeurIPS 2024）：把数据流分析拆成 source/sink 识别、函数摘要、路径可行性检查；是“LLM 做数据流”的方法论基础，不是 CWE-401 专用。[R37]
- **LLM4SA**（TOSEM 2024）：用 LLM 检查静态告警，降低误报；适合把 SAST 输出变短，不解决“SAST 没报”的漏报。[R38]
- **InferROI**（ICSE 2025）：LLM 推断资源获取/释放/可达性意图，面向 Java/Android 资源泄漏；在 DroidLeaks/JLeaks 上 detection 59.3%/62.5%、false alarm 18.6%/19.5%。与 C 堆泄漏相邻但不同。[R39]
- **KNighter**（SOSP 2025）：LLM 从历史补丁合成 Clang SA checker；Linux 内核 92 个新 bug、77 确认、57 修复、30 CVE。它不是泄漏专用，但提供“把 LLM 的归纳能力沉淀为可复用 checker”的路线。[R40]
- **TLR**（FSE 2026）：typestate 引导的上下文检索 + LLM 修复；14 个项目/1.57M LOC，修复 37/49 个内存错误，需要 PoC、原生测试和 AFL++ 复验。它是修复，不是检测。[R41]

### 2.8 横向对比

| 工具/版本 | 分析基础 | CWE-401 输出 | 条件分配失败 | still reachable | 路径覆盖 | 真实项目证据 |
|---|---|---|---|---|---|---|
| CodeQL 2.27.4 | 声明式数据流/QL | may-not-be-freed、never-freed、realloc、catch | 有专用 realloc 查询；默认查询路径不敏感 | 赋给字段/全局视为 escape，通常不报全局缓存 | 无执行覆盖；路径可行性需 Z3/手工 | MemHint 54 中回收 19；LeakGuard 的 129 个真实 bug 未评 CodeQL |
| Semgrep 1.185.0 | 模式/taint；Pro 跨文件 | 无堆生命周期证明；可写模式规则 | 只能匹配语法模式，不知道失败 | 不知道 | 无 | MemHint 54 中回收 2（Pro） |
| Infer 1.3.0 / Pulse | 分离逻辑/双向归纳 | MEMORY_LEAK_C/CPP；latent issue | 条件依赖时可能 latent；可用 realloc pattern 建模 | 取决于根/escape 建模 | 过程间；latent 需调用点 manifest | LeakGuard 129 中回收 25；MemHint 54 中回收 3（vanilla）/31（摘要注入） |
| SVF 3.3 / Saber | 稀疏值流/源汇 | `-leak`；source-sink 可达性 | 取决于指针分析/路径条件建模 | 可能把全局根视为 reachable | 值流可达，不是执行覆盖 | LeakGuard Juliet：520 TP/750 FP（作者自报 baseline） |
| Clang SA 22.1.8 | 路径敏感符号执行 | unix.Malloc / NewDeleteLeaks | 标准 realloc 失败模式可报；依赖路径预算 | 全局指针 escape 通常不报 | 符号路径；CTU 可跨 TU | LeakGuard 129 中回收 44 |
| LSan (LLVM 22) | 退出时根集扫描 | direct/indirect leak | 默认不触发失败；需故障注入 | 默认不报（globals 是根） | 仅执行路径；无覆盖 instrumentation | 本项目全量：1467 TP/0 FP/1658 TN/190 FN |
| Valgrind 3.27.1/3.28.0 | 动态二进制插桩 | definite/indirect/possible/still reachable | 默认不触发失败；需故障注入 | 默认不单列；`--show-leak-kinds=all` 可见 | 仅执行路径；可检查点/增量 | 本项目全量：1459 TP/0 FP/1658 TN/188 FN |

**表注**：表中的“回收数”都是“在某个已知 bug 集上能否找回”，不是总体 precision/recall；不同研究用的项目、版本、构建、超时不同，不能横向排名。[R33][R34]

---

## 3. 真实项目迁移：可执行路线

### 3.1 迁移前：版本、构建、基线

1. **固定工具链版本并记录来源**：CodeQL 2.27.4、Semgrep 1.185.0、Infer 1.3.0、SVF 3.3、Clang 22.1.8、Valgrind 3.27.1（或升级到 3.28.0 后重跑基线）。版本、SHA/安装路径、query pack 版本都要进 manifest。
2. **固定代码版本与构建**：记录 commit、编译命令、`compile_commands.json`、依赖版本、编译失败的 TU。没有构建就没有 CodeQL/Infer/Clang CTU 的可比结果。
3. **先跑基线，不先看新告警**：在迁移前版本上跑同一套工具，保存 SARIF/JSON，建立“已存在告警”基线；CI 只 gate new-only。
4. **定义排除项**：第三方库、生成代码、测试代码、平台特定代码；排除项要写原因和 owner，不能静默 `paths-ignore`。

### 3.2 工具链接入命令（WSL）

以下命令是模板；路径、构建命令、query suite 按项目替换。所有命令都在 WSL 中运行。

```bash
# 0) 版本记录（写入 manifest，不写 key）
clang --version | head -1
valgrind --version
codeql version
semgrep --version
infer --version | head -2

# 1) 生成编译数据库（CMake 项目）
cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
# 非 CMake：bear -- make -j"$(nproc)"

# 2) CodeQL：C/C++ 数据库 + 安全查询
codeql database create /tmp/qdb --language=c-cpp --command='make -j1'
codeql database analyze /tmp/qdb \
  --format=sarif-latest --output=/tmp/codeql.sarif \
  codeql/cpp-queries:codeql-suites/cpp-security-extended.qls

# 3) Infer：Pulse + 自定义分配器模型
infer capture --compilation-database compile_commands.json
infer analyze --pulse-only \
  --pulse-model-alloc-pattern '^(my_alloc|my_new)$' \
  --pulse-model-free-pattern '^(my_free|my_delete)$' \
  --pulse-model-realloc-pattern '^(my_realloc)$'

# 4) Clang SA：推荐 CodeChecker 驱动 CTU
CodeChecker analyze --ctu compile_commands.json -o /tmp/cc-reports
# 或单 TU：scan-build --use-analyzer=clang make

# 5) Semgrep：模式/taint 预过滤
semgrep scan --pro --config p/default --sarif --output /tmp/semgrep.sarif

# 6) SVF：先转 LLVM bitcode，再跑 Saber
clang -emit-llvm -c -g -O0 case.c -o case.bc
saber -leak case.bc
```

注意：

- CodeQL 的 `--build-mode=none` 可用于构建失败时的降级，但应单独标注，不能与正常构建结果混算。[R9]
- CodeChecker 是 Clang CTU 的推荐驱动；官方明确说 `scan-build-py` 的 CTU 不活跃、只适合非常简单的项目。[R23]
- Infer 的 `--pulse-model-*` 是正则匹配；模型错了会同时制造 FP/FN，必须用标注样本验证。
- Semgrep 的 `--pro` 需要 Pro engine；CE 只有单函数 taint，不能把 CE 的结果与 Pro 混在一起。[R11]

### 3.3 自定义分配器建模

真实项目的泄漏大多经过项目自定义的 alloc/free 包装器；LeakGuard 的 129 个 bug、MemHint 的 54 个 bug 都说明了这一点。[R33][R34] 四条建模路线：

**Clang SA（源码注解）**：

```c
void *my_alloc(size_t n) __attribute__((ownership_returns(malloc, 1)));
void my_free(void *p) __attribute__((ownership_takes(malloc, 1)));
void my_hold(void *p) __attribute__((ownership_holds(malloc, 1)));
```

`ownership_returns` 的第一个参数是分配类别（可以是 `malloc`、`new` 或自定义标识），第二个参数是 1-based 的 size 参数下标；`ownership_takes` 表示“调用即释放”；`ownership_holds` 表示“接管所有权、未来某时释放”。[R24]

**CodeQL（扩展 pack）**：

```yaml
extensions:
  - addsTo:
      pack: codeql/cpp-all
      extensible: allocationFunctionModel
    data:
      - ["", "", false, "my_alloc", "0", "", "", true]
  - addsTo:
      pack: codeql/cpp-all
      extensible: deallocationFunctionModel
    data:
      - ["", "", false, "my_free", "0"]
```

字段顺序以当前 CodeQL `allocationFunctionModel`/`deallocationFunctionModel` 定义为准；上面的形状来自 MemHint 附录的示例，使用前用 `codeql resolve extensions`/`codeql database analyze` 校验，不要直接复制到生产。[R34]

**Infer（正则模型）**：

```bash
infer analyze --pulse-only \
  --pulse-model-alloc-pattern '^(my_alloc|my_new)$' \
  --pulse-model-free-pattern '^(my_free|my_delete)$' \
  --pulse-model-realloc-pattern '^(my_realloc)$'
```

**Semgrep（规则）**：

```yaml
rules:
  - id: realloc-result-overwrites-pointer
    languages: [c, cpp]
    severity: WARNING
    message: "realloc result overwrites the only pointer; on failure the original block is lost"
    patterns:
      - pattern: $P = realloc($P, $S)
```

这条规则只抓语法反模式，不证明失败路径可达；它适合作为 CodeQL/Clang 的补充，不适合单独 gate。

**LLM 生成注解**：LAMeD/MemHint 的路线是“LLM 生成 + 符号/人工验证”。落地时至少要有：

- 一个 100–300 函数的标注样本（allocator/deallocator/neither），报告 precision/recall；
- 对 LLM 生成的每条摘要做 CFG 可达性验证（Z3 或等价 SMT）；
- 对新增告警做抽样人工确认，记录“新增 TP/FP”；
- 不把未验证的注解直接合入 CI 基线。

### 3.4 条件分配失败：故障注入

动态工具默认不会制造分配失败；要覆盖 `realloc` 失败路径，必须注入。可选方案：

| 方案 | 做法 | 能回答什么 | 注意 |
|---|---|---|---|
| **FAINT** | `faint ./program`；它用 `LD_PRELOAD` 替换 malloc/calloc/realloc/new，先 profile 再逐个注入失败 | 程序在每次分配失败时是否崩溃；适合先找 OOM 处理缺陷 | 主要报告 crash，不直接报告 leak；若要同时接 LSan/Valgrind，需处理多个 `LD_PRELOAD` 的顺序/冲突 |
| **failmalloc** | `LD_PRELOAD=libfailmalloc.so FAILMALLOC_INTERVAL=1 ./program` | 每次/每隔 N 次分配失败；快速看错误路径 | glibc only；概率/间隔模式下失败点不唯一，难复现 |
| **libfiu** | `fiu-run -x -c 'enable name=libc/mm/malloc' ./program` | 精确控制 POSIX malloc 失败 | 需要安装/配置；与 ASan 的 LD_PRELOAD 可能冲突 |
| **自定义 shim** | `dlsym(RTLD_NEXT, "malloc")`，计数到第 N 次返回 NULL；realloc 失败时保持原块有效 | 精确到调用序号、可复现；可与 LSan 合用 | 要处理 `dlsym` 自身递归、线程安全、`calloc`/`realloc` 语义 |

最小自定义 shim 的核心逻辑（示意，不是完整实现）：

```c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdatomic.h>

static void *(*real_malloc)(size_t);
static _Atomic long calls;
static long fail_at = -1;

void *malloc(size_t n) {
    if (!real_malloc) real_malloc = dlsym(RTLD_NEXT, "malloc");
    long c = atomic_fetch_add(&calls, 1);
    if (fail_at >= 0 && c == fail_at) return NULL;
    return real_malloc(n);
}
```

对 `realloc`，失败时必须返回 NULL 且**不释放** `ptr`；不要在 shim 里提前 free，否则会改变被测语义。

**推荐流程**：

1. 先跑默认执行（不注入），记录 `covered_clean`/`uncovered`。
2. 对每个 positive case，按分配序号注入一次失败；每个注入点单独跑一个进程，避免状态污染。
3. 在 LSan/Valgrind 下跑注入版本；记录 `definite/indirect`、still reachable、崩溃、超时。
4. 把“默认执行 clean、注入后 leak”的 case 标为 `conditional_leak`，不要改写原标签；在主表里单列。
5. 对 `realloc` 失败，优先注入 `realloc` 调用本身，而不是它前面的 `malloc`；否则可能只测到“初始分配失败”。

### 3.5 路径覆盖：把“没报”拆开

**动态侧**：

- 用 `-fprofile-instr-generate -fcoverage-mapping` 编译，跑与泄漏检测相同的输入；用 `llvm-cov export` 取 branch/region 数据。[R30]
- 对每个 case，记录泄漏点所在函数的 branch 覆盖；如果泄漏点在 `if (ret != NULL)` 的 false 分支，必须确认该分支被执行。
- 对 fuzzing，用 libFuzzer 的 `-detect_leaks=1`（默认开）或 AFL++ 的 `AFL_USE_LSAN=1` + `__AFL_LEAK_CHECK()`；仍然要记录覆盖，而不是只报 crash/leak。[R31][R32]

**静态侧**：

- 对 Clang SA，保留 plist/SARIF 的路径注释；如果路径包含不可行条件，标 `infeasible`。
- 对 CodeQL，`MemoryMayNotBeFreed` 的报告路径是 CFG 可达，不是 SMT 可行；需要 Z3/手工确认。[R6]
- 对 Infer/Pulse，区分 `manifest` 与 `latent`；latent 不应算作“已检测”，也不应算作“无泄漏”。[R14]
- 对 LLM，记录是否给出证据（工具 trace/代码行）、是否 abstain；不要用自然语言解释代替路径。

**报告口径**：

```text
raw_recall        = TP / (TP + FN)
covered_recall    = TP / (TP + FN_covered)
coverage_rate     = (TP + TN_covered) / all_labeled_positive_and_negative
```

其中 `FN_uncovered` 单列，不进入 `covered_recall`；`FN_covered` 才是“工具在已执行路径上漏报”。这样既不会把“没走到”洗成“工具差”，也不会把“没走到”洗成“工具好”。

### 3.6 结果归一化与去重

1. **只把 CWE-401 计入主表**：`PULSE_RESOURCE_LEAK`、`cpp/descriptor-never-freed` 等资源泄漏归 CWE-772，不混入内存泄漏主指标。
2. **按报告类型分开**：may-leak、never-freed、realloc-failure、catch-missing-free、latent、definite、indirect、possible、still-reachable、suppressed。
3. **去重键**：`(allocation site, leak kind, normalized stack hash)`；同一分配点在不同路径报多次，合并为一条，但保留路径数。
4. **失败分类**：`build_failed`、`timeout`、`tool_error`、`unavailable` 不进混淆矩阵；单独报告覆盖率。
5. **基线**：按 commit + tool version + config hash 建基线；只 gate new/changed。
6. **抑制**：每条 suppression 有 owner、reason、expiry；到期自动提醒，不允许永久 blanket suppression。

### 3.7 CI 门禁与成本

- **分层**：Semgrep/模式规则 → Clang SA → CodeQL/Infer → SVF/CTU/LLM（按需）。各层的实际耗时以本机实测为准，不引用厂商的绝对时间。
- **diff-aware**：只分析改动文件/调用者；Infer 的 `--changed-files-index`/`--incremental-analysis`、CodeQL 的增量数据库、Clang 的增量分析都可以用。[R16]
- **超时**：每个工具设置 per-project/per-file timeout；超时算 `timeout`，不算 clean。
- **成本**：记录 wall-clock、峰值内存、告警数、人工 triage 分钟数；不要引用厂商的“快 N 倍”作为本项目预算，必须实测。
- **稳定性**：同一 commit 跑两次，记录告警集合的 Jaccard/差异；不稳定告警不能直接 gate。

### 3.8 验收指标

| 指标 | 定义 | 用途 |
|---|---|---|
| Build success rate | 成功建库/编译的 TU/项目比例 | 先排除“工具没跑起来” |
| Positive coverage | 正例中泄漏点/错误分支被执行的比率 | 解释动态召回 |
| Covered recall | TP / (TP + FN_covered) | 动态工具在已执行路径上的真实召回 |
| Raw recall | TP / (TP + FN) | 与文献/旧结果对齐，但必须带 coverage |
| Precision / FPR | 需要人工确认的 TP/FP | 评估 triage 成本 |
| Still-reachable rate | still reachable 字节/块占比 | 区分 CWE-401 与进程生命周期缓存 |
| Conditional-leak rate | 默认 clean、故障注入后 leak 的比例 | 评估 OOM 路径风险 |
| Triage time per TP | 人工分钟/真阳 | 评估是否值得接入 |
| Warning stability | 两次运行的告警差异 | 评估 CI gate 可行性 |

---

## 4. 对本项目的直接建议

### 4.1 P0：先修动态标签与覆盖

1. **把 `clean` 拆成 `covered_clean` / `uncovered`。**
   现有全量动态 run 的 190 个 FN 中，108 个是 `malloc_realloc` 失败路径未触发，68 个是全局指针 still reachable，14 个是随机分支未覆盖；该 run 没有覆盖率 instrumentation。[R47] 因此，`clean` 不能直接当 TN。建议在 `metrics.md`/leaderboard 旁边增加 `coverage_status` 字段，至少区分 `covered_clean`、`uncovered`、`build_failed`、`timeout`。

2. **给 108 个 `malloc_realloc` 加确定性失败注入。**
   对每个 case，注入 `realloc` 失败（而不是前面的 `malloc`），在 LSan/Valgrind 下重跑；预期一部分会从 `clean` 变成 `definite leak`。这批结果作为 `fault_injection` track 单列，不改写原 Juliet 标签。建议先做 18 个（6 个 feature × 3 个变体）做可行性，再扩到 108 个。

3. **把 68 个全局指针用例（其中 45 个为流变体子集）单列 still reachable。**
   在 Juliet-label view 里它们仍是 FN；在 CERT-exception view 里它们可以排除。两个视图都给，不要静默删除。可以用 `LSAN_OPTIONS=use_globals=0` 做诊断，证明这些块只被全局根指向；该 flag 只用于诊断，不作为主 oracle。[R27]

4. **给动态 run 加 branch coverage。**
   至少对 test 140 做一次 `-fprofile-instr-generate -fcoverage-mapping` + `llvm-cov export`，把正例的泄漏点覆盖率和 `covered_recall` 算出来。没有这个数字，`ASan+LSan F1=0.914` 无法解释。[R30]

### 4.2 P1：补静态对照与 realloc 专项

5. **在 Juliet test 140 上跑 CodeQL 2.27.4 的四个 CWE-401 查询。**
   特别是 `cpp/memory-leak-on-failed-call-to-realloc`：它是与 108 个动态 FN 最直接对应的静态查询。把 CodeQL 的 may-leak/never-freed/realloc 分开统计，与 Clang SA 的 `unix.Malloc` 逐 case 对比；预期能看到“静态报 may-leak、动态默认 clean”的互补矩阵。[R5][R6]

6. **把 Clang SA 的 `unix.Malloc` 报告按 leak/double-free/UAF 拆开。**
   现在只知道 Clang 的总体 F1；`unix.Malloc` 同时报三类问题，若把 double-free/UAF 计入 CWE-401 会污染指标。建议从 plist/SARIF 的 checker 名称/消息过滤，只保留 leak 类。

7. **对 68 个全局用例做 Valgrind `--show-leak-kinds=all` 抽样。**
   选 10–20 个，确认它们是 still reachable 而不是 definite/indirect；把 `--errors-for-leak-kinds=definite,indirect` 与默认 `definite,possible` 的差异记录下来。Valgrind 3.27.1 已在本项目使用；如果升级 3.28.0，需重跑基线。[R28][R29]

8. **给真实项目 pilot 建自定义分配器模型。**
   Juliet 主要用标准 malloc/free，建模收益有限；真实项目（如 cJSON、libtiff、libssh2）更适合验证 Clang ownership 注解、CodeQL extension、Infer `--pulse-model-*`。先做一个项目、一个模型、一个标注样本，报告 annotation precision/recall 和告警变化。

### 4.3 P2：LLM 与真实项目迁移实验

9. **小规模复现 MemHint/LAMeD，不要直接采信论文数字。**
   选 1–2 个真实项目（建议 cJSON + 一个中等规模项目），用现有 runner 的凭证注入方式（不把 key 写入文件/命令），跑：
   - LAMeD 式 annotation 生成 + 人工标注样本；
   - MemHint 式摘要 + Z3/可达性验证（如果时间允许）；
   - 记录新增 TP/FP、annotation precision/recall、每项目耗时、token 成本。
   停止规则：如果新增告警的 TP 率低于 20%，或人工 triage 时间超过收益，停止扩展。

10. **把 LeakGuard 作为“真实项目上界”参考，而不是 CI 工具。**
    它在 18 个项目/70 MLoC 上报告 129 个 bug，单项目最长 14 小时；适合做离线审计/研究对照，不适合每次 CI。[R33] 若要复现，先在一个项目上验证构建和 14 小时预算，再决定是否扩展。

11. **LLM 修复只在检测之后做。**
    TLR 的 37/49 需要 PoC、原生测试和 AFL++ 复验；没有可复现输入和测试，不能把“生成了补丁”当成“修复成功”。[R41] 本项目现有 `juliet_repair` 的 70/70 compile/LSan/behavior 是 harness 结果，不是真实项目修复率；两者不能混写。

### 4.4 建议的实验矩阵

| 实验 | 假设 | 数据 | 主指标 | 停止规则 |
|---|---|---|---|---|
| E1 realloc 失败注入 | 108 个动态 FN 中有一部分在失败执行下会变成 definite leak | Juliet `malloc_realloc` 108 个 | 新增 detected / 108；崩溃/超时 | 先做 18 个；若失败注入无法稳定复现，停止扩展 |
| E2 覆盖率标注 | `clean` 中有相当比例是 `uncovered` | 动态 test 140 + 全量抽样 | `covered_clean` 比例、`covered_recall` | 若覆盖率 instrumentation 无法在 8 workers 下稳定跑，改为抽样 |
| E3 CodeQL realloc 查询 | CodeQL 能补上 Clang/动态的部分缺口 | test 140 | 逐 case 的 may-leak/never/realloc 矩阵 | 若 CodeQL 建库失败率高，先修构建 |
| E4 still reachable 双视图 | 68 个全局用例在 CERT 视图下应排除 | 68 个全局用例 | Juliet view vs CERT view 的差异 | 若 `use_globals=0` 造成大量误报，只做诊断 |
| E5 LLM annotation pilot | LLM 能提高已知 bug 回收，但会增加告警 | 1–2 个真实项目 | annotation P/R、新增 TP/FP、triage 分钟 | TP 率 <20% 或 triage 成本过高则停止 |

---

## 5. 最小语义验证（WSL，2026-11-13）

> 目的：确认 `still reachable` 与 `realloc` 失败路径在 LSan/Clang SA 下的实际行为。不是 benchmark，不产生性能数字，不写入项目结果目录。

**环境**：WSL Ubuntu，Clang 22.1.8，ASan/LSan（LLVM 22）。本次最小验证未重跑 Valgrind；Valgrind 语义以官方手册和项目已有 3.27.1 run 为准。

**程序**：

```c
/* still.c：全局指针，退出时仍可达 */
#include <stdlib.h>
static void *g;
int main(void) { g = malloc(64); return 0; }

/* fail.c：realloc 失败后原块丢失 */
#include <stdlib.h>
#include <stdint.h>
int main(void) {
  char *p = malloc(64);
  if (!p) return 2;
  char *q = realloc(p, (size_t)-1 / 2);
  p = q;              /* 失败：原块丢失 */
  free(p);
  return 0;
}

/* handled.c：失败时释放原块 */
#include <stdlib.h>
#include <stdint.h>
int main(void) {
  char *p = malloc(64);
  if (!p) return 2;
  char *q = realloc(p, (size_t)-1 / 2);
  if (!q) { free(p); return 0; }
  free(q);
  return 0;
}
```

**命令**：

```bash
clang -fsanitize=address -g -O0 still.c -o still
clang -fsanitize=address -g -O0 fail.c -o fail
clang -fsanitize=address -g -O0 handled.c -o handled

ASAN_OPTIONS=detect_leaks=1 ./still
ASAN_OPTIONS=detect_leaks=1:allocator_may_return_null=1 ./fail
ASAN_OPTIONS=detect_leaks=1:allocator_may_return_null=1 ./handled
ASAN_OPTIONS=detect_leaks=1 LSAN_OPTIONS=use_globals=0 ./still
```

**结果**：

| 程序 | LSan 默认 | `use_globals=0` | Clang SA `unix.Malloc` |
|---|---|---|---|
| `still.c`（全局指针） | 无报告，exit 0 | 报 direct leak 64 B | 无报告 |
| `fail.c`（`p = realloc(p, huge)`，强制失败） | 报 direct leak 64 B | — | 无报告（该极端 size 可能被剪枝） |
| `handled.c`（失败时 free 原块） | 无报告，exit 0 | — | 无报告 |
| `juliet_like.c`（标准 Juliet 模式，正常 realloc 成功） | 无报告，exit 0 | — | 报 “Potential leak … Reallocation failed” |

`juliet_like.c` 的内容与 Juliet 坏例同构：

```c
char *data = (char *)malloc(100);
if (data == NULL) return -1;
strcpy(data, "A String");
data = (char *)realloc(data, 130000);
if (data != NULL) {
    strcpy(data, "New String");
    free(data);
}
return 0;
```

**解释**：

- `still.c` 证明 LSan 默认把全局变量当根，因而不报 still reachable；`use_globals=0` 可以把这类块变成报告，但这是诊断，不是默认语义。[R26][R27]
- `fail.c` 证明只要失败路径真的执行，LSan 能报 definite leak；`handled.c` 证明正确保存旧指针后不报。
- `juliet_like.c` 证明 Clang SA 能在标准 Juliet 模式上走失败分支并报 may-leak；但默认 LSan 因 `realloc` 成功而不报。这正是“静态 may-leak / 动态 clean”的互补矩阵，也是本项目 108 个动态 FN 的机制。[R20][R25]

**限制**：只测了 LSan，没有测 Valgrind；只用了 4 个最小程序，不代表真实项目；`fail.c` 用极大 size 强制失败，不是 Juliet 的 130000；没有跑 CodeQL/Infer/Semgrep。不要把本表当性能或召回数据。

---

## 6. 证据台账与未核实事项

### 6.1 已核验的关键事实

| 事实 | 来源 | 级别 | 核验方式 |
|---|---|---|---|
| CWE-401 定义、ChildOf 772/404、Modes of Introduction 包含错误条件 | MITRE CWE-401（2026-10-28 更新） | A | 官方页面 |
| MEM31-C-EX1：生命周期覆盖程序终止的指针可不释放 | CERT MEM31-C | A | 官方页面 |
| `realloc` 失败保留原块；`realloc(p,0)` C17 implementation-defined、C23 UB | cppreference | A | 标准条目 |
| CodeQL 2.27.4：498 查询/169 CWE | CodeQL changelog | C | 官方发布说明 |
| CodeQL CWE-401 四个查询 | CodeQL C++ CWE coverage | C | 官方页面 |
| CodeQL `MemoryMayNotBeFreed` 的 escape/reachability 语义 | CodeQL 源码 | C | 源码 |
| CodeQL 2.18.2 修复 may-not-be-freed 误报 | CodeQL changelog | C | 官方发布说明 |
| Semgrep 1.185.0（2026-11-10） | GitHub release | C | 发布页 |
| Semgrep C/C++ GA、跨文件数据流、150+ Pro rules | Semgrep 官方语言表 | C | 官方文档 |
| Infer 1.3.0（2026-05-12）、Pulse 默认、LLVM 21、Biabduction 移除 | Infer release/changelog | C | 官方发布页 |
| Pulse latent/unknown function 语义 | Infer Pulse 文档 | C | 官方文档 |
| `--pulse-model-alloc/free/realloc-pattern` | Infer CLI 文档/MemHint 附录 | C | 官方文档 + 论文示例 |
| SVF 3.3（2026-05-20） | GitHub release | C | 发布页 |
| SVF source-sink 泄漏检测；Saber `-leak` | SVF 官网/SVF-SVC TACAS 2025 | A/C | 官方页 + 论文 |
| Clang SA 路径敏感、TU 边界、CTU 需要额外配置 | Clang 官方文档 | C | 官方文档 |
| Clang 20 `unix.Malloc` ownership 一致性改进 | Clang 20 release notes | C | 官方发布说明 |
| LSan 根集包含 globals/stacks/registers/TLS；只报不可达 | LSan 设计文档 | C | 官方文档 |
| LSan flags 默认值 | compiler-rt `lsan_flags.inc` | C | 源码 |
| Valgrind 四类泄漏、默认 `summary`/`definite,possible` | Valgrind 手册 | C | 官方手册 |
| Valgrind 检查点/增量泄漏检查 client request | Valgrind 手册 | C | 官方手册 |
| Valgrind 3.28.0（2026-10-23） | Valgrind NEWS | C | 官方 NEWS |
| source-based coverage 命令/字段 | LLVM 文档 | C | 官方文档 |
| libFuzzer `-detect_leaks=1`；AFL++ `AFL_USE_LSAN`/`__AFL_LEAK_CHECK` | LLVM/AFL++ 文档 | C | 官方文档 |
| LeakGuard：18 项目/70 MLoC/129 bug/Juliet 1336 TP/0 FP/28 FN/CSA 44、Infer 25、Cppcheck 1 | arXiv 2504.04422 | B | 论文 |
| MemHint：8 项目/3.6M LOC/54 bug/$1.76/CodeQL 19、Infer 3、Semgrep 2、LeakGuard 20；Z3 86.5%/83.7% | arXiv 2603.27224 v6 | B | 论文 |
| LAMeD：cJSON annotation precision 0.933、recall ~0.60；告警量上升 | arXiv 2505.02376 | B | 论文 |
| IMMI：Linux 内核 80 新 bug（57 泄漏 + 23 破坏）、35% FPR | USENIX Security 2024 | A | 官方论文页 |
| LLMDFA：NeurIPS 2024 | NeurIPS 2024 | A | 会议论文 |
| LLM4SA：TOSEM 2024，DOI 10.1145/3653718 | ACM | A | DOI 页 |
| InferROI：ICSE 2025，Java/Android 资源泄漏 | ICSE 2025/arXiv | A/B | 会议页 + 论文 |
| KNighter：SOSP 2025，Linux 内核 92 新 bug/77 确认/57 修复/30 CVE | SOSP 2025/arXiv | A | 会议页 + 论文 |
| TLR：FSE 2026，14 项目/1.57M LOC，修复 37/49 | FSE 2026 PDF | A | 会议论文 |
| 本项目动态 run：1467 TP/0 FP/1658 TN/190 FN；108/68/14 解释 | 项目 `traditional/dynamic/README.md` | 内部 | 已有冻结结果 |
| 本项目 Tier B：Clang 22.1.8 F1 0.888、ASan+LSan/Valgrind 0.914；无 coverage instrumentation | 项目 `README.md` | 内部 | 已有冻结结果 |

### 6.2 未核实/不应写成事实的事项

- **LeakGuard 的同行评审状态**：arXiv 2504.04422 只有 v1（2025-04-06），页面标注 “Journal: Empirical Software Engineering”，但没有 DOI/卷期；本文按 **B（预印本）** 处理。[R33]
- **MemHint 的同行评审状态**：arXiv 2603.27224 最新 v6（2026-10-20），没有正式会议/DOI；本文按 **B** 处理。[R34]
- **LAMeD 的同行评审状态**：arXiv 2505.02376 v1（2025-05-05），没有正式会议/DOI；本文按 **B** 处理。[R35]
- **Semgrep 的检测性能**：本文只引用官方能力描述和 MemHint 的 baseline 计数；没有独立复现 Semgrep 在 CWE-401 上的 precision/recall。
- **CodeQL `memory-leak-on-failed-call-to-realloc` 的实际命中率**：本文只核验了查询存在与 CWE 映射，没有在真实数据库上运行；不能给出召回数字。
- **Valgrind 3.27.1/3.28.0 的差异**：本文没有重跑两个版本的对比；升级前必须重跑基线。
- **LLM 方法的跨项目迁移**：MemHint/LAMeD 都没有证明“在一个项目上生成的注解能直接迁移到另一个项目”；不能把单项目结果写成通用能力。
- **端到端成本**：MemHint 的 $1.76/bug 是作者自报的 LLM/静态分析成本，不含人工 triage、构建、维护；不能当本项目预算。
- **本文件没有做真实项目迁移**：第 3 节是路线与命令模板；第 5 节只是最小语义验证。真实迁移的构建失败率、告警量、triage 时间都需要在本项目环境中实测。

### 6.3 不能声称的事

- 不能把 LeakGuard/MemHint 的“已知 bug 回收数”写成“某工具的总体召回”。
- 不能把 CodeQL/Semgrep/Infer/SVF/Clang 的原始告警数直接横向排名；它们的 oracle、构建边界、路径敏感度不同。
- 不能把 `still reachable` 算作 CWE-401 的 TP 或 TN；必须单列。
- 不能把动态 `clean` 算作 TN，除非有覆盖率证明泄漏点被执行。
- 不能把 LLM 生成的 annotation 未经抽样验证就合入 CI 基线。
- 不能把 `juliet_repair` 的 compile/LSan/behavior 70/70 写成“真实项目修复率”。

---

## 7. 参考文献

> 访问日期均为 2026-11-13。arXiv 预印本按 B 级处理；官方文档/发布说明按 C 级处理；同行评审论文按 A 级处理。

**[R1]** MITRE. *CWE-401: Missing Release of Memory after Effective Lifetime*. 2026-10-28 更新. https://cwe.mitre.org/data/definitions/401.html

**[R2]** CERT/CMU SEI. *MEM31-C: Free dynamically allocated memory when no longer needed*. https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/rules/memory-management-mem/mem31-c/

**[R3]** cppreference. *realloc*. https://en.cppreference.com/w/c/memory/realloc.html

**[R4]** GitHub. *CodeQL 2.27.4 (2026-11-02)*. https://codeql.github.com/docs/codeql-overview/codeql-changelog/codeql-cli-2.27.4/

**[R5]** GitHub. *CWE coverage for C and C++*. https://codeql.github.com/codeql-query-help/cpp-cwe/

**[R6]** GitHub. *MemoryMayNotBeFreed.ql*. https://github.com/github/codeql/blob/main/cpp/ql/src/Critical/MemoryMayNotBeFreed.ql

**[R7]** GitHub. *MemoryNeverFreed.ql*. https://github.com/github/codeql/blob/main/cpp/ql/src/Critical/MemoryNeverFreed.ql

**[R8]** GitHub. *CodeQL 2.18.2 (2024-08-13)*. https://codeql.github.com/docs/codeql-overview/codeql-changelog/codeql-cli-2.18.2/

**[R9]** GitHub Docs. *Preparing your code for CodeQL analysis*. https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/preparing-your-code-for-codeql-analysis

**[R10]** Semgrep. *Supported languages*. https://semgrep.dev/docs/supported-languages

**[R11]** Semgrep. *Semgrep CE vs Semgrep AppSec Platform*. https://semgrep.dev/docs/semgrep-pro-vs-oss/

**[R12]** Semgrep. *Release v1.185.0 (2026-11-10)*. https://github.com/semgrep/semgrep/releases/tag/v1.185.0

**[R13]** Meta. *Infer version v1.3.0 (2026-05-12)*. https://github.com/facebook/infer/releases/tag/v1.3.0

**[R14]** Infer. *Pulse*. https://fbinfer.com/docs/next/checker-pulse/

**[R15]** Infer. *List of all issue types*. https://fbinfer.com/docs/next/all-issue-types/

**[R16]** Infer. *Steps for CI*. https://fbinfer.com/docs/next/steps-for-ci/

**[R17]** SVF. *SVF: Static Value-Flow Analysis Framework for Source Code*. https://svf-tools.github.io/SVF/

**[R18]** SVF. *SVF-3.3 release (2026-05-20)*. https://github.com/SVF-tools/SVF/releases/tag/SVF-3.3

**[R19]** McGowan, C., Richards, M., Sui, Y. *SVF-SVC: Software Verification Using SVF (Competition Contribution)*. TACAS 2025, LNCS 15698. https://doi.org/10.1007/978-3-031-90660-2_21

**[R20]** LLVM. *Clang Static Analyzer*. https://clang.llvm.org/docs/ClangStaticAnalyzer.html

**[R21]** LLVM. *Clang 20.1.0 Release Notes — Static Analyzer*. https://releases.llvm.org/20.1.0/tools/clang/docs/ReleaseNotes.html

**[R22]** LLVM. *Clang 22.1.0 Release Notes — Static Analyzer*. https://releases.llvm.org/22.1.0/tools/clang/docs/ReleaseNotes.html

**[R23]** LLVM. *Cross Translation Unit (CTU) Analysis*. https://clang.llvm.org/docs/analyzer/user-docs/CrossTranslationUnit.html

**[R24]** LLVM. *Source Annotations*. https://clang.llvm.org/docs/analyzer/user-docs/Annotations.html

**[R25]** LLVM. *LeakSanitizer*. https://clang.llvm.org/docs/LeakSanitizer.html

**[R26]** Google Sanitizers. *LeakSanitizer Design Document*. https://github.com/google/sanitizers/wiki/AddressSanitizerLeakSanitizerDesignDocument

**[R27]** LLVM compiler-rt. *lsan_flags.inc*. https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/lsan/lsan_flags.inc

**[R28]** Valgrind. *Memcheck: a memory error detector*. https://valgrind.org/docs/manual/mc-manual.html

**[R29]** Valgrind. *NEWS — Release 3.28.0 (23 Oct 2026)*. https://valgrind.org/docs/manual/dist.news.html

**[R30]** LLVM. *Source-based Code Coverage*. https://clang.llvm.org/docs/SourceBasedCodeCoverage.html

**[R31]** LLVM. *libFuzzer*. https://llvm.org/docs/LibFuzzer.html

**[R32]** AFL++. *Environment variables*. https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/env_variables.md

**[R33]** Liang, H., Yin, L., Wu, G., Li, Y., Yi, Q., Wang, L. *LeakGuard: Detecting Memory Leaks Accurately and Scalably*. arXiv:2504.04422, 2025. https://arxiv.org/abs/2504.04422

**[R34]** Huang, H., Shi, J., Wang, B., Yang, Z., Lo, D. *Finding Memory Leaks in C/C++ Programs via Neuro-Symbolic Augmented Static Analysis*. arXiv:2603.27224 v6, 2026-10-20. https://arxiv.org/abs/2603.27224

**[R35]** Shemetova, E., Shenbin, I., Smirnov, I., Alekseev, A., Rukhovich, A., Nikolenko, S., Lomshakov, V., Piontkovskaya, I. *LAMeD: LLM-generated Annotations for Memory Leak Detection*. arXiv:2505.02376, 2025. https://arxiv.org/abs/2505.02376

**[R36]** Liu, D., Lu, Z., Ji, S., Lu, K., Chen, J., Liu, Z., Liu, D., Cai, R., He, Q. *Detecting Kernel Memory Bugs through Inconsistent Memory Management Intention Inferences*. USENIX Security 2024. https://www.usenix.org/conference/usenixsecurity24/presentation/liu-dinghao-detecting

**[R37]** Wang, C., Zhang, W., Su, Z., Xu, X., Xie, X., Zhang, X. *LLMDFA: Analyzing Dataflow in Code with Large Language Models*. NeurIPS 2024. https://arxiv.org/abs/2402.10754

**[R38]** Wen, C., et al. *Automatically Inspecting Thousands of Static Bug Warnings with Large Language Model: How Far Are We?* ACM TOSEM, 2024. https://doi.org/10.1145/3653718

**[R39]** Wang, C., Liu, J., Peng, X., Liu, Y., Lou, Y. *Boosting Static Resource Leak Detection via LLM-based Resource-Oriented Intention Inference*. ICSE 2025. https://arxiv.org/abs/2311.04448

**[R40]** Yang, C., Zhao, Z., Xie, Z., Li, H., Zhang, L. *KNighter: Transforming Static Analysis with LLM-Synthesized Checkers*. SOSP 2025. https://arxiv.org/abs/2503.09002

**[R41]** Cheng, X., Guo, Z., Huo, H., Sui, Y. *TLR: Codebase-Level C Memory Management Error Repair with Large Language Models*. Proc. ACM Softw. Eng. 3, FSE, Article FSE057, 2026. https://jumormt.github.io/data/fse26_tlr.pdf

**[R42]** FAINT. *FAult INjection Tester*. https://github.com/misc0110/faint

**[R43]** failmalloc. *Failmalloc*. https://www.nongnu.org/failmalloc/

**[R44]** libfiu. *POSIX fault injection*. https://github.com/albertito/libfiu/blob/master/doc/posix.rst

**[R45]** Wang, C., Zhang, W., Su, Z., Xu, X., Zhang, X. *Sanitizing Large Language Models in Bug Detection with Data-Flow*. Findings of EMNLP 2024, pp. 3790–3805. https://doi.org/10.18653/v1/2024.findings-emnlp.217

**[R46]** 本项目. *README.md*（WSL 复现环境与 Tier B 结果）与 *traditional/dynamic/README.md*（动态泄漏语义与 190 FN 解释）. 内部产物，2026-11-12 冻结.

**[R47]** 本项目. *traditional/dynamic/runs/cwe401_juliet_v1_3_asan_valgrind/metrics.md*（1467 TP/0 FP/1658 TN/190 FN）与 *traditional/dynamic/README.md*（108/68/14 失败分类）. 内部产物.
