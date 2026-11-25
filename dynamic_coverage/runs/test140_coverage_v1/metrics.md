# 动态覆盖率证据：Juliet CWE-401 冻结 test 140

本文件由 `dynamic_coverage/run_dynamic_coverage.py report` 生成。覆盖率的每个数字都来自 `gcov -j -b -c` 的逐行/逐分支记录；没有任何阈值把未执行的行算成已覆盖。泄漏判定沿用 `dynamic_enhanced` 的归因规则，只用于把“已执行且 clean”与“未充分执行”分开。

**口径**：`branch_complete` = 单元自身文件的每个可执行行都执行且每个记录到的分支都至少走一次；`line_complete` = 行全覆盖但至少一个分支未走；`partial` = 有可执行行未走；`not_executed` = 单元自身代码一行都没执行。`coverage_error` 不当作 clean，也不当作负例。报告中的 `effective` 分层把源码中标注 `INCIDENTAL: CWE 561 Dead Code` 的不可达行从分母剔除，同时保留原始行覆盖数和具体行号，剔除规则不是按百分比阈值。

## 1. 三种模式的覆盖率采集

| 模式 | 单元 | 适用 | bad leak | good leak | 有效行覆盖均值 | 分支覆盖均值 | branch_complete | line_complete | partial | not_executed | coverage_error |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| default | 140 | 140 | 58 | 0 | 100.0% | 50.0% | 21 | 119 | 0 | 0 | 0 |
| realloc_fail | 140 | 14 | 7 | 0 | 97.8% | 50.0% | 21 | 105 | 14 | 0 | 0 |
| nogobal | 140 | 140 | 63 | 0 | 100.0% | 50.0% | 21 | 119 | 0 | 0 | 0 |

并集（任意模式执行到的行/分支）：140 单元，有效行覆盖均值 100.0%，原始行覆盖均值 99.9%，分支覆盖均值 52.7%，入口已执行 140/140。表中的 `partial` 是剔除 CWE-561 声明死代码后的有效分层；原始行覆盖下 default/nogobal 各有 6 个 dead-code partial，realloc_fail 有 19 个（其中 14 个是注入后跳过 free 路径）。`branch_complete` 的 21 个全部是 bad（bad 21、good 0）：good 单元的错误处理守卫更多，反而更难走全。因此 `branch_complete` 是本数据上代码形状的副产物，不是质量或 clean 信号。

## 2. 原路径 clean 的执行证据（82 个 clean = 70 good + 12 实际 bad）

原路径 clean = 82（真 good 70，真 bad 12）。先给原始行覆盖分层，再给剔除 Juliet 自带 CWE-561 死代码后的有效分层。


| raw tier | 单元数 |
| --- | --- |
| branch_complete | 2 |
| line_complete | 74 |
| partial | 6 |

原始分层中 `partial` 的 6 个单元，未覆盖行全部是源码中标注 `INCIDENTAL: CWE 561 Dead Code` 的不可达行（共 6 行）。剔除这些声明死代码后：


| effective tier | 单元数 |
| --- | --- |
| branch_complete | 2 |
| line_complete | 80 |

`executed_clean` = 82/82：所有 clean 判定的可执行行都执行了，其中真 good 70、实际是 bad 的 12。`branch_complete` 的 good = 0，原因是 good 单元普遍包含 `if (allocation == NULL) exit(-1)` 之类的失败守卫（以及 `GLOBAL_CONST_FALSE` 死代码分支），不做分配失败注入时无法走全；因此 `branch_complete` 是严格上界，不作为 clean 支持的主判据。

三模式并集重新分层：`executed_clean` 仍为 82，真 bad 仍为 12；增强模式把其中 12 个 bad 从 clean 变成 leak，但这不是靠新增行覆盖，而是靠新增分支/改变根集（见第 6 节）。

### 2.1 逐单元三分类输出


| 视图 | covered_clean | uncovered | compile_error | leak |
| --- | --- | --- | --- | --- |
| default | 82 (good 70, bad 12) | 0 (good 0, bad 0) | 0 | 58 (good 0, bad 58) |
| enhanced union | 70 (good 70, bad 0) | 0 (good 0, bad 0) | 0 | 70 (good 0, bad 70) |

`covered_clean` = clean 且 effective 行覆盖完整且入口已执行；它不是正确性标签：default 视图的 82 个 covered_clean 里有 12 个实际是 bad。`uncovered` = clean 但覆盖不足；`compile_error` 单独计数，从不写成 `y_pred=0`。

## 3. 原路径漏掉的 12 个 bad：覆盖率解释

12 个按证据模式分成两组：`realloc_fail` 7 个，`nogobal` 5 个。前一组的默认路径是 `line_complete`，但 `realloc` 返回 NULL 的分支未走；`realloc_fail` 正好新增这个分支（第 6 节：14 个单元各新增 1 个分支）。后一组即使 `branch_complete`（2 个）或 `line_complete`（3 个）也仍然 clean，因为它们的问题不是执行不足，而是 LSan 把全局指针当根。

默认路径 effective `branch_complete` 的 2 个、`line_complete` 的 10 个、`partial` 的 0 个。这 12 个没有一个是 `not_executed` 或 `partial`：**行覆盖无法区分它们和 70 个 good**。


| 单元 | 证据模式 | 默认 tier | 默认行 | 默认分支 | 并集分支 | 默认未走分支（源码行） |
| --- | --- | --- | --- | --- | --- | --- |
| malloc_realloc_int64_t_01__bad | realloc_fail | line_complete | 11/11 | 2/4 | 3/4 | 28: if (data == NULL) {exit(-1);}；34: if (data != NULL) |
| malloc_realloc_int64_t_09__bad | realloc_fail | line_complete | 12/12 | 3/6 | 4/6 | 26: if(GLOBAL_CONST_TRUE)；30: if (data == NULL) {exit(-1);}；36: if (data != NULL) |
| malloc_realloc_int64_t_18__bad | realloc_fail | line_complete | 13/13 | 2/4 | 3/4 | 30: if (data == NULL) {exit(-1);}；36: if (data != NULL) |
| malloc_realloc_int_01__bad | realloc_fail | line_complete | 11/11 | 2/4 | 3/4 | 28: if (data == NULL) {exit(-1);}；34: if (data != NULL) |
| malloc_realloc_int_18__bad | realloc_fail | line_complete | 13/13 | 2/4 | 3/4 | 30: if (data == NULL) {exit(-1);}；36: if (data != NULL) |
| malloc_realloc_twoIntsStruct_01__bad | realloc_fail | line_complete | 13/13 | 2/4 | 3/4 | 28: if (data == NULL) {exit(-1);}；35: if (data != NULL) |
| malloc_realloc_twoIntsStruct_18__bad | realloc_fail | line_complete | 15/15 | 2/4 | 3/4 | 30: if (data == NULL) {exit(-1);}；37: if (data != NULL) |
| new_TwoIntsClass_68__bad | nogobal | branch_complete | 13/13 | 0/0 | 0/0 | — |
| new_array_twointsStruct_68__bad | nogobal | branch_complete | 12/12 | 0/0 | 0/0 | — |
| twoIntsStruct_malloc_68__bad | nogobal | line_complete | 13/13 | 1/2 | 1/2 | 37: if (data == NULL) {exit(-1);} |
| wchar_t_calloc_68__bad | nogobal | line_complete | 12/12 | 1/2 | 1/2 | 37: if (data == NULL) {exit(-1);} |
| wchar_t_malloc_68__bad | nogobal | line_complete | 12/12 | 1/2 | 1/2 | 37: if (data == NULL) {exit(-1);} |

## 4. 覆盖率分层混淆矩阵

预测使用归档判定，覆盖率只决定分层；“—”表示该层没有可计算的分母。

### 原路径（default）


| tier | n | TP | FP | TN | FN | P | R | F1 | macro-F1 | MCC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| branch_complete | 21 | 19 | 0 | 0 | 2 | 1.000 | 0.905 | 0.950 | — | — |
| line_complete | 119 | 39 | 0 | 70 | 10 | 1.000 | 0.796 | 0.886 | 0.910 | 0.835 |

### 增强并集（default+realloc_fail+nogobal）


| tier | n | TP | FP | TN | FN | P | R | F1 | macro-F1 | MCC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| branch_complete | 21 | 21 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | — | — |
| line_complete | 119 | 49 | 0 | 70 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |

## 5. 覆盖率门控视图

只对负例（clean）门控：clean 且该视图的覆盖层不足时记为 abstain，从分母移除；leak 判定不因覆盖率被撤销。`line_gated` 用剔除 CWE-561 死代码后的有效行覆盖，`line_gated_raw` 用原始行覆盖（保留 6 个死代码行导致的 abstain）作为敏感性。`supported_clean_but_bad` 是“覆盖充分却仍被判 clean 的 bad”，也就是覆盖率无法纠正的错误负例。


| 视图 | TP | FP | TN | FN | abstain | coverage | P | R | F1 | MCC | supported clean 但 bad |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| default_operational | 58 | 0 | 70 | 12 | 0 | 100.0% | 1.000 | 0.829 | 0.906 | 0.841 | 12 |
| default_line_gated_raw | 58 | 0 | 64 | 12 | 6 | 95.7% | 1.000 | 0.829 | 0.906 | 0.835 | 12 |
| default_line_gated | 58 | 0 | 70 | 12 | 0 | 100.0% | 1.000 | 0.829 | 0.906 | 0.841 | 12 |
| default_branch_gated | 58 | 0 | 0 | 12 | 70 | 50.0% | 1.000 | 0.829 | 0.906 | — | 2 |
| enhanced_operational | 70 | 0 | 70 | 0 | 0 | 100.0% | 1.000 | 1.000 | 1.000 | 1.000 | 0 |
| enhanced_line_gated_raw | 70 | 0 | 64 | 0 | 6 | 95.7% | 1.000 | 1.000 | 1.000 | 1.000 | 0 |
| enhanced_line_gated | 70 | 0 | 70 | 0 | 0 | 100.0% | 1.000 | 1.000 | 1.000 | 1.000 | 0 |
| enhanced_branch_gated | 70 | 0 | 0 | 0 | 70 | 50.0% | 1.000 | 1.000 | 1.000 | — | 0 |

## 6. 模式新增覆盖

| 模式 | 相对 default 有新覆盖的单元 | 新增行 | 新增分支 |
| --- | --- | --- | --- |
| default | 0 | 0 | 0 |
| realloc_fail | 14 | 0 | 14 |
| nogobal | 0 | 0 | 0 |

`nogobal` 与 `default` 是同一二进制、同一执行路径，只有 LSan 根集不同；它新增 0 行/0 分支是预期结果，也是“5 个 `_68` 单元的修复不是靠执行更多代码”的直接证据。

## 7. 分配/释放调用点覆盖

| 视图 | 分配调用点执行 | 释放调用点执行 |
| --- | --- | --- |
| default | 167/167 | 89/89 |
| union | 167/167 | 89/89 |

所有 167 个分配调用点和 89 个释放调用点都执行了（default 与 union 相同），包括原路径漏掉的 12 个 bad。调用点覆盖同样不能区分“执行了分配/释放”与“该块被泄漏”。

## 8. 与归档结果的一致性

覆盖率运行与原路径归档判定一致 140/140；与增强并集一致 140/140。原动态运行（ASan/Valgrind）匹配 140 个单元；归档对比 default_vs_old_asan=140、union_vs_old_any=128。

## 9. 限制

1. 覆盖率是**单次执行路径**的覆盖，不是输入空间覆盖。`branch_complete` 只说明该次执行走过了编译出的每个分支，不说明任意输入下都无泄漏。
2. `realloc_fail` 只让第一次非 NULL `realloc` 失败；如果单元只在第二次失败时泄漏，本实验看不到。
3. `nogobal` 关闭全局根是进程级开关，不是逐变量根映射；它不能指出是哪个全局变量持有块。
4. `executed_clean` 不是无泄漏证明。默认路径 82 个 clean 在剔除 6 行声明死代码后全部行覆盖，但其中 12 个实际是 bad；2 个 `_68` 单元甚至 `branch_complete`（另外 3 个 `_68` 是 `line_complete`）。覆盖充分不能替代根集/泄漏判定语义。
5. 覆盖率来自 GCC gcov，泄漏判定来自同一 GCC ASan/LSan 运行；没有使用 Valgrind，也没有把 Valgrind 的旧结果伪装成本次测量。
6. 所有数字只限 `split=test` 的 140 个冻结单元，不能外推到 dev 或其他 CWE。
