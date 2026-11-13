# 动态分析增强结果：test140_enhanced_v3

- 单元：140（bad 70 / good 70）
- 模式：`default`（标准 LSan 根集）、`realloc_fail`（首个非空指针 realloc 强制失败）、`nogobal`（`use_globals=0`）
- 判定：任一适用模式出现**归因到单元源码**的泄漏即 `leak`；否则 `clean`。未归因的运行时/支撑库泄漏不计入。

## 1. 混淆矩阵（140 单元）

| 指标 | 值 |
| --- | ---: |
| TP | 70 |
| FP | 0 |
| TN | 70 |
| FN | 0 |
| undecided | 0 |
| coverage | 1.000 |
| precision | 1.000 |
| recall | 1.000 |
| F1 | 1.000 |

## 2. 各模式证据

| 模式 | 适用单元 | bad 归因泄漏 | good 归因泄漏 | bad 原始泄漏 | good 原始泄漏 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `default` | 140 | 58 | 0 | 58 | 0 |
| `realloc_fail` | 14 | 7 | 0 | 7 | 0 |
| `nogobal` | 140 | 63 | 0 | 70 | 70 |

`good 原始泄漏` 非零不代表误报：`nogobal` 会把 glibc 的 stdout 缓冲区和 libstdc++ 运行时分配暴露出来；这些块的分配栈不在单元源码里，按归因规则被排除。归因规则只看分配栈第一个落在非工具链位置的源码帧，不看文件名或标签。

## 3. 由条件/可达性证据解决的 12 个单元

共 12 个 bad 单元在 `default` 下无归因泄漏，在新模式下得到明确证据：

| 单元 | 主证据 | 模式 | default | realloc_fail | 注入调用 | nogobal | 归因字节 |
| --- | --- | --- | --- | --- | ---: | --- | ---: |
| `CWE401_Memory_Leak__malloc_realloc_int64_t_01__bad` | realloc_fail | realloc_fail | clean | leak | 1 | clean | 800 |
| `CWE401_Memory_Leak__malloc_realloc_int64_t_09__bad` | realloc_fail | realloc_fail | clean | leak | 1 | clean | 800 |
| `CWE401_Memory_Leak__malloc_realloc_int64_t_18__bad` | realloc_fail | realloc_fail | clean | leak | 1 | clean | 800 |
| `CWE401_Memory_Leak__malloc_realloc_int_01__bad` | realloc_fail | realloc_fail | clean | leak | 1 | clean | 400 |
| `CWE401_Memory_Leak__malloc_realloc_int_18__bad` | realloc_fail | realloc_fail | clean | leak | 1 | clean | 400 |
| `CWE401_Memory_Leak__malloc_realloc_twoIntsStruct_01__bad` | realloc_fail | realloc_fail | clean | leak | 1 | clean | 800 |
| `CWE401_Memory_Leak__malloc_realloc_twoIntsStruct_18__bad` | realloc_fail | realloc_fail | clean | leak | 1 | clean | 800 |
| `CWE401_Memory_Leak__new_TwoIntsClass_68__bad` | nogobal | nogobal | clean | clean | — | leak | 8 |
| `CWE401_Memory_Leak__new_array_twointsStruct_68__bad` | nogobal | nogobal | clean | clean | — | leak | 800 |
| `CWE401_Memory_Leak__twoIntsStruct_malloc_68__bad` | nogobal | nogobal | clean | clean | — | leak | 800 |
| `CWE401_Memory_Leak__wchar_t_calloc_68__bad` | nogobal | nogobal | clean | clean | — | leak | 400 |
| `CWE401_Memory_Leak__wchar_t_malloc_68__bad` | nogobal | nogobal | clean | clean | — | leak | 400 |

- `default` 下不可观测的 bad 单元：12 个，全部由新模式给出证据。
- good 误报：0 个

## 4. 失败分类与运行时间

| failure_class | 单元数 |
| --- | ---: |
| `clean` | 70 |
| `leak` | 70 |

- 单元总运行时间（编译 + 3 次运行）：total 315596 ms，mean 2254.3 ms，p50 2062 ms，p95 3746 ms，max 4977 ms。

| 模式 | 运行次数 | 平均运行 | p95 运行 | 最大运行 |
| --- | ---: | ---: | ---: | ---: |
| `default` | 140 | 62.6 ms | 135 ms | 167 ms |
| `realloc_fail` | 140 | 68.9 ms | 142 ms | 186 ms |
| `nogobal` | 140 | 147.9 ms | 180 ms | 221 ms |

## 5. 与旧 ASan/Valgrind 运行对比

- 旧运行：`traditional/dynamic/runs/cwe401_juliet_v1_3_asan_valgrind`（3316 cases；匹配 140/140 单元）。
- 新 `default` 与旧 ASan 判定一致：140/140。
- 新并集与旧 ASan/Valgrind 任一泄漏一致：128/140。
- 旧 ASan 平均运行：74.5 ms；新 `default` 平均运行：62.6 ms。

判定发生变化的单元：

| 单元 | 标签 | 旧 ASan | 旧 Valgrind | 新 default | 新并集 | 主证据 |
| --- | --- | --- | --- | --- | --- | --- |
| `CWE401_Memory_Leak__malloc_realloc_int64_t_01__bad` | bad | clean | clean | clean | leak | realloc_fail |
| `CWE401_Memory_Leak__malloc_realloc_int64_t_09__bad` | bad | clean | clean | clean | leak | realloc_fail |
| `CWE401_Memory_Leak__malloc_realloc_int64_t_18__bad` | bad | clean | clean | clean | leak | realloc_fail |
| `CWE401_Memory_Leak__malloc_realloc_int_01__bad` | bad | clean | clean | clean | leak | realloc_fail |
| `CWE401_Memory_Leak__malloc_realloc_int_18__bad` | bad | clean | clean | clean | leak | realloc_fail |
| `CWE401_Memory_Leak__malloc_realloc_twoIntsStruct_01__bad` | bad | clean | clean | clean | leak | realloc_fail |
| `CWE401_Memory_Leak__malloc_realloc_twoIntsStruct_18__bad` | bad | clean | clean | clean | leak | realloc_fail |
| `CWE401_Memory_Leak__new_TwoIntsClass_68__bad` | bad | clean | clean | clean | leak | nogobal |
| `CWE401_Memory_Leak__new_array_twointsStruct_68__bad` | bad | clean | clean | clean | leak | nogobal |
| `CWE401_Memory_Leak__twoIntsStruct_malloc_68__bad` | bad | clean | clean | clean | leak | nogobal |
| `CWE401_Memory_Leak__wchar_t_calloc_68__bad` | bad | clean | clean | clean | leak | nogobal |
| `CWE401_Memory_Leak__wchar_t_malloc_68__bad` | bad | clean | clean | clean | leak | nogobal |

## 6. 运行清单

- 创建时间（UTC）：2026-11-12T16:35:37Z
- 完成时间（UTC）：2026-11-12T16:36:18Z
- 总墙钟：41.68 s
- `results_units.jsonl` SHA-256：`bed73483ea4733dcb5c81ad8559d7e46c525cd9af21e523866e7cb240675f2ae`
- `results_raw.jsonl` SHA-256：`bcd373a5c024689c805c4c13a2f8744d320182c015995718d5ca7cd537c7d3a8`
- 工具：gcc (Ubuntu 15.3.0-4ubuntu1) 15.3.0；g++ (Ubuntu 15.3.0-4ubuntu1) 15.3.0
