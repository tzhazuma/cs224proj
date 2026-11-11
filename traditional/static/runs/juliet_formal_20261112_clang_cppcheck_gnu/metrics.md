# CWE-401 静态检测结果（自动生成）

- 生成时间：`2026-11-11T18:25:32.049+00:00`
- 数据集：`/mnt/c/Users/tzh03/Downloads/cs224proj/juliet/subset_units.jsonl`
- 样本：200 / 输入 200；有标签 200；漏洞 100，非漏洞 100
- 语言：{'cpp': 112, 'c': 88}；CWE-401 过滤：`None`
- 运行墙钟时间：9.00 s

## 工具可用性

| 工具 | 可用 | 版本 | 二进制 |
| --- | --- | --- | --- |
| clang | True | Ubuntu clang version 22.1.8 (1ubuntu1) | `/usr/bin/clang` |
| cppcheck | True | Cppcheck 2.21.0 | `/tmp/cppcheck_probe/cppcheck` |

## clang

状态：{'ok': 194, 'compile_error': 6}；可评估 194/200（覆盖率 0.9700）。

| 视图 | TP | FP | TN | FN | Precision | Recall | Specificity | F1(V) | Macro-F1 | Accuracy | MCC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 可评估 | 73 | 0 | 97 | 24 | 1.0000 | 0.7526 | 1.0000 | 0.8588 | 0.8744 | 0.8763 | 0.7767 |
| 端到端 | 73 | 0 | 100 | 27 | 1.0000 | 0.7300 | 1.0000 | 0.8439 | 0.8625 | 0.8650 | 0.7582 |

运行时间：总计 23.59 s，均值 0.118 s，中位 0.103 s，P95 0.139 s，最大 0.572 s。

原始诊断：152 条，其中 CWE-401 73 条；CWE-401 规则：{'unix.Malloc': 59, 'cplusplus.NewDeleteLeaks': 14}。

| 语言 | N | TP | FP | TN | FN | Recall | Precision | F1(V) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| c | 88 | 39 | 0 | 44 | 5 | 0.8864 | 1.0000 | 0.9398 |
| cpp | 106 | 34 | 0 | 53 | 19 | 0.6415 | 1.0000 | 0.7816 |

错误样例：

- `CWE401_Memory_Leak__new_array_TwoIntsClass_82__bad: /mnt/c/Users/tzh03/Downloads/cs224proj/juliet/raw/testcases/CWE401_Memory_Leak/s02/CWE401_Memory_Leak__new_array_TwoIntsClass_82.h:27:7: error: redefinition of 'CWE401_Memory_Leak__new_array_TwoIntsClass_82_base'`
- `CWE401_Memory_Leak__new_array_TwoIntsClass_82__bad: /mnt/c/Users/tzh03/Downloads/cs224proj/juliet/raw/testcases/CWE401_Memory_Leak/s02/CWE401_Memory_Leak__new_array_TwoIntsClass_82.h:36:7: error: redefinition of 'CWE401_Memory_Leak__new_array_TwoIntsClass_82_bad'`
- `CWE401_Memory_Leak__new_array_TwoIntsClass_82__good: /mnt/c/Users/tzh03/Downloads/cs224proj/juliet/raw/testcases/CWE401_Memory_Leak/s02/CWE401_Memory_Leak__new_array_TwoIntsClass_82.h:27:7: error: redefinition of 'CWE401_Memory_Leak__new_array_TwoIntsClass_82_base'`
- `CWE401_Memory_Leak__new_array_TwoIntsClass_82__good: /mnt/c/Users/tzh03/Downloads/cs224proj/juliet/raw/testcases/CWE401_Memory_Leak/s02/CWE401_Memory_Leak__new_array_TwoIntsClass_82.h:46:7: error: redefinition of 'CWE401_Memory_Leak__new_array_TwoIntsClass_82_goodG2B'`
- `CWE401_Memory_Leak__new_array_TwoIntsClass_82__good: /mnt/c/Users/tzh03/Downloads/cs224proj/juliet/raw/testcases/CWE401_Memory_Leak/s02/CWE401_Memory_Leak__new_array_TwoIntsClass_82.h:52:7: error: redefinition of 'CWE401_Memory_Leak__new_array_TwoIntsClass_82_goodB2G'`
- `CWE401_Memory_Leak__new_array_TwoIntsClass_82__good: /mnt/c/Users/tzh03/Downloads/cs224proj/juliet/raw/testcases/CWE401_Memory_Leak/s02/CWE401_Memory_Leak__new_array_TwoIntsClass_82.h:27:7: error: redefinition of 'CWE401_Memory_Leak__new_array_TwoIntsClass_82_base'`
- `CWE401_Memory_Leak__new_array_TwoIntsClass_82__good: /mnt/c/Users/tzh03/Downloads/cs224proj/juliet/raw/testcases/CWE401_Memory_Leak/s02/CWE401_Memory_Leak__new_array_TwoIntsClass_82.h:46:7: error: redefinition of 'CWE401_Memory_Leak__new_array_TwoIntsClass_82_goodG2B'`
- `CWE401_Memory_Leak__new_array_TwoIntsClass_82__good: /mnt/c/Users/tzh03/Downloads/cs224proj/juliet/raw/testcases/CWE401_Memory_Leak/s02/CWE401_Memory_Leak__new_array_TwoIntsClass_82.h:52:7: error: redefinition of 'CWE401_Memory_Leak__new_array_TwoIntsClass_82_goodB2G'`
- `CWE401_Memory_Leak__new_twoIntsStruct_82__bad: /mnt/c/Users/tzh03/Downloads/cs224proj/juliet/raw/testcases/CWE401_Memory_Leak/s02/CWE401_Memory_Leak__new_twoIntsStruct_82.h:27:7: error: redefinition of 'CWE401_Memory_Leak__new_twoIntsStruct_82_base'`
- `CWE401_Memory_Leak__new_twoIntsStruct_82__bad: /mnt/c/Users/tzh03/Downloads/cs224proj/juliet/raw/testcases/CWE401_Memory_Leak/s02/CWE401_Memory_Leak__new_twoIntsStruct_82.h:36:7: error: redefinition of 'CWE401_Memory_Leak__new_twoIntsStruct_82_bad'`

## cppcheck

状态：{'ok': 200}；可评估 200/200（覆盖率 1.0000）。

| 视图 | TP | FP | TN | FN | Precision | Recall | Specificity | F1(V) | Macro-F1 | Accuracy | MCC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 可评估 | 30 | 4 | 96 | 70 | 0.8824 | 0.3000 | 0.9600 | 0.4478 | 0.5848 | 0.6300 | 0.3461 |
| 端到端 | 30 | 4 | 96 | 70 | 0.8824 | 0.3000 | 0.9600 | 0.4478 | 0.5848 | 0.6300 | 0.3461 |

运行时间：总计 8.97 s，均值 0.045 s，中位 0.044 s，P95 0.061 s，最大 0.082 s。

原始诊断：111 条，其中 CWE-401 34 条；CWE-401 规则：{'memleak': 19, 'memleakOnRealloc': 15}。

| 语言 | N | TP | FP | TN | FN | Recall | Precision | F1(V) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| c | 88 | 19 | 0 | 44 | 25 | 0.4318 | 1.0000 | 0.6032 |
| cpp | 112 | 11 | 4 | 52 | 45 | 0.1964 | 0.7333 | 0.3099 |

## 口径与限制

- 正类为“存在 CWE-401 内存泄漏诊断”，负类为“无 CWE-401 诊断”。
- `可评估` 只含工具正常完成（status=ok）的样本；编译失败、超时和工具错误不计入。
- `端到端` 把编译失败和超时按“未报泄漏”计入混淆矩阵，工具错误与不可用工具仍排除；该视图更接近部署成本，但会惩罚无法解析的输入。
- Clang 仅把 `unix.Malloc`/`cplusplus.NewDeleteLeaks` 中含 leak 语义的诊断映射为 CWE-401；double free、use-after-free 等不计入。Cppcheck 使用 `memleak`/`memleakOnRealloc` 或 `cwe=401`。
- 文件级标签会把文件中任意位置的泄漏算作命中；若清单提供 `line_start`/`line_end`，只统计目标区间。函数级基准应由数据清单给出精确区间或独立翻译单元。
