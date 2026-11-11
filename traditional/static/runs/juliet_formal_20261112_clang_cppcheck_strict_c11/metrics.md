# CWE-401 静态检测结果（自动生成）

- 生成时间：`2026-11-11T18:04:18.226+00:00`
- 数据集：`/mnt/c/Users/tzh03/Downloads/cs224proj/juliet/manifest.json`
- 样本：200 / 输入 200；有标签 200；漏洞 100，非漏洞 100
- 语言：{'cpp': 112, 'c': 88}；CWE-401 过滤：`None`
- 运行墙钟时间：19.91 s

## 工具可用性

| 工具 | 可用 | 版本 | 二进制 |
| --- | --- | --- | --- |
| clang | True | Ubuntu clang version 22.1.8 (1ubuntu1) | `/usr/bin/clang` |
| cppcheck | True | Cppcheck 2.21.0 | `/tmp/cppcheck_probe/cppcheck` |

## clang

状态：{'ok': 188, 'compile_error': 12}；可评估 188/200（覆盖率 0.9400）。

| 视图 | TP | FP | TN | FN | Precision | Recall | Specificity | F1(V) | Macro-F1 | Accuracy | MCC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 可评估 | 71 | 0 | 94 | 23 | 1.0000 | 0.7553 | 1.0000 | 0.8606 | 0.8758 | 0.8777 | 0.7790 |
| 端到端 | 71 | 0 | 100 | 29 | 1.0000 | 0.7100 | 1.0000 | 0.8304 | 0.8519 | 0.8550 | 0.7419 |

运行时间：总计 49.53 s，均值 0.248 s，中位 0.223 s，P95 0.330 s，最大 0.966 s。

原始诊断：147 条，其中 CWE-401 71 条；CWE-401 规则：{'unix.Malloc': 57, 'cplusplus.NewDeleteLeaks': 14}。

| 语言 | N | TP | FP | TN | FN | Recall | Precision | F1(V) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| c | 82 | 37 | 0 | 41 | 4 | 0.9024 | 1.0000 | 0.9487 |
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
- `CWE401_Memory_Leak__strdup_char_01__bad: /mnt/c/Users/tzh03/Downloads/cs224proj/juliet/raw/testcases/CWE401_Memory_Leak/s02/CWE401_Memory_Leak__strdup_char_01.c:31:16: error: call to undeclared function 'strdup'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]`
- `CWE401_Memory_Leak__strdup_char_01__bad: /mnt/c/Users/tzh03/Downloads/cs224proj/juliet/raw/testcases/CWE401_Memory_Leak/s02/CWE401_Memory_Leak__strdup_char_01.c:31:14: error: incompatible integer to pointer conversion assigning to 'char *' from 'int' [-Wint-conversion]`

## cppcheck

状态：{'ok': 200}；可评估 200/200（覆盖率 1.0000）。

| 视图 | TP | FP | TN | FN | Precision | Recall | Specificity | F1(V) | Macro-F1 | Accuracy | MCC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 可评估 | 30 | 4 | 96 | 70 | 0.8824 | 0.3000 | 0.9600 | 0.4478 | 0.5848 | 0.6300 | 0.3461 |
| 端到端 | 30 | 4 | 96 | 70 | 0.8824 | 0.3000 | 0.9600 | 0.4478 | 0.5848 | 0.6300 | 0.3461 |

运行时间：总计 18.77 s，均值 0.094 s，中位 0.087 s，P95 0.151 s，最大 0.180 s。

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
