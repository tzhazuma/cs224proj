# CWE-401 静态检测结果（自动生成）

- 生成时间：`2026-11-11T18:22:54.132+00:00`
- 数据集：`/mnt/c/Users/tzh03/Downloads/cs224proj/datasets/independent_200.json`
- 样本：3 / 输入 200；有标签 3；漏洞 2，非漏洞 1
- 语言：{'cpp': 1, 'c': 2}；CWE-401 过滤：`CWE-401`
- 运行墙钟时间：0.28 s

## 工具可用性

| 工具 | 可用 | 版本 | 二进制 |
| --- | --- | --- | --- |
| clang | True | Ubuntu clang version 22.1.8 (1ubuntu1) | `/usr/bin/clang` |
| cppcheck | True | Cppcheck 2.21.0 | `/tmp/cppcheck_probe/cppcheck` |

## clang

状态：{'compile_error': 3}；可评估 0/3（覆盖率 0.0000）。

| 视图 | TP | FP | TN | FN | Precision | Recall | Specificity | F1(V) | Macro-F1 | Accuracy | MCC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 可评估 | 0 | 0 | 0 | 0 | — | — | — | — | — | — | — |
| 端到端 | 0 | 0 | 1 | 2 | — | 0.0000 | 1.0000 | 0.0000 | 0.2500 | 0.3333 | — |

运行时间：总计 0.09 s，均值 0.029 s，中位 0.029 s，P95 0.030 s，最大 0.030 s。

原始诊断：0 条，其中 CWE-401 0 条；CWE-401 规则：{}。

错误样例：

- `17743: /mnt/c/Users/tzh03/Downloads/cs224proj/traditional/static/runs/secvuleval_cwe401_snippets_both/work/00117_17743.cpp:1:32: error: unknown type name 'LST_HEAD'`
- `17743: /mnt/c/Users/tzh03/Downloads/cs224proj/traditional/static/runs/secvuleval_cwe401_snippets_both/work/00117_17743.cpp:1:1: error: a type specifier is required for all declarations`
- `17743: /mnt/c/Users/tzh03/Downloads/cs224proj/traditional/static/runs/secvuleval_cwe401_snippets_both/work/00117_17743.cpp:3:5: error: unknown type name 'PRV_PRESENTATIONCONTEXTITEM'`
- `17743: /mnt/c/Users/tzh03/Downloads/cs224proj/traditional/static/runs/secvuleval_cwe401_snippets_both/work/00117_17743.cpp:5:5: error: unknown type name 'DUL_SUBITEM'`
- `17743: /mnt/c/Users/tzh03/Downloads/cs224proj/traditional/static/runs/secvuleval_cwe401_snippets_both/work/00117_17743.cpp:8:15: error: use of undeclared identifier 'NULL'`
- `17743: /mnt/c/Users/tzh03/Downloads/cs224proj/traditional/static/runs/secvuleval_cwe401_snippets_both/work/00117_17743.cpp:11:15: error: use of undeclared identifier 'PRV_PRESENTATIONCONTEXTITEM'`
- `17743: /mnt/c/Users/tzh03/Downloads/cs224proj/traditional/static/runs/secvuleval_cwe401_snippets_both/work/00117_17743.cpp:11:43: error: expected expression`
- `17743: /mnt/c/Users/tzh03/Downloads/cs224proj/traditional/static/runs/secvuleval_cwe401_snippets_both/work/00117_17743.cpp:12:22: error: use of undeclared identifier 'NULL'`
- `17743: /mnt/c/Users/tzh03/Downloads/cs224proj/traditional/static/runs/secvuleval_cwe401_snippets_both/work/00117_17743.cpp:13:20: error: use of undeclared identifier 'DUL_SUBITEM'`
- `17743: /mnt/c/Users/tzh03/Downloads/cs224proj/traditional/static/runs/secvuleval_cwe401_snippets_both/work/00117_17743.cpp:13:32: error: expected expression`

## cppcheck

状态：{'compile_error': 1, 'ok': 2}；可评估 2/3（覆盖率 0.6667）。

| 视图 | TP | FP | TN | FN | Precision | Recall | Specificity | F1(V) | Macro-F1 | Accuracy | MCC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 可评估 | 0 | 0 | 1 | 1 | — | 0.0000 | 1.0000 | 0.0000 | 0.3333 | 0.5000 | — |
| 端到端 | 0 | 0 | 1 | 2 | — | 0.0000 | 1.0000 | 0.0000 | 0.2500 | 0.3333 | — |

运行时间：总计 0.06 s，均值 0.019 s，中位 0.018 s，P95 0.024 s，最大 0.024 s。

原始诊断：2 条，其中 CWE-401 0 条；CWE-401 规则：{}。

| 语言 | N | TP | FP | TN | FN | Recall | Precision | F1(V) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| c | 2 | 0 | 0 | 1 | 1 | 0.0000 | — | 0.0000 |

错误样例：

- `17743: syntaxError: syntax error`

## 口径与限制

- 正类为“存在 CWE-401 内存泄漏诊断”，负类为“无 CWE-401 诊断”。
- `可评估` 只含工具正常完成（status=ok）的样本；编译失败、超时和工具错误不计入。
- `端到端` 把编译失败和超时按“未报泄漏”计入混淆矩阵，工具错误与不可用工具仍排除；该视图更接近部署成本，但会惩罚无法解析的输入。
- Clang 仅把 `unix.Malloc`/`cplusplus.NewDeleteLeaks` 中含 leak 语义的诊断映射为 CWE-401；double free、use-after-free 等不计入。Cppcheck 使用 `memleak`/`memleakOnRealloc` 或 `cwe=401`。
- 文件级标签会把文件中任意位置的泄漏算作命中；若清单提供 `line_start`/`line_end`，只统计目标区间。函数级基准应由数据清单给出精确区间或独立翻译单元。
