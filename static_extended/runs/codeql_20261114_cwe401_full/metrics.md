# CodeQL CWE-401 结果（自动生成）

- 生成时间：`2026-11-13T17:28:06Z`
- 数据集：`/mnt/c/Users/tzh03/Downloads/cs224proj/juliet/subset_units.jsonl` (sha256 `4827d1da6a196675…`)
- 单元：200（test 140 / dev 60）
- 运行墙钟时间：1434.7 s
- 工具：CodeQL command-line toolchain release 2.27.4.

## 状态

状态计数：`{'ok': 194, 'compile_error': 6}`；可评估 194/200（覆盖率 0.9700）。

## 汇总（端到端，编译失败按未报泄漏计）

| 视图 | TP | FP | TN | FN | Precision | Recall | Specificity | F1(V) | Macro-F1 | Accuracy | MCC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 可评估 | 96 | 30 | 67 | 1 | 0.7619 | 0.9897 | 0.6907 | 0.8610 | 0.8366 | 0.8402 | 0.7130 |
| 端到端 | 96 | 30 | 70 | 4 | 0.7619 | 0.9600 | 0.7000 | 0.8496 | 0.8271 | 0.8300 | 0.6835 |

## 分查询（可评估）

| 查询 | TP | FP | TN | FN | Precision | Recall | F1(V) | MCC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `cpp/memory-never-freed` | 63 | 0 | 97 | 34 | 1.0000 | 0.6495 | 0.7875 | 0.6935 |
| `cpp/memory-may-not-be-freed` | 33 | 30 | 67 | 64 | 0.5238 | 0.3402 | 0.4125 | 0.0330 |

## 分语言（可评估）

| 语言 | N | TP | FP | TN | FN | Precision | Recall | F1(V) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| c | 88 | 44 | 0 | 44 | 0 | 1.0000 | 1.0000 | 1.0000 |
| cpp | 106 | 52 | 30 | 23 | 1 | 0.6341 | 0.9811 | 0.7704 |

## 分 split（可评估）

| split | N | TP | FP | TN | FN | Precision | Recall | F1(V) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| dev | 58 | 28 | 7 | 22 | 1 | 0.8000 | 0.9655 | 0.8750 |
| test | 136 | 68 | 23 | 45 | 0 | 0.7473 | 1.0000 | 0.8553 |

## 计时

总计 8504.027 s，均值 42.5201 s，中位 43.0131 s，P95 51.664 s，最大 60.5094 s。

## 口径

- 正类 = 目标源文件中存在 `cpp/memory-never-freed` 或 `cpp/memory-may-not-be-freed` 结果。
- 可评估只含 `status=ok`；端到端把 `compile_error`/`timeout` 按未报泄漏计入。
- 每个单元单独建 CodeQL 数据库（`gcc`/`g++` 编译），多文件单元按基线同样方式合成一个 TU。
- 头文件中的结果不计入（与 Clang/Cppcheck 基线 `--include-external` 关闭一致）。
