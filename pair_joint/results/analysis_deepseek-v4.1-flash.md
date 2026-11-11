# Pair-joint A/B 结果：deepseek-v4.1-flash

- 运行目录：`test_deepseek_180`
- 数据：`splits/test_pairs_180.json`（SHA-256 `21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d`，180 对）
- Prompt：`pair-joint-2026-11-12.1`；A/B 位置按位置映射文件 SHA-256 `82c40fd03b1d0ae6d34eb51ad780da3cd543bb5d38f45d7e44d86c7044e6e7c8`
- 部分运行：`False`；开始 `2026-11-11T19:18:13.959+00:00`，结束 `2026-11-11T19:20:43.461+00:00`
- 位置计数：{'A': 90, 'B': 90}

## 1. 输出有效性（四类 + 无效）

| 类别 | 计数 | 占全部对 | 占可解析输出 |
| --- | ---: | ---: | ---: |
| correct（选对漏洞版本） | 138 | 76.67% | 76.67% |
| swapped（判反） | 42 | 23.33% | 23.33% |
| both_vulnerable（称两侧都有漏洞） | 0 | 0.00% | 0.00% |
| both_safe（称两侧都安全） | 0 | 0.00% | 0.00% |
| invalid（不可解析/API 错误） | 0 | 0.00% | 0.00% |

- 可解析输出：180/180；强制二选一输出：180/180。
- 无效原因：`{}`。
- 恒等式残差（一致率 − both_vulnerable − both_safe − 1）：`0.0`。

## 2. 配对判别准确率（DA）

| 口径 | 值 | 95% Wilson | 分母 |
| --- | ---: | --- | ---: |
| DA（全部 180 对，invalid 记错） | 76.67% | 76.67% [69.97%, 82.25%] | 180 |
| DA（可解析输出） | 76.67% | 76.67% [69.97%, 82.25%] | 180 |
| DA（强制二选一输出） | 76.67% | 76.67% [69.97%, 82.25%] | 180 |

## 2.1 长度混淆检查（post-hoc，不是预注册基线）

| 子集（按字符长度） | n | joint correct | joint DA |
| --- | ---: | ---: | ---: |
| 漏洞版本更短 | 130 | 109 | 83.85% |
| 漏洞版本更长 | 44 | 25 | 56.82% |
| 等长 | 6 | 4 | 66.67% |

| 平凡启发式 | 正确 | DA |
| --- | ---: | ---: |
| 选较短版本（字符，tie=A） | 134 | 74.44% |
| 选较短版本（行数，tie=A） | 133 | 73.89% |

- joint vs 字符长度启发式 McNemar：b=25，c=21，p=0.6587。
- 该诊断在测试结果之后加入，仅用于判断“修复版本通常更长”这一数据伪影能在多大程度上解释 DA；它不改变主指标，也不把长度当作模型能力。

## 3. Position bias

| 漏洞版本位置 | n | correct | swapped | both | neither | invalid | DA（全部） | DA（可解析） |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A | 90 | 83 | 7 | 0 | 0 | 0 | 92.22% | 92.22% |
| B | 90 | 55 | 35 | 0 | 0 | 0 | 61.11% | 61.11% |

- DA(A) − DA(B)（全部）：31.11%；Fisher 精确 p = 1.000e-06。
- DA(A) − DA(B)（可解析）：31.11%；Fisher 精确 p = 1.000e-06。
- 选择 A/B 的次数：{'A': 118, 'B': 62}；在 A/B 选择中 A 的占比 = 65.56%，二项检验 p = 3.600e-05。
- 选择矩阵（行=漏洞版本位置，列=模型选择）：`{"A": {"A": 83, "B": 7}, "B": {"A": 35, "B": 55}}`。

## 4. 证据行与定位

| 指标 | 值 |
| --- | ---: |
| 有 evidence 的可解析输出 | 180 (100.00%) |
| schema 完全匹配 | 180 (100.00%) |
| evidence 合规（引用所选版本、行号在范围、code 非空） | 177 (98.33%) |
| 正确且 evidence 合规 | 136 (75.56% of all) |
| evidence 行文本精确匹配 | 348/356 (97.75%) |
| localization 可评分（correct） | 129 |
| localization 命中（correct） | 120 (93.02%) |
| 判对且定位命中 | 120 (66.67% of all) |

## 5. 与原分侧调用对比

### pair_joint (deepseek-v4.1-flash) vs separate direct (deepseek-v4.1-flash)

- 基线：`test_v1_direct_pairs`（deepseek-v4.1-flash，策略 `direct`）；基线数据集 SHA-256 `21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d`。
- 基线检测记录状态：`{"ok": 360}`；有效对 180/180。
- 基线四类：`{"both_safe": 113, "both_vulnerable": 44, "correct": 21, "swapped": 2}`。

| 方法 | 正确/对 | DA（全部） | 95% Wilson |
| --- | ---: | ---: | --- |
| pair_joint (deepseek-v4.1-flash) | 138 | 76.67% | 76.67% [69.97%, 82.25%] |
| separate direct (deepseek-v4.1-flash) | 21 | 11.67% | 11.67% [7.76%, 17.18%] |

- 2×2：both correct=20，joint-only=118，baseline-only=1，both wrong=41。
- McNemar 精确检验（全部 180 对，invalid 记错）：b=118，c=1，p=3.611e-34，风险差=0.6500。
- 仅双方都有效的 180 对：joint 138 vs baseline 21；McNemar p=3.611e-34。
- 项目聚类 bootstrap ΔDA 95% CI（10k）：[0.5865, 0.7791]；joint DA CI [0.6797, 0.8899]；baseline DA CI [0.0473, 0.1702]。
- 配对级 bootstrap ΔDA 95% CI（敏感性）：[0.5778, 0.7222]。

### pair_joint (deepseek-v4.1-flash) vs separate context (deepseek-v4.1-flash)

- 基线：`test_v1_context_pairs`（deepseek-v4.1-flash，策略 `context`）；基线数据集 SHA-256 `21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d`。
- 基线检测记录状态：`{"ok": 360}`；有效对 180/180。
- 基线四类：`{"both_safe": 108, "both_vulnerable": 49, "correct": 22, "swapped": 1}`。

| 方法 | 正确/对 | DA（全部） | 95% Wilson |
| --- | ---: | ---: | --- |
| pair_joint (deepseek-v4.1-flash) | 138 | 76.67% | 76.67% [69.97%, 82.25%] |
| separate context (deepseek-v4.1-flash) | 22 | 12.22% | 12.22% [8.21%, 17.81%] |

- 2×2：both correct=21，joint-only=117，baseline-only=1，both wrong=41。
- McNemar 精确检验（全部 180 对，invalid 记错）：b=117，c=1，p=7.162e-34，风险差=0.6444。
- 仅双方都有效的 180 对：joint 138 vs baseline 22；McNemar p=7.162e-34。
- 项目聚类 bootstrap ΔDA 95% CI（10k）：[0.5689, 0.7961]；joint DA CI [0.6797, 0.8899]；baseline DA CI [0.0490, 0.1777]。
- 配对级 bootstrap ΔDA 95% CI（敏感性）：[0.5722, 0.7167]。

## 6. 用量、成本、延迟

| 指标 | 值 |
| --- | ---: |
| prompt tokens 合计 | 431045 |
| completion tokens 合计 | 30080 |
| cached prompt tokens | 40192 |
| reasoning tokens | 0 |
| 每对 prompt tokens | 2394.69 |
| 总成本 USD | 0.153593 |
| 每对成本 USD | 0.000853 |
| 每正确对成本 USD | 0.001113 |
| 延迟 mean / p50 / p95 / max (s) | 6.4259 / 6.2752 / 8.0319 / 16.9746 |
| run wall (s) | 149.5020 |

## 7. 解释限制

- 联合提示强制模型二选一，不能直接复现“两侧分别调用”时的 both_flagged / both_safe 失败模式；本表的 both_vulnerable / both_safe 是模型违反指令的输出，不是两次独立判定的组合。
- 主推断按项目聚类 bootstrap；但 180 对中 `linux` 占 53 对，项目聚类区间受少数大项目支配，配对级 bootstrap 仅作敏感性分析。
- McNemar 以对为单位且假设独立；同项目相关会使 p 值偏小，因此只作为次要检验。
- 证据行定位使用 `difflib` 对漏洞/修复版本做行级 diff；源码注释中的 CVE/CWE 字符串属于数据残留，不是注入的元数据，详见 `leak_audit.json`。
- 单次贪心解码（temperature=0），没有重复采样；结果不代表模型方差。

