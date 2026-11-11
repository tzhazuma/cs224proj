# Pair-joint A/B 结果：mimo-v2.6-flash

- 运行目录：`test_mimo_180`
- 数据：`splits/test_pairs_180.json`（SHA-256 `21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d`，180 对）
- Prompt：`pair-joint-2026-11-12.1`；A/B 位置按位置映射文件 SHA-256 `82c40fd03b1d0ae6d34eb51ad780da3cd543bb5d38f45d7e44d86c7044e6e7c8`
- 部分运行：`False`；开始 `2026-11-11T19:20:45.974+00:00`，结束 `2026-11-11T19:22:04.815+00:00`
- 位置计数：{'A': 90, 'B': 90}

## 1. 输出有效性（四类 + 无效）

| 类别 | 计数 | 占全部对 | 占可解析输出 |
| --- | ---: | ---: | ---: |
| correct（选对漏洞版本） | 156 | 86.67% | 86.67% |
| swapped（判反） | 24 | 13.33% | 13.33% |
| both_vulnerable（称两侧都有漏洞） | 0 | 0.00% | 0.00% |
| both_safe（称两侧都安全） | 0 | 0.00% | 0.00% |
| invalid（不可解析/API 错误） | 0 | 0.00% | 0.00% |

- 可解析输出：180/180；强制二选一输出：180/180。
- 无效原因：`{}`。
- 恒等式残差（一致率 − both_vulnerable − both_safe − 1）：`0.0`。

## 2. 配对判别准确率（DA）

| 口径 | 值 | 95% Wilson | 分母 |
| --- | ---: | --- | ---: |
| DA（全部 180 对，invalid 记错） | 86.67% | 86.67% [80.93%, 90.87%] | 180 |
| DA（可解析输出） | 86.67% | 86.67% [80.93%, 90.87%] | 180 |
| DA（强制二选一输出） | 86.67% | 86.67% [80.93%, 90.87%] | 180 |

## 2.1 长度混淆检查（post-hoc，不是预注册基线）

| 子集（按字符长度） | n | joint correct | joint DA |
| --- | ---: | ---: | ---: |
| 漏洞版本更短 | 130 | 123 | 94.62% |
| 漏洞版本更长 | 44 | 28 | 63.64% |
| 等长 | 6 | 5 | 83.33% |

| 平凡启发式 | 正确 | DA |
| --- | ---: | ---: |
| 选较短版本（字符，tie=A） | 134 | 74.44% |
| 选较短版本（行数，tie=A） | 133 | 73.89% |

- joint vs 字符长度启发式 McNemar：b=29，c=7，p=0.0003。
- 该诊断在测试结果之后加入，仅用于判断“修复版本通常更长”这一数据伪影能在多大程度上解释 DA；它不改变主指标，也不把长度当作模型能力。

## 3. Position bias

| 漏洞版本位置 | n | correct | swapped | both | neither | invalid | DA（全部） | DA（可解析） |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A | 90 | 80 | 10 | 0 | 0 | 0 | 88.89% | 88.89% |
| B | 90 | 76 | 14 | 0 | 0 | 0 | 84.44% | 84.44% |

- DA(A) − DA(B)（全部）：4.44%；Fisher 精确 p = 0.5114。
- DA(A) − DA(B)（可解析）：4.44%；Fisher 精确 p = 0.5114。
- 选择 A/B 的次数：{'A': 94, 'B': 86}；在 A/B 选择中 A 的占比 = 52.22%，二项检验 p = 0.6020。
- 选择矩阵（行=漏洞版本位置，列=模型选择）：`{"A": {"B": 10, "A": 80}, "B": {"A": 14, "B": 76}}`。

## 4. 证据行与定位

| 指标 | 值 |
| --- | ---: |
| 有 evidence 的可解析输出 | 180 (100.00%) |
| schema 完全匹配 | 180 (100.00%) |
| evidence 合规（引用所选版本、行号在范围、code 非空） | 176 (97.78%) |
| 正确且 evidence 合规 | 152 (84.44% of all) |
| evidence 行文本精确匹配 | 363/370 (98.11%) |
| localization 可评分（correct） | 146 |
| localization 命中（correct） | 140 (95.89%) |
| 判对且定位命中 | 140 (77.78% of all) |

## 5. 与原分侧调用对比

### pair_joint (mimo-v2.6-flash) vs separate direct (mimo-v2.6-flash)

- 基线：`test_v1_mimo_direct_pairs`（mimo-v2.6-flash，策略 `direct`）；基线数据集 SHA-256 `21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d`。
- 基线检测记录状态：`{"ok": 331, "invalid": 29}`；有效对 154/180。
- 基线四类：`{"both_safe": 108, "both_vulnerable": 27, "correct": 14, "invalid": 26, "swapped": 5}`。

| 方法 | 正确/对 | DA（全部） | 95% Wilson |
| --- | ---: | ---: | --- |
| pair_joint (mimo-v2.6-flash) | 156 | 86.67% | 86.67% [80.93%, 90.87%] |
| separate direct (mimo-v2.6-flash) | 14 | 7.78% | 7.78% [4.69%, 12.63%] |

- 2×2：both correct=14，joint-only=142，baseline-only=0，both wrong=24。
- McNemar 精确检验（全部 180 对，invalid 记错）：b=142，c=0，p=3.587e-43，风险差=0.7889。
- 仅双方都有效的 154 对：joint 133 vs baseline 14；McNemar p=3.009e-36。
- 项目聚类 bootstrap ΔDA 95% CI（10k）：[0.7415, 0.8762]；joint DA CI [0.8092, 0.9550]；baseline DA CI [0.0340, 0.1226]。
- 配对级 bootstrap ΔDA 95% CI（敏感性）：[0.7278, 0.8500]。

### pair_joint (mimo-v2.6-flash) vs separate context (mimo-v2.6-flash)

- 基线：`test_v1_mimo_context_pairs`（mimo-v2.6-flash，策略 `context`）；基线数据集 SHA-256 `21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d`。
- 基线检测记录状态：`{"ok": 345, "invalid": 15}`；有效对 166/180。
- 基线四类：`{"both_safe": 106, "both_vulnerable": 38, "correct": 19, "invalid": 14, "swapped": 3}`。

| 方法 | 正确/对 | DA（全部） | 95% Wilson |
| --- | ---: | ---: | --- |
| pair_joint (mimo-v2.6-flash) | 156 | 86.67% | 86.67% [80.93%, 90.87%] |
| separate context (mimo-v2.6-flash) | 19 | 10.56% | 10.56% [6.86%, 15.90%] |

- 2×2：both correct=19，joint-only=137，baseline-only=0，both wrong=24。
- McNemar 精确检验（全部 180 对，invalid 记错）：b=137，c=0，p=1.148e-41，风险差=0.7611。
- 仅双方都有效的 166 对：joint 142 vs baseline 19；McNemar p=1.881e-37。
- 项目聚类 bootstrap ΔDA 95% CI（10k）：[0.7134, 0.8488]；joint DA CI [0.8092, 0.9550]；baseline DA CI [0.0537, 0.1538]。
- 配对级 bootstrap ΔDA 95% CI（敏感性）：[0.7000, 0.8222]。

## 6. 用量、成本、延迟

| 指标 | 值 |
| --- | ---: |
| prompt tokens 合计 | 461720 |
| completion tokens 合计 | 30598 |
| cached prompt tokens | 10240 |
| reasoning tokens | 0 |
| 每对 prompt tokens | 2565.11 |
| 总成本 USD | 0.071803 |
| 每对成本 USD | 0.000399 |
| 每正确对成本 USD | 0.000460 |
| 延迟 mean / p50 / p95 / max (s) | 6.6841 / 6.1088 / 12.9217 / 40.1151 |
| run wall (s) | 78.8410 |

## 7. 解释限制

- 联合提示强制模型二选一，不能直接复现“两侧分别调用”时的 both_flagged / both_safe 失败模式；本表的 both_vulnerable / both_safe 是模型违反指令的输出，不是两次独立判定的组合。
- 主推断按项目聚类 bootstrap；但 180 对中 `linux` 占 53 对，项目聚类区间受少数大项目支配，配对级 bootstrap 仅作敏感性分析。
- McNemar 以对为单位且假设独立；同项目相关会使 p 值偏小，因此只作为次要检验。
- 证据行定位使用 `difflib` 对漏洞/修复版本做行级 diff；源码注释中的 CVE/CWE 字符串属于数据残留，不是注入的元数据，详见 `leak_audit.json`。
- 单次贪心解码（temperature=0），没有重复采样；结果不代表模型方差。

