# SecVulEval 统计分析聚合

## 0. 分析配置

| 项目 | 值 |
| --- | --- |
| 生成时间 (UTC) | 2026-11-11T12:15:33Z |
| analysis 版本 | 1.0.0 |
| 状态 | ok |
| 是否包含真实实验结果 | True |
| fixture 模式 | False |
| runs root | runner/runs |
| datasets root | /mnt/c/Users/tzh03/Downloads/zy/datasets |
| bootstrap 次数 | 10000 |
| bootstrap seed | 42 |
| 置信水平 | 0.95 |
| cluster 单位 | auto (independent=project, pairs=pair) |
| percentile 方法 | linear |

## 1. 运行清单

| run_id | 数据集 | 策略 | 任务 | 模型 | 单元数 | 覆盖率 | partial | fixture | 已入组 | metrics 交叉检查 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| test_v1_context_independent | independent | M3 context | both | deepseek-v4.1-flash | 160 | 1.0000 | 否 | 否 | 是 | ok |
| test_v1_context_pairs | pairs | M3 context | both | deepseek-v4.1-flash | 180 | 1.0000 | 否 | 否 | 是 | ok |
| test_v1_direct_independent | independent | M1 direct | both | deepseek-v4.1-flash | 160 | 1.0000 | 否 | 否 | 是 | ok |
| test_v1_direct_pairs | pairs | M1 direct | both | deepseek-v4.1-flash | 180 | 1.0000 | 否 | 否 | 是 | ok |
| test_v1_few-shot_independent | independent | M2 few-shot | both | deepseek-v4.1-flash | 160 | 1.0000 | 否 | 否 | 是 | ok |
| test_v1_few-shot_pairs | pairs | M2 few-shot | both | deepseek-v4.1-flash | 180 | 1.0000 | 否 | 否 | 是 | ok |

### 跳过的运行

| 路径 | 原因 | 细节 |
| --- | --- | --- |
| /mnt/c/Users/tzh03/Downloads/zy/runner/runs/dev_pilot_context_independent | partial_run | limit=6 |
| /mnt/c/Users/tzh03/Downloads/zy/runner/runs/dev_pilot_context_pairs | partial_run | limit=3 |
| /mnt/c/Users/tzh03/Downloads/zy/runner/runs/dev_pilot_direct_independent | partial_run | limit=6 |
| /mnt/c/Users/tzh03/Downloads/zy/runner/runs/dev_pilot_direct_pairs | partial_run | limit=3 |
| /mnt/c/Users/tzh03/Downloads/zy/runner/runs/dev_pilot_few-shot_independent | partial_run | limit=6 |
| /mnt/c/Users/tzh03/Downloads/zy/runner/runs/dev_pilot_few-shot_pairs | partial_run | limit=3 |
| /mnt/c/Users/tzh03/Downloads/zy/runner/runs/pilot_direct_detection_1 | partial_run | limit=1 |
| /mnt/c/Users/tzh03/Downloads/zy/runner/runs/pilot_direct_detection_nothink_1 | partial_run | limit=1 |

## 2. 数据集上下文审计（不依赖模型运行）

### independent · n=160

- 数据文件：`/mnt/c/Users/tzh03/Downloads/zy/splits/test_detection_160.json`  (SHA-256 `bc83af63329963cb98c2e1f9b6d4f80e98e4dc16018d24b7308346d3abfa2bf8`)
- 项目数：40；标签计数：{'vulnerable': 128, 'non_vulnerable': 32}

| context 分层 | n | 漏洞 | 非漏洞 | 漏洞比例 |
| --- | --- | --- | --- | --- |
| nonempty | 126 | 126 | 0 | 1.0000 |
| empty | 34 | 2 | 32 | 0.0588 |
| unparsed | 0 | 0 | 0 | n/a |
| unknown | 0 | 0 | 0 | n/a |

- **数据层面 M3 伪影风险：`high`**
  - context 非空层 126 条全部为漏洞样本
  - 非空层与空层的漏洞比例相差 0.941
- flags: nonempty_stratum_single_class

### pairs · n=180

- 数据文件：`/mnt/c/Users/tzh03/Downloads/zy/splits/test_pairs_180.json`  (SHA-256 `21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d`)
- 项目数：60；标签计数：{'vulnerable': 180, 'non_vulnerable': 180}

| 漏洞侧/修复侧 context | 对数 |
| --- | --- |
| vulnerable=empty,fixed=empty | 4 |
| vulnerable=nonempty,fixed=nonempty | 176 |

- **数据层面 M3 伪影风险：`low`**
  - 配对数据中漏洞侧与修复侧共享同一函数的上下文可用性；context 非空本身不能区分两侧标签。
  - 配对标签由 side 固定（漏洞侧=1，修复侧=0），因此按 side 展开后每个 context 层都同时包含两类。
  - 以下 context 分层的对数少于 10，分层结果不稳定：{'empty': 4}
- flags: small_stratum

### independent · n=200

- 数据文件：`/mnt/c/Users/tzh03/Downloads/zy/datasets/independent_200.json`  (SHA-256 `055eccc29f640d47653f5289e6b7a9468fead248c05b137aec8779ba7461dc3d`)
- 项目数：80；标签计数：{'vulnerable': 160, 'non_vulnerable': 40}

| context 分层 | n | 漏洞 | 非漏洞 | 漏洞比例 |
| --- | --- | --- | --- | --- |
| nonempty | 156 | 156 | 0 | 1.0000 |
| empty | 44 | 4 | 40 | 0.0909 |
| unparsed | 0 | 0 | 0 | n/a |
| unknown | 0 | 0 | 0 | n/a |

- **数据层面 M3 伪影风险：`high`**
  - context 非空层 156 条全部为漏洞样本
  - 非空层与空层的漏洞比例相差 0.909
- flags: nonempty_stratum_single_class

### pairs · n=200

- 数据文件：`/mnt/c/Users/tzh03/Downloads/zy/datasets/vulnerable_fixed_200_pairs.json`  (SHA-256 `7028b98d6f2c13b960bd08dd2e737e2ba61732b89dba03e3f173fe44c27214d5`)
- 项目数：80；标签计数：{'vulnerable': 200, 'non_vulnerable': 200}

| 漏洞侧/修复侧 context | 对数 |
| --- | --- |
| vulnerable=empty,fixed=empty | 5 |
| vulnerable=nonempty,fixed=nonempty | 195 |

- **数据层面 M3 伪影风险：`low`**
  - 配对数据中漏洞侧与修复侧共享同一函数的上下文可用性；context 非空本身不能区分两侧标签。
  - 配对标签由 side 固定（漏洞侧=1，修复侧=0），因此按 side 展开后每个 context 层都同时包含两类。
  - 以下 context 分层的对数少于 10，分层结果不稳定：{'empty': 5}
- flags: small_stratum

### M3 总体风险：`high`

独立集 context 非空层 126/126 为漏洞样本，空层 34 条中 2 条漏洞、32 条非漏洞；M3 总体差异与 context 可用性混杂，非空层是单类别，macro-F1 不可定义。配对集 176 对两侧非空、4 对两侧为空；空层过小，分层结果不稳定。

### M3 报告要求（与是否有模型运行无关）

- 报告 M3 时必须同时给出 context 非空/空分层的 n 与指标，不能只报总体值。
- 不得把 M3 与 M1 的总体差异单独归因于“上下文推理能力”；差异与上下文可用性混杂。
- 若某个分层是单类别，macro-F1 与 balanced accuracy 不可定义，应报告正类 F1/召回或负类 specificity，而不是填 0。
- 上下文分层属于预先登记的探索性分析；样本过少的分层必须标注 n，并避免强结论。
- 更严格的因果比较需要标签无关的上下文构造，并作为新策略单独登记、重新运行。

## 3. 模型结果聚合

### independent|both|deepseek-v4.1-flash|bc83af633299

- cohort n=160；complete-case n=160；参考策略=direct

| 策略 | n | 有效 | 覆盖率 | Precision | Recall | Specificity | 正类 F1 | Accuracy | Balanced Acc | MCC | Macro-F1 | 严格 Acc（全部） |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| M1 direct | 160 | 160 | 1.0000 [0.9766, 1.0000] | 0.8261 [0.6928, 0.9091] | 0.2969 [0.2246, 0.3810] | 0.7500 [0.5789, 0.8675] | 0.4368 | 0.3875 [0.3155, 0.4648] | 0.5234 [0.4429, 0.6402] | 0.0414 [-0.0996, 0.2481] | 0.3828 [0.3047, 0.5521] | 0.3875 [0.3155, 0.4648] |
| M2 few-shot | 160 | 160 | 1.0000 [0.9766, 1.0000] | 0.8367 [0.7096, 0.9149] | 0.3203 [0.2457, 0.4054] | 0.7500 [0.5789, 0.8675] | 0.4633 | 0.4062 [0.3332, 0.4837] | 0.5352 [0.4494, 0.6675] | 0.0610 [-0.0871, 0.2939] | 0.3995 [0.3054, 0.5933] | 0.4062 [0.3332, 0.4837] |
| M3 context | 160 | 160 | 1.0000 [0.9766, 1.0000] | 0.8125 [0.6806, 0.8981] | 0.3047 [0.2316, 0.3892] | 0.7188 [0.5463, 0.8444] | 0.4432 | 0.3875 [0.3155, 0.4648] | 0.5117 [0.4273, 0.6336] | 0.0205 [-0.1271, 0.2342] | 0.3813 [0.2855, 0.5596] | 0.3875 [0.3155, 0.4648] |

> 表中 n 为 cohort 全部单元数，有效为 complete-case 单元数（在每个策略都有有效预测）；覆盖率为全部 cohort 单元上的有效比例。Macro-F1、Balanced Acc、MCC 的方括号为 10000 次 project cluster bootstrap 的 95% percentile 区间；Precision/Recall/Specificity/Accuracy 的方括号为 Wilson 95% 区间。

#### context 非空/空分层（M3 伪影检查）

| 策略 | context 分层 | n | 漏洞/非漏洞 | 有效 | 覆盖率 | 正类 F1 | 负类 F1 | Accuracy | Macro-F1 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| M1 direct | nonempty | 126 | 126/0 | 126 | 1.0000 [0.9704, 1.0000] | 0.4540 | n/a | 0.2937 [0.2212, 0.3783] | n/a（单类别） |
| M1 direct | empty | 34 | 2/32 | 34 | 1.0000 [0.8985, 1.0000] | 0.1818 | 0.8421 | 0.7353 [0.5688, 0.8540] | 0.5120 |
| M2 few-shot | nonempty | 126 | 126/0 | 126 | 1.0000 [0.9704, 1.0000] | 0.4819 | n/a | 0.3175 [0.2426, 0.4031] | n/a（单类别） |
| M2 few-shot | empty | 34 | 2/32 | 34 | 1.0000 [0.8985, 1.0000] | 0.1818 | 0.8421 | 0.7353 [0.5688, 0.8540] | 0.5120 |
| M3 context | nonempty | 126 | 126/0 | 126 | 1.0000 [0.9704, 1.0000] | 0.4634 | n/a | 0.3016 [0.2283, 0.3866] | n/a（单类别） |
| M3 context | empty | 34 | 2/32 | 34 | 1.0000 [0.8985, 1.0000] | 0.1667 | 0.8214 | 0.7059 [0.5383, 0.8317] | 0.4940 |

- L3 prompt 元数据交叉检查：检查 160 条，不一致 0 条。

**M3 − M1 分层差值（探索性）**

| 分层 | n | Δ严格 Acc | Δ严格 Acc [CI] | ΔAccuracy（有效） | ΔMacro-F1 |
| --- | --- | --- | --- | --- | --- |
| nonempty | 126 | 0.0079 | 0.0079 [-0.0315, 0.0588] | 0.0079 | n/a |
| empty | 34 | -0.0294 | -0.0294 [-0.1071, 0.0000] | -0.0294 | -0.0179 |

> `n/a（单类别）` 表示该分层内只有一个类别；此时 macro-F1/balanced accuracy 不可定义。独立集的 context 非空层全部为漏洞样本（空层以非漏洞样本为主）时，分层 macro-F1 无法估计，只能报告正类 F1/召回（非空层）或 specificity/负类 F1（空层）。

#### M3 伪影风险评估

- **风险等级：`high`**
- 适用对象：M3 (context strategy)
- 数据层面：P(漏洞|context 非空)=1.0000，P(漏洞|context 空)=0.0588，差值=0.9412
- context 非空层 126 条全部为漏洞样本
- 非空层与空层的漏洞比例相差 0.941
- flags: nonempty_stratum_single_class

**报告时必须遵守：**
- 报告 M3 时必须同时给出 context 非空/空分层的 n 与指标，不能只报总体值。
- 不得把 M3 与 M1 的总体差异单独归因于“上下文推理能力”；差异与上下文可用性混杂。
- 若某个分层是单类别，macro-F1 与 balanced accuracy 不可定义，应报告正类 F1/召回或负类 specificity，而不是填 0。
- 上下文分层属于预先登记的探索性分析；样本过少的分层必须标注 n，并避免强结论。
- 更严格的因果比较需要标签无关的上下文构造，并作为新策略单独登记、重新运行。

#### 逐样本 McNemar 精确检验（Holm 校正）

**主分析（全部单元，invalid=错）** · metric=`end_to_end_correctness_all_units`

| 比较 | n | A✓B✗ | A✗B✓ | p（原始） | p（Holm） | 拒绝 H0（α=0.05） | 风险差 | OR |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| M1 direct vs M2 few-shot | 160 | 4 | 7 | 0.5488 | 1.0000 | 否 | -0.0187 | 0.5714 |
| M1 direct vs M3 context | 160 | 4 | 4 | 1.0000 | 1.0000 | 否 | 0.0000 | 1.0000 |
| M2 few-shot vs M3 context | 160 | 6 | 3 | 0.5078 | 1.0000 | 否 | 0.0187 | 2.0000 |

**次要分析（两侧均有效）** · metric=`correctness_on_units_valid_in_both`

| 比较 | n | A✓B✗ | A✗B✓ | p（原始） | p（Holm） | 拒绝 H0（α=0.05） | 风险差 | OR |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| M1 direct vs M2 few-shot | 160 | 4 | 7 | 0.5488 | 1.0000 | 否 | -0.0187 | 0.5714 |
| M1 direct vs M3 context | 160 | 4 | 4 | 1.0000 | 1.0000 | 否 | 0.0000 | 1.0000 |
| M2 few-shot vs M3 context | 160 | 6 | 3 | 0.5078 | 1.0000 | 否 | 0.0187 | 2.0000 |

> McNemar 假设单元独立；同项目单元相关会使 p 值偏小。主推断应以按 project/pair 聚类的 bootstrap 差值区间为准，McNemar 仅作次要证据。

#### 聚类 bootstrap 差值区间

| 比较 | 指标 | Δ [95% bootstrap CI] | 有效重采样 |
| --- | --- | --- | --- |
| direct vs few-shot | Macro-F1 | -0.0167 [-0.0581, 0.0119] | 10000 |
| direct vs few-shot | Balanced Acc | -0.0117 [-0.0444, 0.0084] | 10000 |
| direct vs few-shot | MCC | -0.0196 [-0.0762, 0.0140] | 10000 |
| direct vs few-shot | Accuracy | -0.0187 [-0.0660, 0.0136] | 10000 |
| direct vs context | Macro-F1 | 0.0015 [-0.0328, 0.0364] | 10000 |
| direct vs context | Balanced Acc | 0.0117 [-0.0238, 0.0569] | 10000 |
| direct vs context | MCC | 0.0210 [-0.0397, 0.1024] | 10000 |
| direct vs context | Accuracy | 0.0000 [-0.0390, 0.0362] | 10000 |
| few-shot vs context | Macro-F1 | 0.0182 [-0.0102, 0.0657] | 10000 |
| few-shot vs context | Balanced Acc | 0.0234 [-0.0076, 0.0808] | 10000 |
| few-shot vs context | MCC | 0.0406 [-0.0126, 0.1434] | 10000 |
| few-shot vs context | Accuracy | 0.0187 [-0.0120, 0.0654] | 10000 |

| 比较 | 指标（end-to-end） | Δ [95% bootstrap CI] | 有效重采样 |
| --- | --- | --- | --- |
| direct vs few-shot | 严格 Acc（全部） | -0.0187 [-0.0660, 0.0136] | 10000 |
| direct vs few-shot | 覆盖率 | 0.0000 [0.0000, 0.0000] | 10000 |
| direct vs context | 严格 Acc（全部） | 0.0000 [-0.0390, 0.0362] | 10000 |
| direct vs context | 覆盖率 | 0.0000 [0.0000, 0.0000] | 10000 |
| few-shot vs context | 严格 Acc（全部） | 0.0187 [-0.0120, 0.0654] | 10000 |
| few-shot vs context | 覆盖率 | 0.0000 [0.0000, 0.0000] | 10000 |

> 差值方向为 A−B（按策略顺序）；同一 cluster 重采样同时用于两个策略，因此区间是配对差值区间。有效重采样少于总数 90% 时标记为不稳定。

---

### pairs|both|deepseek-v4.1-flash|21218fd8db79

- cohort 对数=180；complete-case 对数=180；参考策略=direct

| 策略 | 对数 | 有效对 | 覆盖率 | 联合 Acc（有效对） | 联合 Acc（全部对） | 正确区分 | 双报漏洞 | 双报安全 | 判反（漏报+误报） |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| M1 direct | 180 | 180 | 1.0000 [0.9791, 1.0000] | 0.1167 [0.0776, 0.1718] | 0.1167 [0.0776, 0.1718] | 21 (0.1167) | 44 (0.2444) | 113 (0.6278) | 2 (0.0111) |
| M2 few-shot | 180 | 180 | 1.0000 [0.9791, 1.0000] | 0.0889 [0.0555, 0.1395] | 0.0889 [0.0555, 0.1395] | 16 (0.0889) | 49 (0.2722) | 113 (0.6278) | 2 (0.0111) |
| M3 context | 180 | 180 | 1.0000 [0.9791, 1.0000] | 0.1222 [0.0821, 0.1781] | 0.1222 [0.0821, 0.1781] | 22 (0.1222) | 49 (0.2722) | 108 (0.6000) | 1 (0.0056) |

> 表中“对数”为 cohort 全部 pair 数，“有效对”为 complete-case pair 数；覆盖率为全部 cohort pair 上的有效比例。联合 Acc（有效对）只使用两侧都有效的 pair；联合 Acc（全部对）把任一侧无效的 pair 计为失败。口径与 `runner/secvul_runner/metrics.py` 的 `discrimination_accuracy_valid_pairs` / `discrimination_accuracy_all_pairs` 一致。

#### 分侧指标（Table 8 准备）

| 策略 | 覆盖率 | 漏洞侧 n | 漏洞侧 P | 漏洞侧 R | 漏洞侧 F1 | 修复侧 n | 修复侧 Accuracy | 修复侧 Specificity | 总体 Accuracy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| M1 direct | 1.0000 [0.9791, 1.0000] | 180 | 1.0000 [0.9442, 1.0000] | 0.3611 [0.2945, 0.4335] | 0.5306 | 180 | 0.7444 [0.6761, 0.8026] | 0.7444 [0.6761, 0.8026] | 0.5528 [0.5011, 0.6033] |
| M2 few-shot | 1.0000 [0.9791, 1.0000] | 180 | 1.0000 [0.9442, 1.0000] | 0.3611 [0.2945, 0.4335] | 0.5306 | 180 | 0.7167 [0.6468, 0.7774] | 0.7167 [0.6468, 0.7774] | 0.5389 [0.4873, 0.5897] |
| M3 context | 1.0000 [0.9791, 1.0000] | 180 | 1.0000 [0.9487, 1.0000] | 0.3944 [0.3260, 0.4673] | 0.5657 | 180 | 0.7222 [0.6527, 0.7825] | 0.7222 [0.6527, 0.7825] | 0.5583 [0.5067, 0.6087] |

> 分侧指标把每个版本当作一条检测记录，仅作次要描述；配对相关未在 Wilson 区间中校正。

#### context 非空/空分层（M3 伪影检查）

| 策略 | context 分层 | 对数 | 有效对 | 覆盖率 | 联合 Acc（有效对） | 联合 Acc（全部对） | 双报漏洞 | 双报安全 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| M1 direct | nonempty | 176 | 176 | 1.0000 [0.9786, 1.0000] | 0.1193 [0.0794, 0.1755] | 0.1193 [0.0794, 0.1755] | 0.2386 | 0.6307 |
| M1 direct | empty | 4 | 4 | 1.0000 [0.5101, 1.0000] | 0.0000 [0.0000, 0.4899] | 0.0000 [0.0000, 0.4899] | 0.5000 | 0.5000 |
| M2 few-shot | nonempty | 176 | 176 | 1.0000 [0.9786, 1.0000] | 0.0909 [0.0567, 0.1426] | 0.0909 [0.0567, 0.1426] | 0.2670 | 0.6307 |
| M2 few-shot | empty | 4 | 4 | 1.0000 [0.5101, 1.0000] | 0.0000 [0.0000, 0.4899] | 0.0000 [0.0000, 0.4899] | 0.5000 | 0.5000 |
| M3 context | nonempty | 176 | 176 | 1.0000 [0.9786, 1.0000] | 0.1250 [0.0840, 0.1820] | 0.1250 [0.0840, 0.1820] | 0.2670 | 0.6023 |
| M3 context | empty | 4 | 4 | 1.0000 [0.5101, 1.0000] | 0.0000 [0.0000, 0.4899] | 0.0000 [0.0000, 0.4899] | 0.5000 | 0.5000 |

- L3 prompt 元数据交叉检查：检查 360 条，不一致 0 条。

**M3 − M1 分层差值（探索性）**

| 分层 | 对数 | Δ联合 Acc | Δ [bootstrap CI] |
| --- | --- | --- | --- |
| nonempty | 176 | 0.0057 | 0.0057 [-0.0284, 0.0455] |
| empty | 4 | 0.0000 | 0.0000 [0.0000, 0.0000] |

> `n/a（单类别）` 表示该分层内只有一个类别；此时 macro-F1/balanced accuracy 不可定义。独立集的 context 非空层全部为漏洞样本（空层以非漏洞样本为主）时，分层 macro-F1 无法估计，只能报告正类 F1/召回（非空层）或 specificity/负类 F1（空层）。

#### M3 伪影风险评估

- **风险等级：`low`**
- 适用对象：M3 (context strategy)
- 配对 context：非空 176 对，空 4 对，小分层 {'empty': 4}
- 配对数据中漏洞侧与修复侧共享同一函数的上下文可用性；context 非空本身不能区分两侧标签。
- 配对标签由 side 固定（漏洞侧=1，修复侧=0），因此按 side 展开后每个 context 层都同时包含两类。
- 以下 context 分层的对数少于 10，分层结果不稳定：{'empty': 4}
- flags: small_stratum

**报告时必须遵守：**
- 报告 M3 时必须同时给出 context 非空/空分层的 n 与指标，不能只报总体值。
- 不得把 M3 与 M1 的总体差异单独归因于“上下文推理能力”；差异与上下文可用性混杂。
- 若某个分层是单类别，macro-F1 与 balanced accuracy 不可定义，应报告正类 F1/召回或负类 specificity，而不是填 0。
- 上下文分层属于预先登记的探索性分析；样本过少的分层必须标注 n，并避免强结论。
- 更严格的因果比较需要标签无关的上下文构造，并作为新策略单独登记、重新运行。

#### 逐样本 McNemar 精确检验（Holm 校正）

**主分析（全部单元，invalid=错）** · metric=`joint_correct_all_pairs`

| 比较 | n | A✓B✗ | A✗B✓ | p（原始） | p（Holm） | 拒绝 H0（α=0.05） | 风险差 | OR |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| M1 direct vs M2 few-shot | 180 | 8 | 3 | 0.2266 | 0.4531 | 否 | 0.0278 | 2.6667 |
| M1 direct vs M3 context | 180 | 5 | 6 | 1.0000 | 1.0000 | 否 | -0.0056 | 0.8333 |
| M2 few-shot vs M3 context | 180 | 3 | 9 | 0.1460 | 0.4380 | 否 | -0.0333 | 0.3333 |

**次要分析（两侧均有效）** · metric=`joint_correct_on_pairs_valid_in_both`

| 比较 | n | A✓B✗ | A✗B✓ | p（原始） | p（Holm） | 拒绝 H0（α=0.05） | 风险差 | OR |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| M1 direct vs M2 few-shot | 180 | 8 | 3 | 0.2266 | 0.4531 | 否 | 0.0278 | 2.6667 |
| M1 direct vs M3 context | 180 | 5 | 6 | 1.0000 | 1.0000 | 否 | -0.0056 | 0.8333 |
| M2 few-shot vs M3 context | 180 | 3 | 9 | 0.1460 | 0.4380 | 否 | -0.0333 | 0.3333 |

> McNemar 假设单元独立；同项目单元相关会使 p 值偏小。主推断应以按 project/pair 聚类的 bootstrap 差值区间为准，McNemar 仅作次要证据。

#### 聚类 bootstrap 差值区间

| 比较 | 指标 | Δ [95% bootstrap CI] | 有效重采样 |
| --- | --- | --- | --- |
| direct vs few-shot | Macro-F1 | 0.0119 [-0.0121, 0.0369] | 10000 |
| direct vs few-shot | Balanced Acc | 0.0139 [-0.0083, 0.0361] | 10000 |
| direct vs few-shot | MCC | 0.0311 [-0.0163, 0.0807] | 10000 |
| direct vs few-shot | 联合 Acc（有效对） | 0.0278 [-0.0056, 0.0667] | 10000 |
| direct vs context | Macro-F1 | -0.0104 [-0.0321, 0.0105] | 10000 |
| direct vs context | Balanced Acc | -0.0056 [-0.0250, 0.0139] | 10000 |
| direct vs context | MCC | -0.0092 [-0.0537, 0.0341] | 10000 |
| direct vs context | 联合 Acc（有效对） | -0.0056 [-0.0390, 0.0278] | 10000 |
| few-shot vs context | Macro-F1 | -0.0223 [-0.0464, 0.0009] | 10000 |
| few-shot vs context | Balanced Acc | -0.0194 [-0.0417, 0.0000] | 10000 |
| few-shot vs context | MCC | -0.0403 [-0.0866, 0.0032] | 10000 |
| few-shot vs context | 联合 Acc（有效对） | -0.0333 [-0.0722, 0.0056] | 10000 |

| 比较 | 指标（end-to-end） | Δ [95% bootstrap CI] | 有效重采样 |
| --- | --- | --- | --- |
| direct vs few-shot | 联合 Acc（全部对） | 0.0278 [-0.0056, 0.0667] | 10000 |
| direct vs few-shot | 覆盖率 | 0.0000 [0.0000, 0.0000] | 10000 |
| direct vs context | 联合 Acc（全部对） | -0.0056 [-0.0390, 0.0278] | 10000 |
| direct vs context | 覆盖率 | 0.0000 [0.0000, 0.0000] | 10000 |
| few-shot vs context | 联合 Acc（全部对） | -0.0333 [-0.0722, 0.0056] | 10000 |
| few-shot vs context | 覆盖率 | 0.0000 [0.0000, 0.0000] | 10000 |

> 差值方向为 A−B（按策略顺序）；同一 cluster 重采样同时用于两个策略，因此区间是配对差值区间。有效重采样少于总数 90% 时标记为不稳定。

---

## 4. 警告

- independent dataset: context availability is strongly associated with the label; M3 overall comparisons are confounded and must be reported with context strata.
- independent dataset: context availability is strongly associated with the label; M3 overall comparisons are confounded and must be reported with context strata.

## 5. 复现命令

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && \
python3 analysis/analyze_runs.py \
  --runs-root runner/runs \
  --bootstrap 10000 --seed 42'
```

自检（临时合成 fixture，运行后自动删除，不写入正式结果）：

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && python3 analysis/selftest.py'
```

## 6. 限制

- All model metrics come from results.jsonl of completed runs; this script never imputes or mocks predictions.
- Wilson intervals are reported for proportions. macro-F1, balanced accuracy, MCC, and paired differences use the cluster percentile bootstrap.
- Project-cluster bootstrap treats projects as independent; this does not guarantee generalization to unseen projects.
- McNemar assumes independent units; same-project correlation can make p-values anti-conservative.
- Context strata are a data-level stratification. In this dataset context availability is correlated with the label, so M3 overall effects are confounded with context availability.
- Results reflect the single run per strategy listed above; they are not a multi-seed or multi-model estimate.
