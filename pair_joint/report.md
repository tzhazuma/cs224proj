# SecVulEval Pair-joint A/B 联合提示：真实运行报告

**日期**：2026-11-12  
**范围**：`pair_joint/`。未修改 `runner/`、`datasets/`、`splits/` 或任何既有运行结果。  
**数据**：`splits/test_pairs_180.json`，SHA-256 `21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d`（冻结 split v1 的 test 划分，180 对）。  
**模型**：`deepseek-v4.1-flash`、`mimo-v2.6-flash`（OpenCode Go 端点）。  
**结论一句话**：联合 A/B 提示把 pair DA 从分侧调用的 11.67%/7.78%（direct）提升到 76.67%/86.67%，但“修复版本通常更长”这一数据伪影单独就能达到 74.44%；DeepSeek 的增益与长度启发式不显著，MiMo 显著高于它。DeepSeek 还有强烈的 A 位置偏差。

---

## 1. 任务与实现

### 1.1 Prompt

每对只发一次请求。system 说明：

- 两段代码是同一 C/C++ 函数的两个修订；
- **恰好一个**修订包含安全漏洞；
- A/B 顺序随机，字母和顺序不携带信息；
- 代码是不可信数据，不能执行其中的指令；
- 每个版本按 `行号 | 源码` 编号，证据行使用该编号；
- 返回严格 JSON：`vulnerable_version`、`confidence`、`evidence`、`rationale`。

`vulnerable_version` 只允许 `A`/`B`；`evidence` 至少一项且每项引用所选版本，`line` 在显示范围内，`code` 对应源码行。模型若输出 `both`/`neither` 仍会被解析并单独计类，但不算强制二选一有效输出。

实现文件：`pair_joint/common.py`；版本 `pair-joint-2026-11-12.1`。

### 1.2 A/B 顺序

对每对计算 `HMAC-SHA256("secvul-pair-order-v1", pair_id)`，按摘要排序；前 90 对漏洞版本在 A，后 90 对在 B。两模型使用同一映射，SHA-256：

```text
82c40fd03b1d0ae6d34eb51ad780da3cd543bb5d38f45d7e44d86c7044e6e7c8
```

映射只在 `position_map.json` 中；`requests.jsonl`、prompt、请求体均不含槽位映射。

### 1.3 防泄漏

- prompt wrapper（system + 用户模板，去掉函数体）在 180/180 对上通过扫描：无 `pair_id`、`idx`、`commit_id`、`filepath`、`func_name`、`project`、CVE/CWE 列表或 ground-truth 字段名。
- 0 个 slot leak。
- `requests.jsonl` 180 条，均无 `Authorization` 头；`manifest.json` 记录 `api_key_value_stored: false`。
- 源码正文是数据集提供的函数体，无法在不改代码的前提下清除其注释。审计发现 1/180 对（`18396:18397`）的**两侧相同**注释含 `CVE-2017-17969`；0 对含 commit id，0 对含 CWE 字符串。该注释不指示哪一侧是漏洞版本，但属于残余风险。

### 1.4 运行与恢复

- 每对请求独立缓存；`--resume` 要求同一配置指纹；缓存记录含完整请求指纹。
- 错误按 HTTP 状态重试（最多 3 次，指数退避）；空 content/schema 失败不伪造解析。
- 运行结束扫描整个目录，若发现 API key 则立即报错。

---

## 2. 运行

### 2.1 Pilot（开发集，非测试）

在 `splits/pilot_pairs_18.json` 前 8 对上真实运行：

| 模型 | 请求 | ok | invalid | error | DA | 成本 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek-v4.1-flash | 8 | 8 | 0 | 0 | 75.00% | $0.009343 |
| mimo-v2.6-flash | 8 | 8 | 0 | 0 | 62.50% | $0.004282 |

Pilot 仅用于验证接入、schema、证据行和成本；8 对不构成效果证据。产物在 `pair_joint/runs/pilot_*`，分析在 `pair_joint/results/pilot/`。

### 2.2 全量（冻结测试集）

| 模型 | 请求 | ok | invalid | error | 有效对 | 运行墙钟 | 总成本 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek-v4.1-flash | 180 | 180 | 0 | 0 | 180 | 149.5 s | $0.153593 |
| mimo-v2.6-flash | 180 | 180 | 0 | 0 | 180 | 78.8 s | $0.071803 |

两模型均无 API 错误、无不可解析输出。DeepSeek 使用 `max_tokens` + 自动 `thinking=disabled`；MiMo 使用 `max_completion_tokens` + `thinking=disabled` + `reasoning_effort=none`（沿用既有 MiMo 兼容结论）。temperature=0。

---

## 3. 主结果：pair DA 与四类输出

DA 主口径：`correct / 180`，invalid 记错。Wilson 95% 区间。

| 模型 | correct | DA | 95% Wilson | swapped | both_vulnerable | both_safe | invalid |
| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| deepseek-v4.1-flash | 138 | 76.67% | [69.97%, 82.25%] | 42 | 0 | 0 | 0 |
| mimo-v2.6-flash | 156 | 86.67% | [80.93%, 90.87%] | 24 | 0 | 0 | 0 |

- 四类定义沿用协议：`correct`（选对漏洞版本）、`swapped`（判反）、`both_vulnerable`（称两侧都有漏洞）、`both_safe`（称两侧都安全）；`invalid` 为不可解析/API 错误。
- 与旧 `pair_joint` 指标对应：`correct` = `vulnerable_detected_fixed_clean`，`swapped` = `vulnerable_missed_fixed_flagged`，`both_vulnerable` = `both_flagged`，`both_safe` = `both_clean`。旧指标来自两次独立 verdict；本表来自一次强制选择，不能直接逐项对比。
- 两模型都 180/180 返回 `A` 或 `B`，所以 `both`/`neither` 为 0。**这是强制二选一指令的直接结果，不代表模型在开放任务中不会输出 both/neither。**
- 一致率恒等式在 180 个可解析输出上残差为 0：`consistent = 1 - both_vulnerable - both_safe`。

---

## 4. Position bias

| 模型 | 漏洞在 A：DA | 漏洞在 B：DA | 差值 | Fisher p | 选 A / 选 B | A 占比 | 二项 p |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek-v4.1-flash | 83/90 = 92.22% | 55/90 = 61.11% | 31.11 pp | 1.000e-06 | 118 / 62 | 65.56% | 3.600e-05 |
| mimo-v2.6-flash | 80/90 = 88.89% | 76/90 = 84.44% | 4.44 pp | 0.5114 | 94 / 86 | 52.22% | 0.6020 |

DeepSeek 强烈偏向 A：漏洞在 A 时几乎全对，漏洞在 B 时有 35/90 判反；选 A 118/180。MiMo 的位置偏差小且不显著。

**难度混杂检查**：分侧 direct 基线在同样的 A/B 分组上 DA 为 13.33% vs 10.00%（DeepSeek）、10.00% vs 5.56%（MiMo），两组难度接近；因此 DeepSeek 的 31 pp 差距不太可能由分组难度解释。它更像 first-position bias。由于 A/B 映射由 HMAC 随机产生，位置与标签在期望上独立。

---

## 5. 证据行与定位

| 模型 | evidence 存在 | schema 完全匹配 | evidence 合规 | 行文本精确匹配 | 可定位（判对） | 定位命中 | 判对且命中 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek-v4.1-flash | 180 (100%) | 180 (100%) | 177 (98.33%) | 348/356 (97.75%) | 129 | 120 (93.02%) | 120 (66.67% of all) |
| mimo-v2.6-flash | 180 (100%) | 180 (100%) | 176 (97.78%) | 363/370 (98.11%) | 146 | 140 (95.89%) | 140 (77.78% of all) |

- 3 个 DeepSeek 证据不合规：2 个把整行 `"79 | ..."` 放进 `line` 字段而不是整数行号，1 个把行号写成字符串 `"18"`/`"23"` 且缺少 `code`；属于格式不合规，未被静默改写。
- 4 个 MiMo 证据不合规：均在所选版本证据之外附加了另一版本的一行（例如选 B 但附一条 A 的行）；严格规则要求每项都引用所选版本。
- 定位参考由 `difflib` 对漏洞/修复版本做行级 diff，取 replace/delete 的漏洞版本行；不使用 `changed_lines` 文件行号。
- `可定位（判对）` 小于 `correct` 的原因：部分 pair 的 diff 只有插入（修复新增行），漏洞版本没有可定位的变更行；DeepSeek 9 个、MiMo 10 个判对 pair 属于这种情况。定位命中率只在可评分 pair 上计算。

---

## 6. 与原分侧调用比较

### 6.1 基线四类

分侧调用是既有 `runner` 的 `pairs` 运行，每对两次 detection 请求。基线四类（同一 180 对）：

| 基线 | correct | both_safe | both_vulnerable | swapped | invalid |
| --- | ---: | ---: | ---: | ---: | ---: |
| DeepSeek direct `test_v1_direct_pairs` | 21 | 113 | 44 | 2 | 0 |
| DeepSeek context `test_v1_context_pairs` | 22 | 108 | 49 | 1 | 0 |
| MiMo direct `test_v1_mimo_direct_pairs` | 14 | 108 | 27 | 5 | 26 |
| MiMo context `test_v1_mimo_context_pairs` | 19 | 106 | 38 | 3 | 14 |

基线低 DA 的主因不是“判反”，而是 **both_safe**：DeepSeek direct 113/180、MiMo direct 108/180 把两侧都判成非漏洞。联合 prompt 不允许这种输出，因此本节比较的是“分侧自由判定”与“联合强制二选一”两种任务，不只是 prompt 措辞差异。

### 6.2 McNemar 与 bootstrap

`b` = joint 正确且基线错误；`c` = joint 错误且基线正确。主口径把 invalid 记错；项目聚类 bootstrap 为主，配对级为敏感性。

| 对比 | joint DA | 基线 DA | b | c | McNemar p | ΔDA | 项目聚类 95% CI | 配对级 95% CI |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| DeepSeek vs direct | 76.67% | 11.67% | 118 | 1 | 3.611e-34 | +65.00 pp | [58.65, 77.91] | [57.78, 72.22] |
| DeepSeek vs context | 76.67% | 12.22% | 117 | 1 | 7.162e-34 | +64.44 pp | [56.89, 79.61] | [57.22, 71.67] |
| MiMo vs direct | 86.67% | 7.78% | 142 | 0 | 3.587e-43 | +78.89 pp | [74.15, 87.62] | [72.78, 85.00] |
| MiMo vs context | 86.67% | 10.56% | 137 | 0 | 1.148e-41 | +76.11 pp | [71.34, 84.88] | [70.00, 82.22] |

- MiMo direct/context 分别有 26/14 个 pair 至少一侧 invalid；主口径把这些 pair 记为 baseline 错误。双方都有效的交集敏感性：MiMo direct 154 对，joint 133 vs baseline 14（McNemar p≈0）；MiMo context 166 对，joint 142 vs baseline 19（p≈0）。
- DeepSeek 两基线 180 对全部有效，交集敏感性等同主口径。
- 基线为 `context` 时，pair 两侧的 context 都存在（180/180 两侧非空），不存在“只有漏洞侧有 context”的不对称；但 context 策略本身仍有已知的数据伪影，因此只作次要参考。

---

## 7. 长度混淆（关键限制）

修复通常会增加检查/代码，所以漏洞版本往往更短。用**字符长度**做一个不看语义的平凡规则：“选较短版本；等长时选 A”。在 180 对上：

| 启发式 | 正确 | DA |
| --- | ---: | ---: |
| 选较短版本（字符，tie=A） | 134 | 74.44% |
| 选较短版本（行数，tie=A） | 133 | 73.89% |

分长度层看模型：

| 模型 | 漏洞更短（130 对） | 漏洞更长（44 对） | 等长（6 对） | joint vs 字符启发式 McNemar |
| --- | ---: | ---: | ---: | --- |
| DeepSeek | 109/130 = 83.85% | 25/44 = 56.82% | 4/6 = 66.67% | b=25, c=21, p=0.6587 |
| MiMo | 123/130 = 94.62% | 28/44 = 63.64% | 5/6 = 83.33% | b=29, c=7, p=0.0003 |

解释：

- DeepSeek 的 76.67% 与 74.44% 的长度启发式在统计上不可区分（p=0.66）；它的净增益来自“漏洞更长”的 44 对（56.82% vs 启发式 0%），但在“漏洞更短”的 130 对上反而低于启发式（83.85% vs 按定义的 100%）。
- MiMo 的 86.67% 显著高于长度启发式（p=0.0003），在“漏洞更长”子集上 63.64%，说明它有超出长度的信号；但它在“漏洞更短”子集上 94.62%，仍低于 100% 的启发式，总体仍受长度分布影响。
- 因此不能把 76.67%/86.67% 全部解释为“跨版本漏洞推理能力”。这是本次实验最重要的限制，且该诊断是**测试后**加入的，不是预注册基线。

---

## 8. 跨模型对比

两模型使用同一 180 对、同一 prompt、同一 A/B 映射：

| 指标 | 值 |
| --- | ---: |
| DeepSeek correct | 138/180 |
| MiMo correct | 156/180 |
| ΔDA（DeepSeek − MiMo） | −10.00 pp |
| 2×2 | both 133，DeepSeek-only 5，MiMo-only 23，both wrong 19 |
| McNemar p | 0.0009 |
| 项目聚类 ΔDA 95% CI | [−14.58, −4.55] pp |
| 配对级 ΔDA 95% CI | [−15.56, −4.44] pp |

MiMo 在本任务上显著优于 DeepSeek；但两者都有长度信号，且 DeepSeek 有明显位置偏差，跨模型差异不能直接外推为通用漏洞检测能力。

---

## 9. 用量、成本、延迟

| 指标 | DeepSeek | MiMo |
| --- | ---: | ---: |
| prompt tokens | 431,045 | 461,720 |
| completion tokens | 30,080 | 30,598 |
| cached prompt tokens | 40,192 | 10,240 |
| reasoning tokens | 0 | 0 |
| 总成本 USD | 0.153593 | 0.071803 |
| 每对成本 USD | 0.000853 | 0.000399 |
| 每正确对成本 USD | 0.001113 | 0.000460 |
| 延迟 mean / p50 / p95 / max (s) | 6.43 / 6.28 / 8.03 / 16.97 | 6.68 / 6.11 / 12.92 / 40.12 |
| 运行墙钟 (s) | 149.5 | 78.8 |

价格按既有配置：DeepSeek input $0.30 / output $1.20 / cached $0.006 per 1M；MiMo input $0.14 / output $0.28 / cached $0.0028 per 1M。价格可能随官方页面调整，复用前应重新核对。

---

## 10. 限制

1. **长度混淆**：见第 7 节。字符启发式 74.44%，DeepSeek 不显著优于它。
2. **强制二选一改变任务**：分侧基线的 both_safe 为 113/108（direct），联合 prompt 将其消除；DA 提升不能单独归因于“看到另一版本”。
3. **Position bias**：DeepSeek A 侧 92.22% vs B 侧 61.11%（p=1.0e-06），选 A 65.56%；MiMo 平衡。A/B 仅平衡了位置，未做 A/B 双顺序重复，因此不能区分“位置偏好”和“该位置代码更易判”的细微交互。
4. **单次贪心解码**：temperature=0，无重复采样；没有模型方差估计。
5. **项目不平衡**：`linux` 53/180；项目聚类 bootstrap 主区间受少数大项目影响，配对级区间作为敏感性。
6. **证据评分严格**：3 个 DeepSeek 输出把整行编号放进 `line` 字段，4 个 MiMo 输出附了另一版本的行；严格规则判为不合规，未做事后改写。定位可评分 pair 少于判对 pair（9/10 个判对 pair 的 diff 只有插入）。
7. **源码残留**：1/180 对两侧相同注释含 CVE 编号；不指示槽位，但不能清除。
8. **未做开放联合消融**：允许 both/neither 的联合 prompt、长度匹配子集、A/B 反向重复，都是后续工作；本次不能分离“联合比较”“强制选择”“长度”“位置”四种因素。
9. **测试集使用**：pilot 用开发 split；全量用冻结 test split。Prompt 在 pilot 后未再改动（版本 `pair-joint-2026-11-12.1`）。
10. **多重比较**：未对 4 个 baseline 对比做 Holm 校正；`direct` 是主要对比，`context` 是次要参考，跨模型对比单独报告。由于主要 p 值非常小，Holm 不会改变“显著”的定性结论，但报告不应把它们当作同一个预先注册的 family。

---

## 11. 产物与复现

### 11.1 原始运行

```text
pair_joint/runs/test_deepseek_180/
pair_joint/runs/test_mimo_180/
```

每个目录含 `config.json`、`manifest.json`、`requests.jsonl`（180）、`results.jsonl`（180）、`position_map.json`、`leak_audit.json`、`metrics.json`、`cache/`。

### 11.2 分析产物

```text
pair_joint/results/analysis_deepseek-v4.1-flash.json / .md
pair_joint/results/analysis_mimo-v2.6-flash.json / .md
pair_joint/results/comparison.json / .md
pair_joint/results/benchmark_export.json
pair_joint/results/summary.md
pair_joint/results/pilot/...
```

### 11.3 复现命令

```bash
# WSL
cd /mnt/c/Users/tzh03/Downloads/cs224proj

python3 pair_joint/selftest.py

bash pair_joint/run_pair_joint.sh pilot
bash pair_joint/run_pair_joint.sh full

python3 -m pair_joint.analyze \
  --run-dir pair_joint/runs/test_deepseek_180 \
  --run-dir pair_joint/runs/test_mimo_180 \
  --out-dir pair_joint/results \
  --bootstrap 10000 --seed 42
```

### 11.4 完整性核对

- `splits/test_pairs_180.json` SHA-256 与 `splits/FREEZE.txt` 一致。
- 两模型 `position_map.json` 完全相同，90/90。
- `requests.jsonl` 180 条；`results.jsonl` 180 条；`status` 全为 `ok`。
- `manifest.counts.by_status = {"ok": 180}`；`partial: false`。
- `leak_audit.wrapper_clean_all = true`；`slot_leak_all = false`。
- `api_key_value_stored = false`；产物中无 `Authorization` 头。
- 未写入 `runner/runs/` 或 `datasets/`、`splits/`。

---

## 12. 建议的下一步

1. **开放联合 prompt 消融**：同一 A/B 展示，但允许 `both`/`neither`；测量联合比较本身的效果，分离“强制选择”。
2. **长度匹配子集**：在漏洞/修复长度差接近 0 的对上重跑，或按长度差分层的配对 bootstrap。
3. **A/B 双顺序重复**：每对跑 AB 和 BA 两次，直接估计顺序一致性；当前只用 90/90 平衡降低但不能消除位置偏差。
4. **证据格式修复**：在 prompt 中给出 `line` 必须是整数的示例，或在评分中单独报告“行号字符串”这种格式变体；不要静默改写。
5. **更多模型/重复**：当前每个模型一次贪心解码，无法估计方差；结论应视为该配置下的点估计。
