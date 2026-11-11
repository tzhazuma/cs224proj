# repair_eval — SecVulEval 修复质量盲评工具

本目录只负责 **修复结果的人工质量评价**。它读取 `runner/` 的真实产物和 `datasets/` 的配对数据，生成盲评包、导入两位评分者的独立打分、计算 Cohen's kappa、生成分歧裁决模板并汇总最终结果。

**当前状态（2026-11-11）**：仓库中没有任何真实的修复 `results.jsonl`。此前真实 DeepSeek 调用因 OpenCode Go key 过期返回 401，因此本目录**没有生成正式盲评包**，也没有任何模型修复分数。运行验证包括 `selftest` 在 `TemporaryDirectory` 中创建的合成 fixture，以及一次“真实数据集 + `/tmp` 合成 runner 记录”的集成检查；两者结束都会删除，不进入项目，不能当作实验结果。

本目录不修改 `runner/`、`report/`、`research/`、`datasets/`。

---

## 1. 三种证据等级（不要混用）

| 等级 | 本工具做什么 | 能支持的说法 | 不能支持的说法 |
| --- | --- | --- | --- |
| **自动结构检查** | 读取 runner 的 `validation` 字段；重新计算完整函数启发式、是否改动、与上游修复的文本相等、行 diff。写入 `private/auto_checks.jsonl`。 | “输出是完整函数文本”“输出与输入不同”“输出与参考修复文本相同/不同” | “补丁正确”“漏洞已消除”“行为保持不变”“可编译” |
| **人工质量评价** | 20–30 对分层抽样；隐藏策略/模型；两位评分者按七维 rubric 独立打分；kappa、分歧裁决、最终汇总。 | “在给定 rubric 下，评分者认为 VR=2 的比例为 X”“评分者一致性为 κ” | “漏洞在真实构建中不可利用”“修复通过测试” |
| **编译 / PoC oracle** | **未实现，也没有运行。** `compile_status` 只是评分者填写的外部审计字段；没有编译器、stub harness 或 exploit harness。 | 只有在外部真实构建/PoC 证据存在时才可引用该证据 | 用 `COM`、`compile_status` 或结构检查代替编译/PoC 结论 |

### 1.1 关键区分

- `COM`（完整性）是 **文本完整性**：是否为完整函数、签名和括号是否完整、是否像 diff/截断。它不是编译结果。
- `CQ`（代码质量）是可读性、惯用法、死代码/调试残留等，不是漏洞是否消除。
- `compile_status` 的取值是 `NOT_RUN` / `UNVERIFIED` / `PASS` / `FAIL`。默认 `NOT_RUN`；没有真实构建证据时不能填 `PASS`。
- `VR=2` 是人工判断“处理了标注 CWE 的根因”，不是 PoC 证明。
- `summary.json` 的 `posthoc_structural_checks` 明确标注为结构检查，不参与 rubric 分数，也不能替代人工评分。

---

## 2. 输入要求

### 2.1 数据

- 必须是配对数据：`datasets/vulnerable_fixed_200_pairs.json` 或同 schema 的冻结文件。
- 每个 pair 需要 `pair_id`、`vulnerable.func_body`、`fixed.func_body`、`cwe_list`、`project`、`func_name` 等字段。
- 盲评需要上游修复版本作为上下文（可用 `--hide-reference` 完全隐藏）。

### 2.2 runner 结果

- `--results` 接收一个或多个 **真实** `results.jsonl`。
- 只处理 `task == "repair"` 且 `status == "ok"`、`validation.schema_valid == true`、`parsed.fixed_function` 非空的记录。
- 同一个 `(pair_id, strategy)` 只能出现一次；同一策略不要传两个重复运行的文件。
- 每个结果文件旁边默认必须有 `manifest.json`。build 会检查：
  - `manifest.status == "completed"`（可用 `--allow-incomplete-runs` 放宽，但只应针对已理解的部分真实运行）；
  - `manifest.dataset.sha256` / `config.dataset_sha256` 与 `--dataset` 一致；
  - `manifest.config.task` 为 `repair` 或 `both`；
  - `manifest.api.model` 和 `manifest.api.endpoint` 存在；默认要求所有结果使用同一个模型 ID（`--allow-multiple-models` 只用于明确标注的敏感性分析）；
  - 端点不是 `localhost`/`127.0.0.1` 等本地 mock（除非显式 `--allow-local-endpoint`，且只应用于已核实的本地部署）；
  - 结果记录有真实 HTTP 200 响应、模型 ID 和与数据集一致的函数 SHA-256。
- 如果一整次运行都是 401/API error，build 会报错：
  `no schema-valid repair candidates were found`。**不要用 mock 或手填补丁绕过这个错误。**
- `--allow-missing-manifest` 只用于归档的真实结果；它不是生成合成结果的开关。

---

## 3. 盲评设计

### 3.1 隐藏什么

正式盲评包 `blind/` 中不出现：

- 策略名（`direct` / `few-shot` / `context`）；
- 模型名、run ID、`manifest`；
- `pair_id`、`sample_id`、`idx`、项目、文件路径；
- `validation`、`exact_match_reference_fixed`、`whitespace_collapsed_match_reference_fixed`、`reference_match` 等候选级标签。

候选 ID 和案例 ID 由**私有随机 salt + HMAC-SHA256** 生成；salt 只保存在 `private/blind_key.json`。即使知道算法，没有私有 salt 也无法从 ID 反推策略。候选在每个案例内随机排序；案例顺序也随机化。`verify` 会重新检查盲评包没有禁用字段。

### 3.2 上游修复版本

默认情况下，盲评包展示 `upstream_fixed_version`，标注为“上下文，不是候选，不评分”。这是为了按 rubric 判断根因；但**不会**告诉评分者某个候选是否与上游修复相同，也不会提供参考匹配标签。

如果希望连上游修复也完全隐藏，使用 `--hide-reference`。此时 rubric 的 VR 判断只依据漏洞函数、CWE 和候选代码本身。

### 3.3 不能保证的盲法

候选代码和解释本身可能暴露模型风格。盲法只能降低策略识别，不能消除。评分说明要求评分者不要猜测来源，也不要把猜测写进理由。

---

## 4. 分层抽样

- 默认 `--pairs 30`，允许 20–30；少于 20 个合格 pair 时 build 直接失败，不会用合成数据补齐。
- 固定 `--seed`（默认 `20261111`）。同一份输入、同一 seed 会选出同一组 pair；盲 ID 因随机 salt 每次不同，映射保存在私有 key 中。
- 抽样框：
  - 漏洞函数长度不超过 `--max-function-chars`（默认 4000）；
  - 至少 `--min-candidates-per-case`（默认 2）个策略有 schema-valid 修复输出；
  - 参考修复非空且与漏洞函数不同（数据集已保证）。
- 分层：`CWE 家族 × 函数长度桶`。CWE 家族是粗粒度映射（内存缓冲区、生命周期、注入、整数、访问控制等），不是权威分类。
- 项目多样性：默认每个项目最多 2 对（`--max-per-project 2`）。如果某些分层配额因项目上限无法填满，会先从其他分层补足剩余名额，同时继续遵守项目上限；仍无法达到目标时，才依次放宽到 3、再不限，并在 `private/sampling.json` 与 `manifest.json` 的 `warnings` 中记录。`strata` 中同时给出 `allocated` 和 `selected`，可审计补位情况。
- 被排除的原因和数量写入 `sampling.json` 的 `frame_exclusions`：`function_too_long`、`no_valid_candidate`、`insufficient_valid_candidates` 等。

注意：候选集只包含 schema-valid 输出。某个策略在某个 pair 上返回 invalid/API error 时，该候选不会进入盲评；这会改变各策略的候选数，不能把“候选数不同”误读为质量差异。`manifest.json` 的 provenance 块给出每个结果文件的记录数和有效候选数。

---

## 5. Rubric

每维 0/1/2，固定版本 `repair-eval-rubric-2026-11-11.1`。完整锚点见 `blind/rubric.md`，摘要：

> 与 `research/evaluation_protocol.md` 的六维 rubric 相比，本工具保留 VR/SP/MIN/EF/NS，新增 COM/CQ，并把原 CV 改为单独的 `compile_status` 审计字段（不计入质量分）。引用结果时必须注明 rubric 版本，不能把七维分数与协议六维分数直接混表。

| 维度 | 0 | 1 | 2 |
| --- | --- | --- | --- |
| **VR 漏洞消除** | 未处理根因、仍可利用；只改注释/格式；引入新可利用路径 | 缓解一条路径，但仍有绕过/遗漏 | 处理标注 CWE 的根因；替代性正确修复也可得 2 |
| **SP 行为保持** | 改变签名/返回约定或明显破坏调用方 | 常见路径可能保持，边界/错误路径不确定 | 签名与预期行为保持 |
| **MIN 最小性** | 大范围重写/无关改动 | 中等改动，部分超出漏洞区域 | 局限在漏洞区域，必要且充分 |
| **COM 完整性** | 截断、diff、Markdown、缺函数体/括号 | 是函数文本但有可疑截断/签名漂移 | 完整函数文本（**不是编译证明**） |
| **CQ 代码质量** | 难读、死代码/调试残留、危险惯用法 | 可理解但有重复/混乱/不必要复杂化 | 清晰、惯用、与周边风格一致 |
| **EF 解释忠实** | 解释与 patch 矛盾/幻觉 | 部分一致但遗漏关键点 | 准确说明改动与 CWE 关系 |
| **NS 无新风险** | 引入新的明显危险模式 | 不确定或可疑 | 未引入新的明显风险 |

通过规则：

- 主要：`VR == 2`。
- 严格：`VR == 2 and SP >= 1 and NS == 2 and EF >= 1 and COM >= 1`。
- 七维均值仅供参考，不替代主要/严格通过率。

编译状态（单独记录，不计入 rubric）：

| 值 | 含义 |
| --- | --- |
| `NOT_RUN` | 没有尝试编译（本工具默认；工具本身不编译） |
| `UNVERIFIED` | 人工判断语法像完整函数，但缺项目头文件/类型/宏，无法确认 |
| `PASS` | 有外部构建证据表明通过 stub harness 或项目构建 |
| `FAIL` | 有明显语法错误或不完整函数 |

---

## 6. 命令（必须在 WSL 中运行）

以下路径以 `cd /mnt/c/Users/tzh03/Downloads/zy` 为工作目录。

### 6.1 生成正式盲评包（只有真实结果存在后）

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && \
python3 -m repair_eval build \
  --results runner/runs/<run_direct>/results.jsonl \
            runner/runs/<run_fewshot>/results.jsonl \
            runner/runs/<run_context>/results.jsonl \
  --dataset datasets/vulnerable_fixed_200_pairs.json \
  --out-dir repair_eval/packages/repair_blind_<date> \
  --seed 20261111 \
  --pairs 30'
```

如果一次 `--task both` 运行已经包含三种策略，只需传对应文件；如果每种策略是独立运行，传三个文件。不要重复传同一策略。

成功后会打印案例数、候选数、按策略候选数、抽样警告和 `Package verification: OK`。正式包只应在真实结果上生成；当前仓库没有这样的结果，因此本命令尚未产生项目内正式包。

### 6.2 两位评分者独立打分

把 `blind/` 交给两位评分者。每人只填自己的 `rater_A.tsv` / `rater_B.tsv`，不要看 `private/`。

导入并计算一致性：

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && \
python3 -m repair_eval agreement \
  --package repair_eval/packages/repair_blind_<date> \
  --rater-a /path/to/rater_A.tsv \
  --rater-b /path/to/rater_B.json \
  --out-dir repair_eval/analysis/repair_blind_<date>/agreement'
```

输出：

- `agreement.json`：每维 unweighted κ、quadratic weighted κ、exact agreement、within-one agreement、bootstrap CI、分歧列表；
- `agreement.md`：可读报告；
- `adjudication.tsv`：只列出有分歧的候选-维度，`final_value` / `rationale` 留空；
- `disagreements.json`：机器可读分歧列表。

### 6.3 分歧裁决与最终汇总

第三人填写 `adjudication.tsv`：

- 评分维度：`final_value` 填 0/1/2；
- `COMPILE_STATUS` 行：填 `NOT_RUN` / `UNVERIFIED` / `PASS` / `FAIL`；
- `rationale` 必须非空。

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && \
python3 -m repair_eval finalize \
  --package repair_eval/packages/repair_blind_<date> \
  --rater-a /path/to/rater_A.tsv \
  --rater-b /path/to/rater_B.json \
  --adjudication /path/to/adjudication_filled.tsv \
  --out-dir repair_eval/analysis/repair_blind_<date>/final'
```

如果没有分歧，可省略 `--adjudication`。有分歧但未提供或未填全时，`finalize` 会报错，不会静默用某一方分数代替。

输出：

- `summary.json` / `summary.md`：最终维度均值、0/1/2 分布、主要/严格通过率、按策略（解盲后）和 CWE 家族的汇总、一致性、裁决数量、事后结构检查、限制；逐条裁决记录在 `adjudication_used.json`；
- `final_scores.tsv` / `final_scores.jsonl`：候选级 A/B/最终分数与策略映射；
- `adjudication_used.json`：实际使用的裁决决定与理由。

### 6.4 校验包完整性

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && \
python3 -m repair_eval verify --package repair_eval/packages/repair_blind_<date>'
```

会检查 manifest 中的 artifact SHA-256、盲评包禁用字段、重复 ID、评分模板表头。修改任何 blind/private 文件后校验会失败。

### 6.5 临时合成 fixture 自测

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && \
python3 -m repair_eval selftest'
```

自测在 `TemporaryDirectory` 中生成合成数据集、三份合成 `results.jsonl` 和 manifest，跑完 build → 两人评分（TSV + JSON）→ kappa/裁决模板 → finalize → verify，并测试：
- 401-only 结果不能生成盲评包；
- 固定 seed 选中相同 pair 集合；
- `--hide-reference` 确实移除上游修复；
- 候选顺序随机化；
- 临时目录自动删除。

输出只用于工具验证，**不是实验结果**。

---

## 7. 输出结构

```text
<out-dir>/
├── manifest.json                 # 包 ID、seed、数据/结果 SHA-256、provenance、抽样、盲法检查、artifact 哈希
├── blind/                        # 可以交给评分者
│   ├── blind_package.json        # 无策略/模型/pair_id/参考匹配标签
│   ├── review.md                 # 漏洞函数、上游修复上下文（可隐藏）、随机候选
│   ├── rubric.md                 # 七维 rubric 与编译状态说明
│   ├── rater_A.tsv               # 空评分表
│   ├── rater_B.tsv               # 空评分表
│   └── README.md
└── private/                      # 不要交给评分者
    ├── blind_key.json            # case/candidate → pair/strategy/model 映射、私有 salt
    ├── sampling.json             # 抽样框、分层、项目 cap、排除原因、选中 pair
    └── auto_checks.jsonl         # 结构检查、参考文本匹配、diff、compile/PoC=NOT_RUN
```

评分/裁决输出写到盲评包**外部**的 `analysis/` 目录（例如
`repair_eval/analysis/repair_blind_<date>/`），避免污染盲评包本身；`verify` 会把包内未登记的新文件视为失败。

---

## 8. 评分文件格式

### 8.1 TSV

表头固定为：

```text
candidate_id	case_id	VR	SP	MIN	COM	CQ	EF	NS	compile_status	notes
```

- 每行一个候选；`candidate_id` 必须与包内一致。
- 每维必须是 `0`、`1`、`2` 的整数。
- `compile_status` 为空时按 `NOT_RUN` 处理。
- `notes` 可写 1–2 句理由。
- 必须覆盖包内所有候选；缺行、重复 ID、未知 ID 都会报错。

### 8.2 JSON

```json
{
  "rater_id": "A",
  "scores": [
    {
      "candidate_id": "PATCH-AB12CD34EF",
      "case_id": "CASE-1234567890",
      "VR": 2,
      "SP": 2,
      "MIN": 1,
      "COM": 2,
      "CQ": 2,
      "EF": 2,
      "NS": 2,
      "compile_status": "UNVERIFIED",
      "notes": "Adds a bounds check; no unrelated changes."
    }
  ]
}
```

也支持顶层数组、`{"candidate_id": ..., "scores": {...}}` 嵌套写法，以及维度中文名/英文全名作为键。评分仍然必须覆盖所有维度和所有候选。

---

## 9. 一致性与裁决口径

- 每维报告：
  - exact agreement（完全一致比例）；
  - within-one agreement（相差不超过 1 的比例）；
  - Cohen's unweighted κ；
  - quadratic weighted κ（0–2 序数）；
  - 按候选 item-level bootstrap 的 95% percentile CI；
  - 分歧数。
- 二值通过条件（主要/严格）单独报告 κ 和一致率。
- `compile_status` 作为四值分类变量单独报告一致率/κ，不参与质量分。
- κ 在期望一致率为 1 时（例如两位评分者都给同一常数）是**未定义**的；工具返回 `null` 并说明原因，不会伪造成 1.0。
- 解释区间：`<0` 差、`0–0.2` 轻微、`0.2–0.4` 一般、`0.4–0.6` 中等、`0.6–0.8` 较好、`>0.8` 很好。20–30 个案例的 CI 可能很宽，不应把 κ 当作强结论。
- 分歧必须先记录在 `adjudication.tsv`，再由第三人裁决；最终分使用裁决分，原始两方分数保留在 `final_scores.tsv` 中。不要事后把两位评分者“讨论一致”的分数覆盖原始分。

---

## 10. 限制与不能声明的内容

1. **没有编译 oracle。** 本工具不运行 `clang`、不构建项目、不生成 stub harness。`COM` 和 `compile_status` 不能证明可编译。
2. **没有 PoC/exploit oracle。** 不运行漏洞利用，不证明修复后不可利用。`VR=2` 只是 rubric 下的人工判断。
3. **没有行为等价 oracle。** `SP` 是人工判断；没有测试、差分执行或形式化验证。
4. **结构检查不是正确性。** `complete_function`、`changed_from_input`、参考文本相等、行 diff 都是文本启发式；与参考修复文本相同也不等于正确。
5. **候选覆盖率不完整。** schema-invalid/API-error 输出不进入盲评；各策略候选数可能不同。必须同时报告 `manifest.json` 的 provenance 和覆盖情况。
6. **盲法有限。** 代码风格、解释措辞可能泄露方法；私有 salt 和随机排序只能降低识别。
7. **样本量小。** 20–30 个案例的 κ 和均值不稳定；bootstrap CI 按候选重采样，未建模同一案例内多候选的相关性。
8. **人工评分主观。** 即使 κ 高，也只说明评分者一致，不说明评分标准客观上正确。
9. **当前没有真实结果。** 本目录的 selftest 是合成 fixture；不得把它的任何数字写入报告、论文或结果表。

报告中建议的写法：

- 可以写：“在七维 rubric 下，两位评分者的 VR=2 比例为 …，κ=…；该结果基于 30 对分层抽样，属于人工质量评价。”
- 不可以写：“修复成功率为 …”“漏洞已消除”“补丁通过编译/测试”，除非另有真实编译/PoC 证据并单独引用。

---

## 11. 已验证内容

在 WSL（Python 3.14.8）中执行：

```bash
python3 -m compileall -q repair_eval
python3 -m repair_eval --version
python3 -m repair_eval selftest
python3 -m repair_eval selftest --bootstrap 100
```

结果：

- `compileall` 通过。
- `selftest` 通过（默认 2000 次 bootstrap 与 `--bootstrap 100` 均通过）；临时 fixture 在 `TemporaryDirectory` 中创建并自动删除。
- 自测覆盖 build、盲法字段检查、固定 seed、三种策略候选、TSV/JSON 两位评分者导入、κ/一致率、裁决模板、finalize、verify，以及 401-only 结果拒绝生成包。
- 在真实 `datasets/vulnerable_fixed_200_pairs.json` 上只读解析：200 对、80 个项目、171 对函数长度 ≤4000。抽样算法在真实分层上选 30 对时，项目上限 2 可满足（27 个项目，最大 2 对/项目）。
- 另做了一次**临时集成检查**：真实数据集 + `/tmp` 中的合成 runner 记录，生成 24 案例/72 候选的包，verify 通过，22 个项目、最大 2 对/项目；随后临时目录自动删除。该检查只验证工具链，不是模型结果，也没有在项目内留下包。
- 自测与集成检查都使用合成数据，不是模型实验；没有生成项目内正式盲评包。

---

## 12. 责任边界

- 本目录只写 `repair_eval/`。
- 不修改 `runner/`、`report/`、`research/`、`datasets/`。
- 不调用任何模型 API；不读取 API key；不把 mock 结果写入正式包。
- 真实运行完成后，再由负责人用 `build` 生成正式包，并把 `blind/` 交给评分者。
