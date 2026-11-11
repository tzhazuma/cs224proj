# `benchmark/` — 统一但分层的漏洞检测 benchmark

本目录定义了 CS224 项目的**统一比较协议、结果 schema、实验矩阵和校验/指标工具**。它解决一个具体问题：现有结果、MiMo 对比、Juliet CWE-401 静态/动态/LLM/混合实验如果各自用不同的标签、分母和指标，数字无法放在一起读。

答案不是把所有东西池化成一个 leaderboard，而是：

> **统一契约，分层比较。** 同一套字段、指标、失败分类、成本模型和统计方法；两个独立层级，各自有主终点、分母和外推边界，绝不跨层合并。

规范全文见 [`PROTOCOL.md`](PROTOCOL.md)；机器可读契约见 [`schemas/`](schemas/README.md)；计划表见 [`matrix/`](matrix/README.md)。

---

## 1. 当前状态（诚实版）

| 部分 | 状态 | 说明 |
| --- | --- | --- |
| 协议 / schema / 工具 | **ready** | `PROTOCOL.md`、4 个 schema、validator/metrics/compare/importer、Tier B 收集/汇总、final summary、selftest |
| Tier A DeepSeek 三策略 | **done_frozen** | 6 个 `test_v1_*` run，2,484 请求；只读派生到 `results/tier_a/deepseek_*` |
| Tier A MiMo 三策略 | **done_frozen** | 6 个 `test_v1_mimo_*` run，2,484 请求；真实全量，不是 pilot；派生到 `results/tier_a/mimo_*` |
| Tier A evidence prompt | **done_frozen** | 2 个真实 run（DeepSeek / MiMo × 160）；recall 上升，FPR 也上升；见 `LEADERBOARD.md` §2.2 |
| Tier A pair-joint | **done_frozen（独立任务）** | 2 个真实 run × 180 对；强制二选一，单独报告，不与分侧 pair 合并 |
| Tier A 模型比较 | **done_frozen** | 6 个同策略/同任务比较（detection + pair × 3 strategies）；McNemar + Holm；另有 evidence 与 pair-joint 比较 |
| Tier A 静态可行性 | **planned** | 只做 compile/applicability 审计；不把失败写成 F1=0；本目录不报告 Tier A 静态 F1 |
| Tier B Juliet 数据 | **done_frozen（数据）** | 200 units / 100 groups / 42 families；`subset_units.jsonl` 与数据卡已冻结；B9 的 label-only baseline 仍未做 |
| Tier B 静态 | **done_frozen** | Clang SA 22.1.8 + Cppcheck 2.21.0，200 单元，6 个 Clang compile error（test 4 个）保留为 `compile_error` |
| Tier B 动态 | **done_frozen** | ASan/LSan + Valgrind 3.27.1 全量 3,316 cases，映射到冻结 200 单元；clean 无覆盖率证据，不是 TN |
| Tier B LLM（MiMo postleakfix） | **done_frozen（端点受限）** | 140 test，**Xiaomi 官方端点**，postleakfix 正式 run；不是 OpenCode Go；DeepSeek 140 无结果（401/402） |
| Tier B 混合证据 | **done_frozen（canonical v2）** | 2 模型 × {direct, static, dynamic, combined, shuffled} × 140 = 1,400 真实请求，leak-fixed v2 输入；OpenCode Go |
| Tier B 修复 | **done_frozen（条件口径）** | 70 bad；58 个 baseline 可观测单元 strict pass = 58/58；12 个不可观测单元不入分母 |
| 新实验结果 | **有（本目录）** | 34 个 canonical run（Tier A 16、Tier B 18，含 2 repair）；另有 11 个以 `superseded/` 冻结保留、但不进入主表的历史 run |

> `examples/` 是手写合成 fixture，只用于 schema 自检，**不是结果**。`results/` 下的 run 是真实产物的派生视图；Tier A legacy 没有重新调用模型，Tier B 传统工具没有重新运行；round-2 的 evidence/pair-joint/hybrid v2/LLM postleakfix/repair 是真实调用的只读导入。**最终统一 leaderboard 是 [`results/LEADERBOARD.md`](results/LEADERBOARD.md)，机器可读结果是 [`results/final_summary.json`](results/final_summary.json)**；`tier_a_leaderboard.md` / `tier_b_leaderboard.md` 保留为整合前的详细视图。

---

## 2. 两个层级

| | **Tier A：SecVulEval** | **Tier B：Juliet CWE-401** |
| --- | --- | --- |
| 问题 | 跨 CWE 真实项目函数上，LLM 模型/策略如何 | 同一 CWE-401 用例上，静态/动态/LLM/混合如何 |
| 数据 | `splits/test_detection_160.json`（160 函数）；`splits/test_pairs_180.json`（180 对） | `juliet-cwe401-v1.3-subset-v1` core set（已冻结） |
| 单元 | 函数；pair | case variant（bad/good）；family 为 cluster |
| 方法 | DeepSeek / MiMo × direct / few-shot / context / evidence；pair-joint（独立） | 静态 / 动态 / LLM / AI+传统（direct/static/dynamic/combined/shuffled） |
| 主终点 | 检测 `macro_f1`；分侧配对 `pair_da`；joint 强制二选一 DA（单列） | 泄漏 `macro_f1` + `mcc`，强制 coverage/strata |
| 不做 | 静态工具跑不完整 CVE 函数；跨层外推 | Juliet 结果外推到真实项目；动态 clean 当安全 |

**为什么不能合并**：两个层级的标签来源、单元结构、类别先验、代码形态、分母和成本口径都不同。把 160 个真实函数和 Juliet 变体池化，会制造一个没有解释的“平均 F1”。

---

## 3. Tier A 结果（真实、只读派生）

Legacy 来源：`runner/runs/test_v1_*`（DeepSeek）与 `runner/runs/test_v1_mimo_*`（MiMo），各 6 个 run、每模型 2,484 请求。Round-2 来源：`evidence_prompt/`（2×160）与 `pair_joint/`（2×180）。统一指标由 `bench_metrics.py` 重算；比较由 `bench_compare.py` / `bench_final_summary.py` 生成。

| 模型 | 策略 | 检测 macro-F1 | 配对 DA | 检测 coverage | USD（legacy 两 run 含 repair；round-2 为 task only） |
| --- | --- | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash | direct | 0.383 | 0.117 | 1.000 | 0.645585 |
| DeepSeek V4.1 Flash | few-shot | 0.399 | 0.089 | 1.000 | 1.131383 |
| DeepSeek V4.1 Flash | context | 0.381 | 0.122 | 1.000 | 0.662251 |
| DeepSeek V4.1 Flash | evidence | 0.422 | — | 0.994 | 0.085622（detection only） |
| MiMo-V2.6-Flash | direct | 0.346 | 0.091 | 0.938 | 0.186884 |
| MiMo-V2.6-Flash | few-shot | 0.346 | 0.094 | 1.000 | 0.244105 |
| MiMo-V2.6-Flash | context | 0.365 | 0.114 | 0.956 | 0.192166 |
| MiMo-V2.6-Flash | evidence | 0.407 | — | 0.988 | 0.035933（detection only） |

检测 160（128 V / 32 NV）；配对 180 对；每模型 legacy 2,484 请求（含 308 repair 请求，repair 不计分）。模型间 6 个比较（同策略、同任务）经 Holm 后 McNemar 均不显著；few-shot 检测的 macro-F1 差值 CI 为 `[0.010, 0.129]`（DeepSeek − MiMo），但次级 McNemar p=0.078、Holm p=0.235，不能据此宣称稳定优劣。

**Round-2 evidence prompt**：两个模型各 160 检测请求。DeepSeek macro-F1 0.3828→0.4223，MiMo 0.3456→0.4067；召回显著上升（Holm p=0.0055 / 0.0010），但 FPR 点估计也上升（+9.4 / +13.8 pp，n=32/29，检验不显著），BA/MCC 没有一致提升。完整分解见 [`results/LEADERBOARD.md`](results/LEADERBOARD.md) §2.2。

**Round-2 pair-joint（独立任务）**：每对一次请求，强制在 A/B 中二选一。DeepSeek DA 138/180=76.67%，MiMo 156/180=86.67%。这不是分侧四分类任务：联合任务没有 both/neither 类别，不能与分侧 direct/context 的约 9–12% 直接相减。长度启发式单独达到 74.44%，DeepSeek 不显著高于它；DeepSeek 还有强烈 A 位置偏差（A 92.22% vs B 61.11%）。详见 [`results/LEADERBOARD.md`](results/LEADERBOARD.md) §2.3–§2.4。

完整表、CI、成本/延迟见 [`results/LEADERBOARD.md`](results/LEADERBOARD.md)；整合前的 12-run 详细视图见 [`results/tier_a_leaderboard.md`](results/tier_a_leaderboard.md)。

MiMo 使用 `mimo-v2.6-flash` + `reasoning_effort=none` + `max_completion_tokens`（OpenCode Go，2026-11-12 价格快照）；DeepSeek 使用 non-thinking + `max_tokens`。两者语义对齐但传输/解码配置不同，比较是“模型+配置”比较。详见 `mimo/README.md`。

### 3.1 Tier B 结果（Juliet CWE-401，主 test 140）

静态/动态全量结果映射到同一冻结 200 单元，主分析取 test 140（dev 60 只作参考）。`macro-F1` 是 valid-only；`strict` 把非 ok 记录算错；静态 `compile_error` 从未写成 `y_pred=0`。

| 方法 | 家族 | valid/140 | coverage | macro-F1 | 95% CI | MCC | strict | compile/inconcl |
| --- | --- | ---: | ---: | ---: | --- | ---: | ---: | --- |
| Clang SA 22.1.8 | static | 136 | 0.971 | 0.888 | [0.818, 0.948] | 0.799 | 0.864 | 4 / 0 |
| Cppcheck 2.21.0 | static | 140 | 1.000 | 0.588 | [0.497, 0.671] | 0.331 | 0.629 | 0 / 0 |
| ASan+LSan | dynamic | 140 | 1.000 | 0.914 | [0.850, 0.966] | 0.841 | 0.914 | 0 / 0 |
| Valgrind 3.27.1 | dynamic | 140 | 1.000 | 0.914 | [0.850, 0.966] | 0.841 | 0.914 | 0 / 0 |
| ASan+Valgrind (any) | dynamic | 140 | 1.000 | 0.914 | [0.850, 0.966] | 0.841 | 0.914 | 0 / 0 |

- **动态 clean 不是 TN**：该动态 run 没有行/分支覆盖率 instrumentation；clean 只表示“执行路径上未观察到 definite/indirect leak”。leaderboard 同时给 operational 和 conservative（clean 弃权）两视图；后者 macro-F1 未定义，只报告 recall/precision。
- **runtime-supported 128（test）**：排除 12 个“标签 bad 但 LSan 未观察到 leak”的 test 单元。ASan 在该子群接近满分的部分原因是该子群由 LSan preflight 定义（循环性）；Valgrind/静态更有信息量。
- **LLM（MiMo postleakfix）**：140 test，macro-F1 0.9500、MCC 0.901、coverage 1.000；端点是 **Xiaomi 官方 API**，不是 OpenCode Go。DeepSeek 的 Juliet LLM 140 没有结果（OpenCode 401、官方 402），不报告数字。旧 harness run 已 superseded，不进入主表。
- **混合证据（v2）**：2 模型 × {direct, static, dynamic, combined, shuffled} × 140 = 1,400 真实请求。DeepSeek combined 136/140（macro-F1 0.9714），MiMo combined 136/140（0.9714）；相对 direct 的 +1/0 个单元在 Holm 后不显著，shuffled 安慰剂与 direct 的差异在 ±3 单元内。**v1 不再使用**：v1 的 6 个 good 单元仍含 Juliet 字面标签短语，属于 leakage-sensitive 历史，已移到 `results/superseded/`，旧满分结论撤回。
- **修复**：70 个 test bad；58 个 baseline 可观测单元 strict pass 58/58（两个模型），12 个 LSan 不可观测单元不入分母；它们仍编译/LSan 干净/行为保持，但不能证明泄漏被移除。
- 完整表、all 200、dev 60、成本/延迟见 [`results/LEADERBOARD.md`](results/LEADERBOARD.md)；整合前的 5-tool 详细视图见 [`results/tier_b_leaderboard.md`](results/tier_b_leaderboard.md)。

---

## 4. 目录

```text
benchmark/
├── README.md                 # 本文件
├── PROTOCOL.md               # 规范：标签/指标/失败/统计/成本/Tier A/B
├── VERSION                   # 1.0.0
├── schemas/
│   ├── prediction.schema.json
│   ├── run_manifest.schema.json
│   ├── metrics.schema.json
│   └── dataset_manifest.schema.json
├── matrix/
│   ├── experiment_matrix.csv/.md
│   ├── innovation_matrix.csv/.md
│   ├── make_matrix.py
│   └── README.md
├── tools/
│   ├── bench_common.py       # 指标/统计/成本原语
│   ├── bench_validate.py     # run 结构/一致性校验
│   ├── bench_validate_dataset.py # 数据卡/哈希/计数校验
│   ├── bench_metrics.py      # 单 run 指标
│   ├── bench_compare.py      # 两 run 配对比较
│   ├── bench_import_legacy.py# 旧 run 派生（只读）；支持 DeepSeek/MiMo
│   ├── bench_import_round2.py # evidence/pair-joint/hybrid/LLM/repair 只读导入
│   ├── bench_collect_tier_b.py # 静态/动态 → 冻结 200 单元的统一 run
│   ├── bench_tier_a_summary.py # 旧 12-run Tier A leaderboard + McNemar/Holm
│   ├── bench_tier_b_summary.py # 旧 5-tool Tier B split/runtime/coverage 视图
│   ├── bench_final_summary.py # 最终统一汇总（LEADERBOARD.md + final_summary.json）
│   └── selftest.py           # 合成 fixture 自检
├── examples/                 # 合成 schema 样例（不是结果）
├── datasets/                 # 数据卡（Tier A 引用；Tier B 已冻结）
└── results/                  # 不可变 run + 分层 leaderboard
    ├── tier_a/               # 16 个 run：12 legacy + 2 evidence + 2 pair-joint
    ├── tier_b/juliet_cwe401/ # 5 传统 + 1 LLM postleakfix + 10 hybrid v2 = 16 run
    ├── tier_b/juliet_cwe401_repair/ # 2 个 repair run
    ├── superseded/           # 11 个被取代的历史 run（冻结保留，主表跳过）
    ├── comparisons/tier_a/   # 18 个历史 bench_compare 输出
    ├── LEADERBOARD.md / final_summary.json # 最终统一汇总
    ├── tier_a_summary.json / tier_a_leaderboard.md # 整合前历史视图
    └── tier_b_summary.json / tier_b_leaderboard.md # 整合前历史视图
```

---

## 5. 快速开始（WSL）

所有命令在 WSL 中执行；路径按项目根目录：

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/tools/selftest.py'
```

校验 Juliet 数据卡（哈希/计数/文件）：

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/tools/bench_validate_dataset.py --jsonschema'
```

校验一个 run（结构 + 可选 JSON Schema）：

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/tools/bench_validate.py \
  --run-dir <run_dir> --jsonschema \
  --json-out <run_dir>/validation.json'
```

计算统一指标（写 `metrics.json` / `metrics.md`）：

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/tools/bench_metrics.py --run-dir <run_dir>'
```

比较两个同数据集、同 task 的 run（common-valid + paired bootstrap + McNemar）：

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/tools/bench_compare.py \
  --run-a <runA> --run-b <runB> --out <comparison.json>'
```

导入 round-2 真实结果并重算指标（只写 `benchmark/`，不覆盖源目录）：

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/tools/bench_import_round2.py --measure --force'
```

生成最终统一 leaderboard 与 JSON（会重新计算所有 run 的指标和配对统计）：

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/tools/bench_final_summary.py'
```

把旧 DeepSeek/MiMo run 派生为统一 schema（不改原文件）：

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/tools/bench_import_legacy.py \
  --run-dir runner/runs/test_v1_direct_independent \
  --out-dir benchmark/results/tier_a/deepseek_direct/legacy__test_v1_direct_independent'
```

只跑工具自检不会产生实验结论；`selftest.py` 的 fixture 在临时目录中创建并删除。

---

## 6. 如何新增一个 run

1. **读协议**：Tier A 看 `PROTOCOL.md` §11；Tier B 看 §12；指标/失败看 §7–§9。
2. **冻结配置**：数据集 SHA-256、prompt/tool config 哈希、主终点、比较族、排除规则、预算。Tier B 先核对 B0 数据卡，再过 B9 gate。
3. **写产物**：`run_manifest.json` + `predictions.jsonl`，每个单元一行；失败保留 `status != "ok"`，不要删除。
4. **校验**：`bench_validate.py --jsonschema` 必须 `errors=[]`。
5. **指标**：`bench_metrics.py`；检查 `counts` 与 manifest 一致。
6. **比较**：同数据集/同 task 才用 `bench_compare.py`；不同数据集直接拒绝。
7. **登记**：只有真实产物通过校验后，才把矩阵行从 `planned` 改为 `done_frozen`，并填 `output_path`。
8. **报告**：主表同时给 strict/valid-only、coverage、CI、失败分布、成本向量；不要只报 accuracy/单个 F1。

### Tier B 最小 gate

- Juliet archive + `dataset_manifest.json` 冻结；
- core set 编译/`-DOMITGOOD`/`-DOMITBAD` 构建通过；
- LSan/Valgrind oracle 与设计标签一致性已记录；
- sanitizer + label-only baseline 通过；
- family-disjoint dev/test 冻结。

B1/B2/B3 已完成正式 run（见 `results/tier_b_leaderboard.md`）。Round-2 后：B5（MiMo，Xiaomi postleakfix）、B6（static evidence）、B7（dynamic evidence）与 B12（hybrid v2）/B11 已 `done_frozen`；B4（DeepSeek Juliet LLM）仍无结果，B8（cascade）未做；B9 的 sanitizer/prompt 审计已通过 200/200，但 label-only baseline 仍未跑，因此记为 `partial`，LLM/混合数字必须带此 caveat 阅读。

---

## 7. 指标与失败（一句话版）

- **P/R/F1/MCC/BA/macro-F1**：valid-only 计算；`macro_f1` 是二类宏平均，不是逐 CWE。
- **strict_accuracy**：所有已落盘记录，非 ok 算错；与 valid-only 并列报告。
- **coverage**：valid / recorded；`missing_units` 另报，不补零。
- **pair DA**：V 判 1 且 F 判 0 的对数 / 有效对数；同时报双报漏洞/双报安全/判反。**pair-joint 是强制二选一**，同一请求落成两侧记录；它没有 both/neither，不能与分侧 DA 直接比较。
- **Tier B 泄漏**：动态 clean + 覆盖不足 = `inconclusive`，不是 TN；leak 观察到即正例，即使覆盖低。
- **修复**：`strict_pass = compile_pass ∧ leak_removed ∧ behavior_preserved ∧ baseline leak observed`；分母只含 `strict_evaluable=true` 的可观测单元（58），12 个不可观测单元不用 0/1 填充。
- **统计**：比例 Wilson；F1/MCC/BA 用 cluster bootstrap（10k，seed 42）；配对正确性 McNemar；族内 Holm。
- **成本**：USD 只对 API 记录的价格快照（list price）求和；provider 实际扣费/额度另记，不冒充账单。另给 **normalized** 口径：按固定价卡（DeepSeek 0.15/0.60/0.003、MiMo 0.14/0.28/0.0028 USD/1M tokens）从逐条 usage 重算，不使用记录值回填。本地静态/动态 `usd=null`，不是 0；报告 wall/CPU/RSS、p50/p95、每 100 单元/每 1000 请求/每 TP；不做单一总分。

详见 `PROTOCOL.md` §7–§10。

---

## 8. 实验矩阵

- [`matrix/experiment_matrix.csv`](matrix/experiment_matrix.csv)：27 行核心单元，含 A0 旧结果、A1 MiMo、A2 模型比较、A4 静态可行性、A6 evidence、A7 pair-joint、B0–B12。
- [`matrix/innovation_matrix.csv`](matrix/innovation_matrix.csv)：11 个创新槽位（证据格式/安慰剂、动态 trace、路径验证、选择性预测、成本级联、分歧分析、消毒压力测试、跨层迁移、模型×策略交互、agent 轮数）。
- 状态词表与比较族见 [`matrix/README.md`](matrix/README.md)。

矩阵是计划，不是结果。`blocked_gate` 表示依赖未过；`partial` 表示只有部分子实验完成；`planned` 的行没有新 run；`done_frozen` 表示真实产物已通过 `bench_validate.py`。A1/A2、A6/A7、B1/B2/B3/B5/B6/B7/B11/B12 已按真实 run 更新；A4、B4、B8、B10、B9 的 label-only baseline 仍未完成；B9 整体记为 `partial`。

---

## 9. 已做的验证（真实执行）

本轮 benchmark 本身没有调用模型或重跑静态/动态工具；Tier A legacy 派生自 `runner/runs/test_v1_*`，Tier B 传统工具派生自 `traditional/static` 与 `traditional/dynamic`，round-2 的 evidence/pair-joint/hybrid v2/LLM postleakfix/repair 则是真实调用的只读导入。

| 验证 | 结果 |
| --- | --- |
| `python3 benchmark/tools/selftest.py` | PASS：validator + detection/pair/leak 指标算术 |
| 3 个 `examples/run_*` + `--jsonschema` | 全部 `errors=[]` |
| 12 个 Tier A run 导入 + `bench_validate.py --jsonschema` | 全部 `errors=[]`；6 DeepSeek + 6 MiMo，各 2,484 请求 |
| Tier A 检测 macro-F1 重算 | DeepSeek direct 0.3828、few-shot 0.3995、context 0.3813；MiMo 0.3456/0.3463/0.3650（valid-only） |
| Tier A 配对 DA 重算 | DeepSeek 0.1167/0.0889/0.1222；MiMo 0.0909/0.0944/0.1145（valid-only） |
| 18 个 `bench_compare.py` 比较 | 6 个模型比较 + 12 个模型内策略比较；全部同 dataset SHA/task；McNemar + Holm 见 leaderboard |
| 5 个 Tier B run 生成 + `--jsonschema` | 全部 `errors=[]`；每 run 200 单元（100 bad + 100 good） |
| 静态映射核对 | Clang 200 单元：194 ok / 6 compile_error；TP73 FP0 TN97 FN24；Cppcheck TP30 FP4 TN96 FN70，与源 `metrics.json` 一致 |
| 动态映射核对 | 3,316 cases 按 `(sources, variant)` 映射到 200 单元，0 missing / 0 duplicate；78 leak / 122 clean，与 `runtime_check` 一致 |
| Tier B test 140 主表 | Clang macro-F1 0.888 (CI 0.818–0.948)、Cppcheck 0.588、ASan/Valgrind 0.914；runtime-supported 128 视图另列 |
| Juliet 数据卡 vs 实际上游 units | `bench_validate_dataset.py --jsonschema` rc=0：200 units / 100 groups / 42 families；dev 60 / test 140 |
| Round-2 导入 + `--jsonschema` | 17 个新 run：2 evidence + 2 pair-joint + 10 **hybrid v2** + 1 **LLM postleakfix** + 2 repair；全部 `errors=[]`、`warnings=0` |
| Round-2 指标重算 | evidence 160/run；pair-joint 180 对/run；hybrid v2 140/run；LLM 140；repair 70（58 evaluable）；全部 `bench_metrics.py` |
| Tier A evidence 配对分解 | DeepSeek Δrecall +9.45 pp（Holm p=0.0055）、MiMo +10.92 pp（Holm p=0.0010）；FPR +9.38/+13.79 pp，检验不显著 |
| Pair-joint 审计 | 180/180 valid；DS 138/180、MiMo 156/180；长度启发式 134/180；位置偏差 DS 92.22% vs 61.11% |
| Tier B hybrid v2 1,400 请求 | 10 run × 140 全部 ok；combined DS 136/140、MiMo 136/140；direct→combined Holm p=1.00/1.00 |
| Tier B LLM postleakfix | MiMo 140/140 valid，macro-F1 0.9500，MCC 0.9008；Xiaomi 官方端点已标注 |
| Repair 审计 | 70/70 编译、70/70 LSan 干净、70/70 行为保持；58/58 可观测 strict pass；12 个 not_applicable 不入分母 |
| 最终 Leaderboard | `LEADERBOARD.md` + `final_summary.json`；34 个 canonical run；11 个 superseded 历史 run 明确排除；Tier A/B 分开，无跨层池化 |

注意：Tier A 旧 run 的 metrics 是 valid-only；统一指标重算的 valid-only 与旧值一致，strict 是新视图。Tier B 动态没有覆盖率 instrumentation，operational 与 conservative 两视图不能混用。Round-2 的 evidence/pair-joint/hybrid v2/LLM postleakfix/repair 是真实调用的只读导入，不是重新运行。

---

## 10. 限制与不能声称的事

- **MiMo 已全量，但不是纯模型比较**：`mimo-v2.6-flash` 使用 `reasoning_effort=none` + `max_completion_tokens`；DeepSeek 使用 non-thinking + `max_tokens`。两者语义对齐，但解码/传输配置不同；不能把差异全部归因于模型能力。
- **Tier A 静态仍 pending**：160 个 SecVulEval 函数是抽取片段，静态工具大多无法解析；本目录不报告 Tier A 静态 F1，也不把 compile error 写成 0。A4 仍为 `planned`。
- **Tier B 静态有真实 compile error**：Clang 在 test 140 中有 4 个 `_82` 组因共享无 include-guard 头而 `compile_error`；valid-only macro-F1 排除它们，strict 算错，但从未写成 `y_pred=0`。
- **动态没有覆盖率 instrumentation**：clean 只是“执行路径上未观察到 definite/indirect leak”，不是安全证明；operational 视图把 clean 当 TN，conservative 视图把 clean 弃权、macro-F1 未定义。两者必须同时读。
- **runtime-supported 有循环性**：178/128 子群由 LSan preflight 定义；ASan 在该子群接近满分部分是选择效应，Valgrind/静态更有信息量。
- **Juliet LLM 只有 MiMo postleakfix**：140 test 来自 Xiaomi 官方端点，不是 OpenCode Go；该端点 run 与 OpenCode Go v2 direct 的差异是 3 个单元，但两者 harness/prompt 版本也不同，不能当作纯端点效应。DeepSeek 没有结果（401/402），不能从 MiMo 推断。
- **混合证据收益很小**：v2 combined 相对 direct 只多修 1 个单元（DeepSeek）或 0 个（MiMo）；5 个不一致样本下 exact McNemar 最小 p=0.0625，Holm 后不显著；shuffled 安慰剂与 direct 的差异在 ±3 单元内。v1 的满分结果已撤回，不得引用。
- **Pair-joint 长度混淆**：字符长度启发式单独 74.44%；DeepSeek 76.67% 不显著高于它，MiMo 86.67% 显著高于它但仍受长度分布影响。DeepSeek 有明显 A 位置偏差。
- **Evidence prompt 是操作点偏移**：recall 显著上升，FPR 点估计也上升；BA/MCC 没有一致提升。证据行与修复行的 ±3 重合接近随机，不能当作可靠定位。
- **单次运行**：每个模型/策略/工具只有一次运行；没有 seed/run-to-run 方差，不能声称稳定。
- **Juliet 不能外推真实项目**：单 CWE、合成、模板化；与 SecVulEval 不可比。
- **Tier A 的 CWE-401 只有 3 条测试函数**：只能做案例系列，不能做逐 CWE 定量结论；Juliet 的 CWE-401 有 70 bad/70 good，但那是合成模板集，也不能外推。
- **修复口径是条件性的**：只在 58 个 baseline 可观测单元上报告 strict pass；12 个不可观测单元不能证明泄漏被移除。B9 的 label-only baseline 仍未跑。
- **成本不可跨范式相加**：API USD 与本地 CPU 分开；本地 `usd=null` 不是 0；不做单一“性价比”总分。
- **派生视图不是新实验**：Tier A 是 `runner/runs/test_v1_*` 的只读派生；Tier B 是 `traditional/static`/`traditional/dynamic` 的只读映射。
- **Schema v1 不是最终版**：新增字段/状态必须升版本并新建 run，不能就地改旧结果。

---

## 11. 归属与并行工作规则

- 本目录只由 benchmark 负责人修改；其他 agent/工作流在自己的分配目录写原始产物。
- 其他目录不得修改 `benchmark/schemas/`、`PROTOCOL.md` 的语义；如需扩展，先提版本变更。
- 旧 `runner/runs/test_v1_*`、`splits/`、`report/` 只读；benchmark 不覆盖、不重写。
- 并行实验建议：
  - MiMo：写 `benchmark/results/tier_a/mimo_*`（或自己的目录 + 显式 `--run-dir`）；当前全量已派生；
  - 静态：Tier A 只写可行性；Tier B 在 B0 后写 `tier_b/juliet_cwe401/static_*`；当前 Clang/Cppcheck 已完成；
  - 动态：B0 后写 `dynamic_*`；当前 ASan/Valgrind 全量已完成（Valgrind 3.27.1 从 /tmp 解包，非系统安装）；
  - 混合/创新：canonical 产物为 `benchmark/results/tier_b/juliet_cwe401/hybrid_*` 下的 hybrid v2；B9 仍缺 label-only baseline，报告必须带 caveat；
  - 报告：只消费通过 `bench_validate.py` 的 run，不手抄未校验数字；最终汇总用 `bench_final_summary.py`。
- 生产者适配器约定见 [`tools/ADAPTERS.md`](tools/ADAPTERS.md)：raw 目录不改，适配器只读映射到 canonical schema。
- 本目录当前不是独立 git 仓库；若项目根目录成为 git repo，由根统一管理，不要在此目录单独 `git init`/commit。

---

## 12. 参考

- 规范：[`PROTOCOL.md`](PROTOCOL.md)
- 并行工作流（只读参考，不是本协议产物）：`juliet/`、`mimo/`、`traditional/static/`、`traditional/dynamic/`
- 现有协议：`research/evaluation_protocol.md`（§4 拆分、§10 指标、§11 统计）
- 旧统计实现：`analysis/stats.py`（Wilson/bootstrap/McNemar/Holm 的同口径参考）
- 旧结果摘要：`report/results_summary.md`
- CWE-401 范围：`research/cwe401_scope.md`
- 冻结记录：`splits/FREEZE.txt`
- 数据说明：`datasets/README.md`
