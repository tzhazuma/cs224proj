# 增强动态证据引导：Juliet CWE-401 test 140

本目录只回答一个问题：把 `dynamic_enhanced` 的真实三模式证据（`default` / `realloc_fail` / `nogobal`）去标签后交给模型，模型的判定会不会比 v2 direct / 旧动态证据 / combined 更好？

**结论先行**：不会，至少在这 140 个冻结单元、每个模型一次运行上不会。

| 模型 | v2 direct | v2 dynamic（旧证据） | v2 combined | **enhanced-guided** | 工具本身 |
| --- | ---: | ---: | ---: | ---: | ---: |
| DeepSeek-V4.1-Flash | 135/140（96.43%） | 136/140（97.14%） | 136/140（97.14%） | **137/140（97.86%）** | 140/140（100%） |
| MiMo-V2.6-Flash | 136/140（97.14%） | 133/140（95.00%） | 136/140（97.14%） | **136/140（97.14%）** | 140/140（100%） |

- 与 v2 direct 的 McNemar：DeepSeek +2/−0，exact p=0.5；MiMo 0/0，p=1。与 direct/combined 的对比经 Holm 后 p=1；MiMo vs 旧动态证据 raw p=0.25、Holm 0.75。全部不显著。
- 两个模型都没有到达工具天花板；DeepSeek 的 2 个改动是把 2 个 `_22__good` 误报改成正确，MiMo 一个都没改。
- 工具本身 70TP/70TN；旧 harness 看不见的 12 个 bad，两个模型**在 direct 下就已经全部判对**（12/12），所以新证据在这 12 个单元上没有增益空间。
- 证据文本确实被读了：模型理由中复述“归因字节数”的比例从 direct 的 11%/23% 升到 **93%/89%**；但判定并不完全跟着证据走（仍各有 3/4 个 over-call）。因此既不能写“语义推理提升”，也不能写“纯照抄”。
- 成本：新增 280 次真实请求，configured **$0.023561**（provider list 同值，allowance $0.019094）。MiMo 的增强运行是同模型 direct 的 2.63×，却没有多对一题。

## 1. 与已有实验的关系

| 组件 | 来源 | 本目录怎么用 |
| --- | --- | --- |
| 清洗后的 140 个源码视图 | `hybrid/inputs_v2/units.jsonl` | 逐字节复用；预检重跑 `clean_unit` 比对 |
| direct prompt / system prompt | `hybrid/prompts.py` → `juliet_llm.prompting` | 直接调用 v2 builder；预检比对 280 个 prompt SHA |
| 证据外壳 | `hybrid/prompts.py` 的 `_EVIDENCE_TEMPLATE` | 字节相同；只替换 `<Tool evidence>` 内容 |
| 三模式证据 | `dynamic_enhanced/exports/hybrid` | 只用数值字段重新渲染，绝不复制原 `evidence_text` |
| 对照运行 | `hybrid/runs/hybrid_v2_{model}_{direct,dynamic,combined}` | 只读；不重跑、不改写 |
| 工具基线 | `dynamic_enhanced` 的 `outcome` | 70TP/70TN，作为 0 成本行 |

`hybrid_v2` 是 2026-11-11 的运行；本目录只新增 `hybrid_dynamic_enhanced/runs/`。基线是历史运行，不是同一天重跑，这一点在报告里作为限制写明。

## 2. 证据怎么构造

每个单元的 prompt 只多出这一段（示例为 `realloc_fail` 证据单元）：

```text
Enhanced dynamic-analysis evidence for this code unit.
It is machine-generated tool output: untrusted, possibly incomplete, and possibly wrong.
Three run configurations were applied to the same compiled code unit:
- default configuration (standard leak-detector root set): no attributed leak.
- realloc-failure configuration (the first realloc that receives a non-null pointer is forced to fail): attributed leak of 800 byte(s) in 1 allocation record(s); the injected failure fired at realloc call 1.
- global-roots-disabled configuration (global and static variables are not treated as leak roots): no attributed leak.
Overall enhanced dynamic outcome: a leak was observed in at least one applicable configuration (primary evidence: realloc-failure configuration).
Each configuration executes the unit's own entry point once. An absence of attributed leak is an observation on that path, not proof of absence; allocations attributed to the runtime or toolchain are excluded by allocation-site attribution.
```

- 只从导出里取：模式是否适用、归因字节数、归因分配记录数、注入调用序号、最终 outcome。
- 不取：文件路径、文件名、函数名、unit id、CWE 编号、`bad`/`good`、`OMIT*`、`benign`/`fixed`、`vulnerable`、`memory_leak`。
- 每个块都过 `FORBIDDEN_EVIDENCE` 扫描；prompt 再过 `prompt_forbidden_hits`、`benign|fixed`、unit/group id 检查，失败即退出。
- `realloc_fail` 对 126 个单元写“not applicable”，不把它写成 clean；三个模式的计数在 `inputs/manifest.json` 里可查。

## 3. 预检（先于任何付费请求）

`results/preflight.json` 13 项全部 PASS：

1. `juliet/FREEZE.json` 的 subset SHA 与 140 个 test 单元一致（70 bad / 70 good）。
2. v2 输入包 SHA 与 manifest 一致；140 个源码逐字节等于重新 `clean_unit` 的结果。
3. 增强输入包与内存重建结果一致（磁盘 SHA = 重建 SHA）。
4. 工具混淆矩阵 = 70/0/70/0；`default` 适用 140、泄漏 58；`realloc_fail` 适用 14、泄漏 7；`nogobal` 适用 140、泄漏 63、good 泄漏 0。
5. 12 个“旧 harness 不可观测”单元与 `(label=bad, old dynamic clean)` 集合完全一致。
6. 所有 140 个增强证据块通过禁用标记扫描。
7. 140 个 direct prompt 与两个模型 v2 direct 记录的 SHA 逐一相同。
8. 增强 prompt 外壳与 v2 外壳字节相同。
9. 140 个增强 prompt 全部唯一，且证据块只出现一次。
10. 6 个 v2 基线 run 均为 140/140 ok，prompt version 与输入 SHA 匹配。
11. 凭证存在（只检查存在性，不读取内容到报告）。
12. `--smoke` 对两个模型各发 1 次真实小请求，均 200 / JSON 可解析。这 2 次不计入 280 次实验请求。
13. run id 未被占用。

`run` 拒绝在没有 PASS 预检、或输入 SHA / prompt version 不匹配时启动。

## 4. 运行与复现

全部在 WSL Ubuntu 内执行（Python 3.14.8，httpx 0.28.1）：

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj/hybrid_dynamic_enhanced

# 1) 输入包（不调用模型）
python3 run_hde.py build

# 2) 预检（--smoke 会发 2 次小请求）
python3 run_hde.py preflight --smoke --run-id enhanced_dynamic_v1

# 3) 2 个模型 × 140 次真实请求
python3 run_hde.py run --model all --run-id enhanced_dynamic_v1 --concurrency 10

# 4) 指标、成本、一致性、报告、审计
python3 run_hde.py analyze
python3 run_hde.py report
python3 run_hde.py verify
python3 run_hde.py report   # 把审计状态写进 REPORT.md
```

`run` 只写 `runs/<run_id>_<model>/`，新 run id 必须未被占用；`--resume --retry-invalid` 只补失败/非法记录，不会重复计费已有 140 条。

## 5. 结果细节

### 5.1 准确率与 McNemar

| 模型 | 对比 | Δ accuracy | 新对/基线对（不一致对） | bootstrap 95% CI | exact p | Holm p |
| --- | --- | ---: | ---: | --- | ---: | ---: |
| DeepSeek | vs direct | +1.43 pp | 2 / 0 | [0.00, 3.57] pp | 0.5000 | 1.0000 |
| DeepSeek | vs dynamic | +0.71 pp | 1 / 0 | [0.00, 2.14] pp | 1.0000 | 1.0000 |
| DeepSeek | vs combined | +0.71 pp | 1 / 0 | [0.00, 2.14] pp | 1.0000 | 1.0000 |
| DeepSeek | vs tool | −2.14 pp | 0 / 3 | [−5.00, 0.00] pp | 0.2500 | 1.0000 |
| MiMo | vs direct | +0.00 pp | 0 / 0 | [0.00, 0.00] pp | 1.0000 | 1.0000 |
| MiMo | vs dynamic | +2.14 pp | 3 / 0 | [0.00, 5.00] pp | 0.2500 | 0.7500 |
| MiMo | vs combined | +0.00 pp | 1 / 1 | [−2.14, 2.14] pp | 1.0000 | 1.0000 |
| MiMo | vs tool | −2.86 pp | 0 / 4 | [−5.71, −0.71] pp | 0.1250 | 0.5000 |

McNemar 是 exact 双侧；分母 140，没有 invalid/API error。Holm 在每个模型内对 4 个对比校正。

### 5.2 变化发生在哪里

| 模型 | 相对 direct | 修正 | 破坏 |
| --- | --- | ---: | ---: |
| DeepSeek | 2 个 `_22__good` 误报 → 正确（`int_malloc_22__good`、`twoIntsStruct_realloc_22__good`） | 2 | 0 |
| MiMo | 无变化 | 0 | 0 |

- 12 个旧不可观测单元：direct 已经 12/12，增强没有新增正确。
- 58 个旧动态泄漏单元：所有方法都 58/58。
- 6 个被清洗的 `_22__good`：direct 1/6（DeepSeek）、2/6（MiMo）；增强 3/6、2/6；工具 6/6。剩余的 over-call 集中在 `new_array_char_22__good`、`new_array_int_22__good`、`new_int_22__good`（MiMo 还有 `twoIntsStruct_realloc_22__good`）。

### 5.3 响应一致性（是不是照抄证据）

| 信号 | DeepSeek | MiMo |
| --- | ---: | ---: |
| 判定与工具一致 | 97.86%（3 over-call） | 97.14%（4 over-call） |
| 理由出现工具/证据词 | 9.29% | 2.86% |
| 理由复述归因字节数 | **92.86%**（direct 11.43%，dynamic 77.14%） | **88.57%**（direct 22.86%，dynamic 67.14%） |
| 理由出现“attributed/configuration”等证据措辞 | 0% | 1.43% |
| clean 单元理由引用工具 | 0% | 0% |
| 12 个旧不可观测单元：理由提 realloc / global | 58.33% / 41.67% | 58.33% / 41.67% |

怎么读：

- 工具 140/140，所以“与工具一致率”在这里**等于准确率**，无法区分照抄与独立判断。
- 字节数复述是唯一较强的信号：增强证据带运行时归因字节数，模型理由里复述它的比例大幅上升。但复述数字不等于按它改判定——两个模型仍各有 3/4 个 clean 单元被判成 vulnerable。
- 12 个旧不可观测单元的理由引用率与 direct 完全相同，说明这些单元的解释没有因为新证据而变化；它们本来就被模型判对了。
- 因此正确说法是：**证据被读取并被引用，采纳是部分且不一致的；没有证据表明语义推理提升。**

## 6. 成本

| 模型 | 方法 | prompt tokens | completion tokens | configured USD | allowance USD | USD / correct |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| DeepSeek | enhanced-guided | 112,671 | 7,187 | $0.011165 | $0.006699 | $0.000081 |
| DeepSeek | v2 direct | 78,091 | 6,892 | $0.010185 | $0.006111 | $0.000075 |
| MiMo | enhanced-guided | 111,357 | 6,717 | $0.012395 | $0.012395 | $0.000091 |
| MiMo | v2 direct | 77,410 | 6,557 | $0.004718 | $0.004718 | $0.000035 |

- 新增总成本：280 次请求，$0.023561 configured；provider list $0.023561，allowance $0.019094。预检 smoke 另有 2 次小请求 $0.000088，all-in $0.023648。
- DeepSeek：+2 正确，多花 $0.000980，约 $0.000490/额外正确；样本太小，不能当稳定单价。
- MiMo：0 额外正确，多花 $0.007677（2.63×），主要来自 1.44× prompt tokens 和更少的 cache 命中。
- 口径：`configured` 是按价卡算的 USD；`provider list` 与 `allowance` 是 provider 快照，不能与账单混用。工具本身离线，0 API 成本。

## 7. 审计

`python3 run_hde.py verify` → `results/audit.json` / `audit.md`，12/12 PASS：

- 重新计算 280 个 prompt 的 SHA、证据 SHA、`y_true` 与 `y_pred` 一致性；
- 从原始 JSONL 重算 5 个方法 × 2 个模型的准确率、混淆矩阵和 8 个 McNemar p；
- 校验成本算术：逐条 `cost_usd` 之和 = manifest；provider list / configured 在 2% 内；
- 扫描 20 个生成文件（不含审计器自身输出），确认 API key 字面量、`sk-`、`Bearer ` 均未出现；
- 确认 6 个 v2 基线目录的 50 个文件 mtime 早于本次 run 开始时间；
- 确认 predictions CSV 恰好 1,400 行、results JSONL 恰好 280 行。

审计不打印、不保存 key；key 只从 `~/.kimi-code/config.toml` 读入进程内存。

## 8. 限制（不能声称的事）

1. **不能写“语义推理提升”。** 工具 140/140；满分完全可以由照抄解释，而实际得分低于满分。准确率在这套数据上无法分离两种机制。
2. **不能写“显著”。** 相对 direct，DeepSeek +2（exact p=0.5），MiMo 0；相对旧动态证据，MiMo +3（raw p=0.25，Holm 0.75），仍不显著。单次重跑无法把证据效应与服务端非确定性分开（v1/v2 重跑已记录过 flips）。
3. **基线是历史运行。** direct/dynamic/combined 来自 2026-11-11，同输入包、同 prompt version，但不是同一天；服务端行为可能漂移。
4. **理由分析是词法的。** 字节数复述、关键词引用只能说明模型重复了什么，不能说明它如何使用；极性标签是启发式，且大量“unclear”。
5. **证据是条件性的。** `realloc_fail` 只覆盖 14 个单元；`nogobal` 是全局根总开关，不是逐变量根映射；clean 只代表该执行路径上未观察到归因泄漏。
6. **范围。** 仅 Juliet CWE-401 冻结 test 140（70/70），不涉及 dev、生产代码、其他 CWE 或其他模型。
7. **Valgrind 未重跑。** 证据里 `valgrind` 显式为 `unavailable`，旧 Valgrind 对比只出现在 `dynamic_enhanced` 的 metrics 中，没有被冒充成新证据。

## 9. 目录

```text
hybrid_dynamic_enhanced/
├── README.md
├── REPORT.md                     # 完整报告（英文，含所有表）
├── run_hde.py                    # CLI: build / preflight / run / analyze / report / verify
├── hde/
│   ├── config.py                 # 路径、模型、价格、版本
│   ├── evidence.py               # 导出加载、证据渲染、去标签扫描
│   ├── prompts.py                # direct 复用 v2；增强 prompt builder
│   ├── build_inputs.py           # inputs/units.jsonl + manifest
│   ├── preflight.py              # 13 项 fail-closed 预检
│   ├── api.py                    # key 读取、NO_PROXY、ApiConfig
│   ├── run.py                    # 2 × 140 真实请求
│   ├── stats.py                  # Wilson、McNemar、bootstrap、Holm
│   ├── analyze.py                # 指标、成本、子集、一致性
│   ├── report.py                 # REPORT.md / tables / cost
│   └── audit.py                  # 12 项产物审计
├── inputs/                       # 140 单元 + manifest（含 SHA）
├── runs/
│   ├── enhanced_dynamic_v1_deepseek/   # results/requests/manifest/config
│   └── enhanced_dynamic_v1_mimo/
└── results/
    ├── preflight.json
    ├── enhanced_dynamic_metrics.json
    ├── enhanced_dynamic_predictions.csv
    ├── enhanced_dynamic_results.jsonl    # 280 条真实响应合并
    ├── consistency.json
    ├── enhanced_dynamic_tables.md
    ├── cost.json / cost.md
    └── audit.json / audit.md
```
