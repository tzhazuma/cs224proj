# 证据行 / 反事实修复提示（SecVulEval Tier A）

本目录实现并真实运行了一个**只输入函数源码**的结构化检测提示，在
`splits/test_detection_160.json` 的 160 个冻结测试函数上分别调用
DeepSeek V4.1 Flash 与 MiMo-V2.6-Flash。每个模型恰好 160 个检测请求，
并与已有的 `direct` 提示 run 做逐样本配对比较。

本目录不修改 `runner/`、`splits/`、`benchmark/`、`report/` 或任何旧 run；
所有新产物写在 `evidence_prompt/` 下。

状态（2026-11-12）：

| 项目 | 状态 |
| --- | --- |
| 提示与严格校验 | 已冻结：`secvul-evidence-prompt-2026-11-12.1` |
| DeepSeek 160 检测 | 完成：159 valid / 1 invalid / 0 API error |
| MiMo 160 检测 | 完成：158 valid / 2 invalid / 0 API error |
| 与 direct 的配对检验 | 完成：精确 McNemar + Holm + 10k cluster bootstrap |
| 证据行审计 | 完成：结构审计 + 与 `changed_lines` 的重合 + 随机基线 |
| 成本 / 延迟 | 完成：按原 baseline 价格配置计算 |
| 多 seed / 消融 | **未做** |

---

## 1. 提示契约

新提示要求模型在一次响应中给出六项：

```json
{
  "is_vulnerable": true,
  "confidence": 0.0,
  "evidence_lines": [1],
  "mechanism": "缺陷机制与数据流",
  "counterfactual_fix": "最小修复",
  "counterfactual_confirms": true
}
```

- `evidence_lines`：提示中打印的 1-based 行号，必须落在 `FUNCTION_SOURCE` 内；
- `mechanism`：缺陷是什么、不可信值如何到达敏感操作；
- `counterfactual_fix`：能移除缺陷的最小修复；
- `counterfactual_confirms`：该修复是否移除缺陷（模型自检，不是执行验证）。

标签一致性规则：

- `is_vulnerable=true`：至少 1 条证据行；`mechanism` 与 `counterfactual_fix`
  不能是 `none`/空；
- `is_vulnerable=false`：证据行为 `[]`，`mechanism` 与 `counterfactual_fix`
  为 `none`，`counterfactual_confirms=false`。

`counterfactual_confirms=false` 的正例**不会**被判定为 schema-invalid，而是记
`counterfactual_unconfirmed` 审计标记；报告同时给出原始视图和“只保留已确认正例”
的事后敏感性视图。

设计上有两个会同时影响召回与 FP 的选择，必须在解读时记住：

- 提示明确说“不要假设未见调用者已经校验输入”，因此函数内部可见、但依赖调用者
  约束的缺陷会被更积极地报出；这既可能提高真阳性，也可能提高需要上下文才能排除的
  假阳性。
- 提示列出缺陷类别并要求给出机制与最小修复，可能让模型整体更倾向回答“有漏洞”；
  实测 predicted positive rate 明显上升，支持这一解释。

## 2. 输入隔离

`evidence_prompt/prompt.py` 只接收 `func_body`。项目名、文件路径、函数名、
commit、CVE/CWE、`changed_lines`、`changed_statements`、`fixed_func_idx`、
`is_vulnerable` 标签和数据集 `context` 列都不会传入提示构造器。

构造时做三项结构校验，任一失败即拒绝生成请求：

1. 用户消息必须以固定 header 开头、以固定 footer 结尾；
2. header/footer 之间的内容必须逐字符等于带行号的源码；
3. 带行号源码去掉 `NNNN | ` 前缀后必须逐行重建原函数。

因此“只输入源码”是结构性的，不是约定。`results.jsonl` 的每个记录还带有
`prompt.only_source_variable=true`、`prompt.source_reconstructed=true`、
`prompt.input_fields=["func_body"]`，`analyze.py` 在计算指标前会逐样本强制校验。

> 函数源码正文本身可能自然包含路径、CVE 注释或类似变量名；这属于源码，
> 不是额外注入的元数据。

已核对：两个真实 run 的 160/160 条 `request.body_sha256` 与对应
`dryrun_evidence_*/dry_run_requests.jsonl` 逐条一致；`analyze.py` 会把该比对写入
`metrics.json` 的 `prompt_body_audit`。dry-run 请求不含 API key、标签或评估元数据。

## 3. 运行配置

| | DeepSeek | MiMo |
| --- | --- | --- |
| 模型 ID | `deepseek-v4.1-flash` | `mimo-v2.6-flash` |
| 端点 | `https://opencode.ai/zen/go/v1` | 同左 |
| 输出预算 | `max_tokens=8192` | `max_completion_tokens=8192` |
| 推理 | 默认（`deepseek-*` 自动 `thinking=disabled`） | `thinking=disabled` + `reasoning_effort=none` |
| temperature | 0.0 | 0.0 |
| 并发 | 8 | 16 |
| 超时 | 180 s | 300 s |
| 价格（USD/1M） | in 0.30 / out 1.20 / cached 0.006 | in 0.14 / out 0.28 / cached 0.0028 |
| 请求数 | 160 | 160 |

价格沿用对应 baseline run 的配置；运行前应重新核对官方页面。凭证由
`run_with_kimi_config.py` 从 Kimi Code 配置读入进程环境变量，不打印、不落盘；
manifest 只记录 `api_key_present`，并固定 `api_key_value_stored=false`、
`authorization_header_stored=false`。

提示在正式 test 之前冻结；只用 4 条 dev 样本做过 schema smoke（`smoke_dev_evidence_*`），
没有用 160 条 test 的输出修改 prompt 或校验规则。test 上的 invalid 按原契约计入
strict，没有做事后格式修复。

## 4. 真实结果

数据集：`splits/test_detection_160.json`，SHA-256
`bc83af63329963cb98c2e1f9b6d4f80e98e4dc16018d24b7308346d3abfa2bf8`
（128 漏洞 / 32 非漏洞）。两个新 run 的 prompt template SHA-256 均为
`a91bda673c2ae8c4b0924c85adeee9ca3ca5bf50616227fe4ae261826f20e2f3`。

### 4.1 检测指标

`valid` = schema-valid 且成功返回；`strict` = 所有 160 条记录，invalid/API error
算错。P/R/F1+ 为 valid-only 的正类指标；macro-F1 为二类宏平均。

| 模型 / 提示 | valid | P | R | F1+ | macro-F1 | strict acc |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek / direct | 160/160 | 0.8261 | 0.2969 | 0.4368 | 0.3828 | 0.3875 |
| DeepSeek / evidence | 159/160 | 0.8167 | **0.3858** | **0.5241** | **0.4223** | **0.4375** |
| MiMo / direct | 150/160 | 0.8056 | 0.2417 | 0.3718 | 0.3456 | 0.3250 |
| MiMo / evidence | 158/160 | 0.8103 | **0.3701** | **0.5081** | **0.4067** | **0.4188** |

> 本表的 R/P/F1 使用各 run 的 all-valid 分母；§4.2 的配对 Δ 使用双方共同 valid
> 子集（DeepSeek 159、MiMo 148），因此表中的水平值与 Δ 不能直接相减。strict
> accuracy 始终是 160 条全记录口径。

混淆矩阵（valid-only）：

| 模型 / 提示 | TP | FP | TN | FN |
| --- | ---: | ---: | ---: | ---: |
| DeepSeek / direct | 38 | 8 | 24 | 90 |
| DeepSeek / evidence | 49 | 11 | 21 | 78 |
| MiMo / direct | 29 | 7 | 23 | 91 |
| MiMo / evidence | 47 | 11 | 20 | 80 |

### 4.2 与原 direct 的逐样本配对检验

主检验在共同 valid 样本上做精确 McNemar：召回只用漏洞样本，FPR 只用非漏洞样本；
四个主检验（2 模型 × 2 终点）做 Holm 校正。

| 模型 | n 共同 valid | Δrecall | 召回 p | Holm p | ΔFPR | FPR p | Holm p |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek | 159 | +0.0945 | 0.0018 | **0.0055** | +0.0938 | 0.2500 | 0.2500 |
| MiMo | 148 | +0.1092 | 0.0002 | **0.0010** | +0.1379 | 0.1250 | 0.2500 |

召回子集 n 分别为 127 / 119，FPR 子集 n 分别为 32 / 29（invalid 记录从共同 valid 中排除）。

配对 discordant 计数（evidence 相对 direct）：

| 模型 | 召回 新增 TP / 丢失 TP | FPR 新增 FP / 修复 FP |
| --- | ---: | ---: |
| DeepSeek | +13 / −1 | +3 / −0 |
| MiMo | +13 / −0 | +4 / −0 |

两个模型都是“新增 TP 远多于丢失 TP”，但新增 FP 没有任何修复；这是召回上升、
FPR 也上升的直接来源。

10,000 次配对 cluster bootstrap（按项目聚类，seed 42，95% 百分位区间）：

| 模型 | Δrecall | ΔFPR | ΔF1+ | Δmacro-F1 |
| --- | --- | --- | --- | --- |
| DeepSeek | [0.0288, 0.1810] | [0.0000, 0.2821] | [0.0254, 0.1546] | [−0.0193, 0.0948] |
| MiMo | [0.0515, 0.1923] | [0.0385, 0.2727] | [0.0543, 0.1653] | [0.0005, 0.0882] |

严格口径（160 条，invalid 算错）：

| 模型 | direct strict | evidence strict | Δstrict | McNemar p |
| --- | ---: | ---: | ---: | ---: |
| DeepSeek | 0.3875 | 0.4375 | +0.0500 | 0.0963 |
| MiMo | 0.3250 | 0.4188 | +0.0938 | **0.0026** |

**解读**：召回提升在两个模型上都通过了 Holm 校正；假阳性点估计分别 +3 和 +4，
但 FPR 的配对检验不显著（n=32/29 个非漏洞样本，功效很低）。全样本 valid-only 的
precision 点估计为 DeepSeek −0.9pp、MiMo +0.5pp；共同 valid 子集上分别为 −0.6pp
和 −2.1pp（没有做配对检验，均在此样本量下无法区分于噪声）。F1 和 strict accuracy 上升。

操作点也发生了明显偏移：共同 valid 子集上的 predicted positive rate 从 28.3%→37.7%
（DeepSeek）、23.7%→35.1%（MiMo）；Δbalanced accuracy 为 +0.0004 / −0.0143，
ΔMCC 为 −0.0020 / −0.0276。也就是说，召回/F1 的上升主要来自“更敢报正例”，
而不是判别力（BA/MCC）的提升。因此“召回提高”有统计支持，但**不能说“没有增加
假阳性”**，也不能说模型整体排序能力变好；在当前样本量下，FPR 增加只是未被检验
判为显著。

### 4.3 证据行可审计性

结构审计：所有 valid 正例的证据行都在 `1..line_count` 内、无重复、非空行；
DeepSeek 60/60 grounded，MiMo 58/58 grounded。

与 ground-truth 修复行的重合（仅真阳性且 `changed_lines` 可映射）：

| 模型 | TP | 可映射 TP | exact hit | exact 随机基线 | ±3 hit | ±3 随机基线 | 引用行 exact 精确率 | 引用行 ±3 精确率 | 修复行 exact 召回 | 修复行 ±3 召回 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek | 49 | 43 | 0.4884 | 0.3446 | 0.6279 | 0.6250 | 0.2189 | 0.3434 | 0.1633 | 0.3568 |
| MiMo | 47 | 44 | 0.4545 | 0.3159 | 0.6364 | 0.5966 | 0.2555 | 0.3965 | 0.1461 | 0.3123 |

随机基线：在同一个函数中随机抽同样多的行，至少碰到一个修复行的期望概率
（超几何分布，再对 TP 取平均）。`changed_lines` 到函数体行号的映射：
128 个漏洞样本中 full=108、partial=9、none=11；716 个修复行条目中 683 个可映射。

**解读**：证据行在结构上可审计，但**定位能力很弱**。exact 重合略高于随机基线
（0.49 vs 0.34；0.45 vs 0.32），±3 重合与随机基线几乎相同（0.63 vs 0.63；
0.64 vs 0.60）。引用行的精确率只有 0.22–0.26，修复行的 exact 召回只有 0.15–0.16。
这些是描述性比较，没有对“观测 vs 随机基线”的差异做显著性检验。因此不能把
`evidence_lines` 当作可靠的漏洞定位或人工复核排序信号。可能的解释是模型引用的是
数据流/上下文行，而 `changed_lines` 只标修复行；但无论原因如何，本数据不支持
“证据行=缺陷位置”的强主张。

反事实确认率：DeepSeek 1.0000，MiMo 0.9828；但在 TP 和 FP 上都接近 1
（MiMo FP 1.0000），没有区分真伪正例的能力。事后“只保留 grounded 且已确认正例”
的敏感性分析几乎不改变指标（见 `analysis/report.md` §4），说明该自检没有提供
额外的降 FP 信号。

### 4.4 成本与延迟

成本按 detection 记录计算；直接基线 run 还包含 repair 请求，故其总成本/总 wall
不可与新 run 直接相加比较。

| 模型 / 提示 | detection 总 USD | 每 100 单元 USD | 每 TP USD | prompt tokens 均值 | completion tokens 均值 | 延迟 p50 | 延迟 p95 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek / direct | 0.066988 | 0.041868 | 0.001763 | 1032.8 | 90.7 | 5.65 s | 10.83 s |
| DeepSeek / evidence | 0.085622 | 0.053514 | 0.001747 | 1750.9 | 122.7 | 6.04 s | 12.06 s |
| MiMo / direct | 0.024397 | 0.015248 | 0.000841 | 960.4 | 78.1 | 4.59 s | 12.00 s |
| MiMo / evidence | 0.035933 | 0.022458 | 0.000765 | 1835.5 | 116.4 | 4.05 s | 10.87 s |

新 run 的 detection-only wall：DeepSeek 142.75 s，MiMo 67.36 s。证据提示的输入
token 约为 direct 的 1.7–1.9 倍；DeepSeek 每 100 单元成本 +27.8%，MiMo +47.3%。
每 TP 成本反而略降，因为 TP 增加；这不是单一“性价比”结论，需与 FP 代价一起读。

### 4.5 失败分类

| 模型 / 提示 | ok | invalid | API error | invalid 说明 |
| --- | ---: | ---: | ---: | --- |
| DeepSeek / direct | 160 | 0 | 0 | — |
| DeepSeek / evidence | 159 | 1 | 0 | idx 3526：模型正文承认“No OOB is concretely reachable”，却仍输出 `is_vulnerable=true` 且 `counterfactual_fix="none"`；按契约 invalid，strict 算错 |
| MiMo / direct | 150 | 10 | 0 | 10 条把 `is_vulnerable` 写成 `is_vulnerability`，旧 runner 严格验键失败 |
| MiMo / evidence | 158 | 2 | 0 | idx 8632（标签非漏洞）与 idx 7125（标签漏洞）：预测为漏洞但修复为 `none`，契约 invalid |

MiMo 的键名漂移在证据提示下消失（0 条键错误），但出现 2 条“预测漏洞但修复为空”
的内部矛盾。DeepSeek 的 1 条 invalid 也是同类矛盾。没有 API error。

strict 口径还要注意**格式合规差异**：MiMo direct 的 10 条 invalid 包含 8 条漏洞样本
和 2 条非漏洞样本，evidence 只有 2 条 invalid（1 正/1 负）。因此 MiMo 的 strict
+9.4pp 中有一部分是“原本判对但格式不合规”的样本被恢复，而不是检测判别提升；
共同 valid 的 accuracy 提升是 +6.1pp（DeepSeek +5.7pp）。DeepSeek 的 evidence
反而新增了 1 条 invalid，所以其 strict 提升不是靠格式合规。

## 5. 结论

1. **召回确实提高了**：共同 valid 上 DeepSeek +9.45pp（Holm p=0.0055），
   MiMo +10.92pp（Holm p=0.0010）。strict accuracy 也上升（全 160 口径），
   但 MiMo 的 strict 提升部分来自格式合规恢复（direct 10 条 invalid → evidence 2 条），
   不能全部归因于检测能力。all-valid 水平值与配对 Δ 的分母不同，见 §4.1–4.2。
2. **假阳性没有被消除**：点估计分别 +3/+4 个 FP，FPR 上升；配对检验不显著，
   但样本量只有 32 个非漏洞函数，不能据此宣称“不增加 FP”。
3. **收益主要来自操作点偏移**：共同 valid 上 predicted positive rate 从 28.3%→37.7%
   （DeepSeek）、23.7%→35.1%（MiMo），而 BA/MCC 基本持平或略降。召回/F1 的上升
   不等于判别力提升。
4. **证据行可审计但不可靠定位**：结构与范围审计 100% 通过；与修复行的 exact
   重合略高于随机，±3 重合接近随机。不能把它当作可靠的人工复核排序。
5. **反事实自检没有提供降 FP 信号**：几乎所有正例（含 FP）都自我确认；它更像
   一致性检查，而不是独立验证。
6. **输入隔离成立**：新 run 只含带行号的函数源码；没有 context、标签或元数据。
   因此召回提升不能归因于 context 伪影。
7. **因果归因未完成**：本实验把证据行、机制、反事实、行号四件事打包在一起；
   没有消融，不能说明是哪一部分带来召回提升。需要后续 2×2 消融（有/无证据行 ×
   有/无反事实）才能拆分。

## 6. 限制

- 单模型、单次运行；temperature=0 不保证确定性，没有多 seed 方差估计。
- 只有 160 个测试函数、32 个非漏洞样本；FPR 的 Wilson 区间很宽（约 0.20–0.53）。
- 这是 Tier A 真实项目函数上的检测；不能外推到 Juliet 或生产环境。
- `changed_lines` 只标修复行，不等于完整缺陷位置；映射 11/128 个漏洞样本失败，
  9 个部分失败；证据行审计的分母已明确列出。
- 反事实修复没有编译、运行或测试；“确认”只是模型自报。
- 两个模型不可横比：DeepSeek 为 non-thinking，MiMo 需 `reasoning_effort=none`
  才关闭推理；价格、延迟和模型能力不同。
- 直接基线 run 同时含 detection+repair；本报告只取 detection 记录，未改写旧结果。
- 没有做置信度阈值/选择性预测；任何事后阈值都会是 test-set 调参，未纳入主结果。

## 7. 复现

所有命令在 WSL 中、项目根目录执行：

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj

# 1. 离线自检（无网络）
python3 evidence_prompt/selftest.py

# 2. 只验证 160 条提示，不调用模型
bash evidence_prompt/run_evidence.sh deepseek dryrun
bash evidence_prompt/run_evidence.sh mimo dryrun

# 3. 4 条 dev 样本的 schema smoke（真实调用，不是测试集结果）
bash evidence_prompt/run_evidence.sh deepseek smoke
bash evidence_prompt/run_evidence.sh mimo smoke

# 4. 正式 160 条测试（真实调用）
bash evidence_prompt/run_evidence.sh deepseek test
bash evidence_prompt/run_evidence.sh mimo test

# 5. 指标、证据审计、配对检验
python3 evidence_prompt/analyze.py
```

`run_evidence.sh` 在目标目录已有 `manifest.json` 时自动加 `--resume`；所有请求
都按内容哈希缓存在 run 目录的 `cache/` 下。脚本不会覆盖 `runner/runs/`。

## 8. 产物

| 路径 | 内容 |
| --- | --- |
| `evidence_prompt/evidence_prompt/prompt.py` | 提示模板、带行号源码、输入隔离结构审计 |
| `evidence_prompt/evidence_prompt/validation.py` | 六字段严格校验与证据审计标记 |
| `evidence_prompt/evidence_prompt/runner.py` | 可恢复 runner、请求/结果/manifest 写入 |
| `evidence_prompt/run_evidence.py` | CLI 入口 |
| `evidence_prompt/run_with_kimi_config.py` | 从 Kimi Code 配置读凭证到进程内存 |
| `evidence_prompt/run_evidence.sh` | dryrun/smoke/test 三种模式 |
| `evidence_prompt/selftest.py` | 离线自检 |
| `evidence_prompt/analyze.py` | 指标、证据行映射、McNemar/Holm/bootstrap、报告生成 |
| `evidence_prompt/runs/test_evidence_deepseek/` | DeepSeek 160 条真实 run（结果 SHA-256 `0e09037d…`） |
| `evidence_prompt/runs/test_evidence_mimo/` | MiMo 160 条真实 run（结果 SHA-256 `c68dfa50…`） |
| `evidence_prompt/runs/dryrun_evidence_*` | 160 条请求体与 prompt 审计，无 API 调用 |
| `evidence_prompt/runs/smoke_dev_evidence_*` | 4 条 dev schema smoke |
| `evidence_prompt/analysis/metrics.json` | 全量指标、配对检验、审计字段 |
| `evidence_prompt/analysis/comparison.json` | 配对比较的紧凑版本 |
| `evidence_prompt/analysis/report.md` | 中文结果报告（含表格与限制） |

旧产物保持只读：`runner/runs/test_v1_direct_independent`、
`runner/runs/test_v1_mimo_direct_independent`、`splits/`、`benchmark/` 均未改写。
