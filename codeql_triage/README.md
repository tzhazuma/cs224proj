# CodeQL + LLM 告警分流（`codeql_triage/`）

本目录只做一件事：在冻结的 Juliet CWE-401 test 140 上，让 LLM 对 CodeQL 的告警做**所有权/别名/全局控制流/跨函数释放**分流，并严格比较分流前后的精确率、召回率、macro-F1、MCC、coverage、TP 误删和成本。

所有代码在 WSL 中运行；只读取 `juliet_llm/build/test.jsonl` 与 `static_extended/runs/codeql_20261114_cwe401_full`；不修改 `juliet/`、`static_extended/`、`benchmark/` 或任何父实验结果。没有执行 `git`/`gh`，没有把 API key 写入任何产物。

## 1. 当前状态（2026-11-22）

| 条件 | 状态 | 说明 |
| --- | --- | --- |
| MiMo `mimo-v2.6-flash`，direct + triage v1 + triage v2 + 91 告警复核 | **完成** | 真实 Xiaomi 官方 API，140×2 + 91 条请求，缓存与逐样本结果已落盘 |
| DeepSeek `deepseek-flash` / `deepseek-v4.1-flash` | **阻塞，无结果** | 官方端点 `402 Insufficient Balance`；OpenCode Go `401 api_key_expired`；Qwen Token Plan `403 AccessDenied`；未伪造任何 DeepSeek 数字 |
| 23 个 CodeQL FP 专项 | **完成** | 逐个样本的模型理由、证据字段、最终保留/撤销均已输出 |
| TP 误删统计 | **完成** | v1 删 7/68；v2 删 0/68；最终策略删 0/68 |
| 成本/延迟 | **完成** | 配置价、token、p50/p95、缓存命中均已记录 |

DeepSeek 的失败证据在：

- `runs/blocked_deepseek_official_v1/`：官方端点 1 条请求，HTTP 402，`Insufficient Balance`
- `runs/blocked_deepseek_opencode_go_v1/`：OpenCode Go 1 条请求，HTTP 401，`api_key_expired`

这不是“DeepSeek 结果为 0”，而是“没有可用凭证，未产生结果”。

## 2. 数据与冻结口径

- 输入视图：`juliet_llm/build/test.jsonl`，140 个清洗单元（70 bad / 70 good；C 58 / C++ 82）。
- CodeQL：`static_extended/runs/codeql_20261114_cwe401_full/predictions.jsonl`，test 140。
- 连接键：`unit_id == sample_id`；`selfcheck` 会校验 140 个单元、68 TP、23 FP、4 compile_error、2 FN。
- 23 个 FP 全部是 **C++ good**，全部来自 `cpp/memory-may-not-be-freed`；`cpp/memory-never-freed` 在 test 140 上 0 FP。
- 4 个 compile_error 是 `CWE401_Memory_Leak__new_twoIntsStruct_82_{bad,good}` 与 `CWE401_Memory_Leak__new_wchar_t_82_{bad,good}`；CodeQL 无法建库，端到端按“未报泄漏”计，但单独列表，不写成负例。
- 2 个 CodeQL FN 正是其中 2 个 `_82__bad`；LLM 能从清洗源码读出泄漏，但 triage 没有告警可分流，所以最终策略仍漏这 2 个。

## 3. 条件与策略

### 3.1 条件

| 条件 | 输入 | 输出 |
| --- | --- | --- |
| `direct` | `juliet_llm` 原始 zero-shot 提示（system + 源码） | `label: vulnerable/not_vulnerable` |
| `triage v1` | CodeQL 状态/告警行 + 同一清洗源码 + 所有权/别名/全局/跨函数证据字段 | `alert_verdict`, `leak_present`, 5 个证据字段, `reason` |
| `triage v2` | 同 v1，但先判 `leak_present`，再判 `alert_verdict`；显式规定 `realloc` 失败路径、禁止“有告警就 true_positive”、强制自检 | 同上，字段顺序改为 `leak_present` 在前 |
| `verify` | 仅 91 个 CodeQL 告警；输入源码 + CodeQL 报告 + v1/v2 首轮 JSON | `final_leak_present`, `final_alert_verdict`, `release_gap` |
| 廉价基线 | 无 API | `never-freed only`；`drop C++ may-not-be-freed`；v2 文本一致性规则 |

### 3.2 预先声明的策略

- **`triage_keep`（一次性主策略）**：CodeQL 有告警时，只有模型明确说 `false_positive` 才撤销；`uncertain`、无效输出、无告警都保留 CodeQL 判定。
- **`triage_verified`（最终策略）**：在 `triage_keep` 基础上，对 91 个告警使用二次复核；复核说 `false_positive` 才撤销，`uncertain` 保留。
- **`rule_text_consistency`（零成本基线）**：不调用第二次 API，只用首轮 `reason`/证据字段中的“no heap leak / released on every path / false positive”等标记与 `leak_present` 的一致性来修正；这是探索性规则，不是预注册方法。
- **`hybrid_cascade_direct`（操作点对照）**：有 CodeQL 告警走 `triage_verified`；无告警走 `direct`。它不是纯 triage，只用于看召回/精确率的交换。
- **coverage** 始终与指标一起报告：CodeQL 可分析 136/140；triage API 有效 140/140（其中 2 条原始输出把“无告警”写成 `uncertain`，按澄清后的规则重解析，未重跑 API；原始有效 138/140，见 `runs/test140_mimo_xiaomi_v2/REPARSE_NOTE.md`）；direct 140/140。

## 4. 主结果（MiMo，test 140，端到端）

| 策略 | TP | FP | TN | FN | P | R | macro-F1 | MCC |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CodeQL | 68 | 23 | 47 | 2 | 0.7473 | 0.9714 | 0.8173 | 0.6739 |
| direct LLM | 69 | 5 | 65 | 1 | 0.9324 | 0.9857 | 0.9571 | 0.9158 |
| triage v1 一次性 | 61 | 5 | 65 | 9 | 0.9242 | 0.8714 | 0.8999 | 0.8013 |
| triage v2 一次性 | 68 | 3 | 67 | 2 | 0.9577 | 0.9714 | 0.9643 | 0.9287 |
| **v2 + 一致性复核（最终）** | **68** | **0** | **70** | **2** | **1.0000** | **0.9714** | **0.9857** | **0.9718** |
| v2 + 文本一致性规则（零额外 API） | 68 | 0 | 70 | 2 | 1.0000 | 0.9714 | 0.9857 | 0.9718 |
| cascade：告警走复核，无告警走 direct | 70 | 2 | 68 | 0 | 0.9722 | 1.0000 | 0.9857 | 0.9718 |
| 廉价规则：丢弃 C++ `may-not-be-freed` | 60 | 0 | 70 | 10 | 1.0000 | 0.8571 | 0.9282 | 0.8660 |
| 廉价规则：只保留 `never-freed` | 46 | 0 | 70 | 24 | 1.0000 | 0.6571 | 0.8234 | 0.6995 |

关键差值（10,000 次配对 bootstrap，精确 McNemar）：

- 最终 vs CodeQL：macro-F1 **+0.1684**，95% CI `[+0.1084, +0.2349]`，p `< 1e-6`。
- 最终 vs direct：macro-F1 **+0.0286**，95% CI `[-0.0072, +0.0714]`，p `0.289`，**不显著**。
- 最终 vs v2 一次性：**+0.0214**，95% CI `[0.0000, +0.0500]`，p `0.25`，只来自 3 个 `_22` FP。
- v2 一次性 vs CodeQL：**+0.1470**，95% CI `[+0.0908, +0.2097]`，p `2e-6`。

结论要分两层读：**v2 显著优于 CodeQL；最终策略在 140 个单元上没有显著优于 direct**。最终策略的优势是 0 FP、0 TP 误删；direct 的优势是少 1 个 FN（它抓到了 2 个 compile_error bad，但漏了 1 个 realloc bad）。两者 macro-F1 接近，属于不同操作点，不是“LLM triage 全面更好”。

### 4.1 与既有 `juliet_llm` direct 的复现差异

本次 fresh direct 是 **69 TP / 5 FP / 65 TN / 1 FN**（macro-F1 0.9571、MCC 0.9158）。既有 `juliet_llm` 的 postleakfix MiMo 是 **68 / 5 / 65 / 2**（macro-F1 0.9500、MCC 0.9008）。差异只有 1 个 TP：`CWE401_Memory_Leak__malloc_realloc_int64_t_18__bad` 这次被判为泄漏。  
这可能是同模型 ID 在 provider 侧的版本/路由漂移，也可能是单次采样差异；不能归因于本目录的提示。为避免混淆，主表用**同一次 run、同一端点、同一时间**的 fresh direct 作对照；既有 run 只作为复现参考。若要严格估计方差，应做 3 次重复采样（见 `IDEAS.md` #7/#10）。

## 5. 23 个 CodeQL FP

| 模式 | 数量 | v1 撤销 | v2 撤销 | 最终撤销 | direct 正确 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `_33` 引用/遮蔽别名 + 独立 ALLOCA 栈路径 | 15 | 14 | 15 | 15 | 15 |
| `_22` 全局标志 + 跨函数 delete | 3 | 0 | 0 | 3 | 0 |
| `_72` vector 容器元素跨文件 | 3 | 3 | 3 | 3 | 3 |
| `_54` 五层 wrapper 链 | 2 | 1 | 2 | 2 | 2 |
| 合计 | 23 | 18 | 20 | 23 | 20 |

- v1 的 5 个残留 FP：3 个 `_22`、1 个 `_54`、1 个 `_33`。
- v2 的 3 个残留 FP 全是 `_22`：模型在 `reason` 里写“all heap allocations released / alerts are false positives”，却仍输出 `alert_verdict=true_positive`、`leak_present=true`。这是**字段极性/自相矛盾**，不是所有权推理失败。
- 二次复核只改了 3 个决策：3 个 `_22` 从 keep 改为 drop；**0 个 TP 被改坏**。文本一致性规则得到完全相同的结果，说明第二次 API 不是必需的；它的价值是避免手写标记，而不是新增判别力。
- direct 也在同样的 3 个 `_22` 上错；它另外在 `int_malloc_22`、`twoIntsStruct_realloc_22` 上误报。triage 最终把这 5 个都处理掉了。

## 6. TP 误删

- v1：**7/68** CodeQL TP 被撤销，全部是 `malloc_realloc_*` 的 `may-not-be-freed`；其中 6 个 direct 判对，1 个 direct 也判错。模型理由是“realloc 失败不是正常路径/不可行”，与题目定义冲突。
- v2：显式加入 realloc 失败路径规则后，**0/68** TP 被撤销。
- 最终：**0/68**。
- 这 7 个 TP 的逐条理由、query、direct 判定在 `runs/test140_mimo_xiaomi_v1/analysis/tp_deleted.md`；v2 的 0 误删在 `runs/test140_mimo_xiaomi_v2/analysis/tp_deleted.md`。

## 7. 成本与延迟

配置价（USD / 1M tokens，非发票）：MiMo 输入 0.14、输出 0.28、缓存输入 0.0028；DeepSeek 参考价 0.30 / 1.20 / 0.006（未使用）。

| 条件 | 请求 | 有效 | 成本 USD | prompt tokens | completion tokens | p50 s | p95 s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| direct | 140 | 140 | 0.00302 | 77,410 | 6,676 | 2.83 | 5.73 |
| triage v2 | 140 | 140 | 0.03054 | 171,675 | 23,250 | 6.91 | 14.20 |
| verify（可选） | 91 | 91 | 0.01223 | — | — | 3.80 | 6.49 |

- direct + triage v2 + 文本规则总成本 **$0.03356 / 140 单元**（约 `$0.00024/单元`、`$0.00037/告警`、`$0.00146/撤销的 FP`、`$0.00049/保留的 TP`）。
- direct + triage v2 + 二次复核总成本 **$0.04579**；多花 $0.01223 没有改变任何最终决策（与文本规则 0 差异）。
- 端到端墙钟：v2 的 280 条请求在并发 6 下 **264.0 s**；v1 为 253.1 s。延迟是观测值，换机器会变。
- CodeQL：test 140 的逐单元运行时长之和 **6,061.8 s**，均值 43.3 s/单元（6 并发跑 200 单元的总墙钟 1,434.7 s）；它没有 API 费用，但需要建库/分析算力。

## 8. 文件

```text
codeql_triage/
├── common.py                  # 数据连接、提示、审计、解析、指标、bootstrap/McNemar
├── run_triage.py              # direct/triage v1/v2 真实 API runner（缓存、断点、manifest）
├── run_with_kimi_config.py    # 从 Kimi TOML 取 provider key，只放内存
├── verify.py                  # 91 个告警的二次一致性复核
├── verify_with_kimi_config.py # 复核的凭证 wrapper
├── analyze.py                 # 策略表、23 FP、TP 误删、direct 关系、成本、报告
├── selftest.py                # 无网络自检（420 条提示、泄漏审计、解析、指标）
├── README.md                  # 本文件
├── REPORT.md                  # 主报告（结果 + 文献 + 欠缺 + idea）
├── LITERATURE.md              # 注释文献
├── GAP_ANALYSIS.md            # 现有 benchmark 的欠缺
├── IDEAS.md                   # 可检验的改进设计
├── HANDOFF.md                 # 交付/复跑说明
├── benchmark_export.json      # 机器可读导出（父层可只读导入）
└── runs/
    ├── test140_mimo_xiaomi_v1/        # v1 一次性 + direct + analysis
    ├── test140_mimo_xiaomi_v2/        # v2 一次性 + direct + verify + analysis
    ├── blocked_deepseek_official_v1/  # 402 证据，不是实验结果
    └── blocked_deepseek_opencode_go_v1/ # 401 证据，不是实验结果
```

每个完整 run 目录有：`requests_*.jsonl`（无 Authorization）、`results_*.jsonl`（原始 content/usage/cost/attempts）、`predictions_*.jsonl`、`metrics_*.json`、`manifest.json`、`cache/`。`analysis/` 有 `comparison.md`、`fp23.md`、`tp_deleted.md`、`direct_relation.md`、`verification.md`、`cost.md`、`compile_errors.md`、`per_sample.csv`、`per_unit.jsonl`、`summary.json`。

## 9. 复跑

MiMo v2：

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj
python3 codeql_triage/run_with_kimi_config.py \
  --kimi-config ~/.kimi-code/config.toml --kimi-provider xiaomi -- \
  --provider xiaomi --model mimo-v2.6-flash \
  --condition all --prompt-version v2 \
  --out-dir codeql_triage/runs/test140_mimo_xiaomi_v2 --concurrency 6
python3 codeql_triage/analyze.py \
  --run-dir codeql_triage/runs/test140_mimo_xiaomi_v2 \
  --out codeql_triage/runs/test140_mimo_xiaomi_v2/analysis \
  --label mimo-v2.6-flash-xiaomi-v2
```

二次复核：

```bash
python3 codeql_triage/verify_with_kimi_config.py \
  --kimi-config ~/.kimi-code/config.toml --kimi-provider xiaomi -- \
  --run-dir codeql_triage/runs/test140_mimo_xiaomi_v2 \
  --provider xiaomi --model mimo-v2.6-flash \
  --out-dir codeql_triage/runs/test140_mimo_xiaomi_v2/verify --concurrency 6
python3 codeql_triage/analyze.py --run-dir ... --out .../analysis --label ...
```

DeepSeek（凭证恢复后）：

```bash
# 官方端点充值后
python3 codeql_triage/run_with_kimi_config.py \
  --kimi-config ~/.kimi-code/config.toml --kimi-provider deepseek -- \
  --provider deepseek --model deepseek-flash \
  --condition all --prompt-version v2 \
  --out-dir codeql_triage/runs/test140_deepseek_official_v2 --concurrency 6

# 或 OpenCode Go 新 key 后
python3 codeql_triage/run_with_kimi_config.py \
  --kimi-config ~/.kimi-code/config.toml --kimi-provider opencode-go -- \
  --provider opencode-go --model deepseek-v4.1-flash \
  --condition all --prompt-version v2 \
  --out-dir codeql_triage/runs/test140_deepseek_opencode_v2 --concurrency 6
```

当前两条命令都会在第一条请求处失败（402/401），不会产生 140 条伪结果。

## 10. 限制

1. **DeepSeek 没有结果。** 只有 MiMo 的 140 单元实验；不能把 MiMo 的数字外推为 DeepSeek。
2. **最终 68/0/70/2 不是“方法全面优于 direct”**：vs direct 的 macro-F1 差 +0.0286，95% CI 跨 0，McNemar p=0.289。显著优势只对 CodeQL。
3. **二次复核不是独立盲审**：它看得到首轮 JSON，91/91 全对很可能包含首轮理由的锚定；文本规则达到同样结果，说明“复核”主要是在修自相矛盾，而不是新增证据。
4. **v2/复核是顺序消融，不是预注册方法**：v2 的 realloc 规则是在 v1 看到 7 个误删后加的；verify/text rule 是在 v2 看到 3 个残留后加的。它们应作为“错误分析驱动的提示迭代”报告，不能当作一次性预先声明的 SOTA。
5. **Juliet 记忆化风险**：清洗只去标签/路径/标识符，保留结构；已有文献报告 LLM 能重建清洗后的 Juliet 身份。140/140 的告警级复核不能当作真实项目泛化证据。
6. **23 个 FP 全是 C++ good、全是 `may-not-be-freed`**；廉价规则 `drop C++ may-not-be-freed` 已有 P=1.0、R=0.857。任何 LLM triage 都必须先超过这个零成本基线。
7. **2 个 CodeQL FN 是 compile_error**；triage 无法从“没有告警”里恢复它们，最终仍漏。cascade 用 direct 补回这 2 个，但引入 2 个 direct FP，macro-F1 相同、操作点不同。
8. **单次采样、temperature 0、单模型**；没有重复采样方差、没有校准/ECE、没有人评。
9. **成本是配置价**，不是发票；没有人类复核成本，也没有把 CodeQL 建库算力折成美元。
10. **证据字段是模型自述**，没有人工验证每条“free/delete 在这里”的事实正确性；只有最终标签可核。
11. **未跨 CWE、未上真实项目**；结论只适用于 Juliet CWE-401 子集。

## 11. 合规

- 全部命令在 WSL 中执行；Python 3.14。
- 只写 `codeql_triage/`；未修改父目录已有结果。
- 未执行 `git`/`gh`；未 push。
- 密钥只从 `~/.kimi-code/config.toml` 读入进程内存，manifest 只记录 `api_key_present` / `api_key_value_stored=false`；请求文件不含 Authorization。
- `selftest.py` 无网络；`results`/`requests` 已做密钥模式扫描：0 个文件包含任何已配置的 key。
