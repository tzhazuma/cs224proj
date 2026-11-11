# SecVulEval 实验运行器

本目录实现一个**真实可运行、可恢复**的 LLM 实验运行器，用于在同一批 SecVulEval 数据上比较 2–3 种提示方法。运行器只使用 Python 标准库和 `httpx`，通过 OpenAI 兼容的 Chat Completions 接口调用模型。

> 当前没有可用的有效 API 凭证。用户原有的 OpenCode Go key 已过期，真实请求返回 `401`；因此本目录**没有产生任何真实模型结果**。验证只使用了 WSL 本地临时 mock HTTP 服务；mock 结果不是模型实验结果，也没有写入项目报告或数据目录。

## 1. 运行环境

- 所有命令在 WSL 中执行，例如：

  ```bash
  wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && python3 --version'
  ```

- 已验证环境：Python `3.14.8`、`httpx` `0.28.1`。运行器不依赖 `openai`、`pandas`、`openpyxl`。
- 不需要安装本项目；直接运行 `runner/run_experiment.py` 即可。脚本所在目录会自动加入模块搜索路径。
- 读取的数据文件：

  | `--dataset` | 默认文件 | 检测请求数 | 修复请求数（仅漏洞函数） |
  | --- | --- | ---: | ---: |
  | `independent` | `datasets/independent_200.json` | 200 | 160 |
  | `pairs` | `datasets/vulnerable_fixed_200_pairs.json` | 400（200 对两侧） | 200（每对漏洞侧） |

  请求数按完整数据集计算；使用 `--limit` 后按选中的单元数计算，并标记为 partial。

## 2. 方法、任务与数据隔离

### 2.1 三种策略

| 策略 | 模型输入 | 用途 |
| --- | --- | --- |
| `direct` | 仅函数源码 | 零样本基线 |
| `few-shot` | 合成开发示例 + 目标函数源码 | 少样本基线；示例标签是方法的一部分，但示例不属于评估集 |
| `context` | 函数源码 + 经过白名单和清洗的上下文 | 上下文增强方法 |

### 2.2 两个任务

- `detection`：输出 `{"is_vulnerable": true/false, "confidence": 0.0-1.0, "rationale": "..."}`。
- `repair`：只对漏洞/原始版本发送请求，输出 `{"fixed_function": "<完整函数>", "explanation": "..."}`。`fixed_function` 必须是完整函数定义，不能是 diff、片段或 Markdown。
- `both`：同一运行中同时执行检测和修复；缓存、请求和指标按任务分开。

### 2.3 防止标签泄露

模型请求**不会**包含以下字段：`is_vulnerable`、`fixed_func_idx`、`changed_lines`、`changed_statements`、`cve_list`、`cwe_list`、`commit_message`、`commit_id`、`project_url`、`hash`、`idx`、`project`、`filepath`、`func_name`。

`context` 策略只读取 `context` 字段中的以下小节：

- `Execution Environment`
- `External Function`
- `Function Argument`
- `Globals`
- `Type Execution Declaration`

`Explanation` 不在白名单中，因为该字段可能直接描述漏洞。原始 context 字符串不会被 `eval`；运行器用 `ast` 解析字面结构，只提取字符串/数值项，并对每个项过滤 CVE、CWE、`fixed_func_idx`、`changed_lines`、`changed_statements`、`is_vulnerable`、`vulnerab*`、`ground truth`、`fixed function`、`patch` 等标记。单个项长度、每节项数和总字符数都有上限；解析失败时该样本不附带上下文，并在 dry-run 摘要中计数。

> 注意：函数源码本身可能自然含有 CVE 注释、变量名或提交说明；运行器不会改写源码。这里的隔离保证针对**额外注入的元数据字段和 context 项**，不针对源码正文。

### 2.5 上下文的残余相关性（必须在报告中说明）

本项目的数据审计已经指出：`independent_200.json` 中 40 条非漏洞样本的 `context` 全部为空结构，而漏洞样本的 `context` 含外部函数/全局变量等内容。因此，即使运行器清除了 CVE/CWE/fixed_idx 等显式字段，**“context 是否有内容”本身仍与标签相关**。运行器不能在不丢弃上下文方法信号的前提下消除这一数据伪影。

使用 `context` 策略时应当：

- 在报告中把 L3 结果解释为“带上下文的提示”，并同时报告 context 覆盖率/空上下文子集结果；
- 不把 L1 与 L3 的差异单方面归因于“上下文推理能力”；
- 若需要更严格的因果比较，应预先构建与标签无关的上下文（例如仅从函数源码提取调用图），并作为新的策略单独登记。

运行器的 prompt 元数据记录 `context.provided`、`context.parse_ok`、`context.nonempty`、`context.section_item_counts`；`metrics.json` 的 `context` 块汇总非空/空上下文与解析失败数，`results.jsonl` 可用于按覆盖率分层分析。

### 2.6 数据集划分与自定义文件

`--dataset-file` 可指向与默认 JSON 同 schema 的冻结子集文件（例如其他实验模块生成的 40/160 开发-测试划分）；运行器会重新校验数量、标签、`fixed_func_idx` 指向和配对一致性，并把文件 SHA-256 写入 manifest。`--dev-examples` 可以指向从开发划分整理的示例 JSON；加载时会对**评估文件中的全部函数**做隔离检查。运行器本身不创建或修改划分文件，也不修改 `datasets/`。

### 2.4 开发示例隔离

默认示例在 `secvul_runner/dev_examples.json`，是手写的 C 代码，不会从评估集抽样。`--dev-examples` 可换用自定义 JSON，但加载时会执行：

- 每个 detection/repair 示例的规范化源码不得与评估集任何函数完全相同；
- 示例声明的 `source_idx`（如有）不得出现在评估集；
- 必须包含正负两类 detection 示例，以及至少一个 repair 示例（按任务检查）；
- detection/repair 的修复前后代码分别检查。

示例文件包含模型需要的标签；这是 few-shot 的教学信号，不是把评估样本的标签泄露给模型。

## 3. 快速开始

### 3.1 Dry-run：只验证请求，不产生实验结果

Dry-run 不需要 API key，不发起任何网络请求，不写 `results.jsonl` 或 `metrics.json`。

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && \
python3 runner/run_experiment.py \
  --dataset independent \
  --strategy context \
  --task both \
  --model "<model-id>" \
  --out-dir /tmp/secvul_dry_run \
  --dry-run'
```

产物只有：

- `dry_run_requests.jsonl`：每个规划的请求、完整 body、prompt 元数据、`User-Agent`/`x-opencode-session` header 和请求指纹；不包含 `Authorization` 请求头，并显式标记 `authorization_header_omitted: true`。
- `dry_run_manifest.json`：请求数、按任务计数、数据集 SHA-256、配置指纹、会话 header 与哈希、context 解析失败数，以及 `no_api_calls: true`、`experimental_results: false`。

输出会明确打印 `No API call was made. No experimental results or metrics were produced.`。不要把 dry-run 摘要当作模型性能。

### 3.2 真实运行

模型名必须显式指定，或通过 `SECVUL_MODEL`/`DEEPSEEK_MODEL` 提供；运行器不硬编码任何模型名。默认 base URL 是 `https://api.deepseek.com/v1`（可配置），API key 只从环境变量读取。

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && \
export SECVUL_MODEL="<provider-model-id>" && \
python3 runner/run_experiment.py \
  --dataset independent \
  --strategy direct \
  --task both \
  --model "$SECVUL_MODEL" \
  --out-dir runner/runs/independent_direct_both'
```

API key（不要把密钥写进命令行历史或文件）：

```bash
export DEEPSEEK_API_KEY   # 值由当前环境提供
```

也可用 `--api-key-env OTHER_ENV_NAME` 指定其他环境变量名。运行器只记录变量名和“是否存在”，不记录值。

### 3.2.1 OpenCode Go（官方端点）

OpenCode Go 的 OpenAI Chat Completions 端点是：

```text
https://opencode.ai/inference/go/openai/v1/chat/completions
```

本项目的模型 ID 使用 `deepseek-v4.1-flash`（OpenCode Console 的模型页列出的 ID）。`deepseek-v4.1-flash-free` 是仅限 OpenCode 客户端内的免费层，第三方客户端会收到 `403`；本运行器使用 Go 模型 ID `deepseek-v4.1-flash`。注意：`deepseek-v4.1-flash` 是 OpenCode Go 的模型 ID；DeepSeek 官方 API 的模型别名是 `deepseek-flash`，两者端点不同，不要混用。`--base-url` 可以传 base URL，运行器会自动追加 `/chat/completions`。请先在 WSL 环境中由外部注入 `OPENCODE_API_KEY`（不要把值写进命令历史或脚本），然后执行：

```bash
# 在 WSL 中执行；OPENCODE_API_KEY 必须已在当前环境中设置
cd /mnt/c/Users/tzh03/Downloads/zy
python3 runner/run_experiment.py \
  --dataset independent \
  --strategy direct \
  --task both \
  --model deepseek-v4.1-flash \
  --base-url https://opencode.ai/inference/go/openai/v1 \
  --api-key-env OPENCODE_API_KEY \
  --out-dir runner/runs/opencode_go_pilot \
  --limit 5

# 续跑同一目录时重复原命令并加 --resume
```

OpenCode Go 凭证只通过 `--api-key-env` 指定的环境变量读取。运行器**不会**读取 `auth.json`、`opencode.json`、keychain 或其他 OpenCode 本地凭证；密钥也不会写入命令行、manifest、请求文件或日志。不要使用过期 key 跑全量：无效/过期凭证会返回 `401`，`401` 不在重试列表内，该请求会被记为 API error，不会被伪装成有效预测。

OpenCode Go 要求每个请求带稳定的会话标识，并要求客户端使用自己的 User-Agent。运行器会自动发送：

| 请求头 | 值 | 说明 |
| --- | --- | --- |
| `User-Agent` | `secvul-eval-runner/1.0` | 可用 `--user-agent` 或 `SECVUL_USER_AGENT` 覆盖 |
| `x-opencode-session` | `ses_<32 hex>` | 每次运行自动生成；所有请求、重试和同一目录的 `--resume` 复用同一个值 |

依据：<https://opencode.ai/v2/docs/console/harnesses/>（Go 端点与 `x-opencode-session`）和 <https://opencode.ai/v2/docs/console/api/inference/>（`usage.opencode` / `opencode.allowance`）。

`x-opencode-session` 是**非敏感的随机会话 ID**，不是 API key。`manifest.json` 的 `api.session` 记录 `value`、`sha256`、`source`（`generated` 或 `resumed_manifest`）和 `is_secret: false`；`requests.jsonl` 与 dry-run 请求文件也会记录该 header，但仍不记录 `Authorization`。该 header 会随所有请求发送；非 OpenCode 端点通常会忽略未知 header。它不进入缓存键，因此续跑不会因会话 ID 变化而重复计费。

OpenCode Go 的响应会在 `usage.opencode` 中报告计划用量。运行器保留原始响应（仅对密钥模式脱敏），并在 `metrics.json` 的 `usage` 中汇总：

- `records_with_opencode_usage`
- `opencode_allowance_known_sum_usd`
- `opencode_allowance_records`
- `opencode_billing_sources`

`opencode.allowance` 是 Go 套餐的美元额度消耗，**不会**填入 `cost_usd` 或 `total_cost_usd`；成本仍然只按显式传入的 `--input-price-usd-per-1m`、`--output-price-usd-per-1m`（以及可选的 `--cached-input-price-usd-per-1m`）计算。

价格必须按**运行当天**的官方页面核对。`deepseek-v4.1-flash` 在 OpenCode Go 上分峰时/谷时计价，官方文档（<https://opencode.ai/v2/docs/console/go/>）在 2026-11-11 列出峰时为 UTC 周一至周五 `01:00-04:00` 和 `06:00-10:00`，其余时间为谷时；价格和时段都可能调整，不能把本文数字当作长期价格。若需要成本列，先用当天价格显式传参，例如：

```bash
--input-price-usd-per-1m <run-date-input-price> \
--output-price-usd-per-1m <run-date-output-price> \
--cached-input-price-usd-per-1m <run-date-cached-read-price>
```

不传价格时 `cost_usd` 保持 `null`；`opencode.allowance` 仍会单独汇总，二者不要混为一谈。

### 3.3 使用 Windows Kimi Code 的 OpenCode Go 配置

`run_with_kimi_config.py` 可在用户明确授权后读取指定 TOML 中某个 provider 的 `api_key`，只把它放入当前进程内存和环境变量，不打印密钥，也不把密钥写入运行产物。以下命令仍在 WSL 中执行：

```bash
python3 runner/run_with_kimi_config.py \
  --kimi-config /mnt/c/Users/tzh03/.kimi-code/config.toml \
  --kimi-provider opencode-go \
  --dataset independent --strategy direct --task detection \
  --model deepseek-v4.1-flash --limit 1
```

对于 `deepseek-*` 模型，请求体默认发送 `thinking={"type":"disabled"}`，避免推理内容耗尽输出预算而最终答案为空。该设置进入请求指纹；首次 pilot 已确认关闭 thinking 后可返回合法 JSON、usage 和成本。`--thinking {default,enabled,disabled}` 可显式覆盖：`disabled`/`enabled` 发送对应 `thinking` 字段，`default` 完全不发送；省略时保持上述 DeepSeek 旧行为。`--reasoning-effort {none,minimal,low,medium,high}` 发送 `reasoning_effort`：MiMo 在 OpenCode Go 上会忽略 `thinking`，但 `reasoning_effort=none` 可真正关闭推理（实测 `reasoning_tokens=0`）。MiMo 的原生输出上限字段是 `max_completion_tokens`，用 `--max-tokens-field max_completion_tokens` 指定；传 `max_tokens` 会被忽略。`runner/run_matrix.sh pilot` 使用开发派生子集做小规模三策略测试；`runner/run_matrix.sh test` 在冻结测试集上运行完整矩阵，已有目录会自动使用 `--resume`。

### 3.4 同一数据集比较三种方法

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && \
export SECVUL_MODEL="<provider-model-id>" && \
for S in direct few-shot context; do
  python3 runner/run_experiment.py \
    --dataset independent \
    --strategy "$S" \
    --task both \
    --model "$SECVUL_MODEL" \
    --out-dir "runner/runs/independent_${S}_both"
done'
```

每个策略独立目录、独立缓存和独立 `metrics.json`。需要重新运行某个目录时，重复原命令并加 `--resume`。

配对数据集：

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && \
python3 runner/run_experiment.py \
  --dataset pairs \
  --strategy context \
  --task both \
  --model "$SECVUL_MODEL" \
  --out-dir runner/runs/pairs_context_both'
```

### 3.5 中断后续跑

配置指纹一致时，已完成请求从每样本缓存读取，不重复计费；缺失/失败请求继续执行。

```bash
# 第一次运行（可能被 Ctrl-C 中断）
python3 runner/run_experiment.py --dataset pairs --strategy direct --task both \
  --model "$SECVUL_MODEL" --out-dir runner/runs/pairs_direct_both

# 用完全相同的配置和目录续跑
python3 runner/run_experiment.py --dataset pairs --strategy direct --task both \
  --model "$SECVUL_MODEL" --out-dir runner/runs/pairs_direct_both --resume
```

续跑行为：

- 已成功缓存：复用，不调用 API。
- schema-invalid 响应：默认复用（避免无限重试模型）；加 `--retry-invalid` 可重新请求。
- API error 响应：默认重新请求（便于修复 401/网络后恢复）；加 `--reuse-cached-errors` 可保留错误并完成汇总。
- `--refresh` 必须与 `--resume` 一起用：忽略全部缓存并重新调用每个请求。
- `--limit`、数据集 SHA、策略、任务、模型、端点、temperature、max tokens、prompt 版本、开发示例哈希和 API 请求体都进入配置/请求指纹。改模型或改数据集后续跑会报错，而不是混合两批结果。
- 价格、并发数、超时、重试次数不会改变请求身份；续跑时按当前配置重新计算缓存响应中的成本（前提是 usage 仍在缓存中）。

## 4. 输出目录

真实运行目录：

```text
runner/runs/<timestamp>_<dataset>_<strategy>_<task>/
├── manifest.json        # 状态、配置指纹、数据集/API 配置、会话 header 哈希、请求计数（无密钥）
├── config.json          # 本次运行配置快照（无密钥）
├── requests.jsonl       # 每个请求的 body、prompt 元数据和 User-Agent/session header；不含 Authorization 头
├── results.jsonl         # 每样本一条：解析结果、原始 API response、usage、延迟、成本、缓存信息
├── cache/
│   └── <dataset>/<task>/<xx>/<key>.json   # 每请求原子缓存，含原始响应和解析/校验结果
├── metrics.json         # 机器可读指标
├── metrics.md           # 本次运行的可读报告
└── run.log              # 文本日志（不含密钥）
```

- `results.jsonl` 和缓存中的 API 原始 body 会做密钥模式脱敏（`sk-...`、`Bearer ...`），防止服务端回显密钥；模型内容不变。
- 缓存文件先写临时文件、`fsync`、再 `os.replace`，减少中断导致的半文件。
- `manifest.json` 的 `status` 为 `running`、`completed`、`interrupted` 或 `failed`。`--resume` 只接受配置指纹相同的已有 manifest。
- dry-run 目录只写 `dry_run_requests.jsonl` 和 `dry_run_manifest.json`，拒绝与真实运行 manifest 混用。

## 5. 指标口径

### 5.1 检测

- 混淆矩阵以 `is_vulnerable` 为阳性类：TP/FP/TN/FN。
- 这些值只统计 **schema-valid** 的检测预测；`valid_predictions`、`schema_invalid`、`api_errors`、`coverage` 同时给出。
- `metrics_valid_only` 中的 precision、recall、specificity、F1、accuracy、balanced accuracy、MCC 只以有效预测为分母。
- `strict_accuracy_all_samples` 把 schema-invalid 和 API-error 记录当作错误，分母是所有规划检测请求。
- `independent` 和 `pairs` 都按函数统计；`pairs` 另有 `by_side`（vulnerable/fixed）。

### 5.2 配对联合结果

仅 `pairs` + detection：

- 每个 pair 同时有漏洞侧和修复侧检测预测。
- `vulnerable_detected_fixed_clean`：漏洞侧判为漏洞、修复侧判为安全（唯一正确区分）。
- `both_flagged`：两侧都判为漏洞。
- `both_clean`：两侧都判为安全。
- `vulnerable_missed_fixed_flagged`：漏洞侧漏报、修复侧误报。
- `discrimination_accuracy_valid_pairs` 只在两侧都有效的 pair 上计算；`discrimination_accuracy_all_pairs` 把无效 pair 当作失败。JSON 还保留 2×2 `matrix`。

### 5.3 修复

修复没有编译/测试 oracle，因此只提供**结构性代理指标**：

- `schema_valid` / `schema_invalid` / `api_errors`；
- `complete_function`：括号配对（忽略字符串、字符和注释）、存在函数式前缀、非 diff、非 Markdown；
- `changed_from_input`：规范化后与输入函数不同；
- `complete_and_changed`；
- 配对数据集上还有与参考修复版本的文本比较：`exact_match_reference_fixed` 和 `whitespace_collapsed_match_reference_fixed`。

这些都不能证明漏洞已被真正修复或行为保持不变；报告中必须明确写成结构代理指标，不能写成“修复正确率”。

### 5.4 成本、token、延迟

- `usage` 保存 API 返回的原始 usage；汇总给出 prompt/completion/cached token 的已知和，以及缺失 usage 的记录数。
- 若响应带 OpenCode 的 `usage.opencode`，原始响应和 usage 原样保留；`metrics.json` 另外汇总 `opencode.allowance` 的已知和、带 allowance 的记录数、带 `usage.opencode` 的记录数和 `billing_source` 计数。`opencode.allowance` 是 Go 套餐额度消耗，**不参与** `cost_usd`。
- **没有配置价格时，所有请求和总计的 `cost_usd` 都是 `null`；运行器不硬编码任何官方价格。**
- 用户可显式传入 `--input-price-usd-per-1m` 和 `--output-price-usd-per-1m`；两者必须同时提供。若 API 报告缓存命中 token，可再传 `--cached-input-price-usd-per-1m`；未传时按普通 input 价格计算并在 `cost_basis` 中标注。
- `total_cost_usd` 只有在价格已配置且**每条记录**都有完整成本时才给出；否则为 `null`，同时给出 `known_cost_usd` 和 `unknown_cost_records`。
- 成本公式：`tokens × price_per_1m / 1,000,000`，币种为 USD（仅当用户提供的价格以 USD 计）。
- OpenCode Go 的峰时/谷时价格会变化；必须按运行日期核对官方页面后显式传入，不能使用本仓库中的任何历史示例价格。
- 延迟同时记录每次 attempt 的耗时、请求累计耗时（不含退避）和总 wall time（含退避）；p50/p95 使用请求累计耗时。

## 6. 确定性与可复现性

- 默认 `temperature=0.0`，prompt 版本固定为 `secvul-prompt-2026-11-11.1`，样本/请求顺序固定，请求和配置使用规范 JSON SHA-256 标识。
- `manifest.json` 记录模型、端点、temperature、max tokens、`response_format`、User-Agent、`x-opencode-session` 的值与 SHA-256、prompt 版本、数据集 SHA-256、开发示例 SHA-256、运行器版本和 Python/httpx 版本。
- `x-opencode-session` 是每次运行生成的随机会话 ID；同一运行的所有请求/重试共享它，续跑时从已有 manifest 复用。它和 `User-Agent` 都不进入配置指纹或缓存键，因此不会因这些 header 改变而使缓存失效。它不是密钥，也不能替代 `Authorization`。
- 缓存键包含数据集/策略/任务/样本/完整请求体/端点/prompt 版本；同一个运行目录不会被另一组配置静默复用。
- `temperature=0` 不能保证供应商端逐位确定性。运行器只保证**提交给 API 的配置和请求可复现**，不承诺模型输出完全一致；报告不应声称 bitwise reproducibility。
- 未发送 `seed` 参数，因为不同 OpenAI 兼容服务的支持不一致；如你的端点支持，可在修改请求体后重新评估，并同步更新 prompt/运行器版本。

## 7. CLI 参数

| 参数 | 说明 |
| --- | --- |
| `--dataset {independent,pairs}` | 必填，选择数据集 |
| `--dataset-file PATH` | 覆盖默认数据文件 |
| `--strategy {direct,few-shot,context}` | 必填，提示策略 |
| `--task {detection,repair,both}` | 默认 `detection` |
| `--model ID` | 模型 ID；也可用 `SECVUL_MODEL` 或 `DEEPSEEK_MODEL`。无默认模型 |
| `--base-url URL` | 可传 base URL 或完整 `/chat/completions`；默认 `$SECVUL_BASE_URL`、`$DEEPSEEK_BASE_URL`、`https://api.deepseek.com/v1` |
| `--api-key-env NAME` | 默认 `DEEPSEEK_API_KEY`；只从环境变量读取密钥；OpenCode Go 示例用 `OPENCODE_API_KEY` |
| `--user-agent TEXT` | 每个请求的 User-Agent；默认 `$SECVUL_USER_AGENT` 或 `secvul-eval-runner/1.0` |
| `--out-dir PATH` | 运行目录；默认 `runner/runs/<UTC>_<dataset>_<strategy>_<task>` |
| `--dev-examples PATH` | 仅 `few-shot`；默认内置合成示例 |
| `--limit N` | 只跑前 N 个单元（独立样本或 pair）；0 为全部。partial 运行必须在报告中标注 |
| `--concurrency N` | 并发请求数，1–32，默认 1 |
| `--temperature F` | 默认 0.0 |
| `--max-tokens N` | 默认 8192；按模型上限调整 |
| `--max-tokens-field {max_tokens,max_completion_tokens}` | 输出上限字段名；MiMo 原生 API 需 `max_completion_tokens`（默认 `max_tokens`，保持旧行为） |
| `--timeout SECONDS` | 单请求超时，默认 120 |
| `--max-attempts N` | HTTP 重试上限，默认 3 |
| `--backoff-base/--backoff-cap` | 指数退避初值和上限，默认 1.5/30 秒 |
| `--response-format {json_object,none}` | 默认发送 `response_format={"type":"json_object"}`；服务不支持时用 `none`，prompt 仍要求严格 JSON |
| `--thinking {default,enabled,disabled}` | 显式控制请求体 `thinking` 字段；省略时 `deepseek-*` 为 `disabled`，其他模型不发送 |
| `--reasoning-effort {none,minimal,low,medium,high}` | 发送 `reasoning_effort`；MiMo 在 OpenCode Go 上用 `none` 可真正关闭推理 |
| `--input-price-usd-per-1m` / `--output-price-usd-per-1m` | 可选用户输入价格；不提供则成本为 null |
| `--cached-input-price-usd-per-1m` | 可选缓存命中输入价格 |
| `--dry-run` | 只验证请求；不需要 key；不产生结果/指标 |
| `--resume` | 续跑已有运行目录；配置指纹必须一致 |
| `--refresh` | 与 `--resume` 连用，忽略缓存重新请求 |
| `--retry-invalid` | 与 `--resume` 连用，重试 schema-invalid 缓存 |
| `--reuse-cached-errors` | 与 `--resume` 连用，保留 API-error 缓存 |
| `--run-label TEXT` | 仅供人读的标签，不影响请求 |
| `--log-level` | `DEBUG`/`INFO`/`WARNING`/`ERROR`，默认 INFO |

退出码：`0` 成功（包括真实运行中个别 API/schema 错误但完整记录）、`2` 配置/数据/运行状态错误、`1` 未预期异常、`130` Ctrl-C 中断。单样本 API 错误不会让运行退出；它进入 `metrics.failures`，以便比较方法的覆盖率。

## 8. 网络与重试

- 端点必须是绝对 `http(s)` URL；如果路径不以 `/chat/completions` 结尾，运行器自动追加。
- 仅对 `408/409/425/429/5xx`、超时、传输错误和非法 API envelope 重试；`400/401/403/404` 等不重试。`Retry-After` 会参考，但受 `--backoff-cap` 限制。
- HTTP 200 但模型输出不是合格 JSON/不符合 schema 时**不会自动重问**；该样本记为 `invalid`，并进入 coverage 和失败原因统计。这样不会用额外采样掩盖方法的失败率。若确实需要重新采样，可在续跑时使用 `--retry-invalid`。
- 单次请求的每次 attempt 都记录 HTTP 状态、错误类型、原始响应 body 和耗时；最终结果保存 attempt 历史。
- `httpx` 默认读取代理环境变量。若本地/内网端点被代理拦截，可把 `localhost`/目标域加入 `NO_PROXY`，或在不走代理的 shell 中运行。不要把 API key 放进 URL 或命令行参数。

## 9. 比较多个运行

`compare_runs.py` 读取已完成的 `metrics.json`，只汇总真实产物；缺少文件会报错，不会补造数值。

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && \
python3 runner/compare_runs.py \
  runner/runs/independent_direct_both \
  runner/runs/independent_few-shot_both \
  runner/runs/independent_context_both \
  --out runner/runs/comparison.md \
  --json-out runner/runs/comparison.json'
```

比较表包含数据集、策略、任务、模型、记录数、检测有效预测数、precision/recall/F1、pair discrimination、修复结构指标、总成本和 p95 延迟。不同数据集或不同 task 的行会带 warning，不能被当作同一实验的对比。

### 9.1 定性案例

定性分析应直接从 `results.jsonl` 取真实记录，不要手工改写模型输出。每条成功检测记录有 `parsed.rationale`，每条成功修复记录有 `parsed.fixed_function`、`parsed.explanation` 和 `validation`；失败记录保留 `status`、`validation.error` 和原始响应。可按策略/标签筛选检测分歧，或按 `pair_id` 对齐两侧预测。`results.jsonl` 中的 `request_index`、`sample_id` 和 `prompt` 元数据可用于引用和审计。

## 10. 已执行的验证与限制

在 WSL 中执行了：

- `python3 -m compileall -q runner`：通过。
- `normalize_endpoint`：`https://opencode.ai/inference/go/openai/v1` 和完整 `.../chat/completions` 都归一化为官方端点；生成的 session ID 满足 `^ses_[0-9a-f]{32}$`，SHA-256 为 64 位十六进制。
- 对完整 600 条函数（独立 200 + 配对 400）逐一提取安全 context：0 个解析失败；`Explanation` 均未进入白名单。
- 对真实数据集跑 dry-run：独立/配对、三种策略、detection/repair/both 的请求构造通过；样例 `pairs --strategy context --task both --limit 2` 规划 6 个请求，没有生成 `metrics.json`/`manifest.json`。
- 临时 mock Chat Completions 服务上的 smoke（测试 fixture 位于 `/tmp`，运行后已删除，不进入项目）：
  - 首次请求返回 503，随后成功；结果记录重试并保留 attempt 历史。
  - 同一运行的 4 个请求及重试使用同一个 `x-opencode-session`；`User-Agent` 为测试指定的自定义值；`requests.jsonl`、dry-run 请求文件和 manifest 中的 session 一致，且目录内任何文件都不含测试 key。
  - `manifest.json` 的 `api.session` 记录 `value`、`sha256` 和 `source=generated`；`--resume` 后 session 不变、`source=resumed_manifest`、4/4 缓存命中、mock 服务请求数不增加。
  - dry-run 不需要 key、不发起请求，并在 `dry_run_requests.jsonl` 中记录同一 session 和 User-Agent；`dry_run_manifest.json` 标记 `no_api_calls: true`。
  - mock 响应带 `usage.opencode.allowance=0.0012`：4 条记录汇总为 `0.0048`，`opencode_billing_sources={"go":4}`；显式价格算出的 `total_cost_usd=0.000108`，与 allowance 分开，未被混用。
  - mock 401：只尝试 1 次（不重试），记录为 API error，`parsed=null`、`valid_predictions=0`，没有把错误响应当成预测。
  - 一个检测响应故意返回非 JSON：指标记录 `schema_invalid=1`、`valid_predictions=1`、`coverage=0.5`，没有静默丢弃或自动重问；不提供价格时所有 `cost_usd` 和 `total_cost_usd` 均为 `null`，但 allowance 仍单独汇总。
- 未调用任何真实模型：用户的 OpenCode Go key 已过期，真实请求返回 `401`；本次没有用过期凭证发起全量运行。本目录没有真实模型分数、成本或延迟。

限制：

- 修复质量的唯一证据是结构文本检查；没有编译、单元测试或漏洞复现 oracle，不能据此声称修复正确。
- `context` 只覆盖 SecVulEval 的 `context` 单元格中的白名单小节；其他元数据字段未作为模型输入。
- 单样本缓存复用相同的请求；若服务端模型版本在两次运行之间变化，缓存不会自动失效，需要 `--refresh`。
- `x-opencode-session` 只保证同一运行/同一续跑目录内稳定；换新的 `--out-dir` 会生成新的随机会话 ID。它不是认证凭证，不能用于恢复权限或绕过配额。
- `usage.opencode.allowance`、`billing_source` 等字段由供应商返回，运行器只做保留与汇总，未独立核对其计费含义；Go 套餐的峰时/谷时价格也没有硬编码，必须在运行日期核对。
- 运行器不实现并发限流令牌桶；默认并发 1，只有明确设置 `--concurrency` 才并发。遇到 429 会依赖退避/重试。
- 运行器不实现硬性美元预算上限；全量 600 请求的规模可控，但真实计费取决于供应商价格。建议先用 `--limit`/pilot 估算，再用 `--resume` 完成全量。
- 真实 API 的 JSON mode、最大输出 token、缓存价格和 usage 字段可能因供应商而异；运行器记录原始响应，不做未经证实的兼容性承诺。过期/无效 key 的 `401` 不会重试，也不会产生看似有效的预测。
