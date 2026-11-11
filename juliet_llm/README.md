# Juliet CWE-401 LLM 直接检测（`juliet_llm/`）

本目录负责冻结 Juliet CWE-401 子集上的 LLM 直接二分类：把 200 个单元清洗成不含标签、路径、CWE 编号、函数名泄漏的源码视图，再用 OpenAI 兼容接口做真实请求，输出逐条 JSONL、原始 usage/成本/延迟，以及严格（strict）与 valid-only 两套指标。

所有代码在 WSL Ubuntu 中运行，只写入 `juliet_llm/`，不修改 `juliet/`、`runner/` 及任何旧结果。

## 1. 结论摘要

| 项目 | 结果 |
| --- | --- |
| 冻结单元 | 200（dev 60 / test 140；bad 100 / good 100；C 88 / C++ 112） |
| 清洗审计 | 200/200 通过；清洗后 11 类禁用 token 计数全部为 0；735 个标签相关标识符被重命名；Juliet 的 `"Benign, fixed string"` 已清除 |
| 输入 | 每个单元仅含 `system` + `user` 两条消息；`user` 只含一个代码块；无路径、无 CWE、无 `bad`/`good`/`benign`/`fixed`、无原始注释 |
| Prompt 版本 | `juliet-llm-binary-2026-11-12.2`（泄漏修复后） |
| MiMo test（140，修复后，正式） | 140/140 有效，Accuracy 0.9500，F1 0.9510，MCC 0.9008，0 个无效答案 |
| MiMo test（140，修复后，复现） | 140/140 有效，Accuracy 0.9500，F1 0.9510，MCC 0.9008（混淆矩阵与正式相同） |
| MiMo test（140，修复前，保留） | 140/140 有效，Accuracy 0.9571，F1 0.9577（另有复现 0.9500）；旧 build 已归档，结果原样保留 |
| DeepSeek test（140） | **未完成**：OpenCode Go 凭证返回 `401 api_key_expired`；官方 DeepSeek 返回 `402 Insufficient Balance`，qwen 网关对 `deepseek-v4.1-flash` 返回 `403 AccessDenied.Unpurchased` |
| 终止性限制 | 请求的 OpenCode Go 路由不可用。下面的 MiMo 140 结果来自 **Xiaomi 官方 API**（同模型 ID `mimo-v2.6-flash`，非 OpenCode Go），仅作为带明确标注的 fallback，不能冒充 OpenCode Go 结果 |

## 2. 目录与产物

```text
juliet_llm/
├── cleaning.py              # 注释剥离、条件编译、头文件内联、标识符/字符串清洗、审计
├── prompting.py             # prompt 版本、system/user 构造、prompt 泄漏审计
├── build_inputs.py          # 生成 build/dev.jsonl、build/test.jsonl、审计 JSON/Markdown
├── metrics.py               # 严格 / valid-only 指标、usage/成本/延迟汇总、Markdown 报告
├── llm_run.py               # 真实请求、并发、断点产物、run manifest、probe/report/compare CLI
├── launch.py                # 复用 runner/run_with_kimi_config.py 的凭证加载器
├── run.sh                   # WSL 下的便捷启动脚本
├── selfcheck.py             # 无网络自检：冻结哈希、prompt 泄漏、解析器、指标、产物一致性、密钥扫描
├── verify_cleaned.py        # 编译 + ASan 运行 200 个清洗视图，与冻结 runtime 标记逐单元比对
├── build/
│   ├── dev.jsonl            # 60 个 dev 输入（含完整 messages、hash、审计字段）
│   ├── test.jsonl           # 140 个 test 输入
│   ├── audit.json           # 200 个单元逐条审计
│   ├── audit_report.md      # 清洗方法、前后计数、逐项检查、示例
│   └── manifest.json
├── build_pre_leakfix_v1/    # 修复前的旧 build 快照（prompt .1），只读保留，供旧 run 对账
├── runs_superseded/         # 修复后、最终代码冻结前的两次中间 run（仅 prompting.py 元数据哈希不同）
└── runs/
    ├── 20261111T192232Z_probe/                         # MiMo 配置 probe（dev 4 单元）
    ├── 20261111T192557Z_pilot_mimo-v2.6-flash_dev_xiaomi_official/
    ├── 20261111T205533Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix/       # 修复后正式 140
    ├── 20261111T205722Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix_repro/ # 修复后复现 140
    ├── 20261111T192252Z_test_mimo-v2.6-flash_test_xiaomi_official/       # 修复前第一次 140（保留）
    ├── 20261111T192747Z_test_mimo-v2.6-flash_test_xiaomi_official_final/ # 修复前最终 140（保留）
    ├── 20261111T191954Z_smoke_deepseek-v4.1-flash_dev_smoke/             # OpenCode 401 证据
    ├── 20261111T192149Z_smoke_deepseek-flash_dev_deepseek_official_smoke/# 官方 DeepSeek 402 证据
    └── 20261111T192505Z_smoke_deepseek-v4.1-flash_dev_qwen_gateway_smoke/ # qwen 网关 403 证据
```

每个完整 run 目录包含：

| 文件 | 内容 |
| --- | --- |
| `inputs.jsonl` | 本次实际发送的 140 条 `messages`（含 prompt hash） |
| `results.jsonl` | 逐单元：`y_true`、`y_pred`、原始 `content`、完整 `usage`、成本、延迟、attempts、原始响应体、validation |
| `predictions.jsonl` | 最小预测表，便于下游 benchmark 合并 |
| `manifest.json` | 模型、endpoint、采样参数、价格快照、模型目录快照、输入/code SHA256、session 哈希；**不含 API key** |
| `metrics.json` / `metrics.md` | strict / valid-only 指标、混淆矩阵、分语言指标、usage/成本/延迟 |
| `run.log` | 请求级日志（只有 URL/状态码，不含 Authorization） |

## 3. 冻结数据与标签

只读取 `juliet/subset_units.jsonl`；`FREEZE.json` 校验通过：

- `subset_units.jsonl` SHA256：`4827d1da6a1966759d66989dfb16678bc3e14d8f0588f9fe59d92a08ae4aac24`
- `manifest.json` SHA256：`8df222f84a4295f3b90ae7cabe165adc04858d91def3fda19a073db6e17cafd6`
- test 140 = 70 bad + 70 good；dev 60 = 30 + 30

`label = bad` 映射为 `y_true = 1`（存在内存泄漏），`good` 映射为 `0`。`selfcheck.py` 会重新计算上述哈希，若冻结文件被改动会失败。

## 4. 源码清洗与审计

原始 Juliet 源码把标签放在至少 6 个位置：文件名、`bad`/`good` 标识符、`OMITBAD`/`OMITGOOD` 条件编译、`CWE401_Memory_Leak__*` 命名空间/类名、`FLAW`/`BadSink`/`GoodSource` 注释，以及若干 good 变体里 `printLine("Benign, fixed string")` 的字面量。清洗管线：

1. 用字符串字面量感知的扫描器删除 `//` 与 `/* */` 注释；
2. 用单元自带的 `defines` 解析 `#ifdef`/`#ifndef`/`#endif`，只保留实际参与构建的分支（`#ifndef _WIN32` 保留 Linux 分支；`INCLUDEMAIN` 保留 `main`）；
3. 内联引号形式的单元局部头文件（`CWE401_..._82.h` 等）；丢弃 `std_testcase.h` 支持头；
4. 把所有含 `bad`/`good`/`cwe`/`memory_leak`/`benign`/`fixed` 的标识符按单元首次出现顺序重命名为 `sym_N`；同一单元内一致，跨单元不携带信号；字符串字面量内的标签词（含 `safe`/`clean`/`patched`/`remediated`）替换为中性词 `unit`；
5. 审计：11 类禁用 token 必须为 0、`unit_id`/`group_id` 不得出现、不得有残留条件编译/注释、花括号平衡；任一失败则构建失败（fail closed）。字符串清洗集合与审计集合保持同步，`selfcheck.py` 用一条包含全部审计类别的合成字面量验证“清洗后审计必须为 0”。

`build/audit_report.md` 的聚合计数：

| 模式 | 原始源码 | 清洗后 |
| --- | ---: | ---: |
| `bad` | 3324 | 0 |
| `good` | 5110 | 0 |
| `cwe` | 2054 | 0 |
| `memory_leak` | 2042 | 0 |
| `omit` | 1908 | 0 |
| `flaw` | 736 | 0 |
| `std_testcase` | 290 | 0 |
| `raw/testcases`、`/mnt/`、`juliet/` | 0 | 0 |
| `benign` | 16 | 0 |
| `fixed` | 16 | 0 |
| `safe`/`clean`/`patched`/`remediated`（整词） | 0 | 0 |

清洗后每个单元都通过：`forbidden_tokens_absent` 200/200、`unit_id_absent` 200/200、`group_id_absent` 200/200、`no_conditional_directives` 200/200、`no_comment_residue` 200/200、`braces_balanced` 200/200。

语义验证（`python3 -m juliet_llm.verify_cleaned`）：把 200 个清洗视图补回 `std_testcase.h`，逐个用 gcc/g++ + AddressSanitizer 编译并运行；200/200 编译通过，78/100 bad 单元观察到泄漏（与 `juliet/manifest.json` 的 `runtime_check` 逐单元一致），100/100 good 单元干净，0 个问题。修复前后该结果完全相同。

### 4.2 泄漏修复（2026-11-12，prompt .1 → .2）

发布前 audit 的 C3/D6：8/200 条清洗后的 prompt（6 条在 test）仍含 `benign`/`fixed`，全部来自 good 单元的 `printLine("Benign, fixed string")`。根因是 `cleaning.py` 的 `FORBIDDEN_PATTERNS` 和字符串替换正则没有收录这两个词，所以 fail-closed 审计看不见它们。

修复内容：

1. `FORBIDDEN_PATTERNS` 增加 `label_benign`、`label_fixed` 和 `label_remediated`（`safe|clean|patched|remediated` 整词）。后三类只作用于代码视图，不进入 prompt 级扫描，因为指令/工具证据文本会正常讨论“not a clean result”，而 `memory_leak` 也继续只在代码级禁止（`prompting.py` 另加本地严格扫描，juliet_llm 的 prompt 同样不允许出现 `memory_leak`）。
2. `_STRING_TOKEN_RE` 与审计集合同步扩展；`_LEAKY_IDENTIFIER_RE` 增加 `benign`/`fixed`，标识符与字符串两条路径一致。
3. 实际只有 8/200 个单元的源码视图变化（6 test + 2 dev），其余 192 个逐字节相同；把所有字符串字面量内容掩码后，200/200 与修复前完全相同，说明改动只落在字符串内容上，没有触碰代码结构/标识符。
4. 旧 build 完整归档到 `build_pre_leakfix_v1/`；修复前的两个 140 run 未改动（哈希逐文件核对一致）。

修复不改变任务定义和 system prompt 文本，只改 prompt 版本号；新 run 的 `manifest.json` 记录 `prompt_version = juliet-llm-binary-2026-11-12.2` 与新的输入 SHA256。

### 4.1 Prompt 内容

- `system`：说明任务、泄漏定义（含“仅在某些路径泄漏”“全局/静态指针在退出时仍持有”也计为泄漏）、运行时支持函数（`printLine` 等只打印，`ALLOCA` 为栈分配，`twoIntsStruct`/`TwoIntsClass` 为普通数据类）、严格 JSON 输出格式；
- `user`：`Audit the code unit below and return the verdict.` + 一个 ```c/```cpp 代码块 + `Return only the JSON object.`；
- 不包含单元 ID、组 ID、文件名、路径、CWE 编号、family/variant 元数据；
- 输出 schema：`{"label": "vulnerable"|"not_vulnerable", "confidence": 0..1, "reason": "<=30 words"}`。

`prompting.audit_prompt()` 对每条消息再做一次禁用 token 扫描（含 prompt 级的 `memory_leak` 严格检查），构建阶段 200/200 通过；`selfcheck.py` 在无网络条件下重算同样的检查。

## 5. 凭证与请求

### 5.1 凭证路径

`run.sh` → `launch.py` → `runner/run_with_kimi_config.py`：

1. wrapper 从 Kimi Code TOML 的 `providers.<name>` 读取 `api_key`，只放进进程环境变量 `OPENCODE_API_KEY`；
2. wrapper 设置 `SECVUL_BASE_URL`；
3. `launch.py` 在 wrapper 执行前把 `secvul_runner.cli.main` 替换为 `juliet_llm.llm_run.main`，因此复用同一条凭证加载路径，没有第二份读 key 的代码；
4. key 不打印、不写日志、不写入任何产物；`manifest.json` 只有 `session_id_sha256`。

### 5.2 OpenCode Go 阻塞（真实证据）

2026-11-12 运行时的真实响应：

| 路由 | 模型 | 结果 |
| --- | --- | --- |
| OpenCode Go `https://opencode.ai/zen/go/v1/chat/completions` | `deepseek-v4.1-flash` | HTTP 401，`{"type":"authentication_error","code":"api_key_expired",...}` |
| OpenCode Zen `https://opencode.ai/zen/v1/chat/completions` | `deepseek-v4.1-flash` | HTTP 401，`api_key_expired` |
| OpenCode Go Responses `.../responses` | `deepseek-v4.1-flash` | HTTP 401，`api_key_expired` |
| DeepSeek 官方 `https://api.deepseek.com` | `deepseek-flash` | HTTP 402，`Insufficient Balance` |
| qwen-tokenplan 网关 | `deepseek-v4.1-flash` | HTTP 403，`AccessDenied.Unpurchased` |

证据保存在 `runs/20261111T191954Z_smoke_deepseek-v4.1-flash_dev_smoke/results.jsonl`、`runs/20261111T192149Z_smoke_deepseek-flash_dev_deepseek_official_smoke/results.jsonl`、`runs/20261111T192505Z_smoke_deepseek-v4.1-flash_dev_qwen_gateway_smoke/results.jsonl`。请求体不含 key，响应体只保留错误信息。

**因此：OpenCode Go 的 `deepseek-v4.1-flash` 与 `mimo-v2.6-flash` 140 test 正式结果均未产生。** 需要更新 OpenCode Go 的 API key 后重跑；命令见第 8 节。

### 5.3 MiMo fallback

OpenCode 阻塞后，用同一 `mimo-v2.6-flash` 模型 ID 在 Xiaomi 官方 OpenAI 兼容端点（`https://api.xiaomimimo.com/v1`）做了真实运行。它验证了请求构造、并发、usage 解析、指标计算和 prompt 清洗，但**不是 OpenCode Go 路由**，不能与 OpenCode 的结果等同。

manifest 中 `api.base_url`、`api.endpoint`、run 目录名（`..._xiaomi_official...`）和本文件都明确标注了这一点。泄漏修复后（prompt `.2`）在同一端点重新运行了两次，目录名带 `postleakfix` / `postleakfix_repro`；修复前的两个 run 原样保留。

## 6. 指标定义

- **strict**：分母固定为全部 140 个单元。API 错误、非 JSON、`label` 非法、`confidence` 越界都算错误：真实 bad 记 FN，真实 good 记 FP；不会因为“解析失败”而白得 TN。
- **valid-only**：只对 schema 合法的答案计算 P/R/F1/Accuracy；必须与 coverage 一起读。
- 正类 = `vulnerable`（bad）。
- 同时报告 TP/FP/TN/FN、specificity、balanced accuracy、MCC，以及分语言（C/C++）两套指标。
- usage/成本/延迟来自 `results.jsonl` 的原始响应，不做插值；缺失记为 `unknown_records`。
- `cost_usd` 按 manifest 记录的每 1M token 价格计算；`api_list_cost_usd` / `api_allowance_usd` 只在 API 返回 `usage.opencode` 时存在（Xiaomi 端点不返回）。

## 7. 真实结果

### 7.1 MiMo probe（dev 4 单元，Xiaomi）

`runs/20261111T192232Z_probe/`：

| 配置 | `max_tokens_field` | `reasoning_effort` | `thinking` | 有效 | reasoning tokens | p50 延迟 |
| --- | --- | --- | --- | ---: | ---: | ---: |
| `mimo_reasoning_none_max_completion_tokens` | `max_completion_tokens` | `none` | `disabled` | 4/4 | 0 | 2.30 s |
| `mimo_legacy_max_tokens` | `max_tokens` | 省略 | `disabled` | 4/4 | 0 | 3.21 s |

在 Xiaomi 官方端点上两种配置都正常，未复现 OpenCode Go“`max_tokens` 被忽略、推理无界”的旧问题；因此该 probe 只能证明本管线在 Xiaomi 上的配置可用，不能替代 OpenCode Go 的兼容性验证。OpenCode 侧的旧证据见 `mimo/pilot_report.md`（另一工作流，本次未重跑）。

### 7.2 MiMo dev pilot（8 单元，Xiaomi）

`runs/20261111T192557Z_pilot_mimo-v2.6-flash_dev_xiaomi_official/`：

- 8/8 有效，TP 3 / FP 0 / TN 4 / FN 1
- Accuracy 0.8750，Precision 1.0000，Recall 0.7500，F1 0.8571，MCC 0.7746
- prompt 4349 tokens，completion 345，reasoning 0，p50 2.58 s，p95 4.78 s
- 唯一错误：`malloc_realloc_char_01__bad`，模型认为“realloc 很少失败”，忽略条件泄漏

### 7.3 MiMo test 140（Xiaomi fallback，修复后正式 + 复现）

正式运行 `runs/20261111T205533Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix/`；
复现运行 `runs/20261111T205722Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix_repro/`。
两次都是 140/140 HTTP 200 + schema 合法，0 个 API error、0 个 invalid，`partial=false`，endpoint 均为 `https://api.xiaomimimo.com/v1`，prompt 版本 `.2`。

| 指标 | 正式（140） | 复现（140） |
| --- | ---: | ---: |
| TP / FP / TN / FN | 68 / 5 / 65 / 2 | 68 / 5 / 65 / 2 |
| Accuracy | 0.9500 | 0.9500 |
| Precision | 0.9315 | 0.9315 |
| Recall | 0.9714 | 0.9714 |
| Specificity | 0.9286 | 0.9286 |
| F1 | 0.9510 | 0.9510 |
| Balanced accuracy | 0.9500 | 0.9500 |
| MCC | 0.9008 | 0.9008 |
| Coverage | 1.0000 | 1.0000 |

- 分语言：C 58 单元 accuracy 0.9310 / F1 0.9310；C++ 82 单元 accuracy 0.9634 / F1 0.9647（两次相同）。
- usage（正式）：prompt 77,410；completion 6,616；reasoning 0；cached prompt 69,312（134 条报告缓存）；total 84,026。
- usage（复现）：prompt 77,410；completion 6,827；reasoning 0；cached prompt 70,464（136 条报告缓存）；total 84,237。
- 延迟：正式 p50 2.57 s / p95 9.40 s / max 65.75 s；复现 p50 2.60 s / p95 6.15 s / max 23.70 s。
- 参考成本：$0.003180（正式）、$0.003081（复现），按 OpenCode Go 列表价 $0.14/$0.28/$0.0028 per 1M 计算；Xiaomi 实际账单未在响应中返回，不能当作真实扣费。

**修复的影响（逐单元）**：两次修复后运行的 140 条 prompt 与 `build/test.jsonl` 逐字节一致，对 `benign|fixed|safe|clean|patched|remediated` 扫描为 0。test 140 中只有 6 个单元的 prompt 发生变化；其中 5 个（`malloc_realloc_int64_t_09__good`、`new_array_char_22__good`、`new_array_int_22__good`、`new_int_22__good`、`twoIntsStruct_realloc_22__good`）的判定在修复前后完全相同，只有 `int_malloc_22__good` 在两次修复后运行中都从 TN 变成 FP（修复前两次都是 TN）。**正式运行与修复前最终运行逐单元相比只差这 1 条预测**，其余 139 条完全相同。正式与复现之间有 2 个 bad 单元（`malloc_realloc_int64_t_01__bad`、`malloc_realloc_int_01__bad`）判定不同，它们的 prompt 没有变化，属于服务端生成的不确定性；两次的混淆矩阵恰好相同。

### 7.4 修复前 MiMo test 140（保留的旧结果，prompt .1）

旧结果原样保留、未覆盖；旧 build 快照在 `build_pre_leakfix_v1/`。

`runs/20261111T192747Z_test_mimo-v2.6-flash_test_xiaomi_official_final/`：

| 指标 | strict（140） | valid-only（140） |
| --- | ---: | ---: |
| TP / FP / TN / FN | 68 / 4 / 66 / 2 | 68 / 4 / 66 / 2 |
| Accuracy | 0.9571 | 0.9571 |
| Precision | 0.9444 | 0.9444 |
| Recall | 0.9714 | 0.9714 |
| Specificity | 0.9429 | 0.9429 |
| F1 | 0.9577 | 0.9577 |
| Balanced accuracy | 0.9571 | 0.9571 |
| MCC | 0.9147 | 0.9147 |
| Coverage | 1.0000 | 1.0000 |

- 140/140 HTTP 200 + schema 合法；0 个 API error、0 个 invalid。
- 分语言：C 58 单元 accuracy 0.9483 / F1 0.9474；C++ 82 单元 accuracy 0.9634 / F1 0.9647。
- usage：prompt 77,416；completion 6,547；reasoning 0；cached prompt 60,096（117 条报告了缓存）；total 83,963。
- 延迟：p50 2.31 s，p95 5.21 s，max 28.58 s。
- 参考成本：$0.004426（按 OpenCode Go 列表价 $0.14/$0.28/$0.0028 per 1M 计算；Xiaomi 实际账单未在响应中返回，不能当作真实扣费）。

复现运行 `runs/20261111T192252Z_test_mimo-v2.6-flash_test_xiaomi_official/`：TP 67 / FP 4 / TN 66 / FN 3，Accuracy 0.9500，F1 0.9504，MCC 0.9001；140/140 有效。两次运行 prompt 和参数完全相同，差异来自服务端生成的不确定性（temperature 0 也不保证逐字节一致），说明 140 单元上的单次结果有约 ±0.7 个百分点的波动。

### 7.5 错误分析（修复后）

正式运行的 7 条错误：

| 单元 | 真值 | 预测 | 模型理由摘要 |
| --- | --- | --- | --- |
| `int_malloc_22__good` | good | vulnerable | 理由算出“both free … No leak”，label 仍是 vulnerable（两次修复后运行都如此） |
| `new_array_char_22__good` | good | vulnerable | 理由论证“all freed … No leak”，label 却是 vulnerable |
| `new_array_int_22__good` | good | vulnerable | 理由论证“all new[] freed … No leak”，label 却是 vulnerable |
| `new_int_22__good` | good | vulnerable | 理由论证“No leak”，label 却是 vulnerable |
| `twoIntsStruct_realloc_22__good` | good | vulnerable | 理由论证“No leak”，label 却是 vulnerable |
| `malloc_realloc_int64_t_01__bad` | bad | not_vulnerable | 理由承认“leaked only if failure occurs, which is a real leak path”，label 却是 not_vulnerable（仅正式运行） |
| `malloc_realloc_int64_t_18__bad` | bad | not_vulnerable | 理由承认“failure path leaks”，label 却是 not_vulnerable |

复现运行也是 7 条错误：同样的 5 个 FP 与 `malloc_realloc_int64_t_18__bad`，FN 换成 `malloc_realloc_int_01__bad`（理由承认“old block lost only if realloc fails”，label 仍是 not_vulnerable）。7/7（两次运行）都是 **理由与 label 自相矛盾**，不是读不懂代码。若按理由文本判定，结果会更好；当前 strict 指标按实际 `label` 字段计分，这是有意为之。可能的改进是调整输出字段顺序（先 `reason` 后 `label`）或加一个自检步骤，但会改变 prompt，需要重新运行，未在本次结果上事后调参。

## 8. 复现命令（WSL）

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj

# 1. 构建并审计（不需要 key）
python3 -m juliet_llm.build_inputs
python3 -m juliet_llm.selfcheck

# 2. MiMo 配置 probe（dev 4 单元）
KIMI_PROVIDER=xiaomi bash juliet_llm/run.sh probe --only mimo --concurrency 4

# 3. dev pilot（8 单元，2/层）
KIMI_PROVIDER=xiaomi bash juliet_llm/run.sh run \
  --model mimo-v2.6-flash --split dev --sample-per-stratum 2 \
  --kind pilot --tag xiaomi_official --concurrency 4

# 4. 140 test（OpenCode Go，凭证有效时）
bash juliet_llm/run.sh run --model mimo-v2.6-flash --split test \
  --kind test --tag opencode_go --concurrency 8
bash juliet_llm/run.sh run --model deepseek-v4.1-flash --split test \
  --kind test --tag opencode_go --concurrency 8

# 5. Xiaomi fallback（修复后正式 + 复现，本次实际执行）
KIMI_PROVIDER=xiaomi bash juliet_llm/run.sh run \
  --model mimo-v2.6-flash --split test --kind test \
  --tag xiaomi_official_postleakfix --concurrency 8
KIMI_PROVIDER=xiaomi bash juliet_llm/run.sh run \
  --model mimo-v2.6-flash --split test --kind test \
  --tag xiaomi_official_postleakfix_repro --concurrency 8

# 6. 重新计算指标 / 汇总多个 run
python3 -m juliet_llm.llm_run report --run-dir <run_dir>
python3 -m juliet_llm.llm_run compare --run <run_a> --run <run_b>
```

`run.sh` 默认读取 `/home/azuma/.kimi-code/config.toml`；可用 `KIMI_CONFIG` 覆盖，用 `KIMI_PROVIDER` 切换 provider（`opencode-go`、`xiaomi` 等）。

## 9. 限制与未完成事项

1. **OpenCode Go 两个模型的正式 140 test 未完成。** 凭证 `api_key_expired`；DeepSeek 官方余额不足；qwen 网关无模型权限。没有用其他模型/其他 prompt 冒充这些结果。
2. **MiMo 的 140 结果是 Xiaomi 官方端点 fallback**，不是 OpenCode Go。相同模型 ID 不等于相同服务栈，延迟、缓存命中、成本、可能的系统提示注入都可能不同。
3. **DeepSeek 完全没有结果**，不能从 MiMo 的结果推断。
4. 修复前 140 test 运行了两次（0.9571 / 0.9500），修复后又运行了两次（0.9500 / 0.9500，混淆矩阵相同）。修复后正式运行与修复前最终运行逐单元只差 1 条（`int_malloc_22__good`），其余 139 条相同；修复后两次之间有 2 个 prompt 未变化的 bad 单元判定不同，说明单次 140 结果仍有约 ±1.4 个百分点（2 条）的服务端波动。报告同时给出全部运行，避免只挑好看的一次。`runs_superseded/` 保留两次更早的修复后运行（结果有效；仅 manifest 记录的 `prompting.py` 哈希早于一行为兼容 audit 而加的 re-export）。
5. 数据存在结构性不对称：good 单元通常包含 2–3 个 good 变体函数（`goodG2B`、`goodB2G`、入口），bad 单元通常只有 1 个；这是 Juliet 原始结构，清洗没有人为抹平。模型可能利用“函数个数/是否存在 `free`”等捷径，需在解释结果时考虑。
6. 22/100 个 bad 单元在默认运行中观察不到 LSan 泄漏（15 个 `malloc_realloc_*` 条件泄漏、7 个 `_68` still-reachable）；prompt 明确把“仅某些路径泄漏”和“全局指针在退出时仍持有”计入泄漏，但模型仍漏判了 test 中的 realloc bad 单元。
7. 成本是参考价，不是 Xiaomi 的实际账单；`usage.opencode` 在该端点不存在。
8. 未做跨 prompt 版本的消融、未用 dev 调参、未做人类复核；这些都不在本次范围。
9. **共享清洗器的影响范围（历史问题，已解决）**：`hybrid/` 直接 import `juliet_llm.cleaning.clean_unit`。修复刚完成时的待办是：`hybrid/inputs/units.jsonl`（v1）仍是修复前生成，audit 的 D1/D4/D6 指向 v1 会失败；`audit/run_final_audit.py` 的 C2 硬编码比较“修复前的两个 MiMo run ↔ 当前 build”，build 更新后会误报；C3 检查函数固定返回 FAIL，无法反映实际命中数。现已处理：audit 已切到 `hybrid/inputs_v2/units.jsonl`（140/140 与当前 `clean_unit` 输出逐字节一致），v1 作为泄漏对照保留；C2 对修复后运行对照当前 `build`、对历史 run 对照 `build_pre_leakfix_v1/test.jsonl`；C3 改为按实际命中数判定，当前 200 条 prompt 为 0 命中，归档的 v1 仍保留 8 条命中（2 dev + 6 test，均为 good）作为泄漏对照。最终 audit 结果为 **PASS_WITH_WARNINGS**（58 PASS / 0 FAIL / 3 WARN / 1 INFO）。
