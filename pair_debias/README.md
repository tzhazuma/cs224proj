# Pair-debias：A/B 反向重复、开放四分类与长度匹配

本目录在冻结的 180 对 SecVulEval 测试集上，对 `pair_joint` 的强制二选一结果做三项去偏/消融：

1. **A/B 反向重复**：同一强制二选一 prompt，把每一对的 A/B 槽位精确交换，得到正序与反序两次观测。
2. **开放 both/neither 联合 prompt**：允许模型输出 `A`、`B`、`both`、`neither`，同样跑正序与反序。
3. **长度匹配 / 长度分层分析**：把“修复通常更长”的平凡信号显式量化，并在长度接近的子集上重新比较模型与启发式。

所有运行均为真实 API 调用；结果来自 `results.jsonl`，没有手工改写的数字。本目录是独立实现，**没有修改** `pair_joint/`、`runner/`、`splits/` 或任何既有运行结果。

## 1. 设计

| 条件 | Prompt | A/B 顺序 | 每对记录数 | 来源 |
| --- | --- | --- | ---: | --- |
| `forced_fwd` | 强制二选一（`pair_joint` 原文） | 冻结正向 | 1 | 复用 `pair_joint/runs/test_*_180`，只读 |
| `forced_rev` | 强制二选一（逐字节相同） | 精确反向 | 1 | 本目录新跑 |
| `open_fwd` | 开放四分类 | 冻结正向 | 1 | 本目录新跑 |
| `open_rev` | 开放四分类 | 精确反向 | 1 | 本目录新跑 |

反向条件不是重新随机洗牌，而是从 `pair_joint` 的 `position_map.json` 逐对取反；`analyze.py` 会校验四个条件的槽位关系，任何不一致都会让分析失败。

每个条件每模型 180 条记录，共 3 个新条件 × 2 模型 × 180 = **1,080 条记录 = 1,029 次新请求 + 51 条缓存复用**。51 条缓存全部来自 `test_mimo_open_rev` 首次中断前的请求；`forced_fwd` 的 360 条记录来自已发布的 `pair_joint` 结果，不重复计费。

### 顺序映射

- `forced_fwd` / `open_fwd`：直接复用 `pair_joint` 的 `position_map.json`（180 对，90/90）。
- `forced_rev` / `open_rev`：逐对交换 `vulnerable_slot` 与 `fixed_slot`，仍是 90/90。
- 映射只写入运行目录的 `position_map.json`；prompt wrapper 不含 `pair_id`、`idx`、`commit_id`、`filepath`、`func_name`、CVE/CWE 列表或槽位标签。源码 body 本身含函数签名；1/180 对的注释含 `CVE-2017-17969`（两侧相同，不指示槽位）。
- `leak_audit.json` 对每个 prompt 的 wrapper 与完整文本做检查；任一 wrapper 命中或 slot leak 都会让 runner 拒绝运行。

### 开放 prompt

与强制 prompt 的唯一实质差异是任务前提：

- 强制：“恰好一个版本含漏洞，另一个修复了它”。
- 开放：“漏洞可能在一个版本、两个版本，或都不存在”。

输出 schema 仍是四个键，`vulnerable_version` 允许 `A`/`B`/`both`/`neither`。证据规则：

- `A`/`B`：至少一条证据，且全部引用所选版本；
- `both`：至少一条证据，可引用任一版本；
- `neither`：证据可为空数组。

## 1.1 状态（2026-11-14）

| 项目 | 结果 |
| --- | --- |
| 自检 | `python3 pair_debias/selftest.py` → `all checks passed (2099 assertions)` |
| 新条件记录 | **1,080 条记录 = 1,029 次新请求 + 51 条缓存复用**；全部 `ok`，0 invalid，0 API error |
| 复用 | `pair_joint` 的 360 条 `forced_fwd` 记录，只读 |
| 完整性 | 四条件精确互补、90/90 平衡、wrapper/slot 泄漏审计全部 clean |
| 成本 | 新条件记录配置价 `$0.676605`；含 `forced_fwd` 复用共 **1,440 条记录** `$0.902001` |
| 结果 | `results/`；中文报告 `report.md` |

主结果（180 对，invalid 记错）：

| 模型 | 条件 | DA | 交换一致 DA | 位置偏差 | 开放弃权率 |
| --- | --- | ---: | ---: | ---: | ---: |
| DeepSeek | 强制正向/反向 | 76.67% / 77.78% | **61.67%** | 31.11pp（p=1e-06） | — |
| MiMo | 强制正向/反向 | 86.67% / 81.67% | **74.44%** | 正向 4.44pp / 反向 21.11pp | — |
| DeepSeek | 开放正向/反向 | 66.11% / 63.89% | **55.56%** | 不显著 | 21.11% / 17.22% |
| MiMo | 开放正向/反向 | 66.11% / 65.56% | **58.33%** | 不显著 | 21.67% / 22.22% |

**关键限制**：单向长度启发式 74.44%，两序同语义版本 72.22%。控制位置后，DeepSeek 的交换一致 DA 显著低于该启发式（p=0.0145），MiMo 仅高 2.22pp（p=0.644，不显著）。因此不能把强制单序的 76.67%/86.67% 直接解释为跨版本推理。详见 `report.md` 与 `results/comparison.md`。

## 2. 指标

| 指标 | 定义 |
| --- | --- |
| `DA` | `correct / n`，invalid 记错；开放条件下 `both`/`neither` 属于错误（真实标签恰好一个版本有漏洞） |
| `committed_picks` | 以实际给出 A/B 的输出为分母的准确率 |
| `abstention` | `(both + neither) / n` |
| `交换一致 DA` | 正序与反序都把漏洞版本判对的比例；对位置偏差不敏感，是更严格的主指标 |
| `语义一致率` | 两序映射到 `vulnerable`/`fixed`/`both`/`neither` 后相同的比例 |
| `同字母率` | 两序都给出 A/B 时选择同一字母的比例；内容驱动（语义不变）应接近 0，位置驱动接近 1，随机约 0.5 |
| `位置偏差` | 漏洞版本在 A 与在 B 时的 DA 差；Fisher 精确检验；选 A 比例的二项检验 |
| `长度启发式` | “选较短版本；等长选 A”，字符数与行数两版 |
| `长度匹配` | 相对字符差 ≤10% 的主子集；5%/20% 与等行数子集为敏感性 |

统计：

- Wilson 95% 区间；
- 精确 McNemar（配对二分类）；
- Fisher 精确检验（A/B 分侧 DA）；
- 二项检验（选 A 比例、同字母率）；
- 10,000 次 percentile bootstrap，种子 42；主区间按 `project` 聚类，配对级为敏感性；
- Holm 校正在预先声明的检验族内进行（顺序效应、任务效应、模型效应、交换一致模型效应、交换一致 vs 长度启发式）。

## 3. 文件

| 路径 | 作用 |
| --- | --- |
| `common.py` | 条件定义、开放 prompt、派生顺序映射、开放/强制解析与证据评分、长度特征 |
| `runner.py` | 可恢复的真实 API runner（每对每条件一次请求），写 requests/results/metrics/position_map/leak_audit |
| `analyze.py` | 四条件指标、交换一致性、位置偏差、开放四分类、长度分层/匹配、跨模型比较、成本 |
| `selftest.py` | 无网络自检：映射、prompt 字节一致性、解析、泄漏、长度计数、统计 |
| `run_pair_debias.sh` | `pilot` / `full` / `analyze` / `analyze-pilot` / `selftest` |
| `runs/pilot_*` | 开发集 8 对 pilot（3 条件 × 2 模型，48 次请求） |
| `runs/test_*` | 冻结测试集 180 对（3 条件 × 2 模型，1,080 条记录 = 1,029 新请求 + 51 缓存复用） |
| `results/` | 全量分析 JSON/Markdown、跨模型对比、`benchmark_export.json` |
| `results/pilot/` | pilot 分析（仅用于验证接入/解析，不作效果证据） |
| `report.md` | 中文结果报告（全量） |

每个运行目录包含：

- `config.json`、`manifest.json`：条件、模型、prompt 版本、数据集哈希、base/position map 哈希、计数、状态、`api_key_value_stored: false`。
- `requests.jsonl`：完整 messages/body，不含 `Authorization`。
- `results.jsonl`：响应、usage、成本、延迟、解析与证据检查。
- `position_map.json`、`leak_audit.json`、`metrics.json`、`cache/`。

## 4. 运行

凭证由 `--kimi-config` 从 `/mnt/c/Users/tzh03/.kimi-code/config.toml` 的 `opencode-go` provider 读入进程内存；不打印、不写入任何产物。也可使用环境变量 `OPENCODE_API_KEY`。

```bash
# 自检（无网络）
python3 pair_debias/selftest.py

# pilot：开发集 8 对，3 条件 × 2 模型
bash pair_debias/run_pair_debias.sh pilot

# 全量：冻结测试集 180 对，3 条件 × 2 模型
bash pair_debias/run_pair_debias.sh full

# 分析
bash pair_debias/run_pair_debias.sh analyze
bash pair_debias/run_pair_debias.sh analyze-pilot
```

`--resume` 仅在原目录/原配置指纹一致时复用缓存；`--limit` 会在 manifest/metrics 标记 `partial: true`。runner 在每次写完后扫描产物，若发现 API key 会立即报错。

价格（与既有 `pair_joint` 运行一致，2026-11-12 检查）：

| 模型 | input / 1M | output / 1M | cached input / 1M |
| --- | ---: | ---: | ---: |
| `deepseek-v4.1-flash` | $0.30 | $1.20 | $0.006 |
| `mimo-v2.6-flash` | $0.14 | $0.28 | $0.0028 |

成本按配置价与报告 token 计算；provider 的 `usage.opencode.list_cost` 快照可能处于峰谷价，报告中单列，不与配置价混用。

### WSL 网络说明

本机 WSL 继承了 Windows 的 `http://127.0.0.1:7890` 代理设置，但该地址在 WSL 内是 Linux 自身；同时 IPv6 路径不可达，Python 解析器优先返回 IPv6 会让请求挂起。runner 因此：

- 只在**进程内**移除指向 `127.0.0.1`/`localhost` 的代理变量；
- 只在**进程内**让 `socket.getaddrinfo` 优先返回 A 记录（IPv4）。

两项都记录在 `config.json` 的 `network` 字段；不修改系统配置，不持久化，不记录代理值。若换到网络正常的机器，可删掉这两个兼容层。

## 5. 主要限制

1. **强制二选一改变了任务**：`forced_fwd`/`forced_rev` 的 prompt 声称恰好一个版本有漏洞；开放条件移除该前提，因此 DA 差异同时包含任务重构与先验变化。
2. **开放四分类更难**：`both`/`neither` 在真实标签下都是错误，但模型可能用它们表达不确定性；`abstention` 必须与 DA 一起读。
3. **长度不是被完全控制的变量**：长度匹配是事后子集分析，样本量下降、统计功效降低；不能证明模型“只”使用长度。
4. **单次贪心解码**：temperature=0，没有重复采样；同字母率与交换一致性仍受模型输出随机性以外的因素影响。
5. **位置与内容不可完全分离**：交换重复只能识别“同一字母”与“同一语义”的差异；若模型对两个版本都给出同一语义错误，交换一致 DA 仍会记错。
6. **项目不平衡**：180 对中 `linux` 占 53 对；项目聚类 bootstrap 受少数大项目影响，配对级区间作为敏感性。
7. **pilot 解释力**：pilot 仅 8 对开发样本，只验证接入/解析与成本，不作为效果证据。
8. **源码残留**：1/180 对的函数体注释含 `CVE-2017-17969`（两侧相同，不指示槽位）；未改写源码。

## 6. 结果

全量结果、逐对数据与限制见：

- `report.md`：中文报告；
- `results/summary.md`：主表；
- `results/comparison.md`：跨模型、顺序/任务效应、长度检验；
- `results/analysis_<model>.json`：逐对结果与完整指标；
- `results/benchmark_export.json`：供上层汇总的紧凑导出。
