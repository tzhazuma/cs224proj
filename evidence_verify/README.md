# evidence_verify：正例二次验证 / 保守操作点（探索性）

本目录对 `evidence_prompt` 冻结 run 的**正例**做一次独立上下文的二次审查：给验证器
带行号函数源码 + 第一遍的 `evidence_lines` / `mechanism`，要求它尝试反驳该判断、给出
函数内守卫或反例，并允许撤销“证据不足”的正例。负例一律不动。

> **状态：探索性、事后分析（post-hoc），不是独立确认。** 160 条测试函数已经用于评估
> 第一遍 evidence 提示，验证器提示也是看到该结果之后设计的；本目录的任何数字都不能
> 当作“在新测试集上确认了检测能力”。详见报告开头的状态说明。

## 结果在哪里

- **完整中文报告**：`analysis/report.md`（指标、TP/FP 撤销、McNemar/超几何/bootstrap、
  成本、验证器一致性、捷径基线、失败分类、限制）。
- 全量指标：`analysis/metrics.json`
- 紧凑比较：`analysis/comparison.json`
- 逐条撤销记录（含 reason / counterexample / 标签）：`analysis/retractions.jsonl`

四个真实 run 在 `runs/test_verify_*`：DeepSeek 正例 × {DeepSeek, MiMo} 验证器，
MiMo 正例 × {DeepSeek, MiMo} 验证器；共 236 条验证请求，未触碰 `evidence_prompt/`、
`runner/runs/`、`splits/` 或任何旧结果。

## 复现（WSL，项目根目录）

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj

# 1. 离线自检（无网络）
python3 evidence_verify/selftest.py

# 2. 只验证请求构造，不调用模型（已有则直接退出）
bash evidence_verify/run_verify.sh deepseek_self dryrun

# 3. 四个臂的真实调用（已有 manifest 时自动 --resume，不重复计费）
bash evidence_verify/run_verify.sh deepseek_self  test   # DeepSeek 正例 → DeepSeek
bash evidence_verify/run_verify.sh deepseek_cross test   # DeepSeek 正例 → MiMo
bash evidence_verify/run_verify.sh mimo_self      test   # MiMo 正例 → MiMo
bash evidence_verify/run_verify.sh mimo_cross     test   # MiMo 正例 → DeepSeek

# 4. 指标、基线与报告
python3 evidence_verify/analyze.py
```

凭证由 `run_with_kimi_config.py` 从 Kimi Code 配置读入进程内存，不打印、不落盘；
manifest 只记录 `api_key_present`，并固定 `api_key_value_stored=false`、
`authorization_header_stored=false`。`run_verify.sh` 会探测不可达的 WSL autoProxy
并仅在代理端口关闭时丢弃代理环境变量；本机 IPv6 到 API 域名不可达，因此
`run_with_kimi_config.py` 默认在进程内把 DNS 结果过滤为 IPv4（`SECVUL_IPV4_ONLY=0`
可关闭），manifest 的 `network` 字段会记录该设置。

## 必须一起读的限制

- **不是独立确认**：test 已看过、提示在看到 test 结果后设计、没有预注册；所有结论只能
  作为探索性/事后证据。
- 只处理 schema-valid 正例；第一遍 invalid 记录（DeepSeek 1、MiMo 2）没有可验证的
  claim，二次验证无法处理，在 strict 口径里始终算错。
- 验证器只看到函数体，无法证明跨函数/调用者约束；“撤销”可能包含真实的、需要上下文
  才能成立的漏洞；反例只是模型生成的文本，没有编译或执行验证。
- 跨模型验证器不是人工标注；两个模型共享预训练语料与同一批测试函数，一致率高不代表正确。
- 每个臂只有一次运行，temperature=0 不保证确定性；160 条里只有 32 个非漏洞样本。
- 捷径基线（label-only、长度、调用数）的阈值在 dev 40 上拟合，而 dev 只有 8 个负例；
  test-tuned 上界只作描述。主结果的验证器决策规则是运行前固定的；`refutation_only`
  与置信度阈值扫描是事后敏感性分析。
- 成本按第一遍 run 的价格快照估算，未重新核对官方页面。

## 目录

| 路径 | 内容 |
| --- | --- |
| `evidence_verify/verifier_prompt.py` | 验证器提示、输入隔离与结构审计 |
| `evidence_verify/verification.py` | 7 字段严格校验与撤销审计 |
| `evidence_verify/runner.py` | 可恢复 runner、缓存、manifest/results |
| `evidence_verify/baselines.py` | label-only、长度/调用数阈值、同预算撤销基线 |
| `evidence_verify/analyze.py` | 指标、统计检验、成本与中文报告 |
| `run_verify.py` / `run_verify.sh` | CLI 与四个实验臂 |
| `run_with_kimi_config.py` | 从 Kimi Code 配置读凭证到进程内存 |
| `selftest.py` | 离线自检 |
| `runs/` | dry-run、dev smoke、四个 test run |
| `analysis/` | 报告与指标产物 |

本目录的实验不改写任何旧 run；发布由主代理统一处理（本目录不执行 git/gh）。
