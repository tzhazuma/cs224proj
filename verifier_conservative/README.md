# verifier_conservative：保守三路正例验证器（探索性）

本目录是 `evidence_verify/` 的**后继实验**，不是对它的修改。`evidence_verify/` 保持
冻结、只读；所有新代码、run 与报告都在本目录内。

> **状态：探索性、事后分析、test-seen。** 160 条测试函数已经用于评估第一遍
> evidence 提示和原验证器；本目录的三路提示与判定规则是在看到那些结果之后设计的。
> 任何数字都不能当作“在新测试集上独立确认”。

## 做了什么

原验证器把正例分成 `sustain` / `retract`，主口径 **fail-closed**：验证器没有给出有效
sustain 就撤销。于是 `insufficient_evidence`（“函数体内看不出可达性/攻击者控制”）
也被当成撤销理由，四个臂的撤销精确率只有 14.3%–23.1%，post macro-F1 低于 pre。

本目录改成三路判定：

| assessment | 含义 | 动作 |
| --- | --- | --- |
| `supported` | 引用行 + 函数内可见流建立具体缺陷 | 保留 |
| `unsupported` | 能指出具体的函数内守卫或反例 | 仅当行号有效时撤销 |
| `insufficient` | 源码不足以建立 claim，但也给不出具体反证 | 保留 |

机械判定规则（`conservative/decision.py`）：

- 只有 `unsupported` + `guard_present` 或 `counterexample` 才可能撤销；
- 引用的行号必须在 `1..N`、不重复，且至少一行是非空白、非纯注释/纯括号代码；
- `guard_present` 还要求该行含守卫词法（`if/return/&&/比较/边界函数` 等）；
- `counterexample` 必须有具体反例文本（不是 `none`）；
- `insufficient`、schema-invalid、API error 一律**保留第一遍预测**，不采用 fail-closed；
- 提示要求守卫覆盖 claim 描述的每一条路径；只击败一个场景的守卫必须判 insufficient。

语义上的支配关系（守卫是否真的覆盖所有路径、反例是否真的不触发）没有编译/执行验证，
仍由模型断言。报告 §8.1 给出两个“行号审计通过但语义错误”的案例。

## 结果在哪里

- **完整中文报告**：`analysis/report.md`
- 全量指标：`analysis/metrics.json`
- 紧凑比较：`analysis/comparison.json`
- 逐条正例决策与引用行文本：`analysis/decisions.jsonl`

四个真实 run 在 `runs/test_conservative_*`：DeepSeek 正例 × {DeepSeek, MiMo}，
MiMo 正例 × {DeepSeek, MiMo}；共 **236 条真实请求**（60/60/58/58）。另有四份
`runs/dryrun_conservative_*` 用于请求体哈希审计。

**关键数字（详见报告）：**

- 保守规则只撤销 4 / 236 条（TP 3、FP 1）；原验证器主口径在同一批正例上撤销 155 条。
- 撤销精确率 25.0%，正例中 FP 基准率 18.3%–19.0%；超几何检验不显著（Holm p=1.0）。
- macro-F1 四个臂都不升（0 到 −0.0052）；MCC 只在 `mimo_cross` +0.0139（95% CI 跨 0），
  代价是 2 个 TP 损失换 1 个 FP 纠正。
- 验证器成本合计 0.151758 USD，与原验证器同一量级；随机/低置信基线增量成本为 0。
- `insufficient` 占 106/236；`unsupported` 只有 4 条，说明模型很少给出可用的具体反证。

## 复现（WSL，项目根目录）

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj

# 1. 离线自检（无网络）
python3 verifier_conservative/selftest.py

# 2. 只验证请求构造，不调用模型
bash verifier_conservative/run_conservative.sh deepseek_self  dryrun
bash verifier_conservative/run_conservative.sh deepseek_cross dryrun
bash verifier_conservative/run_conservative.sh mimo_self      dryrun
bash verifier_conservative/run_conservative.sh mimo_cross     dryrun

# 3. 四个臂的真实调用（已有 manifest 时自动 --resume）
bash verifier_conservative/run_conservative.sh deepseek_self  test
bash verifier_conservative/run_conservative.sh deepseek_cross test
bash verifier_conservative/run_conservative.sh mimo_self      test
bash verifier_conservative/run_conservative.sh mimo_cross     test

# 4. 指标、基线与报告
python3 verifier_conservative/analyze_conservative.py
```

凭证由 `run_with_kimi_config.py` 从 Kimi Code 配置读入进程内存，不打印、不落盘；
manifest 只记录 `api_key_present`，并固定 `api_key_value_stored=false`、
`authorization_header_stored=false`。脚本会探测不可达的 WSL autoProxy 并仅在代理端口
关闭时丢弃代理环境变量；`run_with_kimi_config.py` 默认在进程内把 DNS 结果过滤为 IPv4
（`SECVUL_IPV4_ONLY=0` 可关闭），manifest 记录该设置。

## 目录

| 路径 | 内容 |
| --- | --- |
| `conservative/prompt.py` | 三路提示、带行号源码、输入隔离与结构审计 |
| `conservative/schema.py` | 6 字段严格校验、行号质量与守卫词法审计 |
| `conservative/decision.py` | 保守撤销规则（唯一允许撤销的路径） |
| `conservative/runner.py` | 可恢复 runner、缓存、manifest/results |
| `conservative/evaluate.py` | 与原验证器/随机/低置信的同预算比较、统计检验、成本 |
| `conservative/report.py` | 中文报告 |
| `run_conservative.py` / `run_conservative.sh` | CLI 与四个实验臂 |
| `run_with_kimi_config.py` | 从 Kimi Code 配置读凭证到进程内存 |
| `selftest.py` | 离线自检（提示、schema、判定真值表） |
| `runs/` | dry-run 与四个真实 test run |
| `analysis/` | 报告与指标产物 |

## 定位与文献

这不是“又一个 LLM 自审”的正面结果，而是一个**选择性预测/弃权**的负结果：

- 三路判定把“未证明”与“已反驳”分开，接近 selective prediction 的
  reject/abstain 视角（Chow 1970；Geifman & El-Yaniv, arXiv:1705.08500；
  Angelopoulos & Bates, arXiv:2107.00363）。但 LLM 的弃权并不天然校准：
  它弃权了 106/236，却在少数“具体”输出里仍给出语义错误的守卫/反例。
- 这与“LLM 自我纠错/自 verification 在没有外部信号时收益有限”的结论一致
  （Huang et al., arXiv:2310.01798；Stechly et al., arXiv:2402.08115；
  CoVe, arXiv:2309.11495 也强调需要独立证据/执行）。
- 成本上，验证器是典型的 cascade 第二级（FrugalGPT, arXiv:2305.05176）：
  只有第一级候选足够便宜、第二级能显著提纯时才划算；本实验的第二级没有提纯。

**可做的下一步实验**（按优先级）：

1. **把守卫变成可检查的图性质**：用 Clang CFG/数据流抽取候选守卫，检查它是否支配
   claim 的引用行、是否覆盖 claim 的每条路径；LLM 只负责提出候选，不负责判定。
2. **执行反例**：为 `counterexample` 生成最小 harness，编译并跑 ASan/UBSan；只有
   “不触发”被执行证实时才撤销。这把文本断言变成可复现证据。
3. **风险-覆盖曲线**：在 dev 上校准弃权阈值，在 test 上报告 risk-coverage，而不是
   只报一个操作点；当前 test-tuned 扫描只能作描述。
4. **人工审计小样本**：对原验证器的 152 条 retract 与保守规则的 4 条做盲审，
   估计“具体守卫/反例”的真实精确率与标注者一致性。
5. **结构化多场景 claim**：把 claim 拆成若干 scenario，逐场景判定后用 AND 聚合；
   当前提示要求“覆盖所有路径”，但模型并不稳定遵守。

## 必须一起读的限制

- test-seen、事后、单次运行、temperature=0 不保证确定性；没有多 seed 方差。
- 只处理 schema-valid 正例；第一遍 invalid 记录在 strict 口径里始终算错。
- 只改正例，召回只会下降或不变；32 个非漏洞样本支撑不起精确 FPR 结论。
- 验证器只看函数体，无法证明跨函数/调用者约束；反例没有编译/执行验证。
- 守卫词法检查是启发式，可能拒绝合法写法，也可能接受 `memset` 这类非守卫行；
  行号/注释检查偏保守，可能低估撤销数。
- 跨模型验证器不是人工标注；两模型共享预训练语料与同一批测试函数。
- 成本按第一遍 run 的价格快照估算，未重新核对官方页面。
- 本目录不执行 git/gh；发布由主代理统一处理。
