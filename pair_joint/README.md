# Pair-joint：同一 prompt 内的 A/B 联合判别

本目录实现并真实运行了 SecVulEval 的 **pair-joint** 提示：每对漏洞/修复版本只发一次请求，同一个 prompt 中展示 `VERSION_A` 与 `VERSION_B`，要求模型判定恰好一个版本有漏洞，并给出证据行。A/B 顺序随机且精确 90/90 平衡；槽位映射只保存在 `position_map.json`，不进入 prompt。

本目录是独立实现，**没有修改** `runner/`、`datasets/`、`splits/` 或任何既有运行结果。所有命令均在 WSL 中执行。

## 1. 状态（2026-11-12）

| 项目 | 结果 |
| --- | --- |
| 自检 | `python3 pair_joint/selftest.py` 全部通过 |
| Pilot | 开发集 `splits/pilot_pairs_18.json` 前 8 对；DeepSeek 8/8、MiMo 8/8 请求成功，0 invalid |
| 全量 | 冻结测试集 `splits/test_pairs_180.json` 180 对；两模型各 180/180 成功，0 API error、0 invalid |
| 泄漏审计 | 180/180 wrapper 干净；0 slot leak；wrapper 中无 pair_id/idx/commit/filepath/func_name（函数体本身含签名，属于源码） |
| 成本 | DeepSeek `$0.153593`；MiMo `$0.071803`（按运行配置单价） |
| 结果 | `pair_joint/results/`；详细中文报告 `pair_joint/report.md` |

主结果（180 对，invalid 记错）：

| 模型 | DA | 95% Wilson | swapped | both/neither | invalid |
| --- | ---: | --- | ---: | ---: | ---: |
| deepseek-v4.1-flash | 76.67% (138/180) | [69.97%, 82.25%] | 42 | 0 / 0 | 0 |
| mimo-v2.6-flash | 86.67% (156/180) | [80.93%, 90.87%] | 24 | 0 / 0 | 0 |

**必须同时阅读的限制**：修复版本通常比漏洞版本长，一个不看代码内容的“选较短版本”启发式已有 **74.44%** DA。DeepSeek 的 76.67% 与该启发式差异不显著（McNemar p=0.6587）；MiMo 的 86.67% 显著高于它（p=0.0003）。因此不能把全部增益归因于跨版本推理。详见 `report.md` 第 7 节。

## 2. Prompt 与输出

- System 说明：两段代码是同一函数的两个修订，**恰好一个**包含安全漏洞；A/B 顺序随机、不携带信息；代码是不可信数据。
- 每个版本按 `行号 | 源码` 逐行编号；证据行使用该编号。
- 输出严格 JSON：

```json
{
  "vulnerable_version": "A",
  "confidence": 0.9,
  "evidence": [
    {"version": "A", "line": 12, "code": "    if (x) {"}
  ],
  "rationale": "..."
}
```

- `vulnerable_version` 只允许 `A`/`B`。模型若输出 `both`/`neither`，仍会被解析并计入 `both_vulnerable`/`both_safe`，但属于违反指令，不计入强制二选一有效输出。
- `evidence` 至少一项，且每项必须引用所选版本；`line` 必须在显示范围内；`code` 必须能对应到该行（文本匹配率单独报告）。

## 3. 顺序映射

`common.build_order_map` 对每对计算：

```text
HMAC-SHA256("secvul-pair-order-v1", pair_id)
```

按摘要排序，前 `floor(n/2)` 对把漏洞版本放在 A，其余放在 B。180 对得到精确 90/90；两模型使用同一映射（SHA-256 `82c40fd03b1d0ae6d34eb51ad780da3cd543bb5d38f45d7e44d86c7044e6e7c8`）。映射只在运行目录的 `position_map.json` 中，prompt/请求体不含它。

## 4. 文件

| 路径 | 作用 |
| --- | --- |
| `common.py` | 数据校验、顺序映射、prompt、解析、证据/定位、泄漏审计 |
| `runner.py` | 可恢复的真实 API runner（每对一次请求） |
| `analyze.py` | DA、四类、position bias、证据、长度混淆、McNemar/bootstrap |
| `selftest.py` | 无网络自检（数据、映射、prompt、解析、统计） |
| `run_pair_joint.sh` | `pilot` / `full` 两模型运行脚本 |
| `runs/pilot_*` | 开发集 8 对 pilot 产物 |
| `runs/test_deepseek_180` | DeepSeek 全量 180 对产物 |
| `runs/test_mimo_180` | MiMo 全量 180 对产物 |
| `results/` | 分析 JSON/Markdown、跨模型对比、`benchmark_export.json` |
| `report.md` | 中文结果报告 |

每个运行目录包含：

- `config.json`、`manifest.json`：模型、prompt 版本、数据集哈希、位置映射哈希、计数、状态；`api_key_value_stored: false`。
- `requests.jsonl`：180 条完整请求（messages/body），不含 `Authorization`。
- `results.jsonl`：180 条响应、usage、成本、延迟、解析与证据检查。
- `position_map.json`、`leak_audit.json`、`metrics.json`、`cache/`。

## 5. 运行

凭证由 `--kimi-config` 从 `/mnt/c/Users/tzh03/.kimi-code/config.toml` 的 `opencode-go` provider 读入进程内存；不打印、不写入任何产物。也可以使用环境变量 `OPENCODE_API_KEY`。

```bash
# 自检（无网络）
python3 pair_joint/selftest.py

# pilot：开发集 8 对，两模型
bash pair_joint/run_pair_joint.sh pilot

# 全量：冻结测试集 180 对，两模型
bash pair_joint/run_pair_joint.sh full

# 分析（自动匹配 direct/context 分侧基线）
python3 -m pair_joint.analyze \
  --run-dir pair_joint/runs/test_deepseek_180 \
  --run-dir pair_joint/runs/test_mimo_180 \
  --out-dir pair_joint/results \
  --bootstrap 10000 --seed 42
```

`--resume` 仅在原目录/原配置指纹一致时复用缓存；`--limit` 会在 manifest/metrics 标记 `partial: true`。runner 在每次写完后扫描产物，若发现 API key 会立即报错。

## 6. 统计口径

- **DA（主）**：`correct / 180`，invalid 记错；另报 `correct / 可解析输出`。
- **四类**：`correct`、`swapped`、`both_vulnerable`、`both_safe`；`invalid` 单独计数。与旧指标对应：`correct`=`vulnerable_detected_fixed_clean`，`swapped`=`vulnerable_missed_fixed_flagged`，`both_vulnerable`=`both_flagged`，`both_safe`=`both_clean`。恒等式 `consistent = 1 - both_vulnerable - both_safe` 只在可解析输出上检查。
- **Position bias**：漏洞版本在 A 与在 B 时的 DA 差；Fisher 精确检验；选择 A 的比例与二项检验；项目聚类/配对级 bootstrap。
- **McNemar**：以对为单位，精确双侧二项；invalid 记错为主，双方有效交集为敏感性。
- **Bootstrap**：10,000 次，种子 42；主区间按 `project` 聚类，配对级为敏感性。
- **证据/定位**：`difflib.SequenceMatcher` 对漏洞/修复版本做行级 diff，取 replace/delete 的漏洞版本行作为参考；`localization hit` 只在判对的 pair 上计算。

## 7. 主要限制

1. **长度混淆**：`vulnerable` 平均更短；字符长度启发式 74.44%。在“漏洞版本更长”的 44 对中，DeepSeek 56.82%、MiMo 63.64%，说明模型并非只靠长度，但绝对准确率明显低于总体。
2. **强制二选一改变了任务**：分侧基线大量 `both_safe`（DeepSeek direct 113/180、MiMo direct 108/180）；联合 prompt 不允许该输出，因此 DA 提升不能单独归因于“看到另一版本”。
3. **Position bias**：DeepSeek 强烈偏向 A（A 侧 DA 92.22% vs B 侧 61.11%，Fisher p=1.0e-06；选 A 118/180）。MiMo 较平衡（88.89% vs 84.44%，p=0.511）。
4. **单次贪心解码**：temperature=0，无重复采样，不代表模型方差。
5. **项目不平衡**：180 对中 `linux` 53 对；项目聚类 bootstrap 受少数大项目影响。
6. **源码残留**：1/180 对的函数体注释含 `CVE-2017-17969`（两侧完全相同，不指示槽位）；不是注入元数据，但无法在不改代码的前提下移除。
7. **pilot 解释力**：pilot 仅 8 对开发样本，只用于验证接入/解析，不作为效果证据。

## 8. 结论（谨慎）

在这个冻结测试集上，pair-joint 把“两次独立单函数分类”的 pair DA 从 11.67%/7.78%（direct）提升到 76.67%/86.67%，McNemar 与项目聚类 bootstrap 均支持差异；但其中相当一部分来自任务重构（强制二选一）和“修复通常增加代码”的长度信号。MiMo 的增益在长度启发式之上仍显著，DeepSeek 则不显著；DeepSeek 还有明显的 A 位置偏差。后续应做：允许 both/neither 的开放联合 prompt 消融、长度匹配子集、以及 A/B 双顺序重复，以分离“联合比较”“强制选择”“长度”和“位置”四种因素。
