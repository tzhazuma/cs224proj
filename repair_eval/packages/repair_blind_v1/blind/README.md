# 盲评包 `PKG-3DB061ED2788`

## 文件

- `review.md`：漏洞函数、上游修复上下文（若未隐藏）和随机排序的候选。
- `rubric.md`：七维 0/1/2 rubric、通过规则和编译状态说明。
- `rater_A.tsv` / `rater_B.tsv`：两位评分者各自的空评分表。
- `blind_package.json`：机器可读的盲评材料。

## 流程

1. 两位评分者独立阅读 `rubric.md` 和 `review.md`，分别填写自己的 TSV。
2. 不要交流分数，不要查看 `private/`，不要尝试推断候选来源。
3. 每维填 0/1/2；`compile_status` 见 rubric；`notes` 写 1–2 句理由。
4. 交回两份 TSV 后运行 `agreement`，生成一致性报告和分歧裁决模板。
5. 分歧由第三人裁决；填 `final_value` 和 `rationale` 后运行 `finalize`。

## 注意

- 本包不含策略名、模型名、pair_id 或参考修复匹配标记。
- 上游修复版本（若显示）只是上下文；候选是否与它相同被刻意隐藏。
- 没有编译/PoC oracle；不要把 `COM` 或 `compile_status` 当作漏洞已消除的证明。
