# 一致性报告与裁决

- `agreement.json` / `agreement.md`：两位评分者的一致性结果。
- `adjudication.tsv`：只列出有分歧的候选-维度。
- `disagreements.json`：机器可读的分歧列表。

裁决者填写 `final_value`（评分维度填 0/1/2；编译状态填 `NOT_RUN`/`UNVERIFIED`/`PASS`/`FAIL`）和 `rationale`，然后运行 `finalize`。不要修改原始 `rater_A.tsv` / `rater_B.tsv`。
