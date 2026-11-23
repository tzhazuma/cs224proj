"""Chinese Markdown report for the conservative three-way verifier."""

from __future__ import annotations

from typing import Any

from .evaluate import ARMS, STRATEGY_LABELS

MAIN_STRATEGIES = (
    "pre",
    "original_fail_closed",
    "original_refutation_only",
    "original_guard_only",
    "conservative",
)


def fmt(value: Any, digits: int = 4) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "是" if value else "否"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def pct(value: Any, digits: int = 1) -> str:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return "—"
    return f"{100.0 * float(value):.{digits}f}%"


def signed(value: Any, digits: int = 4) -> str:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return "—"
    return f"{float(value):+.{digits}f}"


def signed_pct(value: Any, digits: int = 1) -> str:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return "—"
    return f"{100.0 * float(value):+.{digits}f}%"


def money(value: Any, digits: int = 6) -> str:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return "—"
    return f"{float(value):.{digits}f}"


def interval(block: dict[str, Any] | None, digits: int = 4) -> str:
    if not isinstance(block, dict):
        return "—"
    low, high = block.get("ci_low"), block.get("ci_high")
    if low is None or high is None:
        return "—"
    return f"[{low:+.{digits}f}, {high:+.{digits}f}]"


def metric_cell(block: dict[str, Any], key: str) -> str:
    value = block.get(key)
    return fmt(value)


def confusion_cell(scores: dict[str, Any]) -> str:
    confusion = scores.get("confusion") or {}
    return (
        f"{confusion.get('tp', '—')}/{confusion.get('fp', '—')}/"
        f"{confusion.get('tn', '—')}/{confusion.get('fn', '—')}"
    )


def strategy_table(arm: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    add = lines.append
    add("| 策略 | 撤销 k（有效） | TP 损失 | TP 损失率 | FP 纠正 | FP 纠正率 | 撤销精确率 | macro-F1 | Δmacro-F1 | MCC | ΔMCC | TP/FP/TN/FN | 流水线 USD |")
    add("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |")
    for name in MAIN_STRATEGIES:
        block = arm["strategies"][name]
        retraction = block["retraction"]
        scores = block["scores"]
        delta = block["delta_vs_pre"]
        cost = block.get("cost") or {}
        k_text = (
            f"{retraction['retracted']} ({retraction['parsed_retracted']})"
            if retraction.get("invalid_forced_retracted")
            else str(retraction["retracted"])
        )
        add(
            f"| {STRATEGY_LABELS[name]} | {k_text} | "
            f"{retraction['tp_retracted']} | {pct(retraction['tp_loss_rate'])} | "
            f"{retraction['fp_retracted']} | {pct(retraction['fp_correction_rate'])} | "
            f"{pct(retraction['retraction_precision'])} | {fmt(scores['macro_f1'])} | "
            f"{signed(delta['macro_f1'])} | {fmt(scores['mcc'])} | {signed(delta['mcc'])} | "
            f"{confusion_cell(scores)} | {money(cost.get('pipeline_usd'))} |"
        )
    return lines


def render_report(result: dict[str, Any]) -> str:
    arms = result["arms"]
    ordered = [arm["arm_id"] for arm in ARMS]
    lines: list[str] = []
    add = lines.append

    total_requests = sum(
        arms[arm_id]["conservative_status_counts"].get(status, 0)
        for arm_id in ordered
        for status in arms[arm_id]["conservative_status_counts"]
    )
    total_retracted = sum(
        arms[arm_id]["strategies"]["conservative"]["retraction"]["retracted"]
        for arm_id in ordered
    )
    total_tp = sum(
        arms[arm_id]["strategies"]["conservative"]["retraction"]["tp_retracted"]
        for arm_id in ordered
    )
    total_fp = sum(
        arms[arm_id]["strategies"]["conservative"]["retraction"]["fp_retracted"]
        for arm_id in ordered
    )
    total_invalid = sum(
        arms[arm_id]["conservative_status_counts"].get("invalid", 0)
        for arm_id in ordered
    )
    total_error = sum(
        arms[arm_id]["conservative_status_counts"].get("error", 0)
        for arm_id in ordered
    )
    total_original_retracted = sum(
        arms[arm_id]["strategies"]["original_fail_closed"]["retraction"]["retracted"]
        for arm_id in ordered
    )
    conservative_cost = sum(
        arms[arm_id]["cost"]["conservative_verifier"]["total_cost_usd"] or 0.0
        for arm_id in ordered
    )

    add("# 保守三路验证器：正例二次审查（SecVulEval 160，探索性）")
    add("")
    add("> **状态：探索性、事后分析（post-hoc），test-seen，不是独立确认。** 这 160 个函数")
    add("> 已经用于评估第一遍 evidence 提示和 `evidence_verify` 的原始验证器；本实验的")
    add("> 三路提示与判定规则是在看到那些结果之后设计的。任何数字都不能当作“在新测试集上")
    add("> 确认了检测能力”。本目录不修改 `evidence_verify/`、`evidence_prompt/`、`splits/`")
    add("> 或 `runner/runs/` 中的任何旧产物。")
    add("")
    add("## 0. 一句话结论")
    add("")
    add(
        f"在 {total_requests} 条真实验证请求中，保守规则只撤销了 **{total_retracted} 条**"
        f"（TP {total_tp} / FP {total_fp}）。它确实消除了原验证器“把 insufficient 也当撤销”"
        " 的大规模误撤销，但代价是几乎不再纠正假阳性：撤销精确率没有显著高于正例中的 FP"
        " 基准率；macro-F1 在四个臂上都不升（0 到 -0.0052），MCC 只在 `mimo_cross` 上升"
        " +0.0139（95% CI 跨 0），而这条臂同时损失 2 个 TP、只纠正 1 个 FP。"
        f"原验证器主口径在同一批正例上撤销了 {total_original_retracted} 条；两者相差"
        f"约 {total_original_retracted / total_retracted if total_retracted else 0:.0f} 倍。"
    )
    add("")
    add("因此，这个“改进”在**判定有效性**上是正确的（不再把‘无法证明’当成‘已被反驳’），")
    add("但在**检测收益**上是负结果：严格到只接受具体守卫/反例时，模型很少给出可用输出，")
    add("验证器退化为惰性步骤。")
    add("")

    add("## 1. 改了什么")
    add("")
    add("原 `evidence_verify` 的两处结构性问题：")
    add("")
    add("1. 提示要求“Retraction is the conservative action”，且主口径 **fail-closed**：")
    add("   验证器没有给出有效 sustain 时就撤销。于是 `insufficient_evidence`（“函数体内看不出")
    add("   可达性/攻击者控制”）也被当成撤销理由。")
    add("2. 事后 `refutation_only` 规则虽然保留 `insufficient_evidence`，但它仍把")
    add("   `no_reachable_flow` / `evidence_mislocated` / `not_security_relevant` 当作撤销；")
    add("   这些类型并不一定给出函数内的具体守卫或反例。")
    add("")
    add("本目录的改法：")
    add("")
    add("| 维度 | 原验证器 | 保守三路验证器 |")
    add("| --- | --- | --- |")
    add("| 输出 | `sustain` / `retract` + 5 类 rebuttal | `supported` / `unsupported` / `insufficient` |")
    add("| 撤销条件 | 任意 `retract`；主口径连 invalid 也撤销 | 仅 `unsupported` + 具体 `guard_present` 或 `counterexample` |")
    add("| 证据不足 | 可撤销（`insufficient_evidence`） | 保留第一遍预测 |")
    add("| 验证器失败 | fail-closed 撤销 | 保留第一遍预测（fail-open） |")
    add("| 行号校验 | 范围 + 非空 | 范围 + 非空 + 至少一行非注释/非括号代码；guard 还需守卫词法匹配 |")
    add("| 多场景 claim | 未要求 | 守卫必须覆盖 claim 描述的每一条路径，否则必须选 insufficient |")
    add("")
    add("判定表（机械执行，不由模型自行决定是否撤销）：")
    add("")
    add("| assessment | rebuttal_kind | 行号有效性 | 动作 |")
    add("| --- | --- | --- | --- |")
    add("| supported | none | — | 保留 |")
    add("| insufficient | none | — | 保留 |")
    add("| unsupported | guard_present | 至少一行有效代码且含守卫词法 | 撤销 |")
    add("| unsupported | guard_present | 空白/注释/括号/无守卫词法 | 保留（ungrounded） |")
    add("| unsupported | counterexample | 至少一行有效代码 + 具体反例文本 | 撤销 |")
    add("| unsupported | counterexample | 缺反例文本或行号无效 | 保留 |")
    add("| invalid / error | — | — | 保留（不采用 fail-closed） |")
    add("")
    add("“行号有效”是可机械检查的部分：行号在 `1..N`、不重复、至少一行既非空白也非纯注释/")
    add("纯括号；`guard_present` 还要求该行含 `if/return/&&/比较/边界函数` 等守卫词法。")
    add("**语义上的支配关系（守卫是否真的覆盖所有路径、反例是否真的不触发）没有被编译或")
    add("执行验证**，仍由模型断言。第 8.1 节给出两个反例。")
    add("")

    add("## 2. 真实运行")
    add("")
    add("四个臂，每个臂只对第一遍的 schema-valid 正例发一次请求；负例与第一遍 invalid 记录")
    add("原样保留。所有调用均为真实 API 调用，temperature=0，单次运行。")
    add("")
    add("| 臂 | 第一遍正例来源 | 验证器 | 请求 | ok | invalid | error | 撤销 | 验证器 USD | p50 / p95 延迟 |")
    add("| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |")
    for arm_id in ordered:
        arm = arms[arm_id]
        counts = arm["conservative_status_counts"]
        vcost = arm["cost"]["conservative_verifier"]
        add(
            f"| `{arm_id}` | {arm['claim_model']} | {arm['verifier_model']} | "
            f"{sum(counts.values())} | {counts.get('ok', 0)} | {counts.get('invalid', 0)} | "
            f"{counts.get('error', 0)} | "
            f"{arm['strategies']['conservative']['retraction']['retracted']} | "
            f"{money(vcost['total_cost_usd'])} | "
            f"{fmt(vcost['latency_seconds']['p50'], 2)} s / "
            f"{fmt(vcost['latency_seconds']['p95'], 2)} s |"
        )
    add("")
    add(f"合计 **{total_requests}** 条请求，invalid {total_invalid}、API error {total_error}，")
    add(f"验证器总成本 **{money(conservative_cost)} USD**（按第一遍 run 的价格快照估算，未重新")
    add("核对官方页面）。`deepseek_self` / `deepseek_cross` 使用 DeepSeek 第一遍的 60 个正例，")
    add("`mimo_self` / `mimo_cross` 使用 MiMo 第一遍的 58 个正例。cross 臂是主分析臂（验证器")
    add("与被审模型不同）；self 臂是同模型新上下文，只作补充。")
    add("")
    add("输入隔离：验证器只看到带行号函数源码 + 第一遍 `evidence_lines` / `mechanism`；")
    add("没有标签、项目、文件路径、commit、`changed_lines`、第一遍 confidence 或修复建议。")
    add("四份 dry-run 请求体与真实请求体逐条哈希一致，隔离审计 0 违规；manifest 记录")
    add("`api_key_value_stored=false`、`authorization_header_stored=false`。")
    add("")

    add("## 3. 主结果（逐臂）")
    add("")
    add("`pre` 为第一遍；`original` 为原验证器主口径 fail-closed；`original refutation-only`")
    add("为原目录的事后规则；`original guard-only replay` 是把原记录按本实验的严格规则重放")
    add("（只接受 grounded `guard_present`，invalid 保留）；`conservative` 是本实验的真实运行。")
    add("所有 post 行只改正例，负例与第一遍 invalid 不变；P/R/F1 为 valid-only，strict 正确数见 §6.1。")
    add("k 括号内为 schema-valid 的撤销数；TP 损失/FP 纠正为端到端（含 fail-closed 强制撤销")
    add("的 invalid）；撤销精确率按 schema-valid 撤销计算，与原目录口径一致。")
    add("")
    for arm_id in ordered:
        arm = arms[arm_id]
        add(f"### `{arm_id}`（{arm['claim_model']} 正例 → {arm['verifier_model']} 验证器）")
        add("")
        lines.extend(strategy_table(arm))
        add("")

    add("### 3.1 跨臂摘要")
    add("")
    add("| 臂 | pre macro-F1 | 原 post | 保守 post | Δ原 | Δ保守 | pre MCC | 原 MCC | 保守 MCC | 原 k | 保守 k |")
    add("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for arm_id in ordered:
        arm = arms[arm_id]
        pre = arm["strategies"]["pre"]
        orig = arm["strategies"]["original_fail_closed"]
        cons = arm["strategies"]["conservative"]
        add(
            f"| `{arm_id}` | {fmt(pre['scores']['macro_f1'])} | {fmt(orig['scores']['macro_f1'])} | "
            f"{fmt(cons['scores']['macro_f1'])} | {signed(orig['delta_vs_pre']['macro_f1'])} | "
            f"{signed(cons['delta_vs_pre']['macro_f1'])} | {fmt(pre['scores']['mcc'])} | "
            f"{fmt(orig['scores']['mcc'])} | {fmt(cons['scores']['mcc'])} | "
            f"{orig['retraction']['retracted']} | {cons['retraction']['retracted']} |"
        )
    add("")
    add("原验证器在四个臂上都把操作点大幅推向保守：撤销数远大于保守规则，macro-F1")
    add("一致下降（-0.0701 到 -0.2043）。MCC 在 3/4 臂上升，但这是 FP 被大量移除的")
    add("操作点副产物：撤销并没有显著偏向 FP（第 6.2 节，超几何 p=0.21–1.00），")
    add("同时 recall 显著下降。保守规则撤销数接近零，指标几乎不动；两个臂")
    add("（`deepseek_cross`、`mimo_self`）完全不动，另外两个臂各撤销 1–3 条。")
    add("")

    add("### 3.2 fail-open 敏感性")
    add("")
    add("原验证器主口径在验证失败时撤销。下表把同一批原记录改为失败保留（fail-open），")
    add("用来分离“失败处理”与“模型真的给出 retract”的影响。")
    add("")
    add("| 臂 | 原 fail-closed k | 原 fail-closed macro-F1 | 原 fail-open k | 原 fail-open macro-F1 | 保守 k | 保守 macro-F1 |")
    add("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for arm_id in ordered:
        arm = arms[arm_id]
        closed = arm["strategies"]["original_fail_closed"]
        opened = arm["strategies"]["original_fail_open"]
        cons = arm["strategies"]["conservative"]
        add(
            f"| `{arm_id}` | {closed['retraction']['retracted']} | "
            f"{fmt(closed['scores']['macro_f1'])} | {opened['retraction']['retracted']} | "
            f"{fmt(opened['scores']['macro_f1'])} | {cons['retraction']['retracted']} | "
            f"{fmt(cons['scores']['macro_f1'])} |"
        )
    add("")

    add("## 4. 与原验证器的决策差异")
    add("")
    add("把“撤销/保留”作为二分类决策，在正例集合上比较原验证器主口径与本实验：")
    add("")
    add("| 臂 | n | 都撤销 | 都保留 | 仅原撤销 | 仅保守撤销 | 一致率 | Cohen κ |")
    add("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for arm_id in ordered:
        block = arms[arm_id]["agreement_original_vs_conservative"]
        add(
            f"| `{arm_id}` | {block['n']} | {block['both_retract']} | {block['both_keep']} | "
            f"{block['left_retract_only']} | {block['right_retract_only']} | "
            f"{pct(block['agreement'])} | {fmt(block['cohen_kappa'])} |"
        )
    add("")
    add("原验证器的撤销类型分布（括号内为 TP/FP）：")
    add("")
    add("| 臂 | 撤销总数 | guard_present | insufficient_evidence | no_reachable_flow | evidence_mislocated | not_security_relevant |")
    add("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for arm_id in ordered:
        types = arms[arm_id]["original_taxonomy"]["rebuttal_types"]
        total = sum(value["total"] for key, value in types.items() if key != "none")
        def cell(name: str) -> str:
            value = types.get(name, {"total": 0, "tp": 0, "fp": 0})
            return f"{value['total']} ({value['tp']}/{value['fp']})"
        add(
            f"| `{arm_id}` | {total} | {cell('guard_present')} | "
            f"{cell('insufficient_evidence')} | {cell('no_reachable_flow')} | "
            f"{cell('evidence_mislocated')} | {cell('not_security_relevant')} |"
        )
    add("")
    add("`insufficient_evidence` 在原目录中占撤销的多数；它按契约不允许给行号，本来就不是")
    add("“函数内存在具体守卫或反例”。保守规则把它全部保留，是撤销数骤降的主要原因。")
    add("上表只统计 schema-valid 的 retract；原主口径 fail-closed 还把 3 条 invalid 验证")
    add("记录直接撤销（DeepSeek cross 2 条、MiMo self 1 条），所以原主口径总撤销数为")
    add(f"{total_original_retracted}，比上表各类型合计多 3 条。")
    add("")

    add("## 5. 随机 / 低置信同预算基线")
    add("")
    add("每个策略的 k 固定为它自己的撤销数；随机基线从同一批正例中均匀抽 k 个（10,000 次，")
    add("seed=42），低置信基线撤销第一遍 confidence 最低的 k 个正例。两者都不调用模型，")
    add("增量成本为 0。若验证器与这些廉价规则在同预算下没有差别，就不能说它“识别出了 FP”。")
    add("原验证器行的撤销精确率按 schema-valid 撤销计算（与 §3 一致）；TP/FP 为端到端，")
    add("所以 `deepseek_cross` 的 23.1% 不等于 7/28：其中 2 条 invalid 被 fail-closed 强制撤销。")
    add("")
    for arm_id in ordered:
        arm = arms[arm_id]
        add(f"### `{arm_id}`")
        add("")
        add("| 策略 | k（有效） | TP 损失 | FP 纠正 | 撤销精确率 | macro-F1 | MCC | 增量 USD |")
        add("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
        for name in ("conservative", "original_fail_closed"):
            block = arm["strategies"][name]
            retraction = block["retraction"]
            scores = block["scores"]
            cost = block.get("cost") or {}
            k_text = (
                f"{retraction['retracted']} ({retraction['parsed_retracted']})"
                if retraction.get("invalid_forced_retracted")
                else str(retraction["retracted"])
            )
            add(
                f"| {STRATEGY_LABELS[name]} | {k_text} | "
                f"{retraction['tp_retracted']} | {retraction['fp_retracted']} | "
                f"{pct(retraction['retraction_precision'])} | {fmt(scores['macro_f1'])} | "
                f"{fmt(scores['mcc'])} | {money(cost.get('verifier_usd'))} |"
            )
            random_block = block["matched_budget"]["random"]
            low_block = block["matched_budget"]["low_confidence"]
            add(
                f"| ↳ random (k={random_block['retracted']}) | {random_block['retracted']} | "
                f"{fmt(random_block['expected_tp_retracted'], 2)} | "
                f"{fmt(random_block['expected_fp_retracted'], 2)} | — | "
                f"{fmt(random_block['macro_f1']['mean'])} "
                f"[{fmt(random_block['macro_f1']['p2_5'])}, {fmt(random_block['macro_f1']['p97_5'])}] | "
                f"{fmt(random_block['mcc']['mean'])} "
                f"[{fmt(random_block['mcc']['p2_5'])}, {fmt(random_block['mcc']['p97_5'])}] | 0 |"
            )
            add(
                f"| ↳ 低置信 (k={low_block['retracted']}) | {low_block['retracted']} | "
                f"{low_block['tp_retracted']} | {low_block['fp_retracted']} | "
                f"{pct(low_block['retraction_precision'])} | {fmt(low_block['macro_f1'])} | "
                f"{fmt(low_block['mcc'])} | 0 |"
            )
        add("")

    add("## 6. 统计检验")
    add("")
    add("### 6.1 McNemar（pre vs post，strict 正确性）")
    add("")
    add("| 臂 | 策略 | pre 正确 | post 正确 | TP→FN | FP→TN | 双侧 p | Holm p |")
    add("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for arm_id in ordered:
        arm = arms[arm_id]
        for name in (
            "original_fail_closed",
            "original_refutation_only",
            "original_guard_only",
            "conservative",
        ):
            block = arm["strategies"][name]["mcnemar_vs_pre"]
            add(
                f"| `{arm_id}` | {STRATEGY_LABELS[name]} | {block['pre_correct']} | "
                f"{block['post_correct']} | {block['pre_correct_post_wrong']} | "
                f"{block['pre_wrong_post_correct']} | "
                f"{fmt(block['p_value_exact_two_sided'])} | "
                f"{fmt(block.get('p_value_holm'))} |"
            )
    add("")
    add("Holm 校正覆盖同一策略下的 4 个臂。结果分三组：原验证器主口径在 4 个臂上全部")
    add("显著变差（p=0.0000–0.0125，Holm 后仍显著），因为它大量撤销 TP；原 refutation-only")
    add("在 2 个臂边缘显著（未校正 p=0.0309/0.0490，Holm 后不显著）；strict guard-only")
    add("重放与保守规则在所有臂上都不显著。也就是说，本实验没有证明保守规则“更好”，")
    add("只证明了它没有像原主口径那样显著破坏 strict 正确性。")
    add("")

    add("### 6.2 撤销是否偏向 FP（超几何检验）")
    add("")
    add("| 臂 | 策略 | 有效撤销 k | 其中 invalid 强制 | 撤销 FP | 随机期望 FP | 撤销精确率 | FP 基准率 | p | Holm p |")
    add("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for arm_id in ordered:
        arm = arms[arm_id]
        for name in ("original_fail_closed", "original_guard_only", "conservative"):
            retraction = arm["strategies"][name]["retraction"]
            add(
                f"| `{arm_id}` | {STRATEGY_LABELS[name]} | "
                f"{retraction['parsed_retracted']} | "
                f"{retraction['invalid_forced_retracted']} | "
                f"{retraction['parsed_fp_retracted']} | "
                f"{fmt(retraction['expected_fp_retracted_under_random'], 2)} | "
                f"{pct(retraction['retraction_precision'])} | "
                f"{pct(retraction['base_fp_rate_among_positives'])} | "
                f"{fmt(retraction['hypergeom_p_fp_enrichment'])} | "
                f"{fmt(retraction.get('hypergeom_p_holm'))} |"
            )
    add("")
    add("零假设是“从正例中均匀抽 k 个”。保守规则的撤销精确率没有显著高于基准率；")
    add("原验证器的主口径同样没有。也就是说，撤销并没有选择性地命中假阳性。")
    add("")

    add("### 6.3 按项目聚类的 bootstrap（Δ = post − pre）")
    add("")
    add("| 臂 | 策略 | Δmacro-F1 [95%] | ΔMCC [95%] | Δrecall [95%] | Δspecificity [95%] | 聚类数 |")
    add("| --- | --- | --- | --- | --- | --- | ---: |")
    for arm_id in ordered:
        arm = arms[arm_id]
        for name in ("original_fail_closed", "conservative"):
            bootstrap = arm["strategies"][name].get("bootstrap_delta") or {}
            deltas = bootstrap.get("deltas") or {}
            add(
                f"| `{arm_id}` | {STRATEGY_LABELS[name]} | "
                f"{interval(deltas.get('macro_f1'))} | {interval(deltas.get('mcc'))} | "
                f"{interval(deltas.get('recall'))} | {interval(deltas.get('specificity'))} | "
                f"{bootstrap.get('cluster_count', '—')} |"
            )
    add("")
    add("原验证器的 Δmacro-F1 区间整体为负；保守规则的区间以 0 为中心或仅轻微为负")
    add("（`mimo_cross` 的 ΔMCC 区间 [-0.0476, +0.0514] 跨 0）。两者的差别主要是")
    add("“撤销多少”，不是“撤销得更准”。")
    add("")

    add("## 7. 成本")
    add("")
    add("| 臂 | 第一遍 USD | 原验证器 USD | 保守验证器 USD | 原流水线 USD | 保守流水线 USD | 保守增量 | 保守/100 单元 | 每个 FP 纠正 USD | 每个 TP 损失 USD |")
    add("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for arm_id in ordered:
        arm = arms[arm_id]
        first = arm["cost"]["first_pass"]["total_cost_usd"]
        orig = arm["cost"]["original_verifier"]["total_cost_usd"]
        cons = arm["cost"]["conservative_verifier"]["total_cost_usd"]
        orig_cost = arm["strategies"]["original_fail_closed"]["cost"]
        cons_cost = arm["strategies"]["conservative"]["cost"]
        add(
            f"| `{arm_id}` | {money(first)} | {money(orig)} | {money(cons)} | "
            f"{money(orig_cost.get('pipeline_usd'))} | {money(cons_cost.get('pipeline_usd'))} | "
            f"{signed_pct(cons_cost.get('verifier_increment_ratio'))} | "
            f"{money(cons_cost.get('verifier_usd_per_100_units'))} | "
            f"{money(cons_cost.get('verifier_usd_per_fp_corrected'))} | "
            f"{money(cons_cost.get('verifier_usd_per_tp_lost'))} |"
        )
    add("")
    add("保守验证器每次请求都要重发带行号源码，输入 token 接近一次完整检测；它的成本与")
    add("原验证器同一量级，但因为几乎不撤销，分摊到“每个 FP 纠正”上极贵（只有")
    add("`mimo_cross` 有 1 个 FP 纠正，其余臂没有）。随机/低置信基线只读第一遍输出，")
    add("增量成本为 0。")
    add("")

    add("## 8. 验证器输出结构与失败")
    add("")
    add("| 臂 | supported | unsupported | insufficient | invalid | error | 撤销 | 其中 TP/FP |")
    add("| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |")
    for arm_id in ordered:
        arm = arms[arm_id]
        taxonomy = arm["conservative_taxonomy"]["by_assessment"]
        counts = arm["conservative_status_counts"]
        retraction = arm["strategies"]["conservative"]["retraction"]
        add(
            f"| `{arm_id}` | {taxonomy.get('supported', {}).get('total', 0)} | "
            f"{taxonomy.get('unsupported', {}).get('total', 0)} | "
            f"{taxonomy.get('insufficient', {}).get('total', 0)} | "
            f"{counts.get('invalid', 0)} | {counts.get('error', 0)} | "
            f"{retraction['retracted']} | {retraction['tp_retracted']}/{retraction['fp_retracted']} |"
        )
    add("")
    add("`insufficient` 占多数（40/60、16/60、11/58、39/58），`unsupported` 很少")
    add("（0–3 条）。这正是三路提示的设计目标：把“函数体内无法证明”与“有具体反证”分开。")
    add("")
    add("失败记录（schema-invalid / API error）全部**保留第一遍预测**，没有 fail-closed：")
    add("")
    add("| 臂 | idx | label | status | family | HTTP / 错误 | 决策 |")
    add("| --- | ---: | --- | --- | --- | --- | --- |")
    for arm_id in ordered:
        for failure in arms[arm_id]["conservative_failures"]["records"]:
            detail = str(failure["error"])
            if failure["status"] == "invalid":
                detail = f"HTTP {failure.get('http_status')} / schema invalid ({failure['error']})"
            elif failure.get("http_status") is not None:
                detail = f"HTTP {failure['http_status']}"
                if failure.get("response_error_type"):
                    detail += f" ({failure['response_error_type']})"
            add(
                f"| `{arm_id}` | {failure['idx']} | {failure['label']} | "
                f"{failure['status']} | {failure['error_family']} | "
                f"{detail} | keep_verifier_failure |"
            )
    add("")

    add("### 8.1 全部撤销案例（逐条审计）")
    add("")
    add("| 臂 | idx | label | kind | 引用行 | 行号审计 | reason（节选） |")
    add("| --- | ---: | --- | --- | --- | --- | --- |")
    for arm_id in ordered:
        for row in arms[arm_id].get("retraction_cases", []):
            audit = row.get("audit") or {}
            flags = (
                f"grounded={audit.get('rebuttal_grounded')}, "
                f"code={audit.get('code_line_cited')}, "
                f"guard_lex={audit.get('guard_lexical_match')}, "
                f"ce={audit.get('counterexample_provided')}"
            )
            add(
                f"| `{arm_id}` | {row['idx']} | {row['label']} | {row['kind']} | "
                f"{row['lines']} | {flags} | {str(row['reason'])[:150]} |"
            )
    add("")
    add("两个需要人工注意的案例：")
    add("")
    add("1. `deepseek_self` 的 idx 24867：模型选择 `counterexample`，但它的 `reason` 明确说")
    add("   “%s scenario is real ... reads out of bounds”，即它描述的是**触发**缺陷的输入，")
    add("   不是不触发的反例。行号审计全部通过，说明**机械 grounding 不能替代语义校验**。")
    add("2. `mimo_cross` 的 idx 24867：模型把 `memset(buf, 0, sizeof(buf))` 当作守卫。")
    add("   memset 只做零初始化；如果后续 `read()` 填满缓冲区且没有 NUL，它并不阻止越界读。")
    add("   这是“具体代码行 + 守卫词法”通过、但支配关系不成立的例子。")
    add("")

    add("## 9. 结论")
    add("")
    add("1. **判定规则修对了，但收益是负的。** 把 `insufficient` 与 `unsupported` 分开、")
    add("   取消 fail-closed 后，撤销数从原验证器的")
    add(f"   {total_original_retracted} 条降到 {total_retracted} 条；但撤销精确率仍只有")
    add(f"   {pct(total_fp / total_retracted if total_retracted else None)}，没有显著高于正例中")
    add("   的 FP 基准率；macro-F1 在四个臂上都不升，MCC 只在 `mimo_cross` 上升 +0.0139")
    add("   （95% CI 跨 0），代价是 2 个 TP 损失换 1 个 FP 纠正。")
    add("2. **模型很少给出可用的具体反证。** 236 条里只有 4 条通过“具体 + grounded”门槛，")
    add("   其中 2 条记录（同一 idx 24867 出现在 `deepseek_self` 与 `mimo_cross`）语义上")
    add("   站不住：一条把触发缺陷的输入当反例，一条把 memset 零初始化当守卫。提示已经把")
    add("   标准写得很窄；继续调提示的边际收益有限。")
    add("3. **成本不低。** 保守验证器与原验证器同一量级（每臂约 0.03–0.05 USD），但因为")
    add("   几乎不撤销，分摊到每个 FP 纠正上的成本极高。随机/低置信基线为 0 成本，")
    add("   在本数据上没有证据表明模型验证优于它们。")
    add("4. **真正有价值的改进方向不是“更严格的提示”，而是外部证据。** 例如用静态分析/")
    add("   符号执行抽取守卫与可达性，把“守卫是否支配”变成可检查的图性质；或者用")
    add("   选择性预测/弃权校准而不是让 LLM 自己判断“是否足够”。在这些外部信号到位前，")
    add("   本实验的保守验证器应作为**审计工具/负结果**，不应作为提分组件。")
    add("")

    add("## 10. 限制")
    add("")
    add("- **test-seen / 事后**：160 条测试函数已用于第一遍与原始验证器；本提示在看到那些")
    add("  结果后设计，没有预注册。所有数字只是探索性证据。")
    add("- 单次运行、temperature=0 不保证确定性；没有多 seed 方差。")
    add("- 只处理 schema-valid 正例；第一遍 invalid 记录（DeepSeek 1、MiMo 2）没有可验证")
    add("  claim，在 strict 口径里始终算错。")
    add("- 只改正例，召回只会下降或不变；32 个非漏洞样本支撑不起精确的 FPR 结论。")
    add("- 验证器只看函数体，无法证明跨函数/调用者约束；被撤销的“缺陷”可能包含真实的、")
    add("  需要上下文才能成立的漏洞。")
    add("- `counterexample` 是模型生成的文本，没有编译、执行或 PoC 验证；`guard_present`")
    add("  的支配关系也没有数据流/控制流验证。第 8.1 节给出两个反例。")
    add("- 守卫词法检查是启发式：它可能拒绝合法的边界函数写法，也可能接受 `memset` 这类")
    add("  非守卫行；它只用于降低盲信，不是语义证明。行号/注释检查还偏保守：以 `*` 开头的")
    add("  指针赋值行会被当作注释续行，短于 12 字符的反例会被 schema 拒绝；这两类都会")
    add("  导致保留而不是误撤销，因此可能低估撤销数。")
    add("- 跨模型验证器不是人工标注；两个模型共享预训练语料与同一批测试函数，一致率高")
    add("  不代表正确。")
    add("- 成本按第一遍 run 的价格快照估算，未重新核对官方页面；随机/低置信基线的 0 成本")
    add("  只指“没有新增 API 调用”，不包含工程与标注成本。")
    add("- 四个臂共享两个 claim 集合，不是四个独立样本；Holm 校正只覆盖臂内策略，")
    add("  不覆盖跨策略的事后比较。")
    add("")

    add("## 11. 复现（WSL，项目根目录）")
    add("")
    add("```bash")
    add("cd /mnt/c/Users/tzh03/Downloads/cs224proj")
    add("python3 verifier_conservative/selftest.py")
    add("bash verifier_conservative/run_conservative.sh deepseek_self dryrun")
    add("bash verifier_conservative/run_conservative.sh deepseek_self test")
    add("bash verifier_conservative/run_conservative.sh deepseek_cross test")
    add("bash verifier_conservative/run_conservative.sh mimo_self test")
    add("bash verifier_conservative/run_conservative.sh mimo_cross test")
    add("python3 verifier_conservative/analyze_conservative.py")
    add("```")
    add("")
    add("`run_conservative.sh` 在目标目录已有 manifest 时自动加 `--resume`；请求按内容哈希")
    add("缓存在 run 目录。脚本不写 `evidence_verify/`、`evidence_prompt/`、`splits/` 或")
    add("`runner/runs/`。凭证由 `run_with_kimi_config.py` 从 Kimi Code 配置读入进程内存，")
    add("不打印、不落盘。")
    add("")

    return "\n".join(lines) + "\n"
