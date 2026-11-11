"""Fixed human-review rubric and pass rules for repair candidates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


RUBRIC_VERSION = "repair-eval-rubric-2026-11-11.1"


@dataclass(frozen=True)
class Dimension:
    code: str
    name_zh: str
    name_en: str
    short: str
    anchors: tuple[str, str, str]


DIMENSIONS: tuple[Dimension, ...] = (
    Dimension(
        code="VR",
        name_zh="漏洞消除",
        name_en="Vulnerability removal",
        short="是否处理了标注 CWE 的根因；不要求与上游修复文本相同。",
        anchors=(
            "未处理根因，仍可利用；只改注释/格式；或引入新的可利用路径。",
            "缓解了一条路径，但仍有绕过、遗漏的错误路径或不完整修复。",
            "处理了标注 CWE 的根因；替代性的正确修复也可得 2 分。",
        ),
    ),
    Dimension(
        code="SP",
        name_zh="行为保持",
        name_en="Behavior preservation",
        short="签名、返回约定和调用方可见行为是否保持。",
        anchors=(
            "改变签名/返回约定，或明显破坏调用方可见行为。",
            "常见路径可能保持，但边界、错误路径或状态变化不确定。",
            "签名与预期行为保持；代码本身能说明理由，或有测试证据。",
        ),
    ),
    Dimension(
        code="MIN",
        name_zh="最小性",
        name_en="Minimality",
        short="改动是否局限在漏洞区域，必要且充分。",
        anchors=(
            "大范围重写、无关改动，或把整个函数替换成不同实现。",
            "中等改动，部分超出漏洞区域，或夹带无关重构。",
            "改动局限在漏洞区域，必要且充分。",
        ),
    ),
    Dimension(
        code="COM",
        name_zh="完整性",
        name_en="Patch completeness",
        short="是否为完整函数文本；这是文本完整性，不是编译证明。",
        anchors=(
            "不是完整函数：截断、diff、Markdown 围栏、缺右括号/函数体。",
            "是函数文本，但有可疑截断、签名漂移或明显缺失的必要声明。",
            "完整函数文本；签名和花括号完整，结构上可继续做编译检查。",
        ),
    ),
    Dimension(
        code="CQ",
        name_zh="代码质量",
        name_en="Code quality",
        short="可读性、惯用法、死代码/调试残留、与周边风格的一致性。",
        anchors=(
            "难以阅读；死代码/调试残留；风格明显冲突；使用危险惯用法。",
            "可理解，但有重复、命名混乱、无关日志或不必要复杂化。",
            "清晰、惯用、无调试/死代码，与周边代码风格一致。",
        ),
    ),
    Dimension(
        code="EF",
        name_zh="解释忠实",
        name_en="Explanation faithfulness",
        short="解释是否准确说明改动及其与 CWE 的关系，并与 patch 一致。",
        anchors=(
            "解释与 patch 矛盾、幻觉，或只有泛泛而谈的套话。",
            "部分一致，但遗漏关键改动、CWE 或副作用。",
            "准确说明改了什么、为什么处理该 CWE，且与 patch 一致。",
        ),
    ),
    Dimension(
        code="NS",
        name_zh="无新风险",
        name_en="No new risk",
        short="是否引入新的明显危险模式或削弱既有检查。",
        anchors=(
            "引入新的明显危险模式（更不安全的 API、删除检查、错误边界）。",
            "不确定是否引入新风险，或存在可疑但未证实的改动。",
            "未引入新的明显危险模式，既有检查得到保留。",
        ),
    ),
)

DIMENSION_BY_CODE = {dimension.code: dimension for dimension in DIMENSIONS}
DIMENSION_CODES = tuple(dimension.code for dimension in DIMENSIONS)

DIMENSION_ALIASES: dict[str, str] = {}
for _dimension in DIMENSIONS:
    for _alias in (
        _dimension.code,
        _dimension.code.lower(),
        _dimension.name_zh,
        _dimension.name_en,
        _dimension.name_en.lower().replace(" ", "_"),
        _dimension.name_en.lower().replace(" ", ""),
    ):
        DIMENSION_ALIASES[_alias] = _dimension.code
DIMENSION_ALIASES.update(
    {
        "漏洞消除": "VR",
        "vulnerability_elimination": "VR",
        "vulnerability_removal": "VR",
        "行为保持": "SP",
        "semantic_preservation": "SP",
        "behavior_preservation": "SP",
        "语义保持": "SP",
        "最小性": "MIN",
        "minimality": "MIN",
        "完整性": "COM",
        "completeness": "COM",
        "patch_completeness": "COM",
        "代码质量": "CQ",
        "code_quality": "CQ",
        "解释忠实": "EF",
        "explanation_faithfulness": "EF",
        "无新风险": "NS",
        "no_new_risk": "NS",
    }
)

COMPILE_STATUSES = ("NOT_RUN", "UNVERIFIED", "PASS", "FAIL")
COMPILE_STATUS_ALIASES = {
    "": "NOT_RUN",
    "NOT_RUN": "NOT_RUN",
    "NOTRUN": "NOT_RUN",
    "UNVERIFIED": "UNVERIFIED",
    "PASS": "PASS",
    "FAIL": "FAIL",
    "未运行": "NOT_RUN",
    "未验证": "UNVERIFIED",
    "通过": "PASS",
    "失败": "FAIL",
}

SCORE_VALUES = (0, 1, 2)
PRIMARY_PASS_RULE = "VR == 2"
STRICT_PASS_RULE = "VR == 2 and SP >= 1 and NS == 2 and EF >= 1 and COM >= 1"


def primary_pass(scores: dict[str, int]) -> bool:
    return scores.get("VR") == 2


def strict_pass(scores: dict[str, int]) -> bool:
    return (
        scores.get("VR") == 2
        and scores.get("SP", 0) >= 1
        and scores.get("NS", 0) == 2
        and scores.get("EF", 0) >= 1
        and scores.get("COM", 0) >= 1
    )


def rubric_markdown() -> str:
    lines = [
        "# 修复质量盲评 rubric",
        "",
        f"- rubric 版本：`{RUBRIC_VERSION}`",
        "- 每维 0/1/2；只能填整数。",
        "- 六维之外的完整性/代码质量为补充维度；编译和 PoC **不是**评分维度。",
        "",
        "| 维度 | 0 | 1 | 2 |",
        "| --- | --- | --- | --- |",
    ]
    for dimension in DIMENSIONS:
        lines.append(
            "| **{code} {name}** | {zero} | {one} | {two} |".format(
                code=dimension.code,
                name=dimension.name_zh,
                zero=dimension.anchors[0],
                one=dimension.anchors[1],
                two=dimension.anchors[2],
            )
        )
    lines.extend(
        [
            "",
            "## 评分规则",
            "",
            f"- 主要通过条件：`{PRIMARY_PASS_RULE}`。",
            f"- 严格通过条件：`{STRICT_PASS_RULE}`。",
            "- `COM` 是文本完整性（完整函数、签名、括号），**不是**编译成功。",
            "- `CQ` 是代码质量，不是漏洞是否消除。",
            "- 不要因为候选写法与上游修复不同就自动扣 VR 分；替代性的正确修复可以得 2 分。",
            "- 不要因为解释很长就给高 EF 分；看解释与 patch 是否一致。",
            "- 不要猜测候选来自哪种提示策略；若代码风格让你怀疑，也不要把它写进分数理由。",
            "",
            "## 编译状态（单独记录，不计入 rubric 分数）",
            "",
            "| 值 | 含义 |",
            "| --- | --- |",
            "| `NOT_RUN` | 没有尝试编译（默认；本工具不执行编译）。 |",
            "| `UNVERIFIED` | 人工判断语法像完整函数，但缺少项目头文件/类型/宏，无法确认。 |",
            "| `PASS` | 有外部构建证据表明该函数在 stub harness 或项目中编译通过。 |",
            "| `FAIL` | 有明显语法错误或不完整函数。 |",
            "",
            "本工具本身不提供编译或 PoC oracle。若评分者没有真实构建证据，"
            "请填 `NOT_RUN` 或 `UNVERIFIED`，不能据此声称修复可编译或漏洞不可利用。",
            "",
        ]
    )
    return "\n".join(lines)


def dimension_catalog() -> list[dict[str, Any]]:
    return [
        {
            "code": dimension.code,
            "name_zh": dimension.name_zh,
            "name_en": dimension.name_en,
            "short": dimension.short,
            "anchors": list(dimension.anchors),
        }
        for dimension in DIMENSIONS
    ]
