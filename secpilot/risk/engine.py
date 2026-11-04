from secpilot.core.finding import (
    Finding,
    FindingSeverity,
    FindingStatus,
)


# ============================================================
# 基础严重程度规则表
#
# 漏洞类型 → 基础严重程度。
#
# 评级由 Risk Engine 统一负责，
# Skill 不直接决定严重程度。
# ============================================================

BASE_SEVERITY: dict[
    str,
    FindingSeverity,
] = {
    "boolean_based_sql_injection": (
        FindingSeverity.HIGH
    ),
}


# ============================================================
# 严重程度阶梯
#
# 用于 SUSPECTED / 低置信度时的降级计算。
# UNRATED 不参与阶梯。
# ============================================================

SEVERITY_LADDER: list[
    FindingSeverity,
] = [
    FindingSeverity.INFO,
    FindingSeverity.LOW,
    FindingSeverity.MEDIUM,
    FindingSeverity.HIGH,
    FindingSeverity.CRITICAL,
]


# ============================================================
# CONFIRMED 置信度门槛
#
# 低于该值时即使确认也降一级。
# ============================================================

CONFIDENCE_CONFIRMED_THRESHOLD = (
    0.6
)


def _downgrade(
    severity: FindingSeverity,
    levels: int = 1,
) -> FindingSeverity:
    """
    在严重程度阶梯上下降 levels 级。

    INFO 已经是最低级，保持不变。
    """

    try:

        index = (
            SEVERITY_LADDER
            .index(severity)
        )

    except ValueError:

        return (
            FindingSeverity.INFO
        )

    index = index - levels

    if index < 0:

        index = 0

    return (
        SEVERITY_LADDER[index]
    )


class RiskEngine:
    """
    SecPilot 规则化风险评级引擎。

    Finding.skill / Evidence 只负责验证，
    严重程度统一由这里评级。

    规则：

        1. REJECTED
            验证结果否定漏洞存在
            → INFO，仅作为审计记录保留

        2. SUSPECTED
            基础严重程度降一级

        3. CONFIRMED + confidence < 0.6
            基础严重程度降一级

        4. CONFIRMED + confidence >= 0.6
            保持基础严重程度

        5. 未知漏洞类型
            基础严重程度 LOW

        6. 已有评级（severity != UNRATED）
            跳过，不覆盖

    评级依据写入：

        Finding.metadata["risk_rationale"]
        Finding.metadata["risk_rule"]
    """

    def rate(
        self,
        finding: Finding,
    ) -> Finding:
        """
        对单个 Finding 评级。

        原地修改 severity 和 metadata，
        并返回同一个 Finding。
        """

        # ================================================
        # 1. 已评级，跳过
        # ================================================

        if (
            finding.severity
            != FindingSeverity.UNRATED
        ):

            finding.metadata[
                "risk_rationale"
            ] = (
                "已有评级，跳过"
            )

            finding.metadata[
                "risk_rule"
            ] = (
                "already_rated"
            )

            return finding

        # ================================================
        # 2. REJECTED
        # ================================================

        if (
            finding.status
            == FindingStatus.REJECTED
        ):

            finding.severity = (
                FindingSeverity.INFO
            )

            finding.metadata[
                "risk_rationale"
            ] = (
                "验证结果否定漏洞存在，"
                "仅作为审计记录保留"
            )

            finding.metadata[
                "risk_rule"
            ] = (
                "rejected"
            )

            return finding

        # ================================================
        # 3. 基础严重程度
        # ================================================

        unknown_type = (
            finding.vulnerability_type
            not in BASE_SEVERITY
        )

        base = BASE_SEVERITY.get(
            finding.vulnerability_type,
            FindingSeverity.LOW,
        )

        # ================================================
        # 4. SUSPECTED 降级
        # ================================================

        if (
            finding.status
            == FindingStatus.SUSPECTED
        ):

            finding.severity = (
                _downgrade(base)
            )

            finding.metadata[
                "risk_rationale"
            ] = (
                f"基础 {base.value}，"
                "证据不足以确认，降一级"
            )

            finding.metadata[
                "risk_rule"
            ] = (
                "suspected_downgrade"
            )

            return finding

        # ================================================
        # 5. CONFIRMED + 低置信度降级
        # ================================================

        if (
            finding.confidence
            < CONFIDENCE_CONFIRMED_THRESHOLD
        ):

            finding.severity = (
                _downgrade(base)
            )

            finding.metadata[
                "risk_rationale"
            ] = (
                f"基础 {base.value}，"
                "已确认但置信度不足，降一级"
            )

            finding.metadata[
                "risk_rule"
            ] = (
                "confirmed_low_confidence"
            )

            return finding

        # ================================================
        # 6. CONFIRMED 正常评级
        # ================================================

        finding.severity = base

        if unknown_type:

            finding.metadata[
                "risk_rationale"
            ] = (
                "未知漏洞类型，"
                "按默认 LOW 评级"
            )

            finding.metadata[
                "risk_rule"
            ] = (
                "unknown_type_default"
            )

        else:

            finding.metadata[
                "risk_rationale"
            ] = (
                f"基于漏洞类型规则评级 {base.value}"
            )

            finding.metadata[
                "risk_rule"
            ] = (
                "base_severity"
            )

        return finding

    def rate_all(
        self,
        findings: list[
            Finding
        ],
    ) -> list[Finding]:
        """
        批量评级。

        列表内每个 Finding 都会被
        原地修改。
        """

        for finding in findings:

            self.rate(
                finding
            )

        return findings
