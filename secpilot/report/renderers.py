import json
from datetime import datetime

from secpilot.core.finding import (
    Finding,
    FindingSeverity,
    FindingStatus,
)
from secpilot.report.models import (
    ScanReport,
    ScanRequestResult,
    ScanRequestStatus,
)


# ============================================================
# Markdown 渲染时的严重程度展示顺序
#
# 数值越小越靠前。
# ============================================================

_SEVERITY_ORDER: dict[
    FindingSeverity,
    int,
] = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3,
    FindingSeverity.INFO: 4,
    FindingSeverity.UNRATED: 5,
}


def render_report_json(
    report: ScanReport,
) -> str:
    """
    渲染机器可读的 JSON 报告。

    datetime 序列化为 ISO 8601，
    StrEnum 序列化为字符串值。
    """

    return (
        report
        .model_dump_json(
            indent=2,
        )
    )


def _sort_findings(
    findings: list[
        Finding
    ],
) -> list[Finding]:
    """
    按严重程度从高到低排序。

    未知严重程度排在最后。
    """

    return sorted(
        findings,

        key=lambda finding: (
            _SEVERITY_ORDER.get(
                finding.severity,
                len(
                    _SEVERITY_ORDER
                ),
            )
        ),
    )


def _format_datetime(
    moment: datetime,
) -> str:
    """
    报告中的时间统一展示为
    ISO 8601。
    """

    return (
        moment.isoformat()
    )


def _render_finding_fields(
    lines: list[str],
    finding: Finding,
) -> None:
    """
    渲染单个 Finding 的基础字段。
    """

    lines.append(
        f"- 漏洞类型: "
        f"`{finding.vulnerability_type}`"
    )

    lines.append(
        f"- 目标: "
        f"{finding.target}"
    )

    lines.append(
        f"- 方法: "
        f"{finding.http_method}"
    )

    if finding.parameter:

        lines.append(
            f"- 参数: "
            f"`{finding.parameter}`"
        )

    lines.append(
        f"- 来源 Skill: "
        f"`{finding.source_skill}`"
    )

    lines.append(
        f"- 置信度: "
        f"{finding.confidence}"
    )

    lines.append(
        f"- Finding ID: "
        f"`{finding.id}`"
    )

    rationale = (
        finding
        .metadata
        .get(
            "risk_rationale"
        )
    )

    if rationale:

        lines.append(
            f"- 评级依据: "
            f"{rationale}"
        )


def _render_evidence(
    lines: list[str],
    finding: Finding,
) -> None:
    """
    渲染 Finding 的证据列表。

    summary 给人阅读，
    data 以 JSON code block 展示。
    """

    if not finding.evidence:

        return

    lines.append("")

    lines.append("#### 证据")

    lines.append("")

    for item in finding.evidence:

        lines.append(
            f"- **{item.summary}** "
            f"(`{item.kind}`)"
        )

        if item.data:

            data_json = json.dumps(
                item.data,

                ensure_ascii=False,

                indent=2,
            )

            lines.append("")

            lines.append(
                "  ```json"
            )

            for data_line in (
                data_json
                .splitlines()
            ):

                lines.append(
                    f"  {data_line}"
                )

            lines.append(
                "  ```"
            )

        lines.append("")


def _render_finding(
    lines: list[str],
    finding: Finding,
    *,
    with_evidence: bool,
) -> None:
    """
    渲染一个完整的 Finding 小节。
    """

    lines.append(
        f"### "
        f"[{finding.severity.value}] "
        f"{finding.title} "
        f"({finding.status.value})"
    )

    lines.append("")

    _render_finding_fields(
        lines,
        finding,
    )

    if with_evidence:

        _render_evidence(
            lines,
            finding,
        )

    lines.append("")


def render_report_markdown(
    report: ScanReport,
) -> str:
    """
    渲染给人阅读的 Markdown 报告。

    结构：

        # SecPilot 扫描报告
        ## 扫描概要
        ## 结果统计
        ## 漏洞发现
        ## 其他请求记录
        ## 已排除（REJECTED）

    REJECTED Finding 不进入正文，
    只出现在"已排除"附段。
    """

    lines: list[str] = []

    lines.append(
        "# SecPilot 扫描报告"
    )

    lines.append("")

    lines.append(
        "> 本报告由 SecPilot 自动生成，"
        "仅覆盖授权测试范围内的目标。"
    )

    lines.append("")

    # ================================================
    # 扫描概要
    # ================================================

    lines.append("## 扫描概要")

    lines.append("")

    lines.append(
        f"- 报告 ID: `{report.id}`"
    )

    lines.append(
        f"- 目标: "
        f"{report.target}"
    )

    lines.append(
        f"- 开始时间: "
        f"{_format_datetime(report.started_at)}"
    )

    lines.append(
        f"- 结束时间: "
        f"{_format_datetime(report.finished_at)}"
    )

    stats = report.stats

    lines.append(
        f"- 请求总数: "
        f"{stats.total_requests}"
        f"（执行 {stats.executed}"
        f" / 无动作 {stats.no_action}"
        f" / 失败 {stats.errors}）"
    )

    lines.append("")

    # ================================================
    # 结果统计
    # ================================================

    lines.append("## 结果统计")

    lines.append("")

    lines.append(
        f"- 漏洞发现总数: "
        f"{stats.total_findings}"
    )

    status_text = " / ".join(
        f"{status} {count}"
        for status, count in (
            stats.by_status.items()
        )
    )

    lines.append(
        f"- 状态分布: "
        f"{status_text}"
    )

    severity_text = " / ".join(
        f"{severity} {count}"
        for severity, count in (
            stats.by_severity.items()
        )
    )

    lines.append(
        f"- 严重程度分布: "
        f"{severity_text}"
    )

    lines.append("")

    # ================================================
    # 漏洞发现 / 已排除
    # ================================================

    sorted_findings = (
        _sort_findings(
            report.findings
        )
    )

    active_findings = [
        finding
        for finding in sorted_findings
        if finding.status
        != FindingStatus.REJECTED
    ]

    rejected_findings = [
        finding
        for finding in sorted_findings
        if finding.status
        == FindingStatus.REJECTED
    ]

    lines.append("## 漏洞发现")

    lines.append("")

    if not active_findings:

        lines.append(
            "本次扫描没有产生需要关注的漏洞发现。"
        )

        lines.append("")

    for finding in active_findings:

        _render_finding(
            lines,
            finding,

            with_evidence=True,
        )

    # ================================================
    # 其他请求记录
    # ================================================

    other_results = [
        result
        for result in (
            report.request_results
        )
        if result.status
        in (
            ScanRequestStatus.NO_ACTION,
            ScanRequestStatus.ERROR,
        )
    ]

    lines.append("## 其他请求记录")

    lines.append("")

    if not other_results:

        lines.append("无。")

        lines.append("")

    for result in other_results:

        detail = (
            _other_result_detail(
                result
            )
        )

        lines.append(
            f"- "
            f"`[{result.status.value}]` "
            f"{result.method} "
            f"{result.url}"
            f" — {detail}"
        )

    lines.append("")

    # ================================================
    # 已排除（REJECTED）
    # ================================================

    lines.append(
        "## 已排除（REJECTED）"
    )

    lines.append("")

    lines.append(
        "以下 Finding 的验证结果"
        "不支持漏洞存在，"
        "仅作为审计记录保留："
    )

    lines.append("")

    if not rejected_findings:

        lines.append("无。")

        lines.append("")

    for finding in rejected_findings:

        _render_finding(
            lines,
            finding,

            with_evidence=False,
        )

    return "\n".join(lines)


def _other_result_detail(
    result: ScanRequestResult,
) -> str:
    """
    生成"其他请求记录"条目的
    补充说明。
    """

    if (
        result.status
        == ScanRequestStatus.NO_ACTION
    ):

        detail = (
            "LLM 未选择任何 Skill"
        )

        if result.plan is not None:

            detail = (
                f"{detail}"
                f"（{result.plan.rationale}）"
            )

        return detail

    return (
        result.error_message
        or "未知错误"
    )
