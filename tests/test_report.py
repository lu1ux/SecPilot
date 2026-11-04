from datetime import datetime
from datetime import timezone

from fakes import (
    build_finding,
)
from secpilot.core.finding import (
    FindingSeverity,
    FindingStatus,
)
from secpilot.core.models import (
    HttpRequest,
)
from secpilot.report.models import (
    ScanReport,
    ScanRequestResult,
    ScanRequestStatus,
    compute_stats,
    derive_target,
)
from secpilot.report.renderers import (
    render_report_json,
    render_report_markdown,
)


def build_result(
    *,
    status: ScanRequestStatus = (
        ScanRequestStatus.EXECUTED
    ),
    finding=None,
    url: str = (
        "http://127.0.0.1/"
        "product"
    ),
) -> ScanRequestResult:

    moment = datetime(
        2026,
        11,
        4,

        12,
        0,
        0,

        tzinfo=timezone.utc,
    )

    return ScanRequestResult(
        method="GET",

        url=url,

        started_at=moment,

        finished_at=moment,

        status=status,

        finding=finding,
    )


def build_report(
    *,
    findings,
    request_results,
) -> ScanReport:

    moment = datetime(
        2026,
        11,
        4,

        12,
        0,
        0,

        tzinfo=timezone.utc,
    )

    return ScanReport(
        target=(
            "http://127.0.0.1"
        ),

        started_at=moment,

        finished_at=moment,

        request_results=(
            request_results
        ),

        findings=findings,

        stats=compute_stats(
            request_results=(
                request_results
            ),

            findings=findings,
        ),
    )


def test_json_report_roundtrip():

    finding = build_finding()

    report = build_report(
        findings=[finding],

        request_results=[
            build_result(
                finding=finding,
            )
        ],
    )

    json_text = (
        render_report_json(
            report
        )
    )

    restored = (
        ScanReport
        .model_validate_json(
            json_text
        )
    )

    assert (
        restored.id
        == report.id
    )

    assert (
        restored.stats
        .total_requests
        == 1
    )

    assert (
        restored.findings[0]
        .severity
        == FindingSeverity.UNRATED
    )

    assert (
        restored
        .request_results[0]
        .status
        == ScanRequestStatus.EXECUTED
    )


def test_markdown_contains_core_content():

    finding = build_finding()

    report = build_report(
        findings=[finding],

        request_results=[
            build_result(
                finding=finding,
            )
        ],
    )

    markdown = (
        render_report_markdown(
            report
        )
    )

    assert (
        "# SecPilot 扫描报告"
        in markdown
    )

    assert (
        "http://127.0.0.1"
        in markdown
    )

    assert (
        "[UNRATED] "
        "Boolean-based SQL Injection"
        in markdown
    )

    assert (
        "Round 1: PASS"
        in markdown
    )

    assert (
        "请求总数: 1"
        in markdown
    )


def test_rejected_finding_in_excluded_section():

    rejected = build_finding(
        status=(
            FindingStatus.REJECTED
        ),

        severity=(
            FindingSeverity.INFO
        ),

        confidence=0.0,
    )

    report = build_report(
        findings=[rejected],

        request_results=[
            build_result(
                finding=rejected,
            )
        ],
    )

    markdown = (
        render_report_markdown(
            report
        )
    )

    excluded_index = (
        markdown.index(
            "## 已排除（REJECTED）"
        )
    )

    finding_index = (
        markdown.index(
            "[INFO] "
            "Boolean-based SQL Injection"
        )
    )

    assert (
        finding_index
        > excluded_index
    )

    assert (
        "本次扫描没有产生"
        "需要关注的漏洞发现。"
        in markdown
    )


def test_active_finding_before_excluded_section():

    confirmed = build_finding(
        severity=(
            FindingSeverity.HIGH
        ),
    )

    rejected = build_finding(
        status=(
            FindingStatus.REJECTED
        ),

        severity=(
            FindingSeverity.INFO
        ),

        confidence=0.0,
    )

    report = build_report(
        findings=[
            rejected,
            confirmed,
        ],

        request_results=[],
    )

    markdown = (
        render_report_markdown(
            report
        )
    )

    active_index = (
        markdown.index(
            "[HIGH] "
            "Boolean-based SQL Injection"
        )
    )

    excluded_index = (
        markdown.index(
            "## 已排除（REJECTED）"
        )
    )

    assert (
        active_index
        < excluded_index
    )


def test_compute_stats_counts_all_statuses():

    confirmed = build_finding(
        severity=(
            FindingSeverity.HIGH
        ),
    )

    request_results = [
        build_result(
            finding=confirmed,
        ),

        build_result(
            status=(
                ScanRequestStatus
                .NO_ACTION
            ),
        ),

        build_result(
            status=(
                ScanRequestStatus
                .ERROR
            ),
        ),
    ]

    stats = compute_stats(
        request_results=(
            request_results
        ),

        findings=[confirmed],
    )

    assert (
        stats.total_requests
        == 3
    )

    assert (
        stats.executed
        == 1
    )

    assert (
        stats.no_action
        == 1
    )

    assert (
        stats.errors
        == 1
    )

    assert (
        stats.total_findings
        == 1
    )

    assert (
        stats.by_status[
            "CONFIRMED"
        ]
        == 1
    )

    assert (
        stats.by_status[
            "REJECTED"
        ]
        == 0
    )

    assert (
        stats.by_severity[
            "HIGH"
        ]
        == 1
    )


def test_derive_target_single_host():

    requests = [
        HttpRequest(
            method="GET",

            url=(
                "http://127.0.0.1:8000/"
                "product"
            ),

            params={
                "id": "1"
            },
        ),

        HttpRequest(
            method="GET",

            url=(
                "http://127.0.0.1:8000/"
                "login"
            ),
        ),
    ]

    assert (
        derive_target(requests)
        == "http://127.0.0.1:8000"
    )


def test_derive_target_multiple_hosts():

    requests = [
        HttpRequest(
            url=(
                "http://a.example.com/"
            ),
        ),

        HttpRequest(
            url=(
                "http://b.example.com/"
            ),
        ),
    ]

    assert (
        derive_target(requests)
        == (
            "a.example.com 等 "
            "2 个目标"
        )
    )


def test_derive_target_empty():

    assert (
        derive_target([])
        == "(无目标)"
    )
