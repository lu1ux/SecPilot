from datetime import datetime
from enum import StrEnum
from urllib.parse import urlparse
from uuid import uuid4

from pydantic import BaseModel, Field

from secpilot.agent.models import (
    SecurityPlan,
)
from secpilot.core.finding import (
    Finding,
    FindingSeverity,
    FindingStatus,
)
from secpilot.core.models import (
    HttpRequest,
)


class ScanRequestStatus(StrEnum):
    """
    扫描中单个请求的最终状态。

    EXECUTED:
        LLM 选择了 Skill 并完成验证。

    NO_ACTION:
        LLM 判断不需要执行任何 Skill。

    ERROR:
        请求处理过程中发生异常，
        扫描继续，不中断整体批次。
    """

    EXECUTED = "EXECUTED"

    NO_ACTION = "NO_ACTION"

    ERROR = "ERROR"


class ScanRequestResult(BaseModel):
    """
    单个请求的扫描结果。

    plan:
        LLM 生成的 SecurityPlan。

        保留在报告中作为审计追踪，
        可以回看 LLM 当时为什么
        选择这个 Skill 和参数。

    finding:
        已经经过 RiskEngine 评级。

    error_message:
        status == ERROR 时的中文错误摘要。
    """

    request_id: str = Field(
        default_factory=lambda: uuid4().hex
    )

    method: str

    url: str

    started_at: datetime

    finished_at: datetime

    status: ScanRequestStatus

    plan: SecurityPlan | None = None

    finding: Finding | None = None

    error_message: str | None = None


class ReportStats(BaseModel):
    """
    扫描结果统计。

    by_status / by_severity
    覆盖全部枚举取值（含 0），
    保证报告渲染结果稳定。
    """

    total_requests: int

    executed: int

    no_action: int

    errors: int

    total_findings: int

    by_status: dict[str, int] = Field(
        default_factory=dict
    )

    by_severity: dict[str, int] = Field(
        default_factory=dict
    )


class ScanReport(BaseModel):
    """
    一次批量扫描的完整报告。

    findings:
        已评级 Finding 列表，
        包含 REJECTED（审计保留）。

    request_results:
        与请求一一对应，
        顺序与扫描顺序一致。
    """

    id: str = Field(
        default_factory=lambda: uuid4().hex
    )

    target: str

    started_at: datetime

    finished_at: datetime

    request_results: list[
        ScanRequestResult
    ] = Field(default_factory=list)

    findings: list[
        Finding
    ] = Field(default_factory=list)

    stats: ReportStats


def derive_target(
    requests: list[
        HttpRequest
    ],
) -> str:
    """
    从请求列表推导报告目标描述。

    单一 host:
        scheme://netloc

    多个 host:
        首个 host 等 N 个目标
    """

    if not requests:

        return "(无目标)"

    hosts: list[str] = []

    for request in requests:

        parsed = urlparse(
            request.url
        )

        netloc = (
            parsed.netloc.lower()
        )

        if netloc not in hosts:

            hosts.append(netloc)

    if len(hosts) == 1:

        parsed = urlparse(
            requests[0].url
        )

        return (
            f"{parsed.scheme}://"
            f"{hosts[0]}"
        )

    return (
        f"{hosts[0]} 等 "
        f"{len(hosts)} 个目标"
    )


def compute_stats(
    *,
    request_results: list[
        ScanRequestResult
    ],
    findings: list[Finding],
) -> ReportStats:
    """
    根据请求结果和 Finding 列表
    计算报告统计。

    by_status / by_severity
    先用全部枚举值初始化为 0，
    再累加实际计数。
    """

    by_status: dict[str, int] = {
        status.value: 0
        for status in FindingStatus
    }

    by_severity: dict[str, int] = {
        severity.value: 0
        for severity in FindingSeverity
    }

    for finding in findings:

        by_status[
            finding.status.value
        ] += 1

        by_severity[
            finding.severity.value
        ] += 1

    executed = sum(
        1
        for result in request_results
        if result.status
        == ScanRequestStatus.EXECUTED
    )

    no_action = sum(
        1
        for result in request_results
        if result.status
        == ScanRequestStatus.NO_ACTION
    )

    errors = sum(
        1
        for result in request_results
        if result.status
        == ScanRequestStatus.ERROR
    )

    return ReportStats(
        total_requests=(
            len(request_results)
        ),

        executed=executed,

        no_action=no_action,

        errors=errors,

        total_findings=(
            len(findings)
        ),

        by_status=by_status,

        by_severity=by_severity,
    )
