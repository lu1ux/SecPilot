from fakes import (
    ScriptedProvider,
    build_finding,
    build_request,
)
from secpilot.agent.analysis import (
    AnalysisAgent,
)
from secpilot.agent.models import (
    AgentAction,
    SecurityPlan,
)
from secpilot.agent.runner import (
    AgentRunner,
)
from secpilot.core.finding import (
    FindingSeverity,
    Finding,
)
from secpilot.core.finding_mapper import (
    FindingMapperRegistry,
)
from secpilot.core.models import (
    HttpRequest,
)
from secpilot.report.models import (
    ScanRequestStatus,
)
from secpilot.risk.engine import (
    RiskEngine,
)
from secpilot.scan.runner import (
    ScanRunner,
)
from secpilot.skills.registry import (
    SkillRegistry,
)


class FlakyFakeSkill:
    """
    parameter == "fail" 时抛异常的假 Skill。

    其余情况返回一个占位结果，
    mapper 不读取其内容。
    """

    async def verify(
        self,
        *,
        request,
        parameter,
    ):
        if parameter == "fail":

            raise RuntimeError(
                "skill exploded"
            )

        return object()


def fake_mapper(
    request,
    result,
) -> Finding:
    """
    忽略 Skill 结果，
    直接返回标准测试 Finding。
    """

    return build_finding()


def build_scan_registry(
) -> SkillRegistry:
    """
    注册带 verify() 接口的
    FlakyFakeSkill。
    """

    registry = SkillRegistry()

    registry.register(
        "boolean_sqli",
        FlakyFakeSkill(),
    )

    return registry


def build_runner(
    *,
    plans,
) -> ScanRunner:
    """
    组装一套完整的批量扫描环境。

    Skill / Mapper 都指向测试 fakes。
    """

    agent = AnalysisAgent(
        provider=ScriptedProvider(
            plans
        ),

        registry=(
            build_scan_registry()
        ),
    )

    agent_runner = AgentRunner(
        agent=agent,

        finding_mappers=(
            build_mapper_registry()
        ),
    )

    return ScanRunner(
        agent_runner=agent_runner,

        risk_engine=RiskEngine(),
    )


def build_mapper_registry(
) -> FindingMapperRegistry:

    registry = (
        FindingMapperRegistry()
    )

    registry.register(
        "boolean_sqli",
        fake_mapper,
    )

    return registry


def build_use_skill_plan(
    parameter: str = "id",
) -> SecurityPlan:

    return SecurityPlan(
        action=(
            AgentAction.USE_SKILL
        ),

        recommended_skill=(
            "boolean_sqli"
        ),

        parameter=parameter,

        rationale="Test.",

        confidence=0.8,
    )


def build_no_action_plan(
) -> SecurityPlan:

    return SecurityPlan(
        action=(
            AgentAction.NO_ACTION
        ),

        recommended_skill=None,

        parameter=None,

        rationale="No skill fits.",

        confidence=0.8,
    )


def build_fail_request(
) -> HttpRequest:

    return HttpRequest(
        method="GET",

        url=(
            "http://127.0.0.1/"
            "broken"
        ),

        params={
            "fail": "1"
        },
    )


async def test_scan_executes_skill_and_rates_finding():

    runner = build_runner(
        plans=[
            build_use_skill_plan()
        ],
    )

    report = (
        await runner.run_scan(
            [build_request()]
        )
    )

    assert (
        report.stats.executed
        == 1
    )

    assert (
        report.stats.total_findings
        == 1
    )

    result = (
        report.request_results[0]
    )

    assert (
        result.status
        == ScanRequestStatus.EXECUTED
    )

    # RiskEngine 已评级：
    # boolean_sqli CONFIRMED → HIGH

    assert (
        result.finding
        is not None
    )

    assert (
        result.finding.severity
        == FindingSeverity.HIGH
    )

    assert (
        result.finding
        is report.findings[0]
    )

    # LLM Plan 保留作审计追踪

    assert (
        result.plan
        is not None
    )

    assert (
        result.plan.parameter
        == "id"
    )


async def test_scan_no_action_records_plan():

    runner = build_runner(
        plans=[
            build_no_action_plan()
        ],
    )

    report = (
        await runner.run_scan(
            [build_request()]
        )
    )

    result = (
        report.request_results[0]
    )

    assert (
        result.status
        == ScanRequestStatus.NO_ACTION
    )

    assert (
        result.finding
        is None
    )

    assert (
        result.plan
        is not None
    )

    assert (
        report.stats.no_action
        == 1
    )

    assert (
        report.stats.total_findings
        == 0
    )


async def test_scan_error_does_not_abort():

    runner = build_runner(
        plans=[
            build_use_skill_plan(
                parameter="fail"
            )
        ],
    )

    report = (
        await runner.run_scan(
            [build_fail_request()]
        )
    )

    result = (
        report.request_results[0]
    )

    assert (
        result.status
        == ScanRequestStatus.ERROR
    )

    assert (
        "RuntimeError"
        in result.error_message
    )

    assert (
        report.stats.errors
        == 1
    )

    assert (
        report.stats.total_findings
        == 0
    )


async def test_scan_mixed_batch_preserves_order():

    runner = build_runner(
        plans=[
            build_use_skill_plan(),

            build_no_action_plan(),

            build_use_skill_plan(
                parameter="fail"
            ),
        ],
    )

    requests = [
        build_request(),

        HttpRequest(
            method="GET",

            url=(
                "http://127.0.0.1/"
                "home"
            ),
        ),

        build_fail_request(),
    ]

    report = (
        await runner.run_scan(
            requests
        )
    )

    statuses = [
        result.status
        for result in (
            report.request_results
        )
    ]

    assert statuses == [
        ScanRequestStatus.EXECUTED,

        ScanRequestStatus.NO_ACTION,

        ScanRequestStatus.ERROR,
    ]

    urls = [
        result.url
        for result in (
            report.request_results
        )
    ]

    assert (
        urls[0]
        == requests[0].url
    )

    assert (
        urls[2]
        == requests[2].url
    )

    stats = report.stats

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
        len(report.findings)
        == 1
    )

    assert (
        report.target
        == "http://127.0.0.1"
    )

    assert (
        report.started_at
        <= report.finished_at
    )
