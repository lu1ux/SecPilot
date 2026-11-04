"""
SecPilot 共享测试 Fakes。

多个测试文件都需要：

    FakeSkill
    FakeProvider
    build_registry
    build_request
    build_finding

这里统一提供，避免重复定义。
"""

from secpilot.agent.models import (
    SecurityPlan,
)
from secpilot.core.finding import (
    Finding,
    FindingEvidence,
    FindingSeverity,
    FindingStatus,
)
from secpilot.core.models import (
    HttpRequest,
)
from secpilot.llm.capabilities import (
    LLMCapabilities,
)
from secpilot.skills.registry import (
    SkillRegistry,
)


class FakeSkill:
    pass


class FakeProvider:

    name = "fake"

    capabilities = (
        LLMCapabilities()
    )

    def __init__(
        self,
        result: SecurityPlan,
    ):
        self.result = result

    async def generate_text(
        self,
        *,
        system_prompt,
        user_prompt,
    ):
        return ""

    async def generate_structured(
        self,
        *,
        system_prompt,
        user_prompt,
        output_model,
    ):
        return self.result


class ScriptedProvider:
    """
    按调用顺序返回不同 Plan 的假 Provider。

    用于批量扫描等
    一次 Run 需要多次 LLM 决策的场景。
    """

    name = "scripted"

    capabilities = (
        LLMCapabilities()
    )

    def __init__(
        self,
        plans: list[
            SecurityPlan
        ],
    ):
        self.plans = list(
            plans
        )

        self.calls: list[
            str
        ] = []

    async def generate_text(
        self,
        *,
        system_prompt,
        user_prompt,
    ):
        return ""

    async def generate_structured(
        self,
        *,
        system_prompt,
        user_prompt,
        output_model,
    ):
        self.calls.append(
            user_prompt
        )

        return self.plans.pop(
            0
        )


def build_registry(
) -> SkillRegistry:

    registry = SkillRegistry()

    registry.register(
        "boolean_sqli",
        FakeSkill(),
    )

    return registry


def build_request(
) -> HttpRequest:

    return HttpRequest(
        method="GET",

        url=(
            "http://127.0.0.1/"
            "product"
        ),

        params={
            "id": "1"
        },
    )


def build_finding(
    *,
    status: FindingStatus = (
        FindingStatus.CONFIRMED
    ),
    severity: FindingSeverity = (
        FindingSeverity.UNRATED
    ),
    confidence: float = 0.9,
    vulnerability_type: str = (
        "boolean_based_sql_injection"
    ),
) -> Finding:
    """
    构造一个标准测试 Finding。

    默认行为完全等同
    boolean_sqli mapper 的产出。
    """

    return Finding(
        vulnerability_type=(
            vulnerability_type
        ),

        title=(
            "Boolean-based SQL Injection"
        ),

        target=(
            "http://127.0.0.1/"
            "product"
        ),

        http_method="GET",

        parameter="id",

        source_skill="boolean_sqli",

        status=status,

        severity=severity,

        confidence=confidence,

        evidence=[
            FindingEvidence(
                kind=(
                    "boolean_response_comparison"
                ),

                summary=(
                    "Round 1: PASS"
                ),

                data={
                    "round": 1,

                    "passed": True,

                    "context": "NUMERIC",

                    "true_similarity": 0.95,

                    "false_similarity": 0.40,
                },
            )
        ],

        metadata={
            "context": "NUMERIC",

            "strategy": "numeric_boolean",

            "passed_rounds": 3,

            "total_rounds": 3,
        },
    )
