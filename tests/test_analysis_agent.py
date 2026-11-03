import pytest

from secpilot.agent.analysis import (
    AgentPlanError,
    AnalysisAgent,
)
from secpilot.agent.models import (
    AgentAction,
    SecurityPlan,
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


@pytest.mark.asyncio
async def test_agent_selects_skill():

    plan = SecurityPlan(
        action=(
            AgentAction.USE_SKILL
        ),

        recommended_skill=(
            "boolean_sqli"
        ),

        parameter="id",

        rationale=(
            "Numeric parameter may "
            "be database-backed."
        ),

        confidence=0.8,
    )

    agent = AnalysisAgent(
        provider=FakeProvider(
            plan
        ),

        registry=build_registry(),
    )

    result = await agent.plan(
        build_request()
    )

    assert (
        result.recommended_skill
        == "boolean_sqli"
    )


@pytest.mark.asyncio
async def test_agent_rejects_fake_skill():

    plan = SecurityPlan(
        action=(
            AgentAction.USE_SKILL
        ),

        recommended_skill=(
            "evil_shell"
        ),

        parameter="id",

        rationale="Test.",

        confidence=0.9,
    )

    agent = AnalysisAgent(
        provider=FakeProvider(
            plan
        ),

        registry=build_registry(),
    )

    with pytest.raises(
        AgentPlanError,
        match="未注册 Skill",
    ):
        await agent.plan(
            build_request()
        )


@pytest.mark.asyncio
async def test_agent_rejects_unknown_parameter():

    plan = SecurityPlan(
        action=(
            AgentAction.USE_SKILL
        ),

        recommended_skill=(
            "boolean_sqli"
        ),

        parameter="user_id",

        rationale="Test.",

        confidence=0.8,
    )

    agent = AnalysisAgent(
        provider=FakeProvider(
            plan
        ),

        registry=build_registry(),
    )

    with pytest.raises(
        AgentPlanError,
        match="不存在的参数",
    ):
        await agent.plan(
            build_request()
        )


@pytest.mark.asyncio
async def test_agent_no_action():

    plan = SecurityPlan(
        action=(
            AgentAction.NO_ACTION
        ),

        recommended_skill=None,

        parameter=None,

        rationale=(
            "No appropriate skill."
        ),

        confidence=0.8,
    )

    agent = AnalysisAgent(
        provider=FakeProvider(
            plan
        ),

        registry=build_registry(),
    )

    result = await agent.plan(
        build_request()
    )

    assert (
        result.action
        == AgentAction.NO_ACTION
    )

    assert (
        agent.resolve_skill(
            result
        )
        is None
    )