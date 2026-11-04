import pytest

from fakes import (
    FakeProvider,
    build_registry,
    build_request,
)
from secpilot.agent.analysis import (
    AgentPlanError,
    AnalysisAgent,
)
from secpilot.agent.models import (
    AgentAction,
    SecurityPlan,
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