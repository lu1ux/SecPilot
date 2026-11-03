import asyncio
from pathlib import Path

from secpilot.agent.analysis import (
    AnalysisAgent,
)
from secpilot.core.models import (
    HttpRequest,
)
from secpilot.llm import (
    LLMConfiguration,
    create_default_provider_registry,
)
from secpilot.policy.engine import (
    PolicyEngine,
)
from secpilot.skills.registry import (
    SkillRegistry,
)
from secpilot.skills.sqli.boolean import (
    BooleanSQLiSkill,
)
from secpilot.tools.http_executor import (
    HttpExecutor,
)


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


async def main():

    # ========================================================
    # LLM Configuration
    # ========================================================

    config = (
        LLMConfiguration.load(
            config_path=(
                PROJECT_ROOT
                / "config"
                / "llm.example.yaml"
            ),

            env_file=(
                PROJECT_ROOT
                / ".env"
            ),
        )
    )

    profile = config.resolve()

    provider_registry = (
        create_default_provider_registry()
    )

    provider = (
        provider_registry.create(
            profile
        )
    )

    # ========================================================
    # SecPilot Runtime
    # ========================================================

    policy = PolicyEngine(
        PROJECT_ROOT
        / "config"
        / "policy.example.yaml"
    )

    executor = HttpExecutor(
        policy
    )

    boolean_sqli = (
        BooleanSQLiSkill(
            executor=executor
        )
    )

    skill_registry = (
        SkillRegistry()
    )

    skill_registry.register(
        "boolean_sqli",
        boolean_sqli,
    )

    # ========================================================
    # Analysis Agent
    # ========================================================

    agent = AnalysisAgent(
        provider=provider,

        registry=(
            skill_registry
        ),
    )

    # ========================================================
    # Example Target Metadata
    #
    # 这里只让 AI 规划，
    # 暂时不会真正发送 SQLi 请求。
    # ========================================================

    request = HttpRequest(
        method="GET",

        url=(
            "http://127.0.0.1/"
            "product"
        ),

        params={
            "id": "1"
        },
    )

    plan = await agent.plan(
        request
    )

    print(
        "\n=== LLM Provider ==="
    )

    print(
        profile.name
    )

    print(
        profile.model
    )

    print(
        "\n=== Security Plan ==="
    )

    print(
        plan.model_dump_json(
            indent=2
        )
    )

    skill = agent.resolve_skill(
        plan
    )

    if skill is None:

        print(
            "\nNo Skill selected."
        )

        return

    print(
        "\n=== Resolved Skill ==="
    )

    print(
        type(skill).__name__
    )


if __name__ == "__main__":

    asyncio.run(
        main()
    )