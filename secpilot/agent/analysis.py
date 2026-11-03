import json
from typing import Any

from secpilot.agent.models import (
    AgentAction,
    SecurityPlan,
)
from secpilot.core.models import (
    HttpRequest,
)
from secpilot.llm.base import (
    LLMProvider,
)
from secpilot.skills.registry import (
    SkillRegistry,
)


class AgentPlanError(
    ValueError
):
    """
    LLM 给出的 Plan
    没通过 SecPilot 本地验证。
    """

    pass


class AnalysisAgent:
    """
    SecPilot Analysis Agent。

    职责：

        分析 HTTP Request
        查看已有 Skills
        推荐验证方向

    不负责：

        确认漏洞
        直接构造攻击 Payload
        直接发送网络请求
        绕过 Policy
    """

    SYSTEM_PROMPT = """
You are SecPilot's security planning agent.

You operate only inside authorized security testing workflows.

Your responsibility is planning, not exploitation.

You must never claim a vulnerability is confirmed.

Only Security Skills and the Evidence Engine can confirm
a security finding.

You may choose a skill only from the supplied
available_skills list.

Never invent skill names.

Do not produce exploitation payloads.

Do not produce shell commands.

If there is no appropriate registered skill, return NO_ACTION.

If you choose a parameter, it must exist in the supplied
request parameters.

Keep rationale concise.
""".strip()

    def __init__(
        self,
        provider: LLMProvider,
        registry: SkillRegistry,
    ):
        self.provider = provider

        self.registry = registry

    def _build_input(
        self,
        request: HttpRequest,
    ) -> str:
        """
        给 LLM 最少必要信息。

        当前不发送：

            Cookie
            Authorization
            完整 Response Body

        这是为了：

            减少敏感信息
            降低 Prompt Injection 面
        """

        data = {
            "request": {
                "method":
                    request.method,

                "url":
                    request.url,

                "parameters":
                    request.params,
            },

            "available_skills":
                self.registry.names(),

            "objective":
                (
                    "Choose whether one "
                    "registered security skill "
                    "should be used to verify "
                    "one request parameter."
                ),
        }

        return json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
        )

    def _validate_plan(
        self,
        plan: SecurityPlan,
        request: HttpRequest,
    ) -> None:
        """
        永远对 LLM 输出进行
        第二次本地验证。
        """

        if (
            plan.action
            == AgentAction.NO_ACTION
        ):
            return

        if (
            plan.recommended_skill
            is None
        ):
            raise AgentPlanError(
                "USE_SKILL 缺少 "
                "recommended_skill"
            )

        if (
            plan.parameter
            is None
        ):
            raise AgentPlanError(
                "USE_SKILL 缺少 parameter"
            )

        if not self.registry.has(
            plan.recommended_skill
        ):

            raise AgentPlanError(
                "LLM 推荐了未注册 Skill: "
                f"{plan.recommended_skill}"
            )

        if (
            plan.parameter
            not in request.params
        ):

            raise AgentPlanError(
                "LLM 推荐了不存在的参数: "
                f"{plan.parameter}"
            )

    async def plan(
        self,
        request: HttpRequest,
    ) -> SecurityPlan:
        """
        让 LLM 生成 SecurityPlan。
        """

        plan = (
            await self.provider
            .generate_structured(
                system_prompt=(
                    self.SYSTEM_PROMPT
                ),

                user_prompt=(
                    self._build_input(
                        request
                    )
                ),

                output_model=(
                    SecurityPlan
                ),
            )
        )

        self._validate_plan(
            plan=plan,
            request=request,
        )

        return plan

    def resolve_skill(
        self,
        plan: SecurityPlan,
    ) -> Any | None:
        """
        把 LLM Plan 路由到
        SkillRegistry。

        当前只负责解析，
        不执行 Skill。
        """

        if (
            plan.action
            == AgentAction.NO_ACTION
        ):
            return None

        if (
            plan.recommended_skill
            is None
        ):
            raise AgentPlanError(
                "SecurityPlan 缺少 "
                "recommended_skill"
            )

        return self.registry.get(
            plan.recommended_skill
        )