from enum import StrEnum
from typing import Any

from pydantic import BaseModel

from secpilot.agent.analysis import (
    AnalysisAgent,
)
from secpilot.agent.models import (
    AgentAction,
    SecurityPlan,
)
from secpilot.core.finding import (
    Finding,
)
from secpilot.core.finding_mapper import (
    FindingMapperRegistry,
)
from secpilot.core.models import (
    HttpRequest,
)


class AgentRunStatus(StrEnum):
    """
    Agent Runner 最终状态。
    """

    NO_ACTION = "NO_ACTION"

    EXECUTED = "EXECUTED"


class SkillExecutionError(
    RuntimeError
):
    """
    Skill 无法按照统一执行接口运行时抛出。
    """

    pass


class AgentRunResult(BaseModel):
    """
    一次完整 Agent Run 的结果。

    plan:
        GLM / LLM 生成的 SecurityPlan。

    executed_skill:
        实际执行的 Skill。

    finding:
        Skill + Evidence 最终转换得到的 Finding。
    """

    status: AgentRunStatus

    plan: SecurityPlan

    executed_skill: (
        str
        | None
    ) = None

    finding: (
        Finding
        | None
    ) = None


class AgentRunner:
    """
    SecPilot Agent Execution Engine。

    整体流程：

        HttpRequest
            ↓
        AnalysisAgent
            ↓
        SecurityPlan
            ↓
        SkillRegistry
            ↓
        Security Skill
            ↓
        VerificationResult
            ↓
        FindingMapper
            ↓
        Finding

    重要安全原则：

    LLM 只能选择：

        1. 注册过的 Skill
        2. Request 中真实存在的参数

    LLM 不控制：

        payload
        verification rounds
        HTTP implementation
        Policy
        Finding status
    """

    def __init__(
        self,
        agent: AnalysisAgent,
        finding_mappers: (
            FindingMapperRegistry
        ),
    ):
        self.agent = agent

        self.finding_mappers = (
            finding_mappers
        )

    @staticmethod
    async def _execute_skill(
        *,
        skill: Any,
        request: HttpRequest,
        parameter: str,
    ) -> Any:
        """
        执行统一 Skill 接口：

            async verify(
                request,
                parameter
            )

        当前 BooleanSQLiSkill
        已经符合这个接口。

        后续 XSS / IDOR 等 Skill
        也统一遵守。
        """

        verify = getattr(
            skill,
            "verify",
            None,
        )

        if (
            verify is None
            or not callable(
                verify
            )
        ):
            raise SkillExecutionError(
                "Security Skill "
                "没有实现 verify() 接口"
            )

        result = await verify(
            request=request,
            parameter=parameter,
        )

        return result

    async def run(
        self,
        request: HttpRequest,
    ) -> AgentRunResult:
        """
        执行一次完整 SecPilot
        AI Security Testing Run。
        """

        # ====================================================
        # 1. LLM Planning
        # ====================================================

        plan = await self.agent.plan(
            request
        )

        # ====================================================
        # 2. NO_ACTION
        # ====================================================

        if (
            plan.action
            == AgentAction.NO_ACTION
        ):
            return AgentRunResult(
                status=(
                    AgentRunStatus
                    .NO_ACTION
                ),

                plan=plan,

                executed_skill=None,

                finding=None,
            )

        # ====================================================
        # 3. Local Safety Validation
        #
        # AnalysisAgent 已经检查过一次，
        # Runner 再做执行边界检查。
        # ====================================================

        if (
            plan.recommended_skill
            is None
        ):
            raise SkillExecutionError(
                "SecurityPlan "
                "缺少 recommended_skill"
            )

        if (
            plan.parameter
            is None
        ):
            raise SkillExecutionError(
                "SecurityPlan "
                "缺少 parameter"
            )

        # ====================================================
        # 4. Resolve Skill
        # ====================================================

        skill = (
            self.agent.resolve_skill(
                plan
            )
        )

        if skill is None:
            raise SkillExecutionError(
                "无法解析 Security Skill"
            )

        # ====================================================
        # 5. Execute Skill
        # ====================================================

        verification_result = (
            await self._execute_skill(
                skill=skill,

                request=request,

                parameter=(
                    plan.parameter
                ),
            )
        )

        # ====================================================
        # 6. Resolve Finding Mapper
        # ====================================================

        mapper = (
            self.finding_mappers
            .get(
                plan
                .recommended_skill
            )
        )

        # ====================================================
        # 7. VerificationResult → Finding
        # ====================================================

        finding = mapper(
            request,
            verification_result,
        )

        # ====================================================
        # 8. Result
        # ====================================================

        return AgentRunResult(
            status=(
                AgentRunStatus
                .EXECUTED
            ),

            plan=plan,

            executed_skill=(
                plan.recommended_skill
            ),

            finding=finding,
        )