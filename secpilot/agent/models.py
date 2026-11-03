from enum import StrEnum

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
)


class AgentAction(StrEnum):
    """
    当前 AnalysisAgent
    允许作出的决策。
    """

    USE_SKILL = "USE_SKILL"

    NO_ACTION = "NO_ACTION"


class SecurityPlan(BaseModel):
    """
    LLM 输出的安全测试计划。

    注意：

    SecurityPlan 不是漏洞结论。

    LLM 只能建议：

        测哪个参数
        用哪个 Skill

    真正漏洞判断仍由：
        Skill
        Evidence
        Finding
    完成。
    """

    model_config = ConfigDict(
        extra="forbid"
    )

    action: AgentAction

    recommended_skill: (
        str
        | None
    )

    parameter: (
        str
        | None
    )

    rationale: str = Field(
        min_length=1,
        max_length=500,
    )

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )