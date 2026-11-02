from enum import StrEnum

from pydantic import BaseModel, Field

from secpilot.evidence.models import (
    ResponseComparison,
)
from secpilot.skills.sqli.context import (
    ParameterContext,
)


class VerificationStatus(StrEnum):
    """
    Security Skill 最终验证状态。
    """

    CONFIRMED = "CONFIRMED"

    SUSPECTED = "SUSPECTED"

    REJECTED = "REJECTED"


class BooleanMutationSet(BaseModel):
    """
    一组 Boolean SQL Injection 参数变异。

    original_value:
        原始参数值。

    true_value:
        Boolean True 测试值。

    false_value:
        Boolean False 测试值。

    strategy_name:
        当前使用的 Mutation Strategy。

    context:
        当前参数上下文。
    """

    original_value: str

    true_value: str

    false_value: str

    strategy_name: str

    context: ParameterContext


class BooleanSQLiRound(BaseModel):
    """
    单轮 Boolean SQL Injection 验证结果。
    """

    round_number: int = Field(
        ge=1
    )

    mutations: BooleanMutationSet

    true_comparison: ResponseComparison

    false_comparison: ResponseComparison

    passed: bool


class BooleanSQLiVerificationResult(
    BaseModel
):
    """
    Boolean SQL Injection Skill
    最终验证结果。
    """

    vulnerability_type: str = (
        "boolean_based_sql_injection"
    )

    parameter: str

    context: ParameterContext

    strategy_name: str

    status: VerificationStatus

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    passed_rounds: int = Field(
        ge=0
    )

    total_rounds: int = Field(
        ge=1
    )

    rounds: list[
        BooleanSQLiRound
    ]