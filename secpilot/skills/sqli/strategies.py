from typing import Protocol

from secpilot.skills.sqli.context import (
    ParameterContext,
)
from secpilot.skills.sqli.models import (
    BooleanMutationSet,
)


class BooleanMutationStrategy(
    Protocol
):
    """
    Boolean SQLi Mutation Strategy 接口。

    每一种 SQL 参数上下文，
    都可以实现自己的变异策略。

    例如：

        NumericBooleanStrategy

        SingleQuoteBooleanStrategy

        DoubleQuoteBooleanStrategy
    """

    name: str

    def supports(
        self,
        context: ParameterContext,
    ) -> bool:
        """
        当前 Strategy 是否支持指定 Context。
        """

        ...

    def build(
        self,
        original_value: str,
        context: ParameterContext,
    ) -> BooleanMutationSet:
        """
        根据原始值生成：

        baseline
        true
        false

        对应的参数变异。
        """

        ...


class NumericBooleanStrategy:
    """
    数字型 Boolean SQL Injection Strategy。

    Example
    -------

    Original:

        1

    TRUE:

        1 AND 1=1

    FALSE:

        1 AND 1=2
    """

    name = "numeric_boolean"

    def supports(
        self,
        context: ParameterContext,
    ) -> bool:
        return (
            context
            == ParameterContext.NUMERIC
        )

    def build(
        self,
        original_value: str,
        context: ParameterContext,
    ) -> BooleanMutationSet:
        """
        为数字型参数生成 Boolean Mutation。
        """

        if not self.supports(
            context
        ):
            raise ValueError(
                "NumericBooleanStrategy "
                "只支持 NUMERIC 上下文"
            )

        true_value = (
            f"{original_value} AND 1=1"
        )

        false_value = (
            f"{original_value} AND 1=2"
        )

        return BooleanMutationSet(
            original_value=original_value,

            true_value=true_value,

            false_value=false_value,

            strategy_name=self.name,

            context=context,
        )