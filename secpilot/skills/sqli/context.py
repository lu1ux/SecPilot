from enum import StrEnum


class ParameterContext(StrEnum):
    """
    SQL 参数上下文类型。

    注意：
    STRING_SINGLE_QUOTE 和 STRING_DOUBLE_QUOTE
    表示的是服务端 SQL 语句中的上下文，
    不能仅根据客户端参数值直接判断。

    当前版本只自动识别 NUMERIC。
    """

    NUMERIC = "NUMERIC"

    STRING_SINGLE_QUOTE = "STRING_SINGLE_QUOTE"

    STRING_DOUBLE_QUOTE = "STRING_DOUBLE_QUOTE"

    UNKNOWN = "UNKNOWN"


class ParameterContextDetector:
    """
    SQL 参数上下文初步识别器。

    当前版本仅通过参数值识别明确的整数数字型参数。

    字符串到底位于：

        'xxx'

    还是：

        "xxx"

    必须通过后续主动探测和 Evidence 判断，
    不能仅根据参数本身猜测。
    """

    @staticmethod
    def detect(
        value: str,
    ) -> ParameterContext:
        """
        识别参数的初步上下文。

        Examples
        --------
        "1"
            NUMERIC

        "-1"
            NUMERIC

        "+10"
            NUMERIC

        "admin"
            UNKNOWN
        """

        normalized = value.strip()

        if not normalized:
            return ParameterContext.UNKNOWN

        if normalized[0] in {
            "+",
            "-",
        }:
            unsigned_value = normalized[1:]
        else:
            unsigned_value = normalized

        if (
            unsigned_value
            and unsigned_value.isdigit()
        ):
            return ParameterContext.NUMERIC

        return ParameterContext.UNKNOWN