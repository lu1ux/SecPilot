from enum import StrEnum


class HttpToolMethod(StrEnum):
    """
    SecPilot MCP HTTP Tool
    当前允许使用的 HTTP Method。

    使用 Enum 的好处是：

    MCP 会根据类型注解自动生成
    JSON Schema enum。

    LLM 只能从这些 Method 中选择，
    而不是随意传入字符串。
    """

    GET = "GET"

    POST = "POST"

    PUT = "PUT"

    PATCH = "PATCH"

    DELETE = "DELETE"

    HEAD = "HEAD"

    OPTIONS = "OPTIONS"