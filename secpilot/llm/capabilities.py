from pydantic import BaseModel


class LLMCapabilities(BaseModel):
    """
    描述当前模型 / API Provider
    可以原生提供哪些能力。

    SecPilot 会根据能力自动选择
    最可靠的调用方式。
    """

    structured_output: bool = False

    json_mode: bool = False

    tool_calling: bool = False

    streaming: bool = False

    vision: bool = False