from typing import (
    Protocol,
    TypeVar,
)

from pydantic import BaseModel

from secpilot.llm.capabilities import (
    LLMCapabilities,
)


StructuredModel = TypeVar(
    "StructuredModel",
    bound=BaseModel,
)


class LLMProvider(Protocol):
    """
    SecPilot 统一 LLM Provider 接口。

    Agent 永远只依赖这个接口。

    Agent 不需要知道底层是：

        GLM
        GPT
        DeepSeek
        Qwen
        Claude
        Gemini
        Ollama
        vLLM
    """

    @property
    def name(
        self,
    ) -> str:
        ...

    @property
    def capabilities(
        self,
    ) -> LLMCapabilities:
        ...

    async def generate_text(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        """
        普通文本生成。
        """

        ...

    async def generate_structured(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        output_model: type[
            StructuredModel
        ],
    ) -> StructuredModel:
        """
        生成结构化 Pydantic 对象。
        """

        ...