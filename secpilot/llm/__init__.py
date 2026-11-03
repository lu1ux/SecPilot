from secpilot.llm.base import (
    LLMProvider,
)
from secpilot.llm.capabilities import (
    LLMCapabilities,
)
from secpilot.llm.config import (
    LLMConfiguration,
    LLMConfigurationError,
    LLMProfile,
    ResolvedLLMProfile,
)
from secpilot.llm.providers.openai_compatible import (
    OpenAICompatibleProvider,
)
from secpilot.llm.registry import (
    ProviderRegistry,
)


def create_default_provider_registry(
) -> ProviderRegistry:
    """
    创建 SecPilot 默认 Provider Registry。
    """

    registry = ProviderRegistry()

    registry.register(
        "openai_compatible",
        OpenAICompatibleProvider,
    )

    return registry


__all__ = [
    "LLMProvider",
    "LLMCapabilities",
    "LLMConfiguration",
    "LLMConfigurationError",
    "LLMProfile",
    "ResolvedLLMProfile",
    "OpenAICompatibleProvider",
    "ProviderRegistry",
    "create_default_provider_registry",
]