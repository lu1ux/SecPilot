from typing import (
    Any,
    Callable,
)

from secpilot.llm.base import (
    LLMProvider,
)
from secpilot.llm.config import (
    ResolvedLLMProfile,
)


class ProviderNotFoundError(
    KeyError
):
    """
    未找到指定 Provider Adapter。
    """

    pass


class DuplicateProviderError(
    ValueError
):
    """
    Provider Adapter 重复注册。
    """

    pass


ProviderFactory = Callable[
    ...,
    LLMProvider,
]


class ProviderRegistry:
    """
    SecPilot LLM Provider Registry。

    与 SkillRegistry 类似。

    SkillRegistry:
        管漏洞验证能力

    ProviderRegistry:
        管模型接入能力
    """

    def __init__(
        self,
    ):
        self._providers: dict[
            str,
            ProviderFactory,
        ] = {}

    @staticmethod
    def _normalize(
        name: str,
    ) -> str:

        normalized = (
            name
            .strip()
            .lower()
        )

        if not normalized:
            raise ValueError(
                "Provider 名称不能为空"
            )

        return normalized

    def register(
        self,
        name: str,
        factory: ProviderFactory,
    ) -> None:

        normalized = (
            self._normalize(
                name
            )
        )

        if normalized in self._providers:

            raise DuplicateProviderError(
                "Provider 已注册: "
                f"{normalized}"
            )

        self._providers[
            normalized
        ] = factory

    def create(
        self,
        profile: ResolvedLLMProfile,
        **kwargs: Any,
    ) -> LLMProvider:

        adapter = (
            self._normalize(
                profile.adapter
            )
        )

        if adapter not in self._providers:

            raise ProviderNotFoundError(
                "Provider Adapter 不存在: "
                f"{adapter}"
            )

        factory = self._providers[
            adapter
        ]

        return factory(
            profile=profile,
            **kwargs,
        )

    def names(
        self,
    ) -> list[str]:

        return sorted(
            self._providers.keys()
        )