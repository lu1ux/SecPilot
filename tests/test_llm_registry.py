import pytest
from pydantic import SecretStr

from secpilot.llm.capabilities import (
    LLMCapabilities,
)
from secpilot.llm.config import (
    ResolvedLLMProfile,
)
from secpilot.llm.registry import (
    DuplicateProviderError,
    ProviderNotFoundError,
    ProviderRegistry,
)


class FakeProvider:

    def __init__(
        self,
        profile,
        **kwargs,
    ):
        self.profile = profile


def build_profile(
) -> ResolvedLLMProfile:

    return ResolvedLLMProfile(
        name="test",

        adapter="fake",

        base_url=(
            "https://example.test"
        ),

        model="test",

        api_key=SecretStr(
            "secret"
        ),

        timeout_seconds=10,

        max_output_tokens=1000,

        capabilities=(
            LLMCapabilities()
        ),

        extra_headers={},

        request_options={},
    )


def test_provider_registry_create():

    registry = ProviderRegistry()

    registry.register(
        "fake",
        FakeProvider,
    )

    provider = registry.create(
        build_profile()
    )

    assert isinstance(
        provider,
        FakeProvider,
    )


def test_duplicate_provider_rejected():

    registry = ProviderRegistry()

    registry.register(
        "fake",
        FakeProvider,
    )

    with pytest.raises(
        DuplicateProviderError,
    ):
        registry.register(
            "fake",
            FakeProvider,
        )


def test_missing_provider_rejected():

    registry = ProviderRegistry()

    with pytest.raises(
        ProviderNotFoundError,
    ):
        registry.create(
            build_profile()
        )