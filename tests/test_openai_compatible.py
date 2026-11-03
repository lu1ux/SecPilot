import json

import httpx
import pytest
from pydantic import (
    BaseModel,
    SecretStr,
)

from secpilot.llm.capabilities import (
    LLMCapabilities,
)
from secpilot.llm.config import (
    ResolvedLLMProfile,
)
from secpilot.llm.providers.openai_compatible import (
    OpenAICompatibleProvider,
)


class TestOutput(BaseModel):

    action: str

    value: int


def build_profile(
    *,
    structured_output: bool = False,
    json_mode: bool = False,
) -> ResolvedLLMProfile:

    return ResolvedLLMProfile(
        name="test",

        adapter="openai_compatible",

        base_url=(
            "https://example.test/v1"
        ),

        model="test-model",

        api_key=SecretStr(
            "test-key"
        ),

        timeout_seconds=10,

        max_output_tokens=500,

        capabilities=(
            LLMCapabilities(
                structured_output=(
                    structured_output
                ),

                json_mode=(
                    json_mode
                ),
            )
        ),

        extra_headers={},

        request_options={},
    )


@pytest.mark.asyncio
async def test_plain_text_generation():

    async def handler(
        request: httpx.Request,
    ) -> httpx.Response:

        return httpx.Response(
            200,

            json={
                "choices": [
                    {
                        "message": {
                            "role":
                                "assistant",

                            "content":
                                "Hello SecPilot",
                        }
                    }
                ]
            },
        )

    provider = (
        OpenAICompatibleProvider(
            profile=build_profile(),

            transport=(
                httpx.MockTransport(
                    handler
                )
            ),
        )
    )

    result = await provider.generate_text(
        system_prompt="system",
        user_prompt="user",
    )

    assert (
        result
        == "Hello SecPilot"
    )


@pytest.mark.asyncio
async def test_prompt_fallback_structured_output():

    async def handler(
        request: httpx.Request,
    ) -> httpx.Response:

        body = json.loads(
            request.content
        )

        assert (
            "response_format"
            not in body
        )

        return httpx.Response(
            200,

            json={
                "choices": [
                    {
                        "message": {
                            "role":
                                "assistant",

                            "content":
                                (
                                    '{"action":"OK",'
                                    '"value":123}'
                                ),
                        }
                    }
                ]
            },
        )

    provider = (
        OpenAICompatibleProvider(
            profile=build_profile(),

            transport=(
                httpx.MockTransport(
                    handler
                )
            ),
        )
    )

    result = (
        await provider
        .generate_structured(
            system_prompt="system",

            user_prompt="user",

            output_model=(
                TestOutput
            ),
        )
    )

    assert result.action == "OK"

    assert result.value == 123


@pytest.mark.asyncio
async def test_json_schema_mode():

    async def handler(
        request: httpx.Request,
    ) -> httpx.Response:

        body = json.loads(
            request.content
        )

        assert (
            body[
                "response_format"
            ][
                "type"
            ]
            == "json_schema"
        )

        return httpx.Response(
            200,

            json={
                "choices": [
                    {
                        "message": {
                            "content":
                                (
                                    '{"action":"OK",'
                                    '"value":1}'
                                )
                        }
                    }
                ]
            },
        )

    provider = (
        OpenAICompatibleProvider(
            profile=build_profile(
                structured_output=True
            ),

            transport=(
                httpx.MockTransport(
                    handler
                )
            ),
        )
    )

    result = (
        await provider
        .generate_structured(
            system_prompt="system",

            user_prompt="user",

            output_model=(
                TestOutput
            ),
        )
    )

    assert result.value == 1


@pytest.mark.asyncio
async def test_json_schema_falls_back_when_unsupported():

    request_count = 0

    async def handler(
        request: httpx.Request,
    ) -> httpx.Response:

        nonlocal request_count

        request_count += 1

        body = json.loads(
            request.content
        )

        if (
            "response_format"
            in body
        ):
            return httpx.Response(
                400,
                json={
                    "error":
                        "unsupported"
                },
            )

        return httpx.Response(
            200,

            json={
                "choices": [
                    {
                        "message": {
                            "content":
                                (
                                    '{"action":"OK",'
                                    '"value":2}'
                                )
                        }
                    }
                ]
            },
        )

    provider = (
        OpenAICompatibleProvider(
            profile=build_profile(
                structured_output=True
            ),

            transport=(
                httpx.MockTransport(
                    handler
                )
            ),
        )
    )

    result = (
        await provider
        .generate_structured(
            system_prompt="system",

            user_prompt="user",

            output_model=(
                TestOutput
            ),
        )
    )

    assert result.value == 2

    assert request_count == 2