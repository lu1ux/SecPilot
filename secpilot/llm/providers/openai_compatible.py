from typing import (
    Any,
    TypeVar,
)

import httpx
from pydantic import BaseModel

from secpilot.llm.capabilities import (
    LLMCapabilities,
)
from secpilot.llm.config import (
    ResolvedLLMProfile,
)
from secpilot.llm.structured import (
    StructuredOutputError,
    build_structured_prompt,
    validate_structured_output,
)


StructuredModel = TypeVar(
    "StructuredModel",
    bound=BaseModel,
)


class LLMProviderError(
    RuntimeError
):
    """
    LLM Provider 通用异常。
    """

    pass


class LLMRequestError(
    LLMProviderError
):
    """
    LLM HTTP API 返回错误。
    """

    def __init__(
        self,
        message: str,
        status_code: (
            int
            | None
        ) = None,
    ):
        super().__init__(
            message
        )

        self.status_code = (
            status_code
        )


class OpenAICompatibleProvider:
    """
    OpenAI-compatible Chat Completions Provider。

    第一版适用于提供：

        POST /chat/completions

    兼容接口的模型服务。

    例如可以用于：

        GLM
        DeepSeek
        Qwen
        vLLM
        部分 Ollama Gateway
        各类兼容网关
    """

    def __init__(
        self,
        profile: ResolvedLLMProfile,
        transport: (
            httpx.AsyncBaseTransport
            | None
        ) = None,
    ):
        self.profile = profile

        self.transport = transport

    @property
    def name(
        self,
    ) -> str:
        return self.profile.name

    @property
    def capabilities(
        self,
    ) -> LLMCapabilities:
        return (
            self.profile
            .capabilities
        )

    def _build_headers(
        self,
    ) -> dict[str, str]:
        """
        构造 HTTP Headers。
        """

        headers = {
            "Authorization":
                "Bearer "
                + self.profile
                .api_key
                .get_secret_value(),

            "Content-Type":
                "application/json",
        }

        headers.update(
            self.profile
            .extra_headers
        )

        return headers

    async def _request(
        self,
        payload: dict[
            str,
            Any,
        ],
    ) -> str:
        """
        调用兼容 Chat Completions API。

        返回 assistant message content。
        """

        client_kwargs: dict[
            str,
            Any,
        ] = {
            "timeout":
                self.profile
                .timeout_seconds,

            "trust_env":
                False,
        }

        if self.transport is not None:
            client_kwargs[
                "transport"
            ] = self.transport

        if (
            self.profile.proxy_url
            is not None
        ):
            client_kwargs[
                "proxy"
            ] = (
                self.profile
                .proxy_url
            )

        try:

            async with httpx.AsyncClient(
                **client_kwargs
            ) as client:

                response = await client.post(
                    (
                        self.profile
                        .base_url
                        + "/chat/completions"
                    ),

                    headers=(
                        self._build_headers()
                    ),

                    json=payload,
                )

                response.raise_for_status()

        except httpx.HTTPStatusError as exc:

            response_text = (
                exc.response
                .text[:500]
            )

            raise LLMRequestError(
                (
                    "LLM API 返回 HTTP 错误: "
                    f"{exc.response.status_code}; "
                    f"{response_text}"
                ),
                status_code=(
                    exc.response
                    .status_code
                ),
            ) from exc

        except httpx.RequestError as exc:

            raise LLMRequestError(
                "LLM API 网络请求失败: "
                f"{exc}"
            ) from exc

        try:

            response_data = (
                response.json()
            )

        except ValueError as exc:

            raise LLMProviderError(
                "LLM API 返回内容 "
                "不是合法 JSON"
            ) from exc

        try:

            message = (
                response_data[
                    "choices"
                ][0][
                    "message"
                ]
            )

            content = message[
                "content"
            ]

        except (
            KeyError,
            IndexError,
            TypeError,
        ) as exc:

            raise LLMProviderError(
                "无法解析 Chat Completions "
                "响应结构"
            ) from exc

        if isinstance(
            content,
            str,
        ):

            if not content.strip():
                raise LLMProviderError(
                    "模型返回空内容"
                )

            return content

        if isinstance(
            content,
            list,
        ):

            text_parts: list[str] = []

            for part in content:

                if not isinstance(
                    part,
                    dict,
                ):
                    continue

                text = part.get(
                    "text"
                )

                if isinstance(
                    text,
                    str,
                ):
                    text_parts.append(
                        text
                    )

            combined = "".join(
                text_parts
            )

            if combined.strip():
                return combined

        raise LLMProviderError(
            "模型响应中没有找到 "
            "可用文本内容"
        )

    def _base_payload(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> dict[str, Any]:
        """
        构造最基础 Chat Completion 请求。
        """

        payload: dict[
            str,
            Any,
        ] = {
            "model":
                self.profile.model,

            "messages": [
                {
                    "role":
                        "system",

                    "content":
                        system_prompt,
                },
                {
                    "role":
                        "user",

                    "content":
                        user_prompt,
                },
            ],

            "stream":
                False,

            "max_tokens":
                self.profile
                .max_output_tokens,
        }

        payload.update(
            self.profile
            .request_options
        )

        return payload

    async def generate_text(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        """
        普通文本生成。
        """

        payload = self._base_payload(
            system_prompt=(
                system_prompt
            ),

            user_prompt=(
                user_prompt
            ),
        )

        return await self._request(
            payload
        )

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
        通用 Structured Output。

        优先级：

        1. Native JSON Schema
        2. JSON Mode
        3. Prompt + JSON Extraction

        即便模型完全没有原生 JSON 能力，
        第三层仍然可以工作。
        """

        schema = (
            output_model
            .model_json_schema()
        )

        structured_instruction = (
            build_structured_prompt(
                output_model
            )
        )

        attempts: list[
            tuple[
                str,
                dict[str, Any],
            ]
        ] = []

        # ====================================================
        # Level 1
        # Native JSON Schema
        # ====================================================

        if (
            self.capabilities
            .structured_output
        ):

            payload = (
                self._base_payload(
                    system_prompt=(
                        system_prompt
                        + structured_instruction
                    ),

                    user_prompt=(
                        user_prompt
                    ),
                )
            )

            payload[
                "response_format"
            ] = {
                "type":
                    "json_schema",

                "json_schema": {
                    "name":
                        output_model
                        .__name__,

                    "strict":
                        True,

                    "schema":
                        schema,
                },
            }

            attempts.append(
                (
                    "json_schema",
                    payload,
                )
            )

        # ====================================================
        # Level 2
        # JSON Mode
        # ====================================================

        if (
            self.capabilities
            .json_mode
        ):

            payload = (
                self._base_payload(
                    system_prompt=(
                        system_prompt
                        + structured_instruction
                    ),

                    user_prompt=(
                        user_prompt
                    ),
                )
            )

            payload[
                "response_format"
            ] = {
                "type":
                    "json_object"
            }

            attempts.append(
                (
                    "json_mode",
                    payload,
                )
            )

        # ====================================================
        # Level 3
        # Universal Prompt Fallback
        # ====================================================

        payload = (
            self._base_payload(
                system_prompt=(
                    system_prompt
                    + structured_instruction
                ),

                user_prompt=(
                    user_prompt
                ),
            )
        )

        attempts.append(
            (
                "prompt_json",
                payload,
            )
        )

        last_error: (
            Exception
            | None
        ) = None

        for (
            strategy_name,
            attempt_payload,
        ) in attempts:

            try:

                text = await self._request(
                    attempt_payload
                )

                return (
                    validate_structured_output(
                        text=text,
                        output_model=(
                            output_model
                        ),
                    )
                )

            except LLMRequestError as exc:

                last_error = exc

                # 如果只是当前 Provider
                # 不支持 response_format，
                # 允许降级到下一层。
                if (
                    strategy_name
                    != "prompt_json"
                    and exc.status_code
                    in {
                        400,
                        404,
                        422,
                    }
                ):
                    continue

                raise

            except StructuredOutputError as exc:

                last_error = exc

                # 原生 Structured Output
                # 或 JSON Mode 返回异常时，
                # 尝试下一层。
                if (
                    strategy_name
                    != "prompt_json"
                ):
                    continue

                raise LLMProviderError(
                    "所有 Structured Output "
                    "策略均失败"
                ) from exc

        raise LLMProviderError(
            "Structured Output 失败"
        ) from last_error