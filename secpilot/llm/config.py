import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import (
    BaseModel,
    Field,
    SecretStr,
)

from secpilot.llm.capabilities import (
    LLMCapabilities,
)


class LLMConfigurationError(
    ValueError
):
    """
    LLM 配置错误。
    """

    pass


class LLMProfile(BaseModel):
    """
    一个 LLM Profile。

    例如：

        glm
        deepseek
        qwen
        local
    """

    adapter: str

    base_url: str

    model: str

    api_key_env: str

    proxy_url_env: (
        str
        | None
    ) = None

    timeout_seconds: float = Field(
        default=60.0,
        gt=0,
    )

    max_output_tokens: int = Field(
        default=1200,
        ge=100,
        le=100000,
    )

    capabilities: LLMCapabilities = Field(
        default_factory=(
            LLMCapabilities
        )
    )

    extra_headers: dict[
        str,
        str,
    ] = Field(
        default_factory=dict
    )

    request_options: dict[
        str,
        Any,
    ] = Field(
        default_factory=dict
    )


class ResolvedLLMProfile(
    BaseModel
):
    """
    已经解析环境变量之后，
    真正交给 Provider 的配置。

    API Key 使用 SecretStr，
    避免日志意外输出。
    """

    name: str

    adapter: str

    base_url: str

    model: str

    api_key: SecretStr

    proxy_url: (
        str
        | None
    ) = None

    timeout_seconds: float

    max_output_tokens: int

    capabilities: LLMCapabilities

    extra_headers: dict[
        str,
        str,
    ]

    request_options: dict[
        str,
        Any,
    ]


class LLMConfiguration(BaseModel):
    """
    SecPilot 完整 LLM 配置。
    """

    active_profile: str

    profiles: dict[
        str,
        LLMProfile,
    ]

    @classmethod
    def load(
        cls,
        config_path: (
            str
            | Path
        ),
        env_file: (
            str
            | Path
            | None
        ) = None,
    ) -> "LLMConfiguration":
        """
        从 YAML 读取 Profile。

        同时加载 .env。

        环境变量：
            SECPILOT_LLM_PROFILE

        可以覆盖 YAML 中的
        active_profile。
        """

        if env_file is not None:
            load_dotenv(
                dotenv_path=env_file,
                override=False,
            )

        path = Path(
            config_path
        )

        if not path.exists():
            raise FileNotFoundError(
                f"LLM 配置文件不存在: "
                f"{path}"
            )

        with path.open(
            "r",
            encoding="utf-8",
        ) as file:

            raw_config = (
                yaml.safe_load(
                    file
                )
                or {}
            )

        environment_profile = (
            os.getenv(
                "SECPILOT_LLM_PROFILE"
            )
        )

        if environment_profile:
            raw_config[
                "active_profile"
            ] = (
                environment_profile
                .strip()
            )

        config = cls.model_validate(
            raw_config
        )

        if (
            config.active_profile
            not in config.profiles
        ):
            raise (
                LLMConfigurationError(
                    "active_profile 不存在: "
                    f"{config.active_profile}"
                )
            )

        return config

    def resolve(
        self,
        profile_name: (
            str
            | None
        ) = None,
    ) -> ResolvedLLMProfile:
        """
        将 Profile 中的环境变量名
        转换成真实 API Key / Proxy。
        """

        selected_name = (
            profile_name
            or self.active_profile
        )

        if (
            selected_name
            not in self.profiles
        ):
            raise LLMConfigurationError(
                "LLM Profile 不存在: "
                f"{selected_name}"
            )

        profile = self.profiles[
            selected_name
        ]

        api_key = os.getenv(
            profile.api_key_env
        )

        if not api_key:
            raise LLMConfigurationError(
                "缺少 API Key 环境变量: "
                f"{profile.api_key_env}"
            )

        proxy_url = None

        if profile.proxy_url_env:

            proxy_url = os.getenv(
                profile.proxy_url_env
            )

            if (
                proxy_url is not None
                and not proxy_url.strip()
            ):
                proxy_url = None

        return ResolvedLLMProfile(
            name=selected_name,

            adapter=(
                profile.adapter
                .strip()
                .lower()
            ),

            base_url=(
                profile.base_url
                .rstrip("/")
            ),

            model=profile.model,

            api_key=SecretStr(
                api_key
            ),

            proxy_url=proxy_url,

            timeout_seconds=(
                profile
                .timeout_seconds
            ),

            max_output_tokens=(
                profile
                .max_output_tokens
            ),

            capabilities=(
                profile.capabilities
            ),

            extra_headers=(
                profile.extra_headers
            ),

            request_options=(
                profile.request_options
            ),
        )