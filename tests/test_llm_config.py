from pathlib import Path

import pytest

from secpilot.llm.config import (
    LLMConfiguration,
    LLMConfigurationError,
)


def write_config(
    path: Path,
) -> None:

    path.write_text(
        """
active_profile: glm

profiles:

  glm:
    adapter: openai_compatible
    base_url: https://example.test/v1
    model: glm-test
    api_key_env: TEST_GLM_KEY

    capabilities:
      structured_output: false
      json_mode: false
""",
        encoding="utf-8",
    )


def test_load_llm_config(
    tmp_path,
    monkeypatch,
):

    config_file = (
        tmp_path
        / "llm.yaml"
    )

    write_config(
        config_file
    )

    monkeypatch.setenv(
        "TEST_GLM_KEY",
        "secret-key",
    )

    config = (
        LLMConfiguration.load(
            config_file
        )
    )

    profile = config.resolve()

    assert profile.name == "glm"

    assert (
        profile.adapter
        == "openai_compatible"
    )

    assert (
        profile.model
        == "glm-test"
    )

    assert (
        profile.api_key
        .get_secret_value()
        == "secret-key"
    )


def test_environment_can_override_profile(
    tmp_path,
    monkeypatch,
):

    config_file = (
        tmp_path
        / "llm.yaml"
    )

    config_file.write_text(
        """
active_profile: glm

profiles:

  glm:
    adapter: openai_compatible
    base_url: https://glm.test/v1
    model: glm-test
    api_key_env: GLM_KEY

  local:
    adapter: openai_compatible
    base_url: http://127.0.0.1:8000/v1
    model: local
    api_key_env: LOCAL_KEY
""",
        encoding="utf-8",
    )

    monkeypatch.setenv(
        "SECPILOT_LLM_PROFILE",
        "local",
    )

    monkeypatch.setenv(
        "LOCAL_KEY",
        "local-key",
    )

    config = (
        LLMConfiguration.load(
            config_file
        )
    )

    profile = config.resolve()

    assert (
        profile.name
        == "local"
    )


def test_missing_api_key_rejected(
    tmp_path,
    monkeypatch,
):

    config_file = (
        tmp_path
        / "llm.yaml"
    )

    write_config(
        config_file
    )

    monkeypatch.delenv(
        "TEST_GLM_KEY",
        raising=False,
    )

    config = (
        LLMConfiguration.load(
            config_file
        )
    )

    with pytest.raises(
        LLMConfigurationError,
        match="缺少 API Key",
    ):
        config.resolve()