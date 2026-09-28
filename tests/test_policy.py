from pathlib import Path

import pytest

from secpilot.policy.engine import (
    PolicyEngine,
    PolicyViolation,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]

POLICY_FILE = (
    PROJECT_ROOT
    / "config"
    / "policy.example.yaml"
)


@pytest.fixture
def policy():
    return PolicyEngine(
        POLICY_FILE
    )


def test_allowed_localhost(policy):
    policy.validate_url(
        "http://localhost:8080/test"
    )


def test_allowed_ipv4(policy):
    policy.validate_url(
        "http://127.0.0.1:8080/"
    )


def test_disallowed_host(policy):
    with pytest.raises(
        PolicyViolation
    ):
        policy.validate_url(
            "https://example.com/"
        )


def test_disallowed_scheme(policy):
    with pytest.raises(
        PolicyViolation
    ):
        policy.validate_url(
            "ftp://localhost/file.txt"
        )


def test_missing_scheme(policy):
    with pytest.raises(
        PolicyViolation
    ):
        policy.validate_url(
            "localhost:8080"
        )


def test_url_with_credentials(policy):
    with pytest.raises(
        PolicyViolation
    ):
        policy.validate_url(
            "http://admin:password@localhost/"
        )