import pytest

from secpilot.core.finding import (
    Finding,
    FindingSeverity,
    FindingStatus,
)
from secpilot.core.finding_mapper import (
    DuplicateFindingMapperError,
    FindingMapperNotFoundError,
    FindingMapperRegistry,
)
from secpilot.core.models import (
    HttpRequest,
)


def fake_mapper(
    request,
    result,
):
    """
    Finding Mapper 测试专用。
    """

    return Finding(
        vulnerability_type="test",

        title="Test Finding",

        target=request.url,

        http_method=request.method,

        parameter="id",

        source_skill="test_skill",

        status=(
            FindingStatus.CONFIRMED
        ),

        severity=(
            FindingSeverity.UNRATED
        ),

        confidence=1.0,
    )


def test_register_and_get_mapper():

    registry = (
        FindingMapperRegistry()
    )

    registry.register(
        "boolean_sqli",
        fake_mapper,
    )

    mapper = registry.get(
        "boolean_sqli"
    )

    assert mapper is fake_mapper


def test_mapper_name_normalization():

    registry = (
        FindingMapperRegistry()
    )

    registry.register(
        " Boolean_SQLi ",
        fake_mapper,
    )

    assert registry.has(
        "boolean_sqli"
    )


def test_duplicate_mapper_rejected():

    registry = (
        FindingMapperRegistry()
    )

    registry.register(
        "boolean_sqli",
        fake_mapper,
    )

    with pytest.raises(
        DuplicateFindingMapperError,
    ):
        registry.register(
            "boolean_sqli",
            fake_mapper,
        )


def test_unknown_mapper_rejected():

    registry = (
        FindingMapperRegistry()
    )

    with pytest.raises(
        FindingMapperNotFoundError,
    ):
        registry.get(
            "xss"
        )