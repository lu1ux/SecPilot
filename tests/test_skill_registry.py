import pytest

from secpilot.skills.registry import (
    DuplicateSkillError,
    SkillNotFoundError,
    SkillRegistry,
)


class FakeSkill:
    """
    Skill Registry 测试专用对象。
    """

    pass


def test_register_and_get_skill():
    """
    注册 Skill 后应该能够取回
    同一个对象。
    """

    registry = SkillRegistry()

    skill = FakeSkill()

    registry.register(
        "boolean_sqli",
        skill,
    )

    result = registry.get(
        "boolean_sqli"
    )

    assert result is skill


def test_skill_name_normalization():
    """
    Skill 名称应该忽略：
    - 前后空格
    - 大小写
    """

    registry = SkillRegistry()

    skill = FakeSkill()

    registry.register(
        " Boolean_SQLi ",
        skill,
    )

    assert registry.has(
        "boolean_sqli"
    )

    assert registry.get(
        "BOOLEAN_SQLI"
    ) is skill


def test_duplicate_skill_rejected():
    """
    同名 Skill 不允许重复注册。
    """

    registry = SkillRegistry()

    registry.register(
        "boolean_sqli",
        FakeSkill(),
    )

    with pytest.raises(
        DuplicateSkillError,
    ):
        registry.register(
            "boolean_sqli",
            FakeSkill(),
        )


def test_unknown_skill_rejected():
    """
    获取不存在的 Skill 时应该报错。
    """

    registry = SkillRegistry()

    with pytest.raises(
        SkillNotFoundError,
    ):
        registry.get(
            "xss_reflection"
        )


def test_registry_names():
    """
    Registry 应该能够返回
    稳定排序后的 Skill 名称。
    """

    registry = SkillRegistry()

    registry.register(
        "boolean_sqli",
        FakeSkill(),
    )

    registry.register(
        "xss_reflection",
        FakeSkill(),
    )

    assert registry.names() == [
        "boolean_sqli",
        "xss_reflection",
    ]

    assert len(registry) == 2