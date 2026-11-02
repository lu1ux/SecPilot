from typing import Any


class SkillNotFoundError(
    KeyError
):
    """
    请求不存在的 Security Skill 时抛出。
    """

    pass


class DuplicateSkillError(
    ValueError
):
    """
    重复注册同名 Skill 时抛出。
    """

    pass


class SkillRegistry:
    """
    SecPilot Security Skill Registry。

    负责：

    1. 注册 Skill
    2. 根据名称查找 Skill
    3. 防止重复 Skill
    4. 向 Agent 提供可用 Skill 列表

    Example
    -------

    registry.register(
        "boolean_sqli",
        boolean_sqli_skill,
    )

    skill = registry.get(
        "boolean_sqli"
    )
    """

    def __init__(self):
        self._skills: dict[
            str,
            Any,
        ] = {}

    @staticmethod
    def _normalize_name(
        name: str,
    ) -> str:
        """
        统一 Skill 名称。

        Example:

            " Boolean_SQLi "

        →

            "boolean_sqli"
        """

        normalized = (
            name
            .strip()
            .lower()
        )

        if not normalized:
            raise ValueError(
                "Skill 名称不能为空"
            )

        return normalized

    def register(
        self,
        name: str,
        skill: Any,
    ) -> None:
        """
        注册一个 Security Skill。
        """

        normalized_name = (
            self._normalize_name(
                name
            )
        )

        if (
            normalized_name
            in self._skills
        ):
            raise DuplicateSkillError(
                f"Skill 已存在: "
                f"{normalized_name}"
            )

        self._skills[
            normalized_name
        ] = skill

    def get(
        self,
        name: str,
    ) -> Any:
        """
        根据 Skill 名称获取实例。
        """

        normalized_name = (
            self._normalize_name(
                name
            )
        )

        if (
            normalized_name
            not in self._skills
        ):
            raise SkillNotFoundError(
                f"Skill 不存在: "
                f"{normalized_name}"
            )

        return self._skills[
            normalized_name
        ]

    def has(
        self,
        name: str,
    ) -> bool:
        """
        判断指定 Skill 是否已经注册。
        """

        normalized_name = (
            self._normalize_name(
                name
            )
        )

        return (
            normalized_name
            in self._skills
        )

    def names(
        self,
    ) -> list[str]:
        """
        返回所有已注册 Skill 名称。

        使用排序保证结果稳定，
        方便测试和后续 Agent 使用。
        """

        return sorted(
            self._skills.keys()
        )

    def __len__(
        self,
    ) -> int:
        """
        返回当前注册 Skill 数量。
        """

        return len(
            self._skills
        )