from collections.abc import Callable
from typing import Any

from secpilot.core.finding import Finding
from secpilot.core.models import HttpRequest


class FindingMapperNotFoundError(
    KeyError
):
    """
    找不到指定 Skill 对应的
    Finding Mapper 时抛出。
    """

    pass


class DuplicateFindingMapperError(
    ValueError
):
    """
    同一个 Skill 重复注册
    Finding Mapper 时抛出。
    """

    pass


FindingMapper = Callable[
    [
        HttpRequest,
        Any,
    ],
    Finding,
]


class FindingMapperRegistry:
    """
    SecPilot Finding Mapper Registry。

    Security Skill 会产生各自不同的
    VerificationResult。

    例如：

        BooleanSQLiVerificationResult
        XSSVerificationResult
        IDORVerificationResult

    但 SecPilot 上层只希望看到统一：

        Finding

    所以：

        Skill Result
             ↓
        Finding Mapper
             ↓
           Finding
    """

    def __init__(
        self,
    ):
        self._mappers: dict[
            str,
            FindingMapper,
        ] = {}

    @staticmethod
    def _normalize_name(
        name: str,
    ) -> str:
        """
        统一 Skill 名称格式。
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
        skill_name: str,
        mapper: FindingMapper,
    ) -> None:
        """
        注册：

            Skill Name
                ↓
            Finding Mapper
        """

        normalized = (
            self._normalize_name(
                skill_name
            )
        )

        if normalized in self._mappers:

            raise (
                DuplicateFindingMapperError(
                    "Finding Mapper "
                    "已经存在: "
                    f"{normalized}"
                )
            )

        self._mappers[
            normalized
        ] = mapper

    def get(
        self,
        skill_name: str,
    ) -> FindingMapper:
        """
        获取指定 Skill 对应的
        Finding Mapper。
        """

        normalized = (
            self._normalize_name(
                skill_name
            )
        )

        if normalized not in self._mappers:

            raise (
                FindingMapperNotFoundError(
                    "Finding Mapper "
                    "不存在: "
                    f"{normalized}"
                )
            )

        return self._mappers[
            normalized
        ]

    def has(
        self,
        skill_name: str,
    ) -> bool:
        """
        判断 Mapper 是否存在。
        """

        normalized = (
            self._normalize_name(
                skill_name
            )
        )

        return (
            normalized
            in self._mappers
        )

    def names(
        self,
    ) -> list[str]:
        """
        返回所有 Mapper 对应的
        Skill Name。
        """

        return sorted(
            self._mappers.keys()
        )

    def __len__(
        self,
    ) -> int:
        return len(
            self._mappers
        )