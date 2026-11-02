from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class FindingStatus(StrEnum):
    """
    SecPilot 统一漏洞状态。

    CONFIRMED:
        有稳定 Evidence 支持漏洞存在。

    SUSPECTED:
        存在异常行为，但证据不足。

    REJECTED:
        当前验证结果不支持漏洞存在。
    """

    CONFIRMED = "CONFIRMED"
    SUSPECTED = "SUSPECTED"
    REJECTED = "REJECTED"


class FindingSeverity(StrEnum):
    """
    漏洞风险等级。

    Skill 默认不直接决定严重程度，
    所以允许 UNRATED。

    后续可以由 Risk Engine
    结合漏洞类型、资产价值和影响进行评级。
    """

    UNRATED = "UNRATED"
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingEvidence(BaseModel):
    """
    一条结构化漏洞证据。

    kind:
        Evidence 类型。

    summary:
        给人阅读的简短说明。

    data:
        机器可读取的详细证据。
    """

    kind: str

    summary: str

    data: dict[str, Any] = Field(
        default_factory=dict
    )


class Finding(BaseModel):
    """
    SecPilot 统一漏洞对象。

    不论漏洞来自：

        SQLi
        XSS
        IDOR
        SSRF
        Upload

    最终都应该转换成 Finding。
    """

    id: str = Field(
        default_factory=lambda: uuid4().hex
    )

    vulnerability_type: str

    title: str

    target: str

    http_method: str

    parameter: str | None = None

    source_skill: str

    status: FindingStatus

    severity: FindingSeverity = (
        FindingSeverity.UNRATED
    )

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    evidence: list[
        FindingEvidence
    ] = Field(
        default_factory=list
    )

    metadata: dict[
        str,
        Any,
    ] = Field(
        default_factory=dict
    )