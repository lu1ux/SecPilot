from pydantic import BaseModel, Field


class ResponseComparison(BaseModel):
    """
    SecPilot HTTP 响应比较结果。

    Evidence Engine 负责产生客观、可量化的响应差异数据，
    但不直接判断某个漏洞是否成立。

    漏洞是否成立应该由对应的 Security Skill
    根据 Evidence 做进一步决策。
    """

    # ========================================================
    # HTTP Status
    # ========================================================

    baseline_status: int
    test_status: int

    status_changed: bool

    # ========================================================
    # Response Body Length
    # ========================================================

    baseline_length: int = Field(
        ge=0
    )

    test_length: int = Field(
        ge=0
    )

    length_diff: int = Field(
        ge=0
    )

    length_ratio: float = Field(
        ge=0
    )

    # ========================================================
    # Response Body Content
    # ========================================================

    baseline_hash: str
    test_hash: str

    body_hash_equal: bool

    text_similarity: float = Field(
        ge=0.0,
        le=1.0,
    )

    # ========================================================
    # Response Latency
    # ========================================================

    baseline_elapsed_ms: float = Field(
        ge=0
    )

    test_elapsed_ms: float = Field(
        ge=0
    )

    latency_diff_ms: float