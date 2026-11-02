from secpilot.core.finding import (
    Finding,
    FindingEvidence,
    FindingSeverity,
    FindingStatus,
)
from secpilot.core.models import (
    HttpRequest,
)
from secpilot.skills.sqli.models import (
    BooleanSQLiVerificationResult,
)


def boolean_sqli_result_to_finding(
    request: HttpRequest,
    result: BooleanSQLiVerificationResult,
) -> Finding:
    """
    将 Boolean SQLi Skill 的验证结果
    转换成 SecPilot 统一 Finding。

    BooleanSQLiVerificationResult
                ↓
             Finding

    Report、Agent、Database 等上层模块
    以后只需要认识 Finding，
    不需要了解 SQLi Skill 内部数据结构。
    """

    evidence: list[
        FindingEvidence
    ] = []

    for round_result in result.rounds:

        true_comparison = (
            round_result
            .true_comparison
        )

        false_comparison = (
            round_result
            .false_comparison
        )

        evidence.append(
            FindingEvidence(
                kind=(
                    "boolean_response_comparison"
                ),

                summary=(
                    f"Round "
                    f"{round_result.round_number}: "
                    f"{'PASS' if round_result.passed else 'FAIL'}"
                ),

                data={
                    "round": (
                        round_result
                        .round_number
                    ),

                    "passed": (
                        round_result
                        .passed
                    ),

                    "context": (
                        round_result
                        .mutations
                        .context
                        .value
                    ),

                    "strategy": (
                        round_result
                        .mutations
                        .strategy_name
                    ),

                    "baseline_value": (
                        round_result
                        .mutations
                        .original_value
                    ),

                    "true_value": (
                        round_result
                        .mutations
                        .true_value
                    ),

                    "false_value": (
                        round_result
                        .mutations
                        .false_value
                    ),

                    "true_similarity": (
                        true_comparison
                        .text_similarity
                    ),

                    "false_similarity": (
                        false_comparison
                        .text_similarity
                    ),

                    "true_status_changed": (
                        true_comparison
                        .status_changed
                    ),

                    "false_status_changed": (
                        false_comparison
                        .status_changed
                    ),

                    "true_length_diff": (
                        true_comparison
                        .length_diff
                    ),

                    "false_length_diff": (
                        false_comparison
                        .length_diff
                    ),

                    "true_latency_diff_ms": (
                        true_comparison
                        .latency_diff_ms
                    ),

                    "false_latency_diff_ms": (
                        false_comparison
                        .latency_diff_ms
                    ),
                },
            )
        )

    status = FindingStatus(
        result.status.value
    )

    return Finding(
        vulnerability_type=(
            result.vulnerability_type
        ),

        title=(
            "Boolean-based SQL Injection"
        ),

        target=request.url,

        http_method=request.method,

        parameter=result.parameter,

        source_skill="boolean_sqli",

        status=status,

        # 暂时不由 Skill 直接决定严重程度。
        severity=(
            FindingSeverity.UNRATED
        ),

        confidence=(
            result.confidence
        ),

        evidence=evidence,

        metadata={
            "context": (
                result.context.value
            ),

            "strategy": (
                result.strategy_name
            ),

            "passed_rounds": (
                result.passed_rounds
            ),

            "total_rounds": (
                result.total_rounds
            ),
        },
    )