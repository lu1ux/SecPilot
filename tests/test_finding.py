from secpilot.core.finding import (
    FindingSeverity,
    FindingStatus,
)
from secpilot.core.models import (
    HttpRequest,
)
from secpilot.evidence.models import (
    ResponseComparison,
)
from secpilot.skills.sqli.context import (
    ParameterContext,
)
from secpilot.skills.sqli.finding import (
    boolean_sqli_result_to_finding,
)
from secpilot.skills.sqli.models import (
    BooleanMutationSet,
    BooleanSQLiRound,
    BooleanSQLiVerificationResult,
    VerificationStatus,
)


def build_comparison(
    similarity: float,
    length_diff: int,
) -> ResponseComparison:
    """
    创建 Finding 测试用 Evidence。
    """

    return ResponseComparison(
        baseline_status=200,
        test_status=200,

        status_changed=False,

        baseline_length=100,
        test_length=(
            100 - length_diff
            if length_diff <= 100
            else 0
        ),

        length_diff=length_diff,

        length_ratio=(
            max(
                0.0,
                (100 - length_diff)
                / 100,
            )
        ),

        baseline_hash="baseline_hash",
        test_hash="test_hash",

        body_hash_equal=False,

        text_similarity=similarity,

        baseline_elapsed_ms=10.0,
        test_elapsed_ms=12.0,

        latency_diff_ms=2.0,
    )


def build_confirmed_result(
) -> BooleanSQLiVerificationResult:
    """
    创建一个已经确认的 SQLi Result。
    """

    mutations = BooleanMutationSet(
        original_value="1",

        true_value=(
            "1 AND 1=1"
        ),

        false_value=(
            "1 AND 1=2"
        ),

        strategy_name=(
            "numeric_boolean"
        ),

        context=(
            ParameterContext.NUMERIC
        ),
    )

    round_result = BooleanSQLiRound(
        round_number=1,

        mutations=mutations,

        true_comparison=(
            build_comparison(
                similarity=0.98,
                length_diff=2,
            )
        ),

        false_comparison=(
            build_comparison(
                similarity=0.20,
                length_diff=80,
            )
        ),

        passed=True,
    )

    return (
        BooleanSQLiVerificationResult(
            parameter="id",

            context=(
                ParameterContext.NUMERIC
            ),

            strategy_name=(
                "numeric_boolean"
            ),

            status=(
                VerificationStatus
                .CONFIRMED
            ),

            confidence=1.0,

            passed_rounds=1,

            total_rounds=1,

            rounds=[
                round_result
            ],
        )
    )


def test_boolean_sqli_result_to_finding():
    """
    SQLi VerificationResult
    应该能够转换成统一 Finding。
    """

    request = HttpRequest(
        method="GET",

        url=(
            "http://127.0.0.1/"
            "product"
        ),

        params={
            "id": "1"
        },
    )

    result = (
        build_confirmed_result()
    )

    finding = (
        boolean_sqli_result_to_finding(
            request=request,
            result=result,
        )
    )

    assert finding.id

    assert (
        finding.vulnerability_type
        == "boolean_based_sql_injection"
    )

    assert (
        finding.title
        == "Boolean-based SQL Injection"
    )

    assert (
        finding.target
        == "http://127.0.0.1/product"
    )

    assert finding.http_method == "GET"

    assert finding.parameter == "id"

    assert (
        finding.source_skill
        == "boolean_sqli"
    )

    assert (
        finding.status
        == FindingStatus.CONFIRMED
    )

    assert (
        finding.severity
        == FindingSeverity.UNRATED
    )

    assert finding.confidence == 1.0

    assert len(
        finding.evidence
    ) == 1


def test_finding_contains_structured_evidence():
    """
    Finding 中应该保留
    SQLi Skill 的结构化 Evidence。
    """

    request = HttpRequest(
        method="GET",

        url=(
            "http://127.0.0.1/"
            "product"
        ),

        params={
            "id": "1"
        },
    )

    finding = (
        boolean_sqli_result_to_finding(
            request=request,
            result=(
                build_confirmed_result()
            ),
        )
    )

    evidence = (
        finding.evidence[0]
    )

    assert (
        evidence.kind
        == "boolean_response_comparison"
    )

    assert (
        evidence.data[
            "true_similarity"
        ]
        == 0.98
    )

    assert (
        evidence.data[
            "false_similarity"
        ]
        == 0.20
    )

    assert (
        evidence.data[
            "strategy"
        ]
        == "numeric_boolean"
    )

    assert (
        finding.metadata[
            "passed_rounds"
        ]
        == 1
    )