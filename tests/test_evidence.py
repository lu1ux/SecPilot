from secpilot.core.models import HttpResponse
from secpilot.evidence.comparator import ResponseComparator


def build_response(
    body: str,
    status_code: int = 200,
    elapsed_ms: float = 10.0,
) -> HttpResponse:
    """
    创建测试用 HttpResponse。

    避免每个测试中重复编写完整 HttpResponse。
    """

    return HttpResponse(
        status_code=status_code,
        url="http://127.0.0.1:8080/",
        headers={},
        body=body,
        body_length=len(
            body.encode("utf-8")
        ),
        elapsed_ms=elapsed_ms,
    )


def test_identical_responses():
    """
    两个完全一致的 Response：

    - Status 不变化
    - Length 不变化
    - Hash 相同
    - Similarity = 1
    """

    comparator = ResponseComparator()

    baseline = build_response(
        "Hello SecPilot"
    )

    test = build_response(
        "Hello SecPilot"
    )

    result = comparator.compare(
        baseline,
        test,
    )

    assert result.status_changed is False

    assert result.length_diff == 0

    assert result.length_ratio == 1.0

    assert result.body_hash_equal is True

    assert result.text_similarity == 1.0


def test_different_response_body():
    """
    两个不同正文应该：

    - Hash 不同
    - Similarity 小于 1
    - Length 存在差异
    """

    comparator = ResponseComparator()

    baseline = build_response(
        "Product exists"
    )

    test = build_response(
        "Product does not exist"
    )

    result = comparator.compare(
        baseline,
        test,
    )

    assert result.body_hash_equal is False

    assert result.text_similarity < 1.0

    assert result.length_diff > 0


def test_status_code_changed():
    """
    HTTP Status 变化应该能够被识别。
    """

    comparator = ResponseComparator()

    baseline = build_response(
        body="OK",
        status_code=200,
    )

    test = build_response(
        body="Forbidden",
        status_code=403,
    )

    result = comparator.compare(
        baseline,
        test,
    )

    assert result.status_changed is True

    assert result.baseline_status == 200

    assert result.test_status == 403


def test_latency_difference():
    """
    验证响应时间差异计算。

    后续 Time-based SQL Injection Skill
    会使用这一指标。
    """

    comparator = ResponseComparator()

    baseline = build_response(
        body="OK",
        elapsed_ms=100.0,
    )

    test = build_response(
        body="OK",
        elapsed_ms=5100.0,
    )

    result = comparator.compare(
        baseline,
        test,
    )

    assert result.latency_diff_ms == 5000.0


def test_empty_response_length_ratio():
    """
    baseline 和 test 都为空时：

    ratio = 1.0
    """

    comparator = ResponseComparator()

    baseline = build_response(
        ""
    )

    test = build_response(
        ""
    )

    result = comparator.compare(
        baseline,
        test,
    )

    assert result.length_ratio == 1.0


def test_empty_baseline_with_nonempty_test():
    """
    baseline 为空但 test 不为空：

    ratio = 0.0
    """

    comparator = ResponseComparator()

    baseline = build_response(
        ""
    )

    test = build_response(
        "SecPilot"
    )

    result = comparator.compare(
        baseline,
        test,
    )

    assert result.length_ratio == 0.0


def test_hash_changes_when_body_changes():
    """
    即使只改变一个字符，
    SHA-256 Hash 也应该发生变化。
    """

    comparator = ResponseComparator()

    baseline = build_response(
        "SecPilot"
    )

    test = build_response(
        "SecPiloT"
    )

    result = comparator.compare(
        baseline,
        test,
    )

    assert result.baseline_hash != result.test_hash

    assert result.body_hash_equal is False