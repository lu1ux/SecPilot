import pytest

from secpilot.core.models import (
    HttpRequest,
    HttpResponse,
)
from secpilot.skills.sqli.boolean import (
    BooleanSQLiSkill,
    UnsupportedParameterContextError,
)
from secpilot.skills.sqli.context import (
    ParameterContext,
    ParameterContextDetector,
)
from secpilot.skills.sqli.models import (
    VerificationStatus,
)


def build_response(
    body: str,
    status_code: int = 200,
    elapsed_ms: float = 10.0,
) -> HttpResponse:
    """
    创建测试用 HttpResponse。
    """

    return HttpResponse(
        status_code=status_code,

        url=(
            "http://127.0.0.1/"
            "product"
        ),

        headers={},

        body=body,

        body_length=len(
            body.encode(
                "utf-8"
            )
        ),

        elapsed_ms=elapsed_ms,
    )


class VulnerableFakeExecutor:
    """
    模拟存在 Boolean SQL Injection
    的 Web 应用。

    baseline:
        PRODUCT_FOUND

    TRUE:
        PRODUCT_FOUND

    FALSE:
        NO_RESULT
    """

    async def execute(
        self,
        request: HttpRequest,
    ) -> HttpResponse:

        value = request.params.get(
            "id",
            "",
        )

        if "1=2" in value:
            return build_response(
                "NO_RESULT"
            )

        return build_response(
            "PRODUCT_FOUND"
        )


class SafeFakeExecutor:
    """
    模拟不存在 Boolean SQL Injection
    的 Web 应用。

    无论参数如何改变，
    都返回相同页面。
    """

    async def execute(
        self,
        request: HttpRequest,
    ) -> HttpResponse:

        return build_response(
            "PRODUCT_FOUND"
        )


class UnstableFakeExecutor:
    """
    模拟一个不稳定目标。

    第一次 False 条件产生明显差异，
    后续 False 条件恢复正常。

    用于验证 SUSPECTED 状态。
    """

    def __init__(self):
        self.false_requests = 0

    async def execute(
        self,
        request: HttpRequest,
    ) -> HttpResponse:

        value = request.params.get(
            "id",
            "",
        )

        if "1=2" in value:

            self.false_requests += 1

            if (
                self.false_requests
                == 1
            ):
                return build_response(
                    "NO_RESULT"
                )

        return build_response(
            "PRODUCT_FOUND"
        )


def test_context_detector_numeric():
    """
    普通整数应识别为 NUMERIC。
    """

    context = (
        ParameterContextDetector
        .detect(
            "123"
        )
    )

    assert (
        context
        == ParameterContext.NUMERIC
    )


def test_context_detector_negative_numeric():
    """
    负整数同样应识别为 NUMERIC。
    """

    context = (
        ParameterContextDetector
        .detect(
            "-10"
        )
    )

    assert (
        context
        == ParameterContext.NUMERIC
    )


def test_context_detector_does_not_guess_string_context():
    """
    不能因为客户端参数是字符串，
    就猜测服务器使用单引号还是双引号。

    所以当前应该返回 UNKNOWN。
    """

    context = (
        ParameterContextDetector
        .detect(
            "admin"
        )
    )

    assert (
        context
        == ParameterContext.UNKNOWN
    )


@pytest.mark.asyncio
async def test_boolean_sqli_confirmed():
    """
    baseline ≈ TRUE
    baseline != FALSE

    三轮全部稳定时：
        CONFIRMED
    """

    skill = BooleanSQLiSkill(
        executor=(
            VulnerableFakeExecutor()
        )
    )

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

    result = await skill.verify(
        request=request,
        parameter="id",
        rounds=3,
    )

    assert (
        result.status
        == VerificationStatus.CONFIRMED
    )

    assert (
        result.context
        == ParameterContext.NUMERIC
    )

    assert (
        result.strategy_name
        == "numeric_boolean"
    )

    assert result.passed_rounds == 3

    assert result.total_rounds == 3

    assert result.confidence == 1.0


@pytest.mark.asyncio
async def test_boolean_sqli_rejected():
    """
    TRUE / FALSE 都与 baseline 相同。

    应：
        REJECTED
    """

    skill = BooleanSQLiSkill(
        executor=SafeFakeExecutor()
    )

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

    result = await skill.verify(
        request=request,
        parameter="id",
        rounds=3,
    )

    assert (
        result.status
        == VerificationStatus.REJECTED
    )

    assert result.passed_rounds == 0

    assert result.confidence == 0.0


@pytest.mark.asyncio
async def test_boolean_sqli_suspected():
    """
    只有部分轮次满足 Evidence。

    应：
        SUSPECTED
    """

    skill = BooleanSQLiSkill(
        executor=(
            UnstableFakeExecutor()
        )
    )

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

    result = await skill.verify(
        request=request,
        parameter="id",
        rounds=3,
    )

    assert (
        result.status
        == VerificationStatus.SUSPECTED
    )

    assert result.passed_rounds == 1

    assert result.total_rounds == 3

    assert result.confidence == 0.3333


@pytest.mark.asyncio
async def test_boolean_sqli_missing_parameter():
    """
    测试不存在的参数应该失败。
    """

    skill = BooleanSQLiSkill(
        executor=SafeFakeExecutor()
    )

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

    with pytest.raises(
        ValueError,
        match="目标参数不存在",
    ):
        await skill.verify(
            request=request,
            parameter="user_id",
        )


@pytest.mark.asyncio
async def test_boolean_sqli_unsupported_context():
    """
    当前没有 String Strategy。

    字符串参数不能被错误地
    当作数字型处理。
    """

    skill = BooleanSQLiSkill(
        executor=SafeFakeExecutor()
    )

    request = HttpRequest(
        method="GET",

        url=(
            "http://127.0.0.1/"
            "search"
        ),

        params={
            "keyword": "apple"
        },
    )

    with pytest.raises(
        UnsupportedParameterContextError,
    ):
        await skill.verify(
            request=request,
            parameter="keyword",
        )


@pytest.mark.asyncio
async def test_boolean_sqli_round_limit():
    """
    单次 Skill 调用最多允许 5 轮，
    防止一次产生过量请求。
    """

    skill = BooleanSQLiSkill(
        executor=SafeFakeExecutor()
    )

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

    with pytest.raises(
        ValueError,
        match="最多允许 5 轮",
    ):
        await skill.verify(
            request=request,
            parameter="id",
            rounds=10,
        )


@pytest.mark.asyncio
async def test_original_request_is_not_modified():
    """
    SQLi Skill 构造 Mutation Request 时，
    不允许污染用户原始 HttpRequest。
    """

    skill = BooleanSQLiSkill(
        executor=(
            VulnerableFakeExecutor()
        )
    )

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

    await skill.verify(
        request=request,
        parameter="id",
        rounds=1,
    )

    assert (
        request.params["id"]
        == "1"
    )