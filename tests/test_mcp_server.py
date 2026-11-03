import pytest

from mcp import Client

from secpilot.core.models import (
    HttpRequest,
    HttpResponse,
)
from secpilot.mcp_gateway.server import (
    create_mcp_server,
)
from secpilot.policy.engine import (
    PolicyViolation,
)


class FakeHttpExecutor:
    """
    MCP Server 单元测试使用的
    Fake HTTP Executor。

    不进行真实网络请求。

    用于验证：

        MCP Input
            ↓
        HttpRequest
            ↓
        Executor
            ↓
        HttpResponse
            ↓
        MCP Structured Output
    """

    def __init__(self):
        self.last_request: (
            HttpRequest
            | None
        ) = None

    async def execute(
        self,
        request: HttpRequest,
    ) -> HttpResponse:

        self.last_request = request

        return HttpResponse(
            status_code=200,

            url=request.url,

            headers={
                "x-secpilot-test":
                    "true"
            },

            body="MCP_OK",

            body_length=6,

            elapsed_ms=1.5,
        )


class DeniedHttpExecutor:
    """
    模拟 PolicyEngine 拒绝请求。
    """

    async def execute(
        self,
        request: HttpRequest,
    ) -> HttpResponse:

        raise PolicyViolation(
            "目标不在授权 Scope 内"
        )


@pytest.mark.asyncio
async def test_mcp_lists_http_request_tool():
    """
    MCP Server 应该正确暴露
    http_request Tool。
    """

    fake_executor = (
        FakeHttpExecutor()
    )

    server = create_mcp_server(
        executor=fake_executor
    )

    async with Client(
        server,
        raise_exceptions=True,
    ) as client:

        result = (
            await client.list_tools()
        )

        tool_names = [
            tool.name
            for tool
            in result.tools
        ]

        assert (
            "http_request"
            in tool_names
        )


@pytest.mark.asyncio
async def test_mcp_http_request_tool():
    """
    MCP Tool 应该：

    1. 接收 MCP 参数
    2. 转换成 HttpRequest
    3. 调用 Executor
    4. 返回结构化 HttpResponse
    """

    fake_executor = (
        FakeHttpExecutor()
    )

    server = create_mcp_server(
        executor=fake_executor
    )

    async with Client(
        server,
        raise_exceptions=True,
    ) as client:

        result = await client.call_tool(
            "http_request",
            {
                "method": "GET",

                "url": (
                    "http://127.0.0.1:8080/"
                ),

                "params": {
                    "id": "1"
                },

                "headers": {
                    "User-Agent":
                        "SecPilot-Test"
                },
            },
        )

        assert (
            result.is_error
            is False
        )

        assert (
            result.structured_content
            is not None
        )

        assert (
            result.structured_content[
                "status_code"
            ]
            == 200
        )

        assert (
            result.structured_content[
                "body"
            ]
            == "MCP_OK"
        )

        assert (
            result.structured_content[
                "body_length"
            ]
            == 6
        )

        assert (
            fake_executor
            .last_request
            is not None
        )

        assert (
            fake_executor
            .last_request
            .method
            == "GET"
        )

        assert (
            fake_executor
            .last_request
            .params["id"]
            == "1"
        )


@pytest.mark.asyncio
async def test_mcp_rejects_invalid_http_method():
    """
    MCP Tool 输入 Schema
    应该拒绝不允许的 HTTP Method。

    TRACE 不在 HttpToolMethod Enum 中。
    """

    server = create_mcp_server(
        executor=(
            FakeHttpExecutor()
        )
    )

    async with Client(
        server,
        raise_exceptions=True,
    ) as client:

        result = await client.call_tool(
            "http_request",
            {
                "method": "TRACE",

                "url": (
                    "http://127.0.0.1/"
                ),
            },
        )

        assert (
            result.is_error
            is True
        )


@pytest.mark.asyncio
async def test_mcp_policy_error_is_tool_error():
    """
    Policy 拒绝请求时，

    MCP Tool 不应该伪装成成功结果。

    应返回：

        is_error = True

    让未来 LLM Agent
    能够识别工具执行失败。
    """

    server = create_mcp_server(
        executor=(
            DeniedHttpExecutor()
        )
    )

    async with Client(
        server,
        raise_exceptions=True,
    ) as client:

        result = await client.call_tool(
            "http_request",
            {
                "method": "GET",

                "url": (
                    "https://example.com/"
                ),
            },
        )

        assert (
            result.is_error
            is True
        )

        assert (
            result.structured_content
            is None
        )

        assert result.content

        error_text = (
            result.content[0].text
        )

        assert (
            "Policy Engine"
            in error_text
        )