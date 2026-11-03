from pathlib import Path
from typing import Protocol

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import (
    ToolError,
)

from secpilot.core.models import (
    HttpRequest,
    HttpResponse,
)
from secpilot.mcp_gateway.models import (
    HttpToolMethod,
)
from secpilot.policy.engine import (
    PolicyEngine,
    PolicyViolation,
)
from secpilot.tools.http_executor import (
    HttpExecutionError,
    HttpExecutor,
)


# ============================================================
# 项目路径
# ============================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

DEFAULT_POLICY_FILE = (
    PROJECT_ROOT
    / "config"
    / "policy.example.yaml"
)


# ============================================================
# HTTP Executor Interface
# ============================================================

class HttpExecutorProtocol(
    Protocol
):
    """
    MCP Gateway 依赖的 HTTP Executor 接口。

    任何对象只要实现：

        async execute(HttpRequest)
            -> HttpResponse

    都可以作为 MCP Gateway
    的底层 HTTP Executor。

    这样测试时可以注入 FakeExecutor，
    正式运行时使用 HttpExecutor。
    """

    async def execute(
        self,
        request: HttpRequest,
    ) -> HttpResponse:
        ...


# ============================================================
# MCP Server Factory
# ============================================================

def create_mcp_server(
    policy_path: (
        str
        | Path
    ) = DEFAULT_POLICY_FILE,

    executor: (
        HttpExecutorProtocol
        | None
    ) = None,
) -> MCPServer:
    """
    创建 SecPilot MCP Server。

    Parameters
    ----------
    policy_path:
        SecPilot Policy 配置文件路径。

    executor:
        可选 HTTP Executor。

        正式运行：
            HttpExecutor

        测试：
            FakeExecutor

    Returns
    -------
    MCPServer
        已注册 SecPilot Tools 的
        MCP Server。
    """

    # ========================================================
    # 1. 创建真实 Executor
    # ========================================================

    if executor is None:

        policy = PolicyEngine(
            policy_path
        )

        executor = HttpExecutor(
            policy
        )

    # ========================================================
    # 2. 创建 MCP Server
    # ========================================================

    server = MCPServer(
        "SecPilot"
    )

    # ========================================================
    # 3. HTTP Tool
    # ========================================================

    @server.tool(
        name="http_request",
        title="Authorized HTTP Request",
        description=(
            "Send an HTTP request through "
            "SecPilot's Policy Engine and "
            "HTTP Executor. "
            "The target must be inside the "
            "authorized security testing scope."
        ),
    )
    async def http_request(
        url: str,

        method: (
            HttpToolMethod
        ) = HttpToolMethod.GET,

        headers: (
            dict[str, str]
            | None
        ) = None,

        params: (
            dict[str, str]
            | None
        ) = None,

        cookies: (
            dict[str, str]
            | None
        ) = None,

        body: (
            str
            | None
        ) = None,
    ) -> HttpResponse:
        """
        Send an authorized HTTP request.

        Every request must pass through:

            MCP Tool
                ↓
            PolicyEngine
                ↓
            HttpExecutor
                ↓
            Target

        The MCP model never receives
        direct socket or shell access.
        """

        request = HttpRequest(
            method=method.value,

            url=url,

            headers=(
                headers
                or {}
            ),

            params=(
                params
                or {}
            ),

            cookies=(
                cookies
                or {}
            ),

            body=body,
        )

        try:

            response = (
                await executor.execute(
                    request
                )
            )

            return response

        except PolicyViolation as exc:

            raise ToolError(
                "Request denied by "
                "SecPilot Policy Engine: "
                f"{exc}"
            ) from exc

        except HttpExecutionError as exc:

            raise ToolError(
                "HTTP execution failed: "
                f"{exc}"
            ) from exc

    return server


# ============================================================
# Default Server
# ============================================================

mcp = create_mcp_server()


# ============================================================
# Entrypoint
# ============================================================

def main() -> None:
    """
    Run SecPilot MCP Server
    using stdio transport.

    stdio is suitable for local MCP hosts.
    """

    mcp.run(
        transport="stdio"
    )


if __name__ == "__main__":
    main()