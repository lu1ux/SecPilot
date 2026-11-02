import threading
from http.server import (
    SimpleHTTPRequestHandler,
    ThreadingHTTPServer,
)
from pathlib import Path

import pytest

from secpilot.core.models import HttpRequest
from secpilot.policy.engine import (
    PolicyEngine,
    PolicyViolation,
)
from secpilot.tools.http_executor import HttpExecutor


# ============================================================
# 项目路径
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

POLICY_FILE = (
    PROJECT_ROOT
    / "config"
    / "policy.example.yaml"
)


# ============================================================
# 本地测试 HTTP Server
# ============================================================

class QuietHTTPRequestHandler(
    SimpleHTTPRequestHandler
):
    """
    测试专用 HTTP Handler。

    关闭 SimpleHTTPRequestHandler 默认的
    Terminal 请求日志，避免 pytest 输出过于杂乱。
    """

    def log_message(
        self,
        format,
        *args,
    ):
        pass


@pytest.fixture
def local_http_server():
    """
    自动启动一个本地 HTTP Server。

    使用端口 0，
    让操作系统自动分配一个当前可用的端口。

    测试结束后自动关闭 Server。
    """

    server = ThreadingHTTPServer(
        (
            "127.0.0.1",
            0,
        ),
        QuietHTTPRequestHandler,
    )

    host, port = server.server_address

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )

    thread.start()

    base_url = (
        f"http://{host}:{port}"
    )

    try:
        yield base_url

    finally:
        server.shutdown()
        server.server_close()

        thread.join(
            timeout=2,
        )


# ============================================================
# HttpExecutor Fixture
# ============================================================

@pytest.fixture
def executor():
    """
    为测试创建 HttpExecutor。

    Executor 内部使用真实 PolicyEngine。
    """

    policy = PolicyEngine(
        POLICY_FILE
    )

    return HttpExecutor(
        policy
    )


# ============================================================
# Test 1
# Scope 外目标必须阻止
# ============================================================

@pytest.mark.asyncio
async def test_executor_blocks_disallowed_target(
    executor,
):
    """
    example.com 不在允许的 Scope 中。

    HttpExecutor 应该在真正发送 HTTP 请求之前，
    直接抛出 PolicyViolation。
    """

    request = HttpRequest(
        method="GET",
        url="https://example.com/",
    )

    with pytest.raises(
        PolicyViolation
    ):
        await executor.execute(
            request
        )


# ============================================================
# Test 2
# 合法本地目标可以访问
# ============================================================

@pytest.mark.asyncio
async def test_executor_local_http_request(
    executor,
    local_http_server,
):
    """
    测试 HttpExecutor 是否能够访问
    Policy 允许的 127.0.0.1。
    """

    request = HttpRequest(
        method="GET",
        url=f"{local_http_server}/",
    )

    response = await executor.execute(
        request
    )

    assert response.status_code == 200

    assert response.url.startswith(
        local_http_server
    )

    assert response.body_length > 0

    assert response.elapsed_ms >= 0

    assert isinstance(
        response.body,
        str,
    )


# ============================================================
# Test 3
# 返回结构符合 HttpResponse 定义
# ============================================================

@pytest.mark.asyncio
async def test_executor_response_structure(
    executor,
    local_http_server,
):
    """
    验证 HttpExecutor 输出的 Response
    是否符合 SecPilot 的统一数据结构。
    """

    request = HttpRequest(
        method="GET",
        url=f"{local_http_server}/",
    )

    response = await executor.execute(
        request
    )

    assert isinstance(
        response.status_code,
        int,
    )

    assert isinstance(
        response.url,
        str,
    )

    assert isinstance(
        response.headers,
        dict,
    )

    assert isinstance(
        response.body,
        str,
    )

    assert isinstance(
        response.body_length,
        int,
    )

    assert isinstance(
        response.elapsed_ms,
        float,
    )