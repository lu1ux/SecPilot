from pathlib import Path

import pytest

from secpilot.core.models import HttpRequest
from secpilot.policy.engine import PolicyEngine, PolicyViolation
from secpilot.tools.http_executor import HttpExecutor

PROJECT_ROOT = Path(__file__).resolve().parents[1]

POLICY_FILE = (
    PROJECT_ROOT
    / "config"
    / "policy.example.yaml"
)


# ============================================================
# Fixture：创建 HttpExecutor
# ============================================================

@pytest.fixture
def executor():
    """
    为每个测试创建一个新的 HttpExecutor。

    HttpExecutor 内部使用 PolicyEngine，
    并读取项目中的 policy.example.yaml。
    """

    policy = PolicyEngine(
        POLICY_FILE
    )

    return HttpExecutor(
        policy
    )


# ============================================================
# 测试 1：禁止访问 Scope 外目标
# ============================================================

@pytest.mark.asyncio
async def test_executor_blocks_disallowed_target(
    executor
):
    """
    HttpExecutor 必须经过 PolicyEngine。

    example.com 不在 allowed_hosts 中，
    所以请求应该在真正发送之前被拒绝。
    """

    request = HttpRequest(
        method="GET",
        url="https://example.com/"
    )

    with pytest.raises(
        PolicyViolation
    ):
        await executor.execute(
            request
        )


# ============================================================
# 测试 2：允许访问本地授权目标
# ============================================================

@pytest.mark.asyncio
async def test_executor_local_http_request(
    executor
):
    """
    测试 HttpExecutor 是否可以正常访问
    Policy 允许的本地 HTTP 服务。

    运行此测试前，需要在本机启动：

        python -m http.server 8080
    """

    request = HttpRequest(
        method="GET",
        url="http://127.0.0.1:8080/"
    )

    response = await executor.execute(
        request
    )

    assert response.status_code == 200

    assert response.url.startswith(
        "http://127.0.0.1:8080"
    )

    assert response.body_length > 0

    assert response.elapsed_ms >= 0

    assert isinstance(
        response.body,
        str
    )


# ============================================================
# 测试 3：响应对象必须包含基础信息
# ============================================================

@pytest.mark.asyncio
async def test_executor_response_structure(
    executor
):
    """
    验证 HttpExecutor 返回的数据
    符合 SecPilot 定义的统一响应结构。
    """

    request = HttpRequest(
        method="GET",
        url="http://127.0.0.1:8080/"
    )

    response = await executor.execute(
        request
    )

    assert isinstance(
        response.status_code,
        int
    )

    assert isinstance(
        response.url,
        str
    )

    assert isinstance(
        response.headers,
        dict
    )

    assert isinstance(
        response.body,
        str
    )

    assert isinstance(
        response.body_length,
        int
    )

    assert isinstance(
        response.elapsed_ms,
        float
    )