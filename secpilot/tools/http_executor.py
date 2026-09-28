import time

import httpx

from secpilot.core.models import (
    HttpRequest,
    HttpResponse,
)
from secpilot.policy.engine import PolicyEngine


class HttpExecutionError(Exception):
    """
    HTTP 请求执行过程中发生错误时抛出。

    用于统一包装底层 httpx 的网络异常，
    避免上层模块直接依赖 httpx 的异常类型。
    """

    pass


class HttpExecutor:
    """
    SecPilot 统一 HTTP 执行器。

    职责：
    1. 请求执行前进行 Policy 检查
    2. 使用 httpx 执行异步 HTTP 请求
    3. 不自动继承系统代理环境变量
    4. 对 HTTP 网络异常进行统一处理
    5. 将 httpx.Response 转换为 SecPilot HttpResponse
    6. 限制进入后续模块的响应正文大小
    """

    def __init__(
        self,
        policy: PolicyEngine,
    ):
        self.policy = policy

    async def execute(
        self,
        request: HttpRequest,
    ) -> HttpResponse:
        """
        执行 HTTP 请求。

        请求执行流程：

        HttpRequest
            ↓
        PolicyEngine
            ↓
        httpx.AsyncClient
            ↓
        Target
            ↓
        HttpResponse
        """

        # ====================================================
        # 1. Policy 检查
        # ====================================================

        # 所有网络请求在真正发送之前，
        # 必须首先通过 Scope Policy。
        self.policy.validate_url(
            request.url
        )

        try:

            # ====================================================
            # 2. 创建异步 HTTP Client
            # ====================================================

            async with httpx.AsyncClient(
                timeout=self.policy.timeout_seconds,
                follow_redirects=self.policy.follow_redirects,

                # 不自动读取：
                # HTTP_PROXY
                # HTTPS_PROXY
                # ALL_PROXY
                #
                # 避免 SecPilot 的请求行为受到
                # 开发者本机代理环境的隐式影响。
                trust_env=False,
            ) as client:

                # ====================================================
                # 3. 记录请求耗时
                # ====================================================

                start_time = time.perf_counter()

                response = await client.request(
                    method=request.method,
                    url=request.url,
                    headers=request.headers,
                    params=request.params,
                    cookies=request.cookies,
                    content=request.body,
                )

                elapsed_ms = (
                    time.perf_counter()
                    - start_time
                ) * 1000

        # ====================================================
        # 4. 超时异常
        # ====================================================

        except httpx.TimeoutException as exc:
            raise HttpExecutionError(
                f"HTTP 请求超时: {request.url}"
            ) from exc

        # ====================================================
        # 5. 其他网络异常
        # ====================================================

        except httpx.RequestError as exc:
            raise HttpExecutionError(
                f"HTTP 请求失败: {exc}"
            ) from exc

        # ====================================================
        # 6. 获取响应正文
        # ====================================================

        raw_body = response.content

        # 保存服务器原始响应正文长度
        body_length = len(raw_body)

        # 限制进入 Evidence Engine / Agent 的正文大小
        if (
            body_length
            > self.policy.max_response_size
        ):
            raw_body = raw_body[
                :self.policy.max_response_size
            ]

        # ====================================================
        # 7. 解码响应正文
        # ====================================================

        encoding = (
            response.encoding
            or "utf-8"
        )

        body = raw_body.decode(
            encoding,
            errors="replace",
        )

        # ====================================================
        # 8. 转换为 SecPilot 统一响应模型
        # ====================================================

        return HttpResponse(
            status_code=response.status_code,
            url=str(response.url),
            headers=dict(response.headers),
            body=body,
            body_length=body_length,
            elapsed_ms=round(
                elapsed_ms,
                2,
            ),
        )