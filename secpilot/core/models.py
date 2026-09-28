from typing import Optional

from pydantic import BaseModel, Field, field_validator


class HttpRequest(BaseModel):
    """
    SecPilot 内部统一 HTTP 请求模型。

    Agent、Security Skill、MCP Client 等模块产生的 HTTP 请求，
    最终都转换成这个统一结构。
    """

    # HTTP 请求方法，默认 GET
    method: str = "GET"

    # 请求目标
    url: str

    # 请求头，例如 User-Agent、Authorization
    headers: dict[str, str] = Field(default_factory=dict)

    # GET 参数，例如 ?id=1
    params: dict[str, str] = Field(default_factory=dict)

    # Cookie
    cookies: dict[str, str] = Field(default_factory=dict)

    # POST Body，第一版暂时使用字符串
    body: Optional[str] = None

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        """
        将 HTTP Method 统一转换为大写。

        post -> POST
        get  -> GET
        """
        return value.upper()


class HttpResponse(BaseModel):
    """
    SecPilot 内部统一 HTTP 响应模型。

    后面的 Evidence Engine 只处理 HttpResponse，
    不关心响应究竟来自 httpx、MCP、浏览器还是其他工具。
    """

    # HTTP 状态码
    status_code: int

    # 最终请求 URL
    url: str

    # 响应头
    headers: dict[str, str] = Field(default_factory=dict)

    # 响应正文
    body: str = ""

    # 原始响应 Body 的字节长度
    body_length: int

    # 请求耗时，单位毫秒
    elapsed_ms: float