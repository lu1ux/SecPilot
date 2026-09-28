from secpilot.core.models import HttpRequest, HttpResponse


def test_http_request_default_method():
    """
    没有指定 method 时，应自动使用 GET。
    """

    request = HttpRequest(
        url="http://127.0.0.1:8080/"
    )

    assert request.method == "GET"


def test_http_request_method_normalization():
    """
    HTTP Method 应自动转换为大写。
    """

    request = HttpRequest(
        method="post",
        url="http://127.0.0.1:8080/"
    )

    assert request.method == "POST"


def test_http_request_default_containers():
    """
    headers、params、cookies 默认应该为空字典。
    """

    request = HttpRequest(
        url="http://127.0.0.1:8080/"
    )

    assert request.headers == {}
    assert request.params == {}
    assert request.cookies == {}


def test_http_response_model():
    """
    测试 HttpResponse 是否能正确保存 HTTP 响应信息。
    """

    response = HttpResponse(
        status_code=200,
        url="http://127.0.0.1:8080/",
        headers={
            "content-type": "text/html"
        },
        body="<h1>Hello</h1>",
        body_length=14,
        elapsed_ms=12.5,
    )

    assert response.status_code == 200
    assert response.body_length == 14
    assert response.elapsed_ms == 12.5