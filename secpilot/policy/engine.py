from pathlib import Path
from urllib.parse import urlparse

import yaml


class PolicyViolation(Exception):
    """
    当 SecPilot 的操作违反安全策略时抛出。
    """

    pass


class PolicyEngine:
    """
    SecPilot 安全策略引擎。
    """

    def __init__(
            self,
            config_path: str | Path
    ):
        self.config_path = Path(config_path)

        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Policy 配置文件不存在: {config_path}"
            )

        with self.config_path.open(
            "r",
            encoding="utf-8"
        ) as file:
            config = yaml.safe_load(file) or {}

        scope = config.get("scope", {})
        http = config.get("http", {})
        network = config.get("network", {})

        self.allowed_hosts = {
            host.lower()
            for host in scope.get(
                "allowed_hosts",
                []
            )
        }

        self.allowed_schemes = {
            scheme.lower()
            for scheme in scope.get(
                "allowed_schemes",
                ["http", "https"]
            )
        }

        self.timeout_seconds = http.get(
            "timeout_seconds",
            10
        )

        self.follow_redirects = http.get(
            "follow_redirects",
            False
        )

        self.max_response_size = network.get(
            "max_response_size",
            1024 * 1024
        )

    def validate_url(self, url: str) -> None:
        """
        判断 URL 是否处于 SecPilot 授权范围内。

        通过：
            不返回任何内容

        失败：
            抛出 PolicyViolation
        """

        parsed = urlparse(url)

        if not parsed.scheme:
            raise PolicyViolation(
                "URL 缺少协议"
            )

        scheme = parsed.scheme.lower()

        if scheme not in self.allowed_schemes:
            raise PolicyViolation(
                f"协议不允许: {scheme}"
            )

        hostname = parsed.hostname

        if hostname is None:
            raise PolicyViolation(
                "无法解析目标主机"
            )

        hostname = hostname.lower()

        if hostname not in self.allowed_hosts:
            raise PolicyViolation(
                f"目标不在授权 Scope 内: {hostname}"
            )

        if parsed.username or parsed.password:
            raise PolicyViolation(
                "URL 中不允许直接携带用户名或密码"
            )