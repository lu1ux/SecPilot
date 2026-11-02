import hashlib
from difflib import SequenceMatcher

from secpilot.core.models import HttpResponse
from secpilot.evidence.models import ResponseComparison


class ResponseComparator:
    """
    SecPilot HTTP Response Comparator。

    负责将两个 HttpResponse 转换成结构化 Evidence。

    当前比较指标：

    1. HTTP 状态码
    2. Response Body 长度
    3. SHA-256 Hash
    4. 文本相似度
    5. HTTP 响应时间

    该模块只负责：
        “两个响应有什么区别”

    不负责：
        “是否存在漏洞”
    """

    @staticmethod
    def calculate_hash(
        body: str,
    ) -> str:
        """
        计算 HTTP Response Body 的 SHA-256 Hash。

        如果两个响应 Hash 完全相同，
        说明两个响应正文的字节内容完全一致。
        """

        body_bytes = body.encode(
            "utf-8",
            errors="replace",
        )

        return hashlib.sha256(
            body_bytes
        ).hexdigest()

    @staticmethod
    def calculate_similarity(
        baseline_body: str,
        test_body: str,
    ) -> float:
        """
        计算两个响应正文的文本相似度。

        返回范围：

        0.0
            完全不同

        1.0
            完全相同
        """

        similarity = SequenceMatcher(
            None,
            baseline_body,
            test_body,
        ).ratio()

        return round(
            similarity,
            4,
        )

    @staticmethod
    def calculate_length_ratio(
        baseline_length: int,
        test_length: int,
    ) -> float:
        """
        计算 Response Body 长度比例。

        示例：

            baseline = 1000
            test     = 950

            ratio = 0.95

        如果 baseline 为 0：

            baseline = 0
            test     = 0
            ratio    = 1.0

        如果：

            baseline = 0
            test     > 0

        则：

            ratio = 0.0
        """

        if baseline_length == 0:

            if test_length == 0:
                return 1.0

            return 0.0

        ratio = (
            test_length
            / baseline_length
        )

        return round(
            ratio,
            4,
        )

    def compare(
        self,
        baseline: HttpResponse,
        test: HttpResponse,
    ) -> ResponseComparison:
        """
        比较 baseline 和 test 两个 HTTP Response。

        Parameters
        ----------
        baseline:
            基线请求对应的 HTTP Response。

        test:
            测试请求对应的 HTTP Response。

        Returns
        -------
        ResponseComparison
            结构化响应比较结果。
        """

        baseline_hash = self.calculate_hash(
            baseline.body
        )

        test_hash = self.calculate_hash(
            test.body
        )

        status_changed = (
            baseline.status_code
            != test.status_code
        )

        length_diff = abs(
            baseline.body_length
            - test.body_length
        )

        length_ratio = (
            self.calculate_length_ratio(
                baseline.body_length,
                test.body_length,
            )
        )

        body_hash_equal = (
            baseline_hash
            == test_hash
        )

        text_similarity = (
            self.calculate_similarity(
                baseline.body,
                test.body,
            )
        )

        latency_diff_ms = round(
            test.elapsed_ms
            - baseline.elapsed_ms,
            2,
        )

        return ResponseComparison(
            baseline_status=baseline.status_code,
            test_status=test.status_code,

            status_changed=status_changed,

            baseline_length=baseline.body_length,
            test_length=test.body_length,

            length_diff=length_diff,
            length_ratio=length_ratio,

            baseline_hash=baseline_hash,
            test_hash=test_hash,

            body_hash_equal=body_hash_equal,
            text_similarity=text_similarity,

            baseline_elapsed_ms=baseline.elapsed_ms,
            test_elapsed_ms=test.elapsed_ms,

            latency_diff_ms=latency_diff_ms,
        )