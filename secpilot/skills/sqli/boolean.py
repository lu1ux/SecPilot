from typing import Protocol

from secpilot.core.models import (
    HttpRequest,
    HttpResponse,
)
from secpilot.evidence.comparator import (
    ResponseComparator,
)
from secpilot.skills.sqli.context import (
    ParameterContext,
    ParameterContextDetector,
)
from secpilot.skills.sqli.models import (
    BooleanSQLiRound,
    BooleanSQLiVerificationResult,
    VerificationStatus,
)
from secpilot.skills.sqli.strategies import (
    BooleanMutationStrategy,
    NumericBooleanStrategy,
)


class UnsupportedParameterContextError(
    ValueError
):
    """
    当前 SQLi Skill 没有可用于指定参数上下文的
    Mutation Strategy 时抛出。
    """

    pass


class HttpExecutorProtocol(
    Protocol
):
    """
    SQLi Skill 所依赖的 HTTP 执行接口。

    Skill 不直接绑定具体 HttpExecutor。

    只要一个对象实现：

        async execute(HttpRequest)
            -> HttpResponse

    就可以作为 Executor 使用。

    未来 MCP HTTP Executor
    也可以直接实现这个接口。
    """

    async def execute(
        self,
        request: HttpRequest,
    ) -> HttpResponse:
        ...


class BooleanSQLiSkill:
    """
    Boolean-based SQL Injection
    Verification Skill。

    工作流程：

        Parameter
            ↓
        Context Detection
            ↓
        Strategy Selection
            ↓
        Baseline Request
            ↓
        Boolean True Request
            ↓
        Boolean False Request
            ↓
        Evidence Comparison
            ↓
        Round Decision
            ↓
        Multi-round Verification
            ↓
        Final Decision

    当前版本真正实现：

        NUMERIC
            ↓
        NumericBooleanStrategy

    后续可以继续加入：

        STRING_SINGLE_QUOTE
        STRING_DOUBLE_QUOTE
    """

    def __init__(
        self,
        executor: HttpExecutorProtocol,
        comparator: (
            ResponseComparator | None
        ) = None,
        strategies: (
            list[
                BooleanMutationStrategy
            ]
            | None
        ) = None,
        true_similarity_threshold: (
            float
        ) = 0.90,
        false_similarity_threshold: (
            float
        ) = 0.70,
        minimum_similarity_gap: (
            float
        ) = 0.15,
    ):
        self.executor = executor

        self.comparator = (
            comparator
            or ResponseComparator()
        )

        self.strategies = (
            strategies
            or [
                NumericBooleanStrategy()
            ]
        )

        self.true_similarity_threshold = (
            true_similarity_threshold
        )

        self.false_similarity_threshold = (
            false_similarity_threshold
        )

        self.minimum_similarity_gap = (
            minimum_similarity_gap
        )

    @staticmethod
    def _validate_parameter(
        request: HttpRequest,
        parameter: str,
    ) -> str:
        """
        检查目标参数是否存在。

        Returns
        -------
        str
            参数原始值。
        """

        if parameter not in request.params:
            raise ValueError(
                f"目标参数不存在: "
                f"{parameter}"
            )

        return request.params[
            parameter
        ]

    @staticmethod
    def _detect_context(
        value: str,
    ) -> ParameterContext:
        """
        调用 ParameterContextDetector
        判断参数上下文。
        """

        return (
            ParameterContextDetector
            .detect(
                value
            )
        )

    def _select_strategy(
        self,
        context: ParameterContext,
    ) -> BooleanMutationStrategy:
        """
        根据 ParameterContext
        选择对应 Mutation Strategy。
        """

        for strategy in self.strategies:

            if strategy.supports(
                context
            ):
                return strategy

        raise (
            UnsupportedParameterContextError(
                "当前没有支持该参数上下文的 "
                f"SQLi Strategy: "
                f"{context}"
            )
        )

    @staticmethod
    def _build_request(
        base_request: HttpRequest,
        parameter: str,
        value: str,
    ) -> HttpRequest:
        """
        根据原始请求构造新的测试请求。

        使用 deep copy 防止修改测试请求时
        污染原始 HttpRequest。
        """

        request = (
            base_request.model_copy(
                deep=True
            )
        )

        request.params[
            parameter
        ] = value

        return request

    def _is_round_passed(
        self,
        true_similarity: float,
        false_similarity: float,
        true_status_changed: bool,
    ) -> bool:
        """
        判断单轮 Evidence
        是否符合 Boolean SQLi 特征。

        当前规则：

        1. TRUE 与 baseline 高度相似

        2. FALSE 与 baseline 明显不同

        3. TRUE/FALSE 之间存在足够大的
           similarity gap

        4. TRUE 请求不应该导致
           HTTP Status 异常变化
        """

        similarity_gap = (
            true_similarity
            - false_similarity
        )

        return (
            true_similarity
            >= self.true_similarity_threshold

            and false_similarity
            <= self.false_similarity_threshold

            and similarity_gap
            >= self.minimum_similarity_gap

            and not true_status_changed
        )

    @staticmethod
    def _decide_status(
        passed_rounds: int,
        total_rounds: int,
    ) -> VerificationStatus:
        """
        根据多轮验证结果生成最终状态。

        All Passed:
            CONFIRMED

        Partial Passed:
            SUSPECTED

        None Passed:
            REJECTED
        """

        if (
            passed_rounds
            == total_rounds
        ):
            return (
                VerificationStatus
                .CONFIRMED
            )

        if passed_rounds > 0:
            return (
                VerificationStatus
                .SUSPECTED
            )

        return (
            VerificationStatus
            .REJECTED
        )

    async def verify(
        self,
        request: HttpRequest,
        parameter: str,
        rounds: int = 3,
    ) -> BooleanSQLiVerificationResult:
        """
        验证指定参数是否存在稳定的
        Boolean-based SQL Injection 行为。

        Parameters
        ----------
        request:
            原始 HTTP Request。

        parameter:
            待测试 GET 参数。

        rounds:
            验证轮数。
            默认 3。
            最多 5。

        Returns
        -------
        BooleanSQLiVerificationResult
        """

        if rounds < 1:
            raise ValueError(
                "rounds 必须大于等于 1"
            )

        if rounds > 5:
            raise ValueError(
                "单次验证最多允许 5 轮"
            )

        # ================================================
        # 1. Parameter
        # ================================================

        original_value = (
            self._validate_parameter(
                request,
                parameter,
            )
        )

        # ================================================
        # 2. Context Detection
        # ================================================

        context = (
            self._detect_context(
                original_value
            )
        )

        # ================================================
        # 3. Strategy Selection
        # ================================================

        strategy = (
            self._select_strategy(
                context
            )
        )

        mutations = strategy.build(
            original_value=(
                original_value
            ),
            context=context,
        )

        round_results: list[
            BooleanSQLiRound
        ] = []

        passed_rounds = 0

        # ================================================
        # 4. Multi-round Verification
        # ================================================

        for round_number in range(
            1,
            rounds + 1,
        ):

            # --------------------------------------------
            # Baseline
            # --------------------------------------------

            baseline_request = (
                self._build_request(
                    base_request=request,
                    parameter=parameter,
                    value=(
                        mutations
                        .original_value
                    ),
                )
            )

            baseline_response = (
                await self.executor.execute(
                    baseline_request
                )
            )

            # --------------------------------------------
            # Boolean TRUE
            # --------------------------------------------

            true_request = (
                self._build_request(
                    base_request=request,
                    parameter=parameter,
                    value=(
                        mutations
                        .true_value
                    ),
                )
            )

            true_response = (
                await self.executor.execute(
                    true_request
                )
            )

            # --------------------------------------------
            # Boolean FALSE
            # --------------------------------------------

            false_request = (
                self._build_request(
                    base_request=request,
                    parameter=parameter,
                    value=(
                        mutations
                        .false_value
                    ),
                )
            )

            false_response = (
                await self.executor.execute(
                    false_request
                )
            )

            # ============================================
            # 5. Evidence
            # ============================================

            true_comparison = (
                self.comparator.compare(
                    baseline_response,
                    true_response,
                )
            )

            false_comparison = (
                self.comparator.compare(
                    baseline_response,
                    false_response,
                )
            )

            # ============================================
            # 6. Round Decision
            # ============================================

            passed = (
                self._is_round_passed(
                    true_similarity=(
                        true_comparison
                        .text_similarity
                    ),

                    false_similarity=(
                        false_comparison
                        .text_similarity
                    ),

                    true_status_changed=(
                        true_comparison
                        .status_changed
                    ),
                )
            )

            if passed:
                passed_rounds += 1

            round_results.append(
                BooleanSQLiRound(
                    round_number=(
                        round_number
                    ),

                    mutations=mutations,

                    true_comparison=(
                        true_comparison
                    ),

                    false_comparison=(
                        false_comparison
                    ),

                    passed=passed,
                )
            )

        # ================================================
        # 7. Final Decision
        # ================================================

        status = self._decide_status(
            passed_rounds=(
                passed_rounds
            ),
            total_rounds=rounds,
        )

        confidence = round(
            passed_rounds
            / rounds,
            4,
        )

        return (
            BooleanSQLiVerificationResult(
                parameter=parameter,

                context=context,

                strategy_name=(
                    strategy.name
                ),

                status=status,

                confidence=confidence,

                passed_rounds=(
                    passed_rounds
                ),

                total_rounds=rounds,

                rounds=round_results,
            )
        )