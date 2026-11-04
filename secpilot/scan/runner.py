from datetime import (
    datetime,
    timezone,
)

from secpilot.agent.runner import (
    AgentRunner,
    AgentRunStatus,
)
from secpilot.core.models import (
    HttpRequest,
)
from secpilot.report.models import (
    ScanReport,
    ScanRequestResult,
    ScanRequestStatus,
    compute_stats,
    derive_target,
)
from secpilot.risk.engine import (
    RiskEngine,
)
from secpilot.scan.models import (
    ScanTask,
)


class ScanRunner:
    """
    SecPilot 批量扫描编排器。

    整体流程：

        list[HttpRequest]
            ↓ 逐个顺序执行
        AgentRunner
            ↓
        ScanRequestResult 列表
            ↓
        RiskEngine 评级
            ↓
        compute_stats
            ↓
        ScanReport

    设计原则：

        1. 顺序执行，不并发，
           对授权目标保持友好

        2. 单请求失败不中断整体扫描，
           异常转换为 ERROR 状态记录

        3. 纯内存操作，不写文件；
           文件输出由调用方通过
           Report 渲染器自行完成

        4. LLM Plan 保留在结果中，
           作为决策审计追踪
    """

    def __init__(
        self,
        agent_runner: AgentRunner,
        risk_engine: RiskEngine,
    ):
        self.agent_runner = (
            agent_runner
        )

        self.risk_engine = (
            risk_engine
        )

    async def _run_task(
        self,
        *,
        task: ScanTask,
    ) -> ScanRequestResult:
        """
        执行单个扫描任务。

        这里捕获 Exception 而不是具体异常：

            Skill / LLM / Mapper 的失败方式
            无法穷举，批量扫描的容错边界
            必须覆盖一切运行期错误。

        BaseException 不捕获，
        KeyboardInterrupt 等仍然向外传播。
        """

        request = task.request

        started_at = datetime.now(
            timezone.utc
        )

        # ================================================
        # 1. AgentRunner 执行
        # ================================================

        try:

            run_result = (
                await
                self.agent_runner
                .run(request)
            )

        except Exception as error:

            finished_at = datetime.now(
                timezone.utc
            )

            return ScanRequestResult(
                request_id=task.id,

                method=(
                    request.method
                ),

                url=request.url,

                started_at=started_at,

                finished_at=finished_at,

                status=(
                    ScanRequestStatus
                    .ERROR
                ),

                error_message=(
                    f"{type(error).__name__}: "
                    f"{error}"
                ),
            )

        finished_at = datetime.now(
            timezone.utc
        )

        # ================================================
        # 2. NO_ACTION
        # ================================================

        if (
            run_result.status
            == AgentRunStatus.NO_ACTION
        ):

            return ScanRequestResult(
                request_id=task.id,

                method=(
                    request.method
                ),

                url=request.url,

                started_at=started_at,

                finished_at=finished_at,

                status=(
                    ScanRequestStatus
                    .NO_ACTION
                ),

                plan=(
                    run_result.plan
                ),
            )

        # ================================================
        # 3. EXECUTED + RiskEngine 评级
        # ================================================

        finding = (
            run_result.finding
        )

        if finding is not None:

            finding = (
                self.risk_engine
                .rate(finding)
            )

        return ScanRequestResult(
            request_id=task.id,

            method=request.method,

            url=request.url,

            started_at=started_at,

            finished_at=finished_at,

            status=(
                ScanRequestStatus
                .EXECUTED
            ),

            plan=run_result.plan,

            finding=finding,
        )

    async def run_scan(
        self,
        requests: list[
            HttpRequest
        ],
    ) -> ScanReport:
        """
        顺序扫描一批请求，
        产出完整 ScanReport。
        """

        scan_started_at = (
            datetime.now(
                timezone.utc
            )
        )

        request_results: list[
            ScanRequestResult
        ] = []

        for request in requests:

            task = ScanTask(
                request=request,
            )

            result = (
                await self._run_task(
                    task=task,
                )
            )

            request_results.append(
                result
            )

        scan_finished_at = (
            datetime.now(
                timezone.utc
            )
        )

        findings = [
            result.finding
            for result in (
                request_results
            )
            if result.finding
            is not None
        ]

        return ScanReport(
            target=derive_target(
                requests
            ),

            started_at=(
                scan_started_at
            ),

            finished_at=(
                scan_finished_at
            ),

            request_results=(
                request_results
            ),

            findings=findings,

            stats=compute_stats(
                request_results=(
                    request_results
                ),

                findings=findings,
            ),
        )
