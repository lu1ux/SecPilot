import asyncio
import threading
from http.server import (
    BaseHTTPRequestHandler,
    ThreadingHTTPServer,
)
from pathlib import Path
from urllib.parse import (
    parse_qs,
    urlparse,
)

from secpilot.agent.analysis import (
    AnalysisAgent,
)
from secpilot.agent.runner import (
    AgentRunner,
)
from secpilot.core.finding_mapper import (
    FindingMapperRegistry,
)
from secpilot.core.models import (
    HttpRequest,
)
from secpilot.llm import (
    LLMConfiguration,
    create_default_provider_registry,
)
from secpilot.policy.engine import (
    PolicyEngine,
)
from secpilot.report.renderers import (
    render_report_json,
    render_report_markdown,
)
from secpilot.risk.engine import (
    RiskEngine,
)
from secpilot.scan.runner import (
    ScanRunner,
)
from secpilot.skills.registry import (
    SkillRegistry,
)
from secpilot.skills.sqli.boolean import (
    BooleanSQLiSkill,
)
from secpilot.skills.sqli.finding import (
    boolean_sqli_result_to_finding,
)
from secpilot.tools.http_executor import (
    HttpExecutor,
)


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


class DemoTargetHandler(
    BaseHTTPRequestHandler
):
    """
    SecPilot 本地授权演示目标。

    这里只模拟一个 Boolean 行为：

        id=1
            → PRODUCT_FOUND

        TRUE condition
            → PRODUCT_FOUND

        FALSE condition
            → NO_RESULT

    这里只用于展示 SecPilot
    完整 AI Security Testing Loop。
    """

    def do_GET(
        self,
    ):
        parsed = urlparse(
            self.path
        )

        if (
            parsed.path
            != "/product"
        ):
            self.send_response(
                404
            )

            self.end_headers()

            return

        params = parse_qs(
            parsed.query
        )

        value = (
            params
            .get(
                "id",
                [""],
            )[0]
        )

        if "1=2" in value:

            body = (
                b"NO_RESULT"
            )

        else:

            body = (
                b"PRODUCT_FOUND"
            )

        self.send_response(
            200
        )

        self.send_header(
            "Content-Type",
            "text/plain; charset=utf-8",
        )

        self.send_header(
            "Content-Length",
            str(
                len(body)
            ),
        )

        self.end_headers()

        self.wfile.write(
            body
        )

    def log_message(
        self,
        format,
        *args,
    ):
        """
        关闭演示 HTTP Server
        默认请求日志。
        """

        pass


def start_demo_target():

    server = ThreadingHTTPServer(
        (
            "127.0.0.1",
            0,
        ),
        DemoTargetHandler,
    )

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )

    thread.start()

    host, port = (
        server.server_address
    )

    return (
        server,
        thread,
        f"http://{host}:{port}",
    )


async def main():

    server = None
    thread = None

    try:

        # ====================================================
        # 1. Local Authorized Demo Target
        # ====================================================

        (
            server,
            thread,
            base_url,
        ) = start_demo_target()

        target_url = (
            f"{base_url}/product"
        )

        print(
            "\n=== Authorized Demo Target ==="
        )

        print(
            target_url
        )

        # ====================================================
        # 2. LLM Configuration
        # ====================================================

        llm_config = (
            LLMConfiguration.load(
                config_path=(
                    PROJECT_ROOT
                    / "config"
                    / "llm.example.yaml"
                ),

                env_file=(
                    PROJECT_ROOT
                    / ".env"
                ),
            )
        )

        profile = (
            llm_config.resolve()
        )

        provider_registry = (
            create_default_provider_registry()
        )

        provider = (
            provider_registry.create(
                profile
            )
        )

        print(
            "\n=== LLM ==="
        )

        print(
            profile.name
        )

        print(
            profile.model
        )

        # ====================================================
        # 3. Security Runtime
        # ====================================================

        policy = PolicyEngine(
            PROJECT_ROOT
            / "config"
            / "policy.example.yaml"
        )

        executor = HttpExecutor(
            policy
        )

        boolean_sqli = (
            BooleanSQLiSkill(
                executor=executor
            )
        )

        # ====================================================
        # 4. Skill Registry
        # ====================================================

        skill_registry = (
            SkillRegistry()
        )

        skill_registry.register(
            "boolean_sqli",
            boolean_sqli,
        )

        # ====================================================
        # 5. Finding Mapper Registry
        # ====================================================

        finding_mappers = (
            FindingMapperRegistry()
        )

        finding_mappers.register(
            "boolean_sqli",
            boolean_sqli_result_to_finding,
        )

        # ====================================================
        # 6. Analysis Agent
        # ====================================================

        agent = AnalysisAgent(
            provider=provider,

            registry=(
                skill_registry
            ),
        )

        # ====================================================
        # 7. Agent Runner
        # ====================================================

        runner = AgentRunner(
            agent=agent,

            finding_mappers=(
                finding_mappers
            ),
        )

        # ====================================================
        # 8. Batch Scan Requests
        #
        # 1. /product?id=1        可注入参数
        # 2. /product?id=7        可注入参数
        # 3. /nonexistent?id=1    不存在的路径
        #    所有验证轮失败
        #    → REJECTED / INFO
        # ====================================================

        requests = [
            HttpRequest(
                method="GET",

                url=target_url,

                params={
                    "id": "1"
                },
            ),

            HttpRequest(
                method="GET",

                url=target_url,

                params={
                    "id": "7"
                },
            ),

            HttpRequest(
                method="GET",

                url=(
                    f"{base_url}"
                    f"/nonexistent"
                ),

                params={
                    "id": "1"
                },
            ),
        ]

        # ====================================================
        # 9. Batch Scan
        #
        # ScanRunner 负责：
        #
        #     顺序执行
        #     单请求失败不中断
        #     RiskEngine 评级
        #     汇总 ScanReport
        # ====================================================

        scan_runner = ScanRunner(
            agent_runner=runner,

            risk_engine=RiskEngine(),
        )

        report = (
            await scan_runner
            .run_scan(requests)
        )

        # ====================================================
        # 10. Report Output
        #
        # output/ 已在 .gitignore 中。
        # 文件名带报告 ID 前缀，
        # 多次运行互不覆盖。
        # ====================================================

        output_dir = (
            PROJECT_ROOT
            / "output"
        )

        output_dir.mkdir(
            exist_ok=True
        )

        json_path = (
            output_dir
            / f"{report.id[:8]}_report.json"
        )

        markdown_path = (
            output_dir
            / f"{report.id[:8]}_report.md"
        )

        json_path.write_text(
            render_report_json(
                report
            ),

            encoding="utf-8",
        )

        markdown_path.write_text(
            render_report_markdown(
                report
            ),

            encoding="utf-8",
        )

        # ====================================================
        # 11. Summary
        # ====================================================

        stats = report.stats

        print(
            "\n=== Scan Summary ==="
        )

        print(
            f"报告 ID: {report.id}"
        )

        print(
            f"目标: {report.target}"
        )

        print(
            f"请求: {stats.total_requests}"
            f"（执行 {stats.executed}"
            f" / 无动作 {stats.no_action}"
            f" / 失败 {stats.errors}）"
        )

        print(
            f"漏洞发现: "
            f"{stats.total_findings}"
        )

        for severity, count in (
            stats.by_severity.items()
        ):

            print(
                f"  {severity}: "
                f"{count}"
            )

        if report.findings:

            print(
                "\n=== Findings ==="
            )

            for finding in (
                report.findings
            ):

                print(
                    f"[{finding.severity.value}] "
                    f"{finding.title} "
                    f"({finding.status.value})"
                    f" -> "
                    f"{finding.target}"
                )

        print(
            f"\nJSON 报告: "
            f"{json_path}"
        )

        print(
            f"Markdown 报告: "
            f"{markdown_path}"
        )

    finally:

        if server is not None:

            server.shutdown()

            server.server_close()

        if thread is not None:

            thread.join(
                timeout=2
            )


if __name__ == "__main__":

    asyncio.run(
        main()
    )