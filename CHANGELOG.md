# Changelog

All notable changes to SecPilot will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Rule-based Risk Engine: rates every Finding from a vulnerability-type base severity table, adjusted by verification status (REJECTED → INFO, SUSPECTED → downgrade one level) and confidence (CONFIRMED below 0.6 → downgrade). Rating rationale is recorded in `Finding.metadata["risk_rationale"]` / `["risk_rule"]`. / 规则化风险评级引擎：以漏洞类型确定基础严重程度，按验证状态与置信度修正评级，评级依据写入 `Finding.metadata`。

- Scan Report module: `ScanReport` model with per-request results (preserving the LLM `SecurityPlan` as an audit trail), aggregate stats, and pure-function renderers for JSON and Markdown output. / 扫描报告模块：`ScanReport` 模型保留 LLM 决策作为审计追踪，含汇总统计，提供 JSON / Markdown 双格式纯函数渲染器。

- `ScanRunner` batch orchestration: scans a list of `HttpRequest` sequentially with per-request fault tolerance — a failing request is recorded as `ERROR` without aborting the batch. / `ScanRunner` 批量扫描编排：顺序扫描请求列表，逐请求容错，单请求失败记录为 `ERROR` 不中断整体扫描。

- Full batch scan pipeline demo in `examples/ai_security_loop.py`: three requests against a local authorized demo target, writing timestamped `output/<id>_report.json` and `output/<id>_report.md`. / `examples/ai_security_loop.py` 演示完整批量扫描流水线，输出带报告 ID 前缀的 JSON / Markdown 报告文件。

- Shared test fakes (`FakeProvider`, `ScriptedProvider`, builders) extracted to `tests/fakes.py`. / 共享测试 fakes 与构造辅助函数提取到 `tests/fakes.py`。
