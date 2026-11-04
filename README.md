# SecPilot

SecPilot is an evidence-driven AI-assisted Web security testing framework.

## Core Architecture

ScanRunner (Batch)
→ Agent
→ Security Skill
→ Policy Engine
→ MCP / Tool
→ Target
→ Evidence Engine
→ Finding
→ Risk Engine
→ Report (JSON / Markdown)

## Core Principles

- Agent decides what to investigate
- Security Skill defines how to investigate
- Policy Engine decides whether the action is allowed
- MCP / Tools execute actions
- Evidence Engine verifies vulnerability evidence

## Roadmap

- [x] HTTP Request / Response Model
- [x] Scope Policy Engine
- [x] HTTP Executor
- [x] Evidence Engine
- [x] Boolean SQL Injection Skill
- [x] MCP Integration
- [x] LLM Agent
- [x] Risk Engine
- [x] Scan Report (JSON / Markdown)
- [x] Batch Scan Orchestration
- [ ] Web Recon
- [ ] Iterative Agent Loop
- [ ] XSS Skill
- [ ] IDOR Skill
- [ ] Benchmark
- [ ] Web UI

## Disclaimer

SecPilot is intended only for authorized security testing, security research and educational environments.
