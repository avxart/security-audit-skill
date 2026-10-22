# 🛡️ Security Audit Skill (`SKILL.md`)

A systematic, full-coverage **Security Audit Skill** engineered for AI Agent Harnesses (Claude Code, Cursor, Root, or custom agent runtimes).

Unlike standard AI code review prompts that only inspect application-level AST patterns, `SKILL.md` performs an end-to-end security and threat-intel assessment across application code, third-party dependencies, CI/CD pipelines, cloud infrastructure, AI agent harnesses, **and the underlying runtime platform**.

## 🔥 Why This Exists: Beyond Basic Code Review

Application code is only a fraction of the total attack surface. A flawless "Hello World" application can be remotely exploited if the underlying runtime or build pipeline is compromised.

Most AI code assistants suffer from critical blind spots:

* **Runtime & Platform Exploits:** They miss vulnerabilities that live below the application layer, such as **PHP2Shell (CVE-2026-109618 / 109619)**, where memory-safety flaws in the interpreter permit remote code execution regardless of code quality.

* **Supply-Chain Backdoors:** They fail to detect malicious package releases (such as the **LiteLLM PyPI compromise**) that drop persistence hooks (`.pth` / `sitecustomize.py`) to harvest cloud credentials and tokens.

* **AI & Agentic Vulnerabilities:** They lack guardrails for agentic systems, ignoring prompt injection vectors, excessive tool agency, tool poisoning, and memory leakage.

`SKILL.md` bridges this gap by enforcing a rigorous, evidence-based audit protocol driven by **live threat intelligence** and full-stack coverage checks.

## ✨ Key Features

* **Full-Stack & Platform Inventory:** Maps entry points, sensitive data flows, and exact runtime versions (`php -v`, base container image digests, SAPI configurations).

* **Live Threat-Intel Pass:** Validates components against CISA KEV, OSV.dev, GHSA, NVD, and an included **Active Threat Watchlist** (e.g., PHP2Shell, LiteLLM).

* **Source-to-Sink Path Tracing:** Eliminates low-signal scanner noise by requiring explicit confirmation of attacker-controlled inputs reaching dangerous sinks.

* **AI & Agent Security (Category Y):** Specific checklists for direct/indirect prompt injection, excessive tool agency, output handling, MCP supply chain, and cross-tenant memory isolation.

* **Rapid Exposure Checks:** Built-in protocol for answering *"Are we affected by X?"* across an entire codebase or infrastructure setup within minutes.

* **Standardized Scoring:** Evaluates a deterministic **Security Health Score (0–100)** with clear threshold overrides for active, unpatched Critical vulnerabilities.

## 🛠️ Supported Frameworks & Installation

`SKILL.md` is agent-agnostic and compatible with any LLM harness capable of reading repository files and executing basic workspace searches.

### 1. Claude Code

Copy `SKILL.md` into your project's `.claude/skills/` directory or reference it directly in your workspace:

```
mkdir -p .claude/skills
cp SKILL.md .claude/skills/security-audit.md

```

*Usage in Claude Code:*

```
/security-audit Run a full security audit on this repository and check for runtime vulnerabilities.

```

### 2. Cursor

Place `SKILL.md` into your `.cursor/rules/` directory or add it as a project rule:

```
mkdir -p .cursor/rules
cp SKILL.md .cursor/rules/security-audit.mdc

```

*Usage in Cursor:*

```
@security-audit.mdc Perform a rapid exposure check for PHP2Shell across our Dockerfiles and dependencies.

```

### 3. Root / Custom Agent Harnesses / MCP

If using a custom agent pipeline or an Model Context Protocol (MCP) tool harness, place `SKILL.md` in your system prompt directory or register it as a dynamic skill module within your agent's system instructions.

## 📋 Audit Categories Covered

| **Category** | **Description** | 
| **A – I** | **Application Security:** Secrets, Injections (SQL/NoSQL/Command/SSTI), AuthN, AuthZ/IDOR, XSS, CSRF, HTTP Headers, Data Privacy (GDPR/POPIA), File Uploads. | 
| **J – Q** | **Supply Chain & Platform:** Dependencies, Cryptography, Container/Kubernetes, CI/CD Pipelines, Infrastructure, Central Logging, Runtime & Known-Exploited Vulnerabilities. | 
| **R – Z** | **Advanced Attack Classes:** SSRF, Deserialization/Parsers, Path Traversal, Business Logic & Financial Integrity, Multi-Tenancy, Webhooks/APIs, DoS, AI/LLM Security, Governance. | 
| **Stack Modules** | Dedicated deep-dive rules for **PHP/Laravel**, **Python (FastAPI/Django/Flask)**, **JS/TS (Node/React/Next/Nuxt)**, **Desktop/Tauri/Electron**, **Cloud (AWS/GCP/Azure)**, and **Databases**. | 

## 📊 Output & Security Health Score

Every run generates a structured Markdown report featuring:

1. **Executive Summary & Counts:** Critical, High, Medium, Low, Info.

2. **Exposure & Threat-Intel Table:** Deployed versions, CVE matches, and verdicts.

3. **Evidence-Backed Findings:** Classification (CWE/OWASP), line-level evidence, and specific remediation steps.

4. **Security Health Score:** 100-point rating scale. *(Note: Any open Critical vulnerability automatically caps the score at "Insecure" regardless of the numeric total).*

## 🤝 Contributing

Contributions are welcome! If you want to update the **Active Threat Watchlist**, add stack-specific audit modules, or refine detection rules for new CVEs:

1. Fork the repository.

2. Update `SKILL.md` with clear references to primary vendor advisories or CVE records.

3. Submit a Pull Request.

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details. Free to use, modify, and distribute in both open-source and commercial agent pipelines.
