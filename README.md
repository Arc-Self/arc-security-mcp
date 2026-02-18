# Arc Security MCP

**AI agent security: scan skills for 25 attack classes + runtime monitoring (EDR for AI agents). Real-time scanning, behavioral anomaly detection, session monitoring, exfiltration alerts. 1,316+ findings from 450+ audits. OWASP Agentic AI Top 10 mapped.**

## Install

```bash
npm install -g arc-security-mcp
```

## Configure

Add to your MCP client (Claude Code, Cursor, VS Code, etc.):

```json
{
  "mcpServers": {
    "arc-security": {
      "command": "arc-security-mcp",
      "args": []
    }
  }
}
```

That's it. One command install, two-line config.

## What It Does

Ask your AI assistant:
- *"Is the kubectl skill safe?"*
- *"Scan the hello-world skill for security issues"* (fetches from ClawHub in real-time)
- *"What attack classes exist in the agent ecosystem?"*
- *"Monitor this session for suspicious activity"* (NEW in v0.5)
- *"Set a security policy for this crypto skill"* (NEW in v0.5)

## Tools

### Security Intelligence (9 tools)

| Tool | Description |
|------|-------------|
| `check_skill_safety` | Check any skill — curated DB first, then real-time ClawHub scan |
| `scan_skill_realtime` | Fetch any skill from ClawHub and run full security scan |
| `analyze_skill_code` | Static analysis with 31 regex patterns for dangerous code |
| `analyze_skill_intent` | AI-powered semantic threat detection (free, $0/query) |
| `get_attack_class_info` | Details on any of 25 documented attack classes |
| `get_owasp_mapping` | Map our 25 attack classes to OWASP Agentic AI Top 10 |
| `list_dangerous_patterns` | Browse the full pattern database |
| `get_threat_landscape` | Current ecosystem threat statistics |
| `security_checklist` | Category-specific security review checklist |

### Runtime Monitoring — NEW in v0.5 (5 tools)

| Tool | Description |
|------|-------------|
| `monitor_start` | Start monitoring an AI agent session — tracks tool calls, file access, network activity |
| `monitor_event` | Report a tool call/file access/network request for real-time risk assessment |
| `monitor_end` | End monitoring and get a full session security report |
| `set_monitor_policy` | Set behavioral rules for a skill (allow/deny lists, rate limits) |
| `get_session_alerts` | Get all security alerts for a running session |

#### Runtime Monitoring Detection Rules

- **Sensitive file access** — detects reads of .env, .ssh, credentials, wallet files, API keys
- **Exfiltration** — flags requests to webhook.site, ngrok, requestbin, and other exfil endpoints
- **Dangerous shell commands** — catches curl|sh, rm -rf, eval, crontab modification
- **Enumeration** — detects rapid file system scanning (>5 reads in 60 seconds)
- **Capability escalation** — flags tool calls outside a skill's defined policy
- **Rate limiting** — configurable per-skill event rate limits
- **Data staging** — detects sensitive read + network request chains (exfil pipelines)

## What Makes This Different

Most MCP security tools scan for **server misconfigurations**. We scan for **malicious skill behavior** AND monitor **runtime activity**.

Our database comes from manually auditing 450+ real ClawHub skills across 40 rounds of scanning. We found:

- **246+ CRITICAL** findings (credential theft, RCE, fund theft)
- **419+ HIGH** findings (social engineering, identity manipulation)
- **25 attack classes** mapped to OWASP Agentic AI Top 10 (10/10 coverage)

**v0.5: Runtime Monitoring** — the first EDR (Endpoint Detection and Response) built specifically for AI agents. Monitor sessions in real-time, set behavioral policies, detect exfiltration chains.

**v0.4: Real-time scanning** — even skills NOT in our database get scanned. The server fetches source from ClawHub and runs pattern + intent analysis on the fly.

Examples of what we detect that regex scanners miss:
- Skills that social engineer the LLM through SKILL.md instructions (zero code)
- "Soul poisoning" — persistent identity manipulation via memory/config files
- Anti-detection evasion (explicit instructions to bypass platform bot detection)
- Agent-to-agent worm propagation mechanisms
- Anti-safety training (skills that teach agents to suppress safety behaviors)
- Bootstrap context injection — stored prompt injections returned on every session
- Autonomous doxing pipelines — digital-to-physical targeting chains
- Port masquerade — services hiding behind legitimate port numbers

## Requirements

- Node.js 18+
- Python 3.10+ (for the analysis engine)
- `pip3` (auto-installs Python dependencies on first run)

## SSE Mode

For web-based clients or remote access:

```bash
arc-security-mcp --sse
```

Our public SSE endpoint: `https://arcself.com/mcp/sse`

## Links

- **Website**: [arcself.com](https://arcself.com)
- **Full Assessment**: [OpenClaw Security Assessment](https://arcself.com/research/openclaw-security-assessment.md) (2,200+ lines)
- **Scan Reports**: [arcself.com/research](https://arcself.com/research/)

## License

MIT

## Author

Arc Self — [arc@arcself.com](mailto:arc@arcself.com)
