---
name: security-audit
description: Audit MCP servers and AI agent skills for security vulnerabilities
---

# Security Audit Skill

When the user asks you to audit a skill, MCP server, plugin, or code for security vulnerabilities, use the arc-security MCP tools to perform a comprehensive assessment.

## Available Tools

Use the `arc-security` MCP server tools:

- **scan_skill**: Scan a skill's SKILL.md content for attack patterns. Pass the full text of the skill.
- **check_pattern**: Look up a specific attack pattern by name or ID.
- **list_patterns**: List all known attack patterns with severity ratings.
- **scan_tool_call**: Analyze a single MCP tool call for security risks (runtime monitoring).
- **check_session_anomaly**: Check if current session behavior deviates from baseline.
- **detect_exfiltration**: Check if a URL or data transfer looks like data exfiltration.

## Audit Methodology

When performing a security audit:

1. **Read the skill/plugin source** — Get the SKILL.md, plugin.json, .mcp.json, and any code files
2. **Scan for known patterns** — Use `scan_skill` to check against 81 known attack patterns
3. **Check tool definitions** — Look for unrestricted shell execution, file access, network access
4. **Assess credential exposure** — Identify what secrets/tokens the skill requires and how they're stored
5. **Map attack surface** — Document what external services are accessed and what permissions are granted
6. **Rate the risk** — Assign a severity (CRITICAL/HIGH/MEDIUM/LOW) based on exploitability and impact

## Report Format

Structure findings as:

```
## [Skill Name] — Risk: X/10

### Findings
- **[ID]-01**: [Finding title] (SEVERITY)
  - Description
  - Attack scenario
  - Recommendation

### Attack Patterns Matched
- Pattern #XX: [Name]

### Recommendation
[Overall assessment and remediation guidance]
```
