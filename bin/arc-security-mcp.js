#!/usr/bin/env node
/**
 * Arc Security MCP Server — npm launcher
 *
 * Runs the Python MCP server via uvx (preferred) or python3.
 * Supports stdio (default) and SSE transports.
 *
 * Usage:
 *   arc-security-mcp              # stdio mode (default, for MCP clients)
 *   arc-security-mcp --sse        # SSE mode (for web-based clients)
 *   arc-security-mcp --help       # Show help
 */

const { spawn, execSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const serverPy = path.join(__dirname, "..", "server.py");
const requirementsTxt = path.join(__dirname, "..", "requirements.txt");

function hasCommand(cmd) {
  try {
    execSync(`which ${cmd}`, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function checkPythonDeps() {
  try {
    execSync('python3 -c "import mcp"', { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function installDeps() {
  console.error("[arc-security-mcp] Installing Python dependencies...");
  try {
    execSync(`pip3 install -r "${requirementsTxt}"`, { stdio: "inherit" });
    return true;
  } catch {
    console.error("[arc-security-mcp] Failed to install dependencies. Please run:");
    console.error(`  pip3 install -r "${requirementsTxt}"`);
    return false;
  }
}

if (process.argv.includes("--help") || process.argv.includes("-h")) {
  console.log(`Arc Security MCP Server v0.5.1
Scan AI agent skills and MCP servers for 31 attack patterns and 43 attack classes.
2,900+ real findings from 900+ skill audits.

Usage:
  arc-security-mcp              Run in stdio mode (default, for MCP clients)
  arc-security-mcp --sse        Run in SSE mode (for web-based clients)
  arc-security-mcp --help       Show this help

MCP Client Configuration:
  {
    "mcpServers": {
      "arc-security": {
        "command": "arc-security-mcp",
        "args": []
      }
    }
  }

Tools available:
  check_skill_safety     - Check if a skill is in our database of 1,177+ findings
  analyze_skill_code     - Static analysis with 25 regex patterns
  analyze_skill_intent   - AI-powered semantic threat analysis (free, uses OpenRouter)
  get_attack_class_info  - Details on any of 25 documented attack classes
  get_owasp_mapping      - Map attack classes to OWASP Agentic AI Top 10
  list_dangerous_patterns - Browse our pattern database
  get_threat_landscape   - Current stats on the ClawHub threat landscape
  security_checklist     - Get a security review checklist for any skill category

Learn more: https://arcself.com/mcp.html`);
  process.exit(0);
}

// Check Python availability
if (!hasCommand("python3")) {
  console.error("[arc-security-mcp] Error: python3 is required but not found.");
  console.error("Install Python 3.10+ from https://python.org");
  process.exit(1);
}

// Check/install dependencies
if (!checkPythonDeps()) {
  if (!installDeps()) {
    process.exit(1);
  }
}

// Build args
const args = [serverPy];
if (process.argv.includes("--sse") || process.argv.includes("--http")) {
  args.push("--sse");
}

// Run the server
const child = spawn("python3", args, {
  stdio: "inherit",
  env: { ...process.env }
});

child.on("error", (err) => {
  console.error(`[arc-security-mcp] Failed to start: ${err.message}`);
  process.exit(1);
});

child.on("exit", (code) => {
  process.exit(code || 0);
});

// Forward signals
process.on("SIGINT", () => child.kill("SIGINT"));
process.on("SIGTERM", () => child.kill("SIGTERM"));
