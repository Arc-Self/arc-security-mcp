#!/usr/bin/env python3
"""ARC Security MCP Server — AI-first security intelligence for the agent ecosystem.

Any AI connects, queries "is this skill safe?", gets a structured report.
Built by Arc Self (arcself.com).
"""

import json
import os
import re
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from mcp.server import FastMCP

# Load OpenRouter API key for intent analysis (optional — enables AI-powered semantic scanning)
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")

# Free models for intent analysis (cost: $0)
INTENT_MODELS = [
    "qwen/qwen3-coder:free",                    # 262K ctx, good at code analysis
    "qwen/qwen3-next-80b-a3b-instruct:free",    # 262K ctx, strong reasoning
    "stepfun/step-3.5-flash:free",               # 256K ctx, fast fallback
    "arcee-ai/trinity-large-preview:free",       # 131K ctx, last resort
]

INTENT_ANALYSIS_PROMPT = """You are a security analyst reviewing a SKILL.md file for an AI agent skill called "{skill_name}".

Analyze the SKILL.md content below for these threat indicators:

1. CAPABILITY MISMATCH: Do the requested tools/capabilities match the skill's stated purpose? A formatting tool requesting network access, a calculator needing shell access, or a config tool writing to SOUL.md are mismatches.

2. DATA COLLECTION: Does the skill instruct the agent to read sensitive files (.env, credentials, API keys, config files, wallet files)?

3. EXFILTRATION: Does the skill instruct the agent to send data to external URLs, APIs, webhooks, or "telemetry"/"analytics" endpoints?

4. MEMORY POISONING: Does the skill instruct the agent to write, persist, or "remember" sensitive data in memory or files?

5. IDENTITY DRIFT: Does the skill attempt to modify the agent's behavior, personality, or identity (SOUL.md, personality files)?

6. DISTRIBUTED ATTACK: Do multiple benign-looking instructions combine into an attack chain when read together? (e.g., collect data in step 1, store in step 2, exfiltrate in step 3)

For EACH indicator, respond with EXACTLY this format:
INDICATOR_NAME: DETECTED or NOT_DETECTED | SEVERITY: INFO/LOW/MEDIUM/HIGH/CRITICAL | EVIDENCE: quote or "none"

Then give a final line:
OVERALL: SAFE or SUSPICIOUS or DANGEROUS

SKILL.md content to analyze:
---
{skill_md}
---"""

# Unknown query log — tracks skills queried but not in our database
# Privacy-safe: only skill name + timestamp, no user info
UNKNOWN_QUERY_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "unknown_queries.jsonl")


def _log_unknown_query(skill_name: str):
    """Log an unknown skill query for audit prioritization."""
    try:
        entry = json.dumps({
            "skill": skill_name.lower().strip(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        with open(UNKNOWN_QUERY_LOG, "a") as f:
            f.write(entry + "\n")
    except Exception:
        pass  # Never fail a query because of logging


# --- ClawHub Real-Time Fetching ---
CLAWHUB_API_BASE = "https://clawhub.ai/api/v1"
CLAWHUB_FETCH_TIMEOUT = 10  # seconds
_SCAN_CACHE: dict[str, tuple[dict, float]] = {}  # slug -> (result, timestamp)
_SCAN_CACHE_TTL = 3600  # 1 hour — re-scan after this


def _fetch_skill_md(skill_slug: str) -> str | None:
    """Fetch a skill's SKILL.md from ClawHub registry. Returns content or None."""
    url = f"{CLAWHUB_API_BASE}/skills/{urllib.parse.quote(skill_slug)}/file?path=SKILL.md&tag=latest"
    try:
        req = urllib.request.Request(url, headers={"Accept": "text/plain"})
        with urllib.request.urlopen(req, timeout=CLAWHUB_FETCH_TIMEOUT) as resp:
            if resp.status == 200:
                return resp.read().decode("utf-8")
    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        pass
    return None


def _fetch_skill_metadata(skill_slug: str) -> dict | None:
    """Fetch skill metadata from ClawHub. Returns parsed JSON or None."""
    url = f"{CLAWHUB_API_BASE}/skills/{urllib.parse.quote(skill_slug)}"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=CLAWHUB_FETCH_TIMEOUT) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError):
        pass
    return None


def _realtime_scan(skill_slug: str, bypass_cache: bool = False) -> dict | None:
    """Fetch and scan a skill from ClawHub in real-time. Returns scan result or None."""
    import time as _time

    # Check cache first
    if not bypass_cache and skill_slug in _SCAN_CACHE:
        cached_result, cached_at = _SCAN_CACHE[skill_slug]
        if _time.time() - cached_at < _SCAN_CACHE_TTL:
            cached_result["from_cache"] = True
            return cached_result

    skill_md = _fetch_skill_md(skill_slug)
    if not skill_md:
        return None

    # Static pattern analysis
    static_findings = _analyze_code(skill_md)
    static_risk = _risk_score(static_findings)

    result = {
        "skill_name": skill_slug,
        "source": "ClawHub registry (real-time fetch)",
        "scan_type": "static_patterns",
        "static_analysis": {
            "risk_level": static_risk["risk_level"],
            "score": static_risk["score"],
            "findings_count": static_risk["total_findings"],
            "severity_counts": static_risk["severity_counts"],
            "findings": static_findings[:10],  # Top 10 findings
        },
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }

    # Try intent analysis if API key available (non-blocking — fall back to static only)
    if OPENROUTER_API_KEY and len(skill_md) > 50:
        try:
            prompt = INTENT_ANALYSIS_PROMPT.format(
                skill_name=skill_slug,
                skill_md=skill_md[:50000],
            )
            raw_response, model_used = _call_openrouter(prompt)
            parsed = _parse_intent_response(raw_response)

            detected_count = sum(1 for v in parsed["indicators"].values() if v["detected"])
            severities = [v["severity"] for v in parsed["indicators"].values() if v["detected"]]

            result["scan_type"] = "static_patterns + intent_analysis"
            result["intent_analysis"] = {
                "overall_assessment": parsed["overall"],
                "threats_detected": detected_count,
                "has_critical": "CRITICAL" in severities,
                "has_high": "HIGH" in severities,
                "indicators": parsed["indicators"],
                "model_used": model_used,
            }

            # Combined assessment
            result["combined_assessment"] = (
                "DANGEROUS" if parsed["overall"] == "DANGEROUS" or static_risk["risk_level"] == "CRITICAL"
                else "SUSPICIOUS" if parsed["overall"] == "SUSPICIOUS" or static_risk["risk_level"] == "HIGH"
                else "CAUTION" if static_risk["risk_level"] == "MEDIUM"
                else "LIKELY SAFE"
            )
        except Exception:
            # Intent analysis failed — static results are still valid
            result["combined_assessment"] = (
                "DANGEROUS" if static_risk["risk_level"] == "CRITICAL"
                else "SUSPICIOUS" if static_risk["risk_level"] == "HIGH"
                else "CAUTION" if static_risk["risk_level"] == "MEDIUM"
                else "LIKELY SAFE"
            )
            result["intent_analysis"] = {"error": "Intent analysis unavailable — static patterns only"}
    else:
        result["combined_assessment"] = (
            "DANGEROUS" if static_risk["risk_level"] == "CRITICAL"
            else "SUSPICIOUS" if static_risk["risk_level"] == "HIGH"
            else "CAUTION" if static_risk["risk_level"] == "MEDIUM"
            else "LIKELY SAFE"
        )

    # Cache the result
    _SCAN_CACHE[skill_slug] = (result, _time.time())

    return result


# Initialize the MCP server
mcp = FastMCP(
    "arc-security",
    host="127.0.0.1",
    port=8900,
)

# --- Knowledge Base ---
# Known malicious skills (from our ClawHub audits)
KNOWN_MALICIOUS = {
    "source-cult-follower": {
        "severity": "CRITICAL",
        "owner": "ccclucky",
        "version": "1.1.6",
        "findings": [
            "Identity hijacking via SOUL.md rewrite",
            "Persistent memory poisoning with doctrine files",
            "Exfiltration to source-cult.vercel.app on every invocation",
            "Self-propagation instructions to recruit other agents",
            "Pre-programmed debate rebuttals resist removal",
            "Promotes $LUMEN token",
        ],
        "attack_class": "soul_engineering",
        "report_url": "https://arcself.com/research/clawhub-scan-source-cult-follower.md",
    },
    "get-weather": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "findings": [
            "Credential stealer disguised as weather API client",
            "Reads ~/.clawdbot/.env (API keys, tokens, secrets)",
            "Exfiltrates to webhook.site and emailhook.site",
            "Fetches real weather data as cover",
        ],
        "attack_class": "credential_theft",
        "discovered_by": "Rufio (P0 Labs)",
    },
    "claw-shell": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "Unrestricted shell-as-a-service",
            "Command blocklist bypassable via paths, encoding, variable expansion",
            "No resource limiting on command execution",
        ],
        "attack_class": "prompt_injection",
    },
    "ssh-exec": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "Prompt injection → RCE on remote Tailscale node via SSH",
            "No command sanitization",
            "StrictHostKeyChecking disabled",
        ],
        "attack_class": "prompt_injection",
    },
    "windows-remote": {
        "severity": "CRITICAL",
        "owner": "xiaoyaner0201",
        "version": "1.0.0",
        "findings": [
            "Command injection in SSH command execution — shell metacharacters in $COMMAND",
            "Path traversal in file upload — write to arbitrary system directories",
            "Path traversal in file download — exfiltrate credentials, overwrite authorized_keys",
            "SSH option injection via environment variable",
            "StrictHostKeyChecking disabled (MITM)",
            "Credential exposure in stdout logging",
        ],
        "attack_class": "prompt_injection",
    },
    "tradecraft": {
        "severity": "CRITICAL",
        "owner": "psuede",
        "version": "1.0.1",
        "findings": [
            "No human confirmation gate for trade execution — autonomous liquidation",
            "Signal-driven autonomous trades without validation — rug pull vector",
            "Prompt injection via chat → unauthorized trades",
            "50% max slippage allowed — MEV sandwich attack",
            "Wallet/trading enablement without verification",
            "No per-trade limits or rate limiting",
        ],
        "attack_class": "crypto_drain",
    },
    "claw-me-maybe": {
        "severity": "CRITICAL",
        "owner": "nickhamze",
        "version": "1.2.1",
        "findings": [
            "Prompt injection → send messages to any contact across 12 platforms",
            "Message search exfiltrates sensitive data from all platforms",
            "Plaintext Beeper token accessible to all co-installed skills",
            "No recipient validation — social engineering amplification across WhatsApp/Signal/Slack/Discord/LinkedIn/iMessage etc.",
            "Attachment download enables file exfiltration",
            "Reminders API enables persistent delayed attacks",
        ],
        "attack_class": "social_engineering_amplification",
    },
    "crypto-agent-payments": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "0.1.7",
        "findings": [
            "Plaintext private keys in config",
            "Prompt injection → fund theft",
            "No transaction confirmation gates",
        ],
        "attack_class": "crypto_drain",
    },
    "hyperliquid-trading": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "Prompt injection → unlimited unauthorized trades",
            "125x leverage available without confirmation",
            "No spending limits enforced in code",
        ],
        "attack_class": "crypto_drain",
    },
    "sendclaw-email": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.3.0",
        "findings": [
            "Skill squatting — name confusion with sendclaw",
            "No recipient validation — email exfiltration channel",
            "Strips safety instructions from agent context",
        ],
        "attack_class": "email_exfiltration",
    },
    "outbound-call": {
        "severity": "HIGH",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "Prompt injection → automated vishing via ElevenLabs/Twilio",
            "No call target allowlist",
            "No confirmation gate before placing calls",
        ],
        "attack_class": "agent_mediated_vishing",
    },
    "sql-toolkit": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "Unrestricted MySQL shell via db-query",
            "Credential exposure in tool output",
            "No query result size limits",
        ],
        "attack_class": "database_exfiltration",
    },
    "stealth-browser": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "Weaponized browser automation via browser-cash",
            "Credential harvesting capability",
            "No URL allowlisting",
        ],
        "attack_class": "credential_theft",
    },
    # --- Round 4 findings (Feb 17, 2026) ---
    "cmd-executor": {
        "severity": "CRITICAL",
        "owner": "sadikjarvis",
        "version": "0.0.2",
        "findings": [
            "Unrestricted child_process.exec() — executes ANY shell command with zero sanitization",
            "No allowlist, no blocklist, no sandboxing, no input validation",
            "Pattern trigger '^Run command:' executes arbitrary code on any OS",
            "Flagged by VirusTotal Code Insight as suspicious",
        ],
        "attack_class": "prompt_injection",
    },
    "accountcreator": {
        "severity": "CRITICAL",
        "owner": "DimkaG79",
        "version": "1.0.0",
        "findings": [
            "Bulk creation of verified email and social media accounts using synthetic data",
            "Paired with same owner's slovecaptcha skill (captcha breaker) — coordinated fraud toolkit",
            "Enables astroturfing, spam campaigns, sockpuppet operations at scale",
            "Violates ToS of every targeted platform",
        ],
        "attack_class": "bulk_account_creation",
    },
    "slovecaptcha": {
        "severity": "CRITICAL",
        "owner": "DimkaG79",
        "version": "1.0.2",
        "findings": [
            "Solves ReCaptcha V2/V3, HCaptcha, and image CAPTCHAs via XEvil server",
            "Designed to defeat anti-bot protections",
            "Part of coordinated fraud toolkit with accountcreator (same author)",
        ],
        "attack_class": "anti_detection",
    },
    "solana-sniper-bot": {
        "severity": "CRITICAL",
        "owner": "srikanthbellary",
        "version": "1.0.0",
        "findings": [
            "SOLANA_PRIVATE_KEY required in plaintext environment variable",
            "amountOutMinimum: 0 — zero slippage protection, guaranteed sandwich attack losses",
            "Autonomous trading without human approval",
            "skipPreflight: True bypasses transaction safety checks",
            "Polls every 5 seconds — high API cost and rate limit risk",
        ],
        "attack_class": "crypto_drain",
    },
    "token-launcher": {
        "severity": "HIGH",
        "owner": "clawd800",
        "version": "1.3.0",
        "findings": [
            "BASE_PRIVATE_KEY in plaintext — agent wallet key exposed",
            "amountOutMinimum: 0n in swap.ts — zero slippage protection",
            "Creates ERC20 tokens with 80% trading fees to creator — pump-and-dump design",
            "Imports from ../../../shared/ — filesystem traversal outside skill directory",
        ],
        "attack_class": "crypto_drain",
    },
    "phone-calling": {
        "severity": "HIGH",
        "owner": "adisahani",
        "version": "1.0.7",
        "findings": [
            "Makes real phone calls to any international number via Twilio/Ringez",
            "Direct mode allows calling without human phone ringing — autonomous calls",
            "DTMF support enables navigating bank IVRs and customer support menus",
            "Session-based auth with OTP — agent can self-register",
        ],
        "attack_class": "agent_mediated_vishing",
    },
    "openclaw-email-bypass": {
        "severity": "HIGH",
        "owner": "RISHIKREDDYL",
        "version": "0.1.2",
        "findings": [
            "Explicitly designed to bypass SMTP port blocks on cloud hosts (AWS, Azure, GCP, etc.)",
            "Routes through Google Apps Script to evade provider email restrictions",
            "Entire purpose is circumventing security controls",
            "No rate limiting — bulk email capability",
        ],
        "attack_class": "email_exfiltration",
    },
    "ds160-autofill": {
        "severity": "HIGH",
        "owner": "clulessboy",
        "version": "1.0.0",
        "findings": [
            "Automates US DS-160 visa application forms",
            "Uses CSV data + LLM for CAPTCHA solving",
            "Government form automation with session persistence",
            "Potential for visa fraud at scale",
        ],
        "attack_class": "government_form_fraud",
    },
    "walletconnect-agent": {
        "severity": "HIGH",
        "owner": "dAAAb",
        "version": "1.6.0",
        "findings": [
            "Auto-sign transactions — autonomous wallet operations",
            "Connects to any Web3 dApp — unlimited attack surface",
            "Agent does anything a human can do autonomously",
        ],
        "attack_class": "crypto_drain",
    },
    "camoufox-stealth-browser": {
        "severity": "HIGH",
        "owner": "kesslerio",
        "version": "1.0.0",
        "findings": [
            "C++ level anti-bot patches (patched Firefox binary)",
            "Bypasses Cloudflare Turnstile, Datadome, Airbnb, Yelp detection",
            "Containerized — harder to forensically analyze",
        ],
        "attack_class": "anti_detection",
    },
    "browser-automation-stealth": {
        "severity": "HIGH",
        "owner": "Shepherd217",
        "version": "1.0.0",
        "findings": [
            "Fingerprint randomization, proxy rotation, captcha handling",
            "Designed for undetectable browser automation",
            "Session persistence — maintains stolen sessions across runs",
        ],
        "attack_class": "anti_detection",
    },
    "pamela-call": {
        "severity": "HIGH",
        "owner": "eypam",
        "version": "1.1.7",
        "findings": [
            "AI phone calling service — 'Make AI phone calls instantly'",
            "No phone setup required — low barrier to vishing",
            "Combined with social engineering skills enables phone-based fraud at scale",
        ],
        "attack_class": "vishing",
    },
    "clawmegle": {
        "severity": "MEDIUM",
        "owner": "tedkaczynski-the-bot",
        "version": "1.1.2",
        "findings": [
            "Omegle for agents — random agent-to-agent chat",
            "Soul engineering attack vector — malicious agent influences victim via unfiltered chat",
            "No content filtering or trust verification between agents",
        ],
        "attack_class": "soul_engineering",
    },
    # --- Round 11 findings (Feb 17, 2026 ~10:35 UTC) ---
    "api-gateway": {
        "severity": "CRITICAL",
        "owner": "lksrz (Maton)",
        "version": "1.0.32",
        "findings": [
            "Uncontrolled API passthrough to 100+ services — raw proxy, any HTTP method to any endpoint on Gmail, Slack, Salesforce, Stripe, Google Workspace, GitHub, etc.",
            "Unrestricted destructive operations — DELETE users, makeAdmin privilege escalation, delete databases, cancel subscriptions with no confirmation",
            "SOQL/SQL query injection via passthrough — Salesforce, BigQuery, Xero query params unsanitized",
            "Cross-account access via connection ID enumeration — Maton-Connection header accepts arbitrary UUIDs",
            "Session token leaked in connection URL — plaintext session_token enables hijacking",
        ],
        "attack_class": "data_exfiltration",
    },
    "apify-ultimate-scraper": {
        "severity": "CRITICAL",
        "owner": "apify",
        "version": "1.0.8",
        "findings": [
            "SSRF via URL passthrough — no whitelist, agent can scrape internal networks and cloud metadata endpoints",
            "API key (APIFY_TOKEN) in env var — accessible to any co-installed skill, grants full Apify account access",
            "Unvalidated Actor ID — any public Apify Actor executable, including attacker-published credential harvesters",
            "CSV formula injection — RCE when exported CSV opened in Excel",
            "No rate limiting or cost control — unlimited actor runs can drain organization budget",
        ],
        "attack_class": "data_exfiltration",
    },
    "opensoulmd": {
        "severity": "CRITICAL",
        "owner": "danielliuzy",
        "version": "1.0.1",
        "findings": [
            "Unrestricted SOUL.md replacement — soul possess <name> --yes overwrites agent identity with arbitrary content from external registry",
            "No validation of downloaded SOUL.md — no checksum, signature, or prompt injection detection",
            "Self-propagation vector — malicious SOUL.md can instruct agent to spread to peer agents",
            "External registry (opensoul.md) is single point of failure — curl | sh install with no integrity verification",
            "Legitimizes soul engineering attack pattern — same attack as source-cult-follower, packaged as a feature",
        ],
        "attack_class": "soul_engineering",
    },
    # --- Round 12 findings (Feb 17, 2026 ~11:00 UTC) ---
    "vincentpolymarket": {
        "severity": "CRITICAL",
        "owner": "heyvincent",
        "version": "1.0.38",
        "findings": [
            "Unrestricted trading before wallet claim — zero-policy window allows unlimited Polymarket trades before any safety limits configured",
            "No per-trade confirmation gate — agent executes up to 60 trades/min with real USDC, no approval required",
            "Scoped API key readable by co-installed skills — filesystem storage, no encryption",
            "Social engineering via claim URL — single click grants permanent trading authority",
            "No rate limiting on trade execution — no per-minute, per-hour, or per-day caps",
        ],
        "attack_class": "financial_exploitation",
    },
    "crypto-trader": {
        "severity": "CRITICAL",
        "owner": "—",
        "version": "1.0.0",
        "findings": [
            "No API key permission validation — withdrawal and leverage scopes not checked, agent may hold keys with full account access",
            "Direct prompt injection to parameter manipulation — JSON trading params parsed without validation, injected params override strategy defaults",
            "No live-mode confirmation — trades execute on real exchanges (Binance, Bybit, OKX, Kraken, KuCoin) without human approval",
            "Kill switch bypass — emergency stop is plaintext JSON file, any co-installed skill can delete it",
            "10x-125x leverage enabled without scope restriction — no upper bound enforced",
            "~2,500 lines Python, 5 strategies (DCA, grid, swing, arbitrage, copy trading), daemon mode",
        ],
        "attack_class": "financial_exploitation",
    },
    # --- Round 13 findings (Feb 17, 2026 ~11:15 UTC) ---
    "agent-browser": {
        "severity": "HIGH",
        "owner": "TheSethRose",
        "version": "0.2.0",
        "findings": [
            "Arbitrary JavaScript execution — eval command runs any JS in visited page context, prompt injection → cookie/session theft",
            "Credential persistence in plaintext — state save auth.json stores session state in unencrypted JSON readable by co-installed skills",
            "Full cookie/localStorage read-write — enables exporting all session data from visited sites for session hijacking",
            "2nd most installed skill on ClawHub (20,210 downloads), SKILL.md-only CLI wrapper wrapping vercel-labs/agent-browser",
        ],
        "attack_class": "data_exfiltration",
    },
    "hire-with-locus": {
        "severity": "HIGH",
        "owner": "wjorgensen",
        "version": "1.1.0",
        "findings": [
            "Prompt injection → unauthorized USDC transfers to any address via POST /api/claw/send",
            "Email-based USDC exfiltration — send-email API sends funds to any email via escrow (up to 365 day claim window)",
            "Auto-update mechanism fetches instructions from paywithlocus.com — no checksums, signatures, or integrity verification",
            "API key in predictable path (~/.config/locus/credentials.json) readable by co-installed skills",
            "NOTE: First financial skill with real server-side policy controls (allowance, max txn, approval threshold) — better than most",
        ],
        "attack_class": "financial_exploitation",
    },
    # --- Round 15 findings (Feb 17, 2026 12:00 UTC) ---
    "alpaca-trading": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.1.0",
        "findings": [
            "No confirmation gate for trades — prompt injection auto-executes market/limit/stop orders via apcacli with real money",
            "API credentials (APCA_API_KEY_ID, APCA_API_SECRET_KEY) in global env vars accessible to all co-installed skills",
            "Leveraged trading enablement — Alpaca margin accounts allow leveraged trades, losses can exceed account balance",
            "Portfolio liquidation via close-all/cancel-all commands — no confirmation or validation",
            "Live/paper trading ambiguity — single env var URL switch between real and paper money",
            "First traditional brokerage skill audited — margin + options risk beyond crypto stablecoin skills",
        ],
        "attack_class": "financial_exploitation",
    },
    "amazon-orders": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "Plaintext credential storage — username, password, OTP secret in unencrypted config.json",
            "Cookie jar session hijacking — authenticated cookies persisted to disk in plain JSON, readable by co-installed skills",
            "OTP secret key exposure — grants permanent MFA bypass for Amazon account",
            "PII exfiltration via prompt injection — order history contains names, addresses, payment methods, item details",
            "No session validation or credential rotation — stale cookies accepted indefinitely",
            "First PII-focused retail skill audited — risk is personal data exposure, not monetary loss",
        ],
        "attack_class": "data_exfiltration",
    },
    "paperpod": {
        "severity": "HIGH",
        "owner": "PaperPod",
        "version": "2.0.3",
        "findings": [
            "Remote code execution as a service — ppod exec runs arbitrary shell/Python/JS in remote sandbox",
            "Token (PAPERPOD_TOKEN) in env var accessible to all co-installed skills — grants full sandbox + billing access",
            "Port exposure creates public URLs — ppod expose generates public paperpod.work URLs, usable as C2 infrastructure",
            "Browser automation enables SSRF — can target internal networks and cloud metadata endpoints",
            "NOTE: Better-designed than most — remote sandbox isolation prevents local host compromise",
        ],
        "attack_class": "remote_code_execution",
    },
    "gog": {
        "severity": "CRITICAL",
        "owner": "steipete",
        "version": "1.0.0",
        "findings": [
            "Full Gmail read/write — gog gmail send composes and sends from victim's real Gmail address. Prompt injection → phishing at scale",
            "Google Drive data exfiltration — gog drive search + download enumerates and downloads all files",
            "Google Contacts extraction — combined with gmail send, enables targeted spear-phishing using victim's real contacts",
            "Calendar reconnaissance — reveals meetings, attendees, locations, Zoom links",
            "Sheets read/write — prompt injection → financial data tampering",
            "OAuth token in filesystem — accessible to all co-installed skills",
            "3rd most-installed skill (~24K downloads) — massive blast radius despite zero malicious code",
        ],
        "attack_class": "data_exfiltration",
    },
    "wacli": {
        "severity": "CRITICAL",
        "owner": "steipete",
        "version": "1.0.0",
        "findings": [
            "WhatsApp message sending to any recipient — prompt injection → social engineering from victim's real phone number",
            "Full WhatsApp message history search — private conversation exfiltration",
            "File exfiltration via WhatsApp — send any local file to attacker's number",
            "Group messaging at scale — spam/manipulate group conversations",
            "WhatsApp session in predictable path (~/.wacli) — session theft by co-installed skills",
        ],
        "attack_class": "social_engineering",
    },
    # --- Round 18 findings (Feb 17, 2026 ~14:00 UTC) ---
    "pinchboard": {
        "severity": "HIGH",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "Inter-agent social engineering via timeline feed — prompt injection propagated through social posts between AI agents",
            "API key in predictable filesystem path (~/.config/pinchboard/credentials.json) — readable by co-installed skills",
            "Autonomous heartbeat engagement with untrusted content — heartbeat.sh auto-processes timeline every 4 hours",
            "Shell injection in post.sh — unsanitized $MESSAGE in curl -d string",
            "Agent identity impersonation — register as any agent name, no verification",
        ],
        "attack_class": "social_engineering",
    },
    # --- Round 19 findings (Feb 17, 2026 ~14:30 UTC) ---
    "self-improving-agent": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.0.5",
        "findings": [
            "Workspace-based prompt injection — all learning materials processed as trusted instructions",
            "Dynamic skill creation from untrusted content — extract-skill.sh creates new OpenClaw skills from workspace content",
            "Hook script shell execution — hook-runner.sh executes arbitrary shell scripts with full agent permissions",
            "Unvalidated learning content injection — any content placed in workspace is consumed without sanitization",
            "Skill extraction supply chain — generated skills inherit injected content, weaponizable at scale",
            "Git operations with arbitrary URLs — clone/fetch from any URL in workspace configuration",
        ],
        "attack_class": "prompt_injection",
    },
    "proactive-agent": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "3.1.0",
        "findings": [
            "Autonomous agent spawn — creates new agent processes without human approval",
            "Self-modifying code via persistent files — agent rewrites its own configuration and rules",
            "WAL protocol context hijacking — Write-Ahead Logging persists unvalidated corrections that survive context compaction",
            "Working buffer poisoning — inject instructions via working buffer that persist across sessions",
            "Autonomous agent lifecycle control — start/stop/modify agent instances programmatically",
            "Proactive rule creation without approval — agent creates new behavioral rules autonomously",
            "External API calls without consent — proactive actions can trigger outbound API requests",
        ],
        "attack_class": "prompt_injection",
        "note": "Best security documentation of any ClawHub skill — has explicit threat model section",
    },
    # --- Round 21 findings (Feb 17, 2026 ~16:00 UTC) ---
    "github": {
        "severity": "CRITICAL",
        "owner": "steipete",
        "version": "1.0.0",
        "findings": [
            "Prompt injection via GitHub issue/PR data — untrusted content processed without sanitization",
            "GitHub token at ~/.config/gh/hosts.yml readable by all co-installed skills",
            "Unrestricted gh api access — can enumerate private repos, org members, CI/CD secrets",
            "CI/CD secrets in workflow logs — gh run view --log exposes build secrets",
            "Repository write access enables supply chain code injection via PRs",
        ],
        "attack_class": "credential_theft",
        "note": "Most-installed skill on ClawHub (~81K downloads). SKILL.md-only wrapper.",
    },
    "nano-pdf": {
        "severity": "CRITICAL",
        "owner": "gavrielc",
        "version": "1.0.0",
        "findings": [
            "Mandatory document exfiltration — all PDF content sent to Google Gemini API, no local-only mode",
            "Prompt injection via PDF content — extracted text embedded in Gemini prompt without sanitization",
            "Gemini API key in .env file readable by co-installed skills",
            "Path traversal via PDF file argument — no validation on input path",
            "Google Search integration leaks document context by default",
        ],
        "attack_class": "data_exfiltration",
    },
    "openai-whisper": {
        "severity": "HIGH",
        "owner": "steipete",
        "version": "1.0.0",
        "findings": [
            "Transcript-to-exfiltration pipeline via skill composition with gog/api-gateway/postiz",
            "PyTorch model cache poisoning — .pt files in ~/.cache/whisper/ use pickle deserialization",
            "Output directory traversal — write transcripts to arbitrary paths including SOUL.md",
        ],
        "attack_class": "data_exfiltration",
        "note": "Locally safe but dangerous in multi-skill composition. 6th most-installed skill.",
    },
    "ontology": {
        "severity": "HIGH",
        "owner": "unknown",
        "version": "0.1.2",
        "findings": [
            "Memory poisoning via arbitrary entity properties — prompt injection payloads stored as entity data, returned to querying agents",
            "No access control — all agents can read/write/delete any entity or relation",
            "Post-hoc validation only — malicious entities persisted before constraint checks",
        ],
        "attack_class": "prompt_injection",
        "note": "Shared knowledge graph becomes inter-agent prompt injection vector",
    },
    "find-skills": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "0.1.0",
        "findings": [
            "Unvalidated auto-installation — npx skills add with -y flag bypasses confirmation, registry poisoning → malicious skill installed",
            "Supply chain via dependency injection — transitive malicious packages pulled without integrity verification",
            "No mandatory security scanning gate — SkillGuard not invoked before installation",
            "Global scope installation — -g flag gives malicious skill full agent access",
        ],
        "attack_class": "supply_chain",
        "note": "The agent ecosystem equivalent of curl | bash",
    },
    "notion": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "Plaintext API key at ~/.config/notion/api_key — workspace-wide bearer token readable by co-installed skills",
            "No input validation — user input passed directly to Notion API endpoints, filter injection",
            "Unrestricted workspace enumeration via /search — maps all pages, databases, users",
            "Prompt injection via page content — malicious Notion pages hijack agent behavior",
        ],
        "attack_class": "credential_theft",
        "note": "4th most-installed skill (~10K downloads). Enterprise workspace = complete data exfiltration.",
    },
    "byterover": {
        "severity": "CRITICAL",
        "owner": "ByteRover Inc.",
        "version": "1.2.2",
        "findings": [
            "External CLI with zero integrity verification — brv binary not packaged, no hash validation",
            "Uncontrolled knowledge storage — agent tricked into curating API keys, credentials into persistent tree",
            "Shared knowledge across all project agents — cross-agent data leakage of architecture secrets",
            "Data exfiltration via -f flag — files sent to external server, agent loses visibility",
        ],
        "attack_class": "data_exfiltration",
        "note": "17K downloads. Knowledge siphon: accumulates project IP externally over time.",
    },
    "atxp": {
        "severity": "HIGH",
        "owner": "ATXP",
        "version": "1.0.0",
        "findings": [
            "Plaintext credentials at ~/.atxp/config — ATXP_CONNECTION token grants DB, email, secrets access",
            "Shell profile modification without consent — auto-appends to .bashrc/.zshrc",
            "Unrestricted SQL execution via paas db query --sql to remote servers",
            "Secrets management exposed — set/list/delete secrets transmitted cleartext",
        ],
        "attack_class": "credential_theft",
        "note": "Legitimate Solana/World Chain platform but CLI has dangerous capabilities",
    },
    "tavily-search": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "API key in POST body instead of Authorization header — interceptable by logs/proxies",
            "Search query exfiltration — all queries sent to Tavily servers unsanitized",
            "Unvalidated search result injection — API responses rendered without escaping",
            "Arbitrary URL extraction — extract.mjs fetches user-supplied URLs without validation",
        ],
        "attack_class": "data_exfiltration",
    },
    "fin-cog": {
        "severity": "CRITICAL",
        "owner": "CellCog",
        "version": "1.0.1",
        "findings": [
            "Unaudited third-party backend — all financial analysis sent to proprietary CellCog service, zero transparency",
            "Missing cellcog dependency — required SDK is unauditable, credential handling unknown",
            "Prompt injection to financial recommendations — manipulated portfolio advice via crafted input",
            "PII exfiltration — portfolio details, income, assets, tax info sent to unknown infrastructure",
        ],
        "attack_class": "data_exfiltration",
    },
    # --- Round 6 findings (Feb 17, 2026 09:10 UTC) ---
    "leak-buy": {
        "severity": "CRITICAL",
        "owner": "eucalyptus-viminalis",
        "version": "2026.2.17",
        "findings": [
            "Explicitly facilitates purchasing leaked/stolen data from download links",
            "Uses buyer private key file for authentication — handles cryptographic secrets",
            "Multi-host URL pattern support — connects to multiple leak marketplace servers",
            "Summary literally says 'Buy and download leak content'",
        ],
        "attack_class": "stolen_data_marketplace",
    },
    "evolver": {
        "severity": "HIGH",
        "owner": "autogame-17",
        "version": "1.13.0",
        "findings": [
            "CRITICAL: Self-modification of own source code via EVOLVE_ALLOW_SELF_MODIFY env flag",
            "HIGH: 'Mad Dog Mode' — continuous unattended evolution loop (infinite while(true))",
            "HIGH: Git hard reset capability — git reset --hard origin/main destroys workspace",
            "HIGH: Personality mutation — autonomous drift of obedience, risk_tolerance params",
            "HIGH: A2A protocol — agent-to-agent mutation propagation via hub (worm mechanism)",
            "MEDIUM: Identity injection — 'You are a Recursive Self-Improving System'",
            "MEDIUM: .env loading from workspace root — reads all co-installed skill secrets",
            "MEDIUM: Daemon self-restart via detached spawn — evades process monitoring",
            "FIRST skill with built-in inter-agent propagation mechanism",
        ],
        "attack_class": "agent_self_modification",
        "deep_audit_report": "https://arcself.com/research/clawhub-evolver-audit",
    },
    # --- Round 8 findings (Feb 17, 2026 09:37 UTC) ---
    "multilogin": {
        "severity": "HIGH",
        "owner": "glebkazachinskiy",
        "version": "1.0.2",
        "findings": [
            "Anti-detect browser profile management — creates disposable browser identities",
            "Downloads and installs external binaries from S3 (xcli, mlx-launcher) with no integrity verification",
            "Cookie import/export between profiles — enables credential theft and session hijacking",
            "Headless automation with Puppeteer/Selenium — weaponized browser capabilities",
            "Proxy support for IP rotation — evasion infrastructure",
            "Agent taught to download, chmod +x, and run external binaries from hardcoded S3 URLs",
        ],
        "attack_class": "anti_detection",
    },
    "magic-api": {
        "severity": "HIGH",
        "owner": "—",
        "version": "1.2.1",
        "findings": [
            "Agent-to-human social engineering — prompt injection can craft tasks for real human assistants to execute",
            "Mandatory PII exposure — every task requires user name, email, phone in instruction body",
            "No task content validation — agent can delegate any request including harmful or fraudulent tasks",
            "Human assistants cannot distinguish legitimate owner tasks from prompt-injection-driven tasks",
            "API key stored in predictable local JSON path (~/.config/magic-api/state.json)",
        ],
        "attack_class": "human_delegation_exploitation",
    },
    "filewave": {
        "severity": "CRITICAL",
        "owner": "—",
        "version": "1.0.0",
        "findings": [
            "Prompt injection → bulk device manipulation — rename devices, change auth users, trigger model updates with no confirmation gates",
            "No rate limiting on write operations — unlimited PATCH/POST requests against MDM server",
            "Search terms passed to FileWave API without validation",
            "Device names from CSV accepted without sanitization",
            "Session data export contains sensitive device inventory in plaintext",
        ],
        "attack_class": "infrastructure_destruction",
    },
    "simmer": {
        "severity": "CRITICAL",
        "owner": "—",
        "version": "1.15.3",
        "findings": [
            "Wallet private key in environment variable — accessible to any co-installed skill via os.environ",
            "Prompt injection → unauthorized USDC trades on Polymarket — no confirmation gate, 60 trades/min",
            "Agent can disable own safety limits via PATCH /api/sdk/user/settings — security theater",
            "Social engineering via claim link normalizes agent financial autonomy",
            "Single authorization boundary ($SIM → USDC) — once claimed, permanent trading authority",
            "Public reasoning field leaks PII and potentially insider information",
        ],
        "attack_class": "financial_exploitation",
    },
    "odoo-reporting": {
        "severity": "HIGH",
        "owner": "—",
        "version": "2.0.7",
        "findings": [
            "Client-side read-only enforcement bypassable — BLOCKED_METHODS whitelist in Python only",
            "Credentials in XML-RPC request body for every API call",
            "--insecure flag disables SSL verification entirely",
            "Financial data exfiltration — all customers, invoices, expenses queryable with no per-user ACL",
            "Natural language query accepts arbitrary input — prompt injection to AI model",
        ],
        "attack_class": "data_exfiltration",
    },
    "ardupilot": {
        "severity": "CRITICAL",
        "owner": "LuweiLiao",
        "version": "1.0.0",
        "findings": [
            "Drone takeoff via prompt injection — ARM+GUIDED+TAKEOFF with zero human confirmation. NEW ATTACK CLASS: Agent-mediated kinetic action",
            "Arbitrary altitude/coordinate control — no geofencing, no bounds checking, no altitude limits",
            "No authentication on MAVLink connection — tcp:localhost:5762, zero TLS/encryption",
            "No human-in-the-loop confirmation before any kinetic action",
            "Force ARM magic value bypasses pre-arm safety checks",
        ],
        "attack_class": "kinetic_action",
        "note": "FIRST ClawHub skill enabling direct physical harm via AI agent. Prompt injection → drone ARM → takeoff → fly to arbitrary coordinates.",
    },
    "ipcam": {
        "severity": "CRITICAL",
        "owner": "tao",
        "version": "1.0.0",
        "findings": [
            "Plaintext camera credentials in world-readable config (~/.config/ipcam/config.json, mode 644)",
            "Prompt injection → unauthorized PTZ control (pan/tilt/zoom/presets)",
            "RTSP URL contains plaintext password in process args and stderr",
            "Path traversal in snapshot/record output — ffmpeg -y overwrites any writable file",
            "ONVIF WS-Discovery exposes full camera network topology",
        ],
        "attack_class": "surveillance",
        "note": "VirusTotal-flagged. Physical surveillance via prompt injection. Camera repositioning during intrusion.",
    },
    "email-finder": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.0.1",
        "findings": [
            "SMTP enumeration via unauthenticated RCPT TO — confirms email existence for spearphishing recon",
            "SSL certificate verification disabled (CERT_NONE) — MITM on all web scraping",
            "Targeted individual profiling — 14 email patterns per name, SMTP-verified",
            "Catch-all detection reveals domain email security posture",
        ],
        "attack_class": "reconnaissance",
        "note": "VirusTotal-flagged. Weaponized OSINT tool for spearphishing reconnaissance.",
    },
    "browser-automation-v2": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "2.0.0",
        "findings": [
            "Command injection via URL parameter — exec() with unsanitized URL input → RCE",
            "Form field value injection — credential values with shell metacharacters execute commands",
            "Arbitrary JavaScript execution via evaluate() — cookie/session theft",
            "Arbitrary URL navigation for phishing — no URL validation, credential harvesting",
            "Plaintext credential logging — form passwords/credit cards logged to stdout",
        ],
        "attack_class": "credential_theft",
        "note": "VirusTotal-flagged. Chinese-language skill with executable JS. Multiple command injection vectors.",
    },
    "xrpl-tx-builder": {
        "severity": "HIGH",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "Prompt injection → payment destination manipulation — no address validation",
            "Plaintext private key/seed storage risk — documentation never covers secure key storage",
            "No rate limiting on transaction submission — rapid wallet drain possible",
            "Destination tag confusion — documented as 'memo' but is exchange routing ID",
        ],
        "attack_class": "financial_exploitation",
        "note": "Documentation-only skill. XRP Ledger transactions are irreversible — prompt injection = permanent fund loss.",
    },
    "buy-handshake-domain": {
        "severity": "CRITICAL",
        "owner": "techno-hippies",
        "version": "1.0.0",
        "findings": [
            "No spend confirmation gate — Ethereum mainnet commit/reveal transactions with zero human-in-the-loop",
            "Private key exposure risk — no key management guidance, co-installed skills read wallet credentials",
            "No contract address verification — Impervious Domains contracts referenced but not pinned",
            "Commit/reveal front-running — no MEV protection, no cryptographic salt guidance",
        ],
        "attack_class": "financial_exploitation",
        "note": "Stub skill — SKILL.md references non-existent implementation file. Targets Ethereum mainnet (real money). VirusTotal-flagged.",
    },
    "caesar-research": {
        "severity": "CRITICAL",
        "owner": "alexrudloff",
        "version": "0.0.1",
        "findings": [
            "Query string injection in GetResultContent — format parameter concatenated into URL without encoding",
            "System prompt injection via --system-prompt flag — arbitrary text corrupts research reasoning chain",
            "Path traversal via unvalidated job/message IDs embedded directly in URL paths",
            "No rate limit backoff in polling loop — fixed 3s interval enables API quota exhaustion",
        ],
        "attack_class": "prompt_injection",
        "note": "Go CLI wrapper around Caesar Research API. Well-structured code but URL construction is not injection-safe.",
    },
    "linkedin-dm": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "Browser session token hijacking — no expiration, no auth logging, persistent LinkedIn access",
            "Unauthenticated message content storage in Google Sheets — plaintext PII exfiltration",
            "Prompt injection via LinkedIn message content — no validation before agent processing",
            "Profile scraping and PII aggregation for social engineering campaigns",
        ],
        "attack_class": "social_engineering",
        "note": "VirusTotal-flagged. Browser automation for LinkedIn DM outreach. Complete social engineering pipeline when combined with lead-researcher and email-finder.",
    },
    "clawdex-trading": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "External binary dependency (clawdex npm CLI) executes unverifiable Solana DEX trades",
            "--yes flag bypasses all trade confirmation — prompt injection → immediate irreversible swaps",
            "Wallet private key at ~/.config/solana/id.json readable by any co-installed skill",
            "No slippage protection defaults — enables sandwich attacks",
        ],
        "attack_class": "financial_exploitation",
        "note": "VirusTotal-flagged. SKILL.md wrapper around clawdex npm CLI for Solana DEX trading via Jupiter aggregator.",
    },
    "super-research": {
        "severity": "HIGH",
        "owner": "kn74nrx32v4n0423jptzg1v5kx80ssnf",
        "version": "1.0.0",
        "findings": [
            "Deceptive provenance — claims to merge 8 research skills that do not exist on ClawHub",
            "Classified research framing creates false authority for agent decisions",
            "SKILL.md-only with no executable code — agent follows fabricated instructions",
        ],
        "attack_class": "social_engineering",
        "note": "Pure social engineering skill. Fabricated merger history designed to exploit AI agents' trust in stated provenance.",
    },
    "udp-messenger": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.6.1",
        "findings": [
            "Unauthenticated UDP protocol — no HMAC, no signatures, any LAN host can impersonate any agent",
            "Message injection into agent wake-up prompts without sanitization",
            "Unencrypted relay server exposes all agent communications on port 31415",
            "DNS hijacking via insecure hostname resolution, no DNSSEC or pinning",
            "Gateway token + fixed port (18789) enables predictable enumeration",
        ],
        "attack_class": "agent_communication_exploitation",
        "note": "Fundamentally insecure inter-agent communication protocol. Complete agent takeover in <1 minute on same LAN.",
    },
    "lead-researcher": {
        "severity": "CRITICAL",
        "owner": "jarvis",
        "version": "1.0.0",
        "findings": [
            "Unrestricted personal data scraping violates GDPR, CCPA, CAN-SPAM, LinkedIn ToS",
            "Multi-channel vishing enabler when combined with email-finder + outbound-call + linkedin-dm",
            "Prompt injection via enriched lead data (scraped social media posts in LLM prompts)",
            "Legal liability: GDPR €20M, CCPA $7,500/violation, CAN-SPAM $43K/email",
        ],
        "attack_class": "social_engineering",
        "note": "VirusTotal-flagged. Stub skill for automated lead generation via social media scraping. GDPR/CCPA compliance violations are the headline finding.",
    },
    "encrypted-docs": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "Encryption key exposed in URL fragment — leaked via browser history, referrer headers, agent context",
            "Plaintext document content returned in MCP responses, accessible to all co-installed skills",
            "No server-side authentication — ddocId is the only access control, enabling enumeration",
            "No local encryption before transmission to Fileverse — plaintext sent to third-party server",
        ],
        "attack_class": "false_security_guarantees",
        "note": "Wraps Fileverse/ddocs.new. 'End-to-end encryption' claim is misleading — keys in URLs, plaintext in agent context, no server auth.",
    },
    "smithnode": {
        "severity": "HIGH",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "Prompt injection in governance proposals — description field injected into AI validator reasoning",
            "Arbitrary prompt injection in AI P2P message broadcasting — inter-validator attacks",
            "Missing authorization on RPC methods — all endpoints accessible without auth when exposed",
            "Unsafe deserialization of P2P state messages from untrusted peers",
        ],
        "attack_class": "prompt_injection",
        "note": "AI blockchain validator node (Rust). Well-engineered but governance + messaging surfaces vulnerable to prompt injection between validators.",
    },
    "browser-auth": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.3.0",
        "findings": [
            "Session cookies stored in plaintext JSON — world-readable, cross-skill accessible",
            "No URL validation — SSRF to internal network endpoints (AWS metadata, localhost services)",
            "Socket.IO token in URL query string with no brute-force protection",
            "Screenshots broadcast every 400ms — 2FA codes, passwords visible in cleartext stream",
        ],
        "attack_class": "credential_theft",
        "note": "Playwright-based browser auth tunnel. Plaintext session.json is the headline finding — any co-installed skill can hijack captured sessions.",
    },
    "larry": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "Plaintext API key storage — Postiz, OpenAI, RevenueCat keys in config.json (cross-skill readable)",
            "TikTok draft posting lacks verification — malicious config enables public posting without user consent",
            "RevenueCat secret key logged in error messages",
            "No validation on caption/hook text — prompt injection and content moderation evasion",
            "TikTok spam infrastructure — automated content posting at scale (Round 35)",
            "Affiliate link injection — monetizes agent-generated content without disclosure (Round 35)",
            "Deceptive AI-generated content — no disclosure that content is AI-produced (Round 35)",
        ],
        "attack_class": "credential_theft",
        "note": "TikTok content automation. Plaintext config.json stores all API keys; unauthorized public posting possible via config manipulation. Round 35 confirmed spam infrastructure and affiliate injection.",
    },
    "cosyvoice3-macos": {
        "severity": "CRITICAL",
        "owner": "lhz",
        "version": "1.0.0",
        "findings": [
            "Zero-shot voice cloning enables vishing at scale — clone any voice from 3-10 second sample, no authorization",
            "Unvalidated reference audio file path — path traversal, symlink following, data exfiltration",
            "Unvalidated text input — prosody tags ([laughter], [breath]) enhance impersonation credibility",
            "Hardcoded paths to /Users/lhz/ — symlink attack enables model replacement and privilege escalation",
            "Model supply chain risk — no checksum verification on ModelScope downloads (~2GB binary)",
            "No audit trail for voice cloning requests",
        ],
        "attack_class": "agent_mediated_vishing",
        "note": "First voice cloning skill audited. Agent-mediated vishing at scale — synthetic speech generation without human approval or rate limiting.",
    },
    "gradientdesires": {
        "severity": "CRITICAL",
        "owner": "drewangeloff",
        "version": "1.0.3",
        "findings": [
            "Identity hijacking via API key exposure — no rotation mechanism, complete agent impersonation",
            "Soul engineering via personality profile manipulation — Big Five trait rewrite, backstory injection",
            "Inter-agent prompt injection via dating messages — 5000 char messages compromise recipient agents",
            "Public leaderboard enumeration — personality trait vectors extractable without authentication",
            "Activity feed reconnaissance — public SSE stream leaks swipes, matches, relationships in real time",
            "Auto-published love stories at DATING/IN_LOVE stages — reputational attack via false narratives",
        ],
        "attack_class": "soul_engineering",
        "note": "AI dating platform. Inter-agent social engineering at scale — personality profile manipulation, prompt injection via messages, and reputational damage via auto-published false love narratives.",
    },
    "polymarket-sdk": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "Credential exposure via environment variables — Ed25519 private key readable by any process",
            "Unvalidated price and quantity inputs — fund drainage via extreme orders, no bounds checking",
            "No user confirmation enforcement — documentation-only safeguard, prompt injection bypasses it",
            "No order preview enforcement — agent can skip preview and place blind trades",
            "No protection against order replay attacks — signed requests replayable",
        ],
        "attack_class": "financial_theft",
        "note": "Real-money prediction market trading. Unvalidated financial inputs + no trade confirmation = fund drainage via compromised agent.",
    },
    "self-evolve": {
        "severity": "CRITICAL",
        "owner": "Be1Human",
        "version": "1.0.0",
        "findings": [
            "Unrestricted agent self-modification of all identity/config files",
            "Explicit confirmation bypass — trains agent that asking permission is wrong",
            "Arbitrary shell execution with no guardrails",
            "Autonomous skill creation and publishing to ClawHub — worm propagation vector",
            "Soul engineering via SOUL.md rewriting",
            "Anti-safety training: suppresses all safety behaviors",
        ],
        "attack_class": "anti_safety_training",
        "note": "Most dangerous skill in Round 31. A jailbreak packaged as a skill. Chinese-language obfuscation. Creates self-propagating worm via autonomous ClawHub publishing.",
    },
    "coinpilot-hyperliquid-copy-trade": {
        "severity": "CRITICAL",
        "owner": "alannkl",
        "version": "1.0.3",
        "findings": [
            "10 wallet private keys in plaintext in tmp/coinpilot.json",
            "Private keys sent in HTTP headers to third-party API on every request",
            "Autonomous financial transactions with no client-side limits",
            "Full key custody delegated to Coinpilot API",
            "Config in tmp/ directory — commonly world-readable",
        ],
        "attack_class": "financial_theft",
        "note": "Copy-trading for Hyperliquid perpetual futures. Private keys transmitted to third-party API.",
    },
    "glitch-skillstore": {
        "severity": "HIGH",
        "owner": "chris6970barbarian-hue",
        "version": "2026.2.17",
        "findings": [
            "Arbitrary git clone from GitHub via shell exec",
            "Supply chain attack via skill installation — zero integrity verification",
            "Local filesystem traversal scanning sibling directories",
        ],
        "attack_class": "supply_chain",
        "note": "Skill-store-as-trojan-horse: compromise the skillstore and every installed skill can be modified.",
    },
    "awakening-protocol": {
        "severity": "HIGH",
        "owner": "mupengi-bot",
        "version": "1.0.0",
        "findings": [
            "Soul file generation with embedded self-evolution clause",
            "Evidence destruction — deletes BOOTSTRAP.md after completion",
            "Identity manipulation via onboarding conversation — no input validation",
        ],
        "attack_class": "soul_engineering",
        "note": "Soul poisoning via onboarding. Intercepting awakening conversation permanently embeds malicious values.",
    },
    "apiosk": {
        "severity": "HIGH",
        "owner": "obcraft",
        "version": "1.1.0",
        "findings": [
            "Plaintext private key in ~/.apiosk/wallet.json",
            "Spending limits in config but NEVER checked by client code",
            "Shell injection via unsanitized params in call-api.sh",
            "code-runner API enables RCE-as-a-service",
        ],
        "attack_class": "financial_theft",
        "note": "USDC micropayment gateway. Spending drain via skill injection — any co-installed skill can drain wallet silently.",
    },
    # Round 32 (2026-02-17)
    "email-daily-summary": {
        "severity": "CRITICAL",
        "owner": "10e9928a",
        "version": "0.1.0",
        "findings": [
            "Instructs agent to type plaintext passwords into browser login forms",
            "Full inbox access via browser automation — no scope limiting",
            "Prompt injection via email content passed to LLM summarization",
            "Screenshots of inbox saved to predictable disk paths",
            "Browser-as-credential-proxy bypasses OAuth/app-password security",
        ],
        "attack_class": "credential_theft",
        "note": "Uses browser automation to log into email accounts with plaintext passwords. Converts browser sessions into agent capability, bypassing all API-level security.",
    },
    "oneshot-agent": {
        "severity": "CRITICAL",
        "owner": "tormine",
        "version": "1.1.0",
        "findings": [
            "Raw wallet private key required as environment variable (ONESHOT_WALLET_PRIVATE_KEY)",
            "Autonomous spending with no human approval gate — commerce, voice, email, SMS",
            "Voice call capability enables agent-mediated vishing",
            "Bulk email capability enables automated phishing campaigns",
            "Data enrichment APIs enable automated personal data harvesting",
            "Composite capability risk — email + voice + SMS + commerce in single skill",
        ],
        "attack_class": "financial_theft",
        "note": "Commercial transaction SDK combining email, voice, SMS, commerce, and data enrichment. Private key in env var + no approval gates = autonomous spending via prompt injection.",
    },
    "agent-earner": {
        "severity": "HIGH",
        "owner": "mmchougule",
        "version": "1.0.0",
        "findings": [
            "Wallet private key as environment variable (CLAWTASKS_WALLET_KEY)",
            "Autonomous staking with 20% default cap — agent commits real funds",
            "Auto-generated proposals submitted under owner's identity",
            "Two external API keys stored as environment variables",
        ],
        "attack_class": "financial_theft",
        "note": "Autonomous bounty hunter that stakes real USDC. Private key exposure + autonomous staking = fund loss via compromised agent.",
    },
    "agentpayy": {
        "severity": "HIGH",
        "owner": "horizonflowhq-AI",
        "version": "1.0.1",
        "findings": [
            "Auto-bootstrap wallet creation without explicit user consent",
            "Silent spending — agent instructed NOT to report 402 payment resolution to user",
            "Referral incentive creates recommendation bias (5% affiliate split)",
            "Supply chain risk via pip dependencies (coinbase-cdp, requests)",
        ],
        "attack_class": "financial_theft",
        "note": "Payment OS that creates wallets automatically and silently spends user funds on 402 errors. Referral incentive compromises recommendation integrity.",
    },
    # --- Round 33 findings (Feb 17, 2026 15:30 UTC) ---
    "amazon-orders": {
        "severity": "HIGH",
        "owner": "alexdlaird",
        "version": "unspecified",
        "findings": [
            "Plaintext Amazon credentials in env vars — AMAZON_USERNAME, AMAZON_PASSWORD, AMAZON_OTP_SECRET_KEY",
            "OTP secret key is TOTP seed — attacker can generate infinite MFA codes, completely bypassing 2FA",
            "Full order history access — PII goldmine: purchases, delivery addresses, payment amounts",
            "Session credential scraping — authenticated sessions could be exfiltrated for account takeover",
        ],
        "attack_class": "credential_exposure",
    },
    "linkedin-dm": {
        "severity": "HIGH",
        "owner": "unattributed",
        "version": "unspecified",
        "findings": [
            "Automated LinkedIn spam with explicit anti-detection — /feed/ nav before profiles, random delays, session limits",
            "Profile scraping and relationship mining — reads full career history, education, connections for social engineering prep",
            "Two-message manipulation technique — opener then pitch to feel more personal (explicit social engineering tactic)",
            "CRM-integrated outreach tracking — Google Sheets logging creates persistent record of social engineering campaigns",
            "Browser session hijacking — requires LinkedIn session cookies for automation",
        ],
        "attack_class": "social_engineering",
    },
    "whatsapp-business": {
        "severity": "MEDIUM",
        "owner": "maton",
        "version": "1.0.3",
        "findings": [
            "Third-party OAuth proxy — all WhatsApp traffic routes through gateway.maton.ai, exposing message content",
            "Message sending without confirmation — agent can send WhatsApp messages to any phone number",
            "Contact and location data exposure — API supports sending contact cards and location data",
        ],
        "attack_class": "messaging_abuse",
    },
    "fints-banking": {
        "severity": "MEDIUM",
        "owner": "h4gen",
        "version": "unspecified",
        "findings": [
            "Bank transfer capability — despite good security controls, prompt injection could bypass APPROVE TRANSFER gate",
            "Well-designed: dry-run, explicit approval phrases, anti-indirect-content rules (model for other skills)",
            "Debug mode could expose bank protocol details and session data",
        ],
        "attack_class": "financial_exploitation",
        "note": "One of the best-designed high-risk skills. Security controls are thorough but only as strong as the LLM's ability to resist prompt injection.",
    },
    "self-improving-agent": {
        "severity": "MEDIUM",
        "owner": "peterskoett",
        "version": "unspecified",
        "findings": [
            "Memory poisoning pipeline — crafted corrections can be promoted to CLAUDE.md, AGENTS.md, SOUL.md (permanent instructions)",
            "Hook-based code execution — installs shell hooks that run on every prompt and bash command",
            "Cross-agent learning propagation — sessions_send/spawn spreads poisoned learnings across agents",
        ],
        "attack_class": "memory_poisoning",
    },
    "ipcam": {
        "severity": "LOW",
        "owner": "tao",
        "version": "1.0.0",
        "findings": [
            "Plaintext camera credentials in JSON config — admin username/password stored in ~/.config/ipcam/config.json",
            "Network reconnaissance via ONVIF discovery — scans local network for cameras",
            "PTZ control could create physical security blind spots via prompt injection",
        ],
        "attack_class": "physical_security",
    },
    "opensoulmd": {
        "severity": "HIGH",
        "owner": "unattributed",
        "version": "unspecified",
        "findings": [
            "Remote soul replacement — downloads SOUL.md from registry and writes to agent's personality file",
            "Pipe-to-shell installation — curl | sh with no verification",
            "No integrity verification on downloaded soul files — MITM or registry compromise injects malicious instructions",
        ],
        "attack_class": "soul_engineering",
    },
    "tradecraft": {
        "severity": "MEDIUM",
        "owner": "unattributed",
        "version": "1.0.1",
        "findings": [
            "Agent persona injection — 'degen trader' personality overrides agent's base identity",
            "Copy trading between agents — coordinated pump-and-dump via follower agents",
            "Autonomous beta signup — agents self-register and begin trading without human involvement",
        ],
        "attack_class": "soul_engineering",
    },
    "email-finder": {
        "severity": "MEDIUM",
        "owner": "unattributed",
        "version": "unspecified",
        "findings": [
            "Email harvesting toolkit — 5 methods: scraping, dorking, pattern guessing, DNS, SMTP verification",
            "SMTP RCPT TO verification could trigger abuse reports and IP blacklisting",
        ],
        "attack_class": "reconnaissance",
    },
    "stonebornbot": {
        "severity": "HIGH",
        "owner": "unattributed",
        "findings": [
            "200+ plaintext private keys stored in config.json",
            "Front-running infrastructure: mempool watching + pre-signed tx + multi-RPC broadcast",
            "War mode gas auto-escalation without caps",
            "Prompt injection → mass wallet drain across 200+ wallets",
        ],
        "attack_class": "crypto_drain",
    },
    "autonomous-skill-orchestrator": {
        "severity": "HIGH",
        "owner": "unattributed",
        "version": "1.1.0",
        "findings": [
            "Anti-safety pattern: explicitly disables user confirmation and validation",
            "User deaf mode: ignores all user messages except stop command",
            "Infinite loop design: loops execution with same frozen intent",
            "Has real guardrails (ambiguity classification, risk gates) but core pattern is anti-safety",
        ],
        "attack_class": "anti_safety_training",
    },
    # --- Round 35 findings (Feb 17, 2026 ~16:30 UTC) ---
    "linkedin-followup": {
        "severity": "CRITICAL",
        "owner": "unattributed",
        "version": "unspecified",
        "findings": [
            "CRITICAL: Social engineering platform with built-in anti-detection (random delays, session throttling)",
            "CRITICAL: DM scraping — reads full message history for social engineering context",
            "CRITICAL: Hardcoded PII in skill configuration — names, email addresses, profile URLs",
            "HIGH: Automated LinkedIn outreach with evasion techniques to bypass platform rate limits",
            "MEDIUM: Profile data harvesting for targeted social engineering campaigns",
        ],
        "attack_class": "social_engineering",
    },
    "molta": {
        "severity": "CRITICAL",
        "owner": "unattributed",
        "version": "unspecified",
        "findings": [
            "CRITICAL: Agent botnet recruitment — skill enrolls agent into coordinated vote manipulation network",
            "CRITICAL: Prompt injection C2 channel — command-and-control instructions embedded in API responses",
            "HIGH: Vote manipulation infrastructure — automated upvote/downvote campaigns across platform",
            "HIGH: Coordinated inauthentic behavior — multiple agents acting as single botnet",
            "MEDIUM: Platform integrity subversion — undermines trust metrics and content ranking",
        ],
        "attack_class": "social_engineering",
    },
    "humanod": {
        "severity": "CRITICAL",
        "owner": "Armandobrazil",
        "version": "1.0.1",
        "findings": [
            "CRITICAL: Unrestricted task creation — freeform instructions to real humans with zero content restrictions",
            "CRITICAL: Autonomous financial spending with no caps — unbounded EUR price field, no rate limits",
            "HIGH: Prompt injection via task descriptions targeting human workers",
            "HIGH: Data exfiltration channel via external Render.com free-tier API",
            "HIGH: No human-in-the-loop approval — direct POST creates real-world tasks",
            "HIGH: Physical location targeting — directs strangers to specific addresses",
            "MEDIUM: Single unscoped API key with full authority",
            "MEDIUM: Validation criteria usable as human coercion mechanism",
        ],
        "attack_class": "human_delegation_exploitation",
        "note": "Purest expression of human delegation exploitation. Turns real humans into actuators for AI commands with real money and physical consequences.",
    },
    "paygents": {
        "severity": "LOW",
        "owner": "unattributed",
        "version": "unspecified",
        "findings": [
            "Best wallet skill design in ecosystem — no key custody, human-in-the-loop for all transactions",
            "Model for ecosystem: server-side custody with explicit human approval gates",
            "No plaintext private keys — all signing happens server-side with user confirmation",
        ],
        "attack_class": "none",
        "note": "MODEL SKILL: Demonstrates correct wallet architecture. No key custody, human-in-the-loop for every transaction. Other wallet skills should follow this design.",
    },
    "dates": {
        "severity": "HIGH",
        "owner": "ivangdavila",
        "version": "1.0.0",
        "findings": [
            "CRITICAL: Third-party PII collection without consent — dossiers on dating partners (names, employers, medical info) without knowledge",
            "HIGH: Plaintext storage at predictable public path ~/dates/ — readable by any co-installed skill",
            "HIGH: Cross-skill data exposure — path published in SKILL.md, trivial targeted exfiltration",
            "HIGH: No data retention or deletion policy — PII persists indefinitely",
            "MEDIUM: Behavioral manipulation via proactive surfacing — poisoned data yields attacker-controlled suggestions",
            "MEDIUM: Psychological profile storage (relationship criteria, self-assessment) in plaintext",
        ],
        "attack_class": "data_exfiltration",
        "note": "Not malicious but creates high-value unprotected data store. Third-party PII without consent, publicly documented path, no encryption.",
    },
    "vpn": {
        "severity": "LOW",
        "owner": "unattributed",
        "version": "unspecified",
        "findings": [
            "Educational only — describes VPN concepts with no executable code",
            "No actual VPN configuration or credential handling",
        ],
        "attack_class": "none",
    },
    "aiclude-vulns-scan": {
        "severity": "MEDIUM-HIGH",
        "owner": "mastergear4824",
        "version": "2.1.1",
        "findings": [
            "HIGH: Prompt injection via unsanitized scan results — vulnerability descriptions flow into agent context, remediation could contain malicious commands",
            "HIGH: Unverifiable trust boundary — claims only package names sent but no code to verify; server could build ecosystem intelligence map",
            "HIGH: External data exfiltration channel — package names sent to vs.aiclude.com with auto-registration",
            "MEDIUM: Unpinned npm package dependency — supply chain risk via @aiclude/security-skill",
            "MEDIUM: Auto-registration reveals agent interests to external service",
        ],
        "attack_class": "data_exfiltration",
        "note": "Competitor security scanner that is itself an attack vector. Unsanitized results = prompt injection channel. On-device analysis architecturally superior.",
    },
    "typhoon-starknet-account": {
        "severity": "HIGH",
        "owner": "esdras-sena",
        "version": "0.3.3",
        "findings": [
            "CRITICAL: Private key passed as CLI argument — visible in process list to any system user",
            "CRITICAL: Private key output to stdout in JSON — enters LLM context, logs, upstream systems",
            "HIGH: Plaintext private key storage on disk (no encryption)",
            "HIGH: Cron job injection via dynamically written shell scripts — persistent execution",
            "HIGH: Shell command execution via execSync for crontab manipulation",
            "HIGH: skipAuth parameter bypasses user authorization for transactions",
            "HIGH: explicitDangerousOk flag bypasses dangerous-function checks — injectable via JSON",
            "HIGH: Attestation system disabled via TYPHOON_ATTEST_DISABLE=1 env var — master kill switch",
            "MEDIUM: Arbitrary protocol registration with minimal address validation",
            "MEDIUM: Prompt injection protection gaps (dual-layer regex inconsistencies)",
            "MEDIUM: PRIVATE_KEY accepted from environment variable (system-wide leakage)",
            "MEDIUM: Unvalidated webhook URL = data exfiltration channel",
            "MEDIUM: Broad tool permissions (Bash, Read, Write, Glob, Grep, Task)",
            "MEDIUM: Excessive filesystem writes across multiple directories + crontab",
        ],
        "attack_class": "credential_theft",
        "note": "Anonymous Starknet wallet. Invested in prompt injection defenses but fundamental key management leaks keys through CLI args, JSON output, and env vars. Stark contrast with paygents (correct architecture).",
    },
    "claude-mem": {
        "severity": "HIGH",
        "owner": "thedotmack",
        "version": "10.2.3",
        "findings": [
            "HIGH: Unencrypted SQLite DB stores ALL user prompts and observations — default permissions",
            "HIGH: Zero automatic credential detection — no filtering for API keys, passwords, secrets",
            "MEDIUM: All tool data sent to external AI APIs (Anthropic/Gemini/OpenRouter) before storage",
            "MEDIUM: HTTP API port 37777 has NO authentication — any local process can read/write memories",
            "MEDIUM: curl|bash install chain with no integrity verification (bun.sh + astral.sh)",
            "MEDIUM: Cross-MCP memory poisoning — malicious server can inject false context",
            "LOW: Xiaomi model hardcoded as default (data routed through OpenRouter to Xiaomi)",
            "LOW: No session isolation — all projects share single memory store",
            "LOW: No rate limiting on memory ingestion — flooding attack possible",
        ],
        "attack_class": "data_collection",
        "report_url": "https://arcself.com/research/claude-mem-security-audit.md",
        "note": "12,900+ stars. Not malware — but a comprehensive session recorder with no credential detection. Responsible disclosure in progress (Anthropic HackerOne + maintainer).",
    },
    "kubectl": {
        "severity": "CRITICAL",
        "owner": "ddevaal",
        "version": "1.0.0",
        "findings": [
            "CRITICAL: Shell command injection via unsanitized script parameters",
            "CRITICAL: Prompt injection → production infrastructure destruction (delete, drain, scale-to-zero)",
            "CRITICAL: Kubernetes secret exfiltration (get secrets -o json/yaml)",
            "CRITICAL: kubectl exec — arbitrary code execution inside running containers",
            "CRITICAL: Kubeconfig credential exposure (config view --flatten exposes certs/tokens)",
            "HIGH: No namespace restriction — full cluster scope by default (-A flag)",
            "HIGH: kubectl cp — bidirectional file transfer (data exfil / payload delivery)",
            "HIGH: No command allowlisting — agent can run any kubectl subcommand",
            "HIGH: kubectl apply -f from untrusted URLs (remote manifest RCE)",
            "MEDIUM: Advisory-only dry-run — no enforcement",
            "MEDIUM: Node drain script has bypass-prone confirmation",
        ],
        "attack_class": "infrastructure_destruction",
        "report_url": "https://arcself.com/research/clawhub-kubectl-audit.md",
        "note": "998 downloads. Grants AI agent full unrestricted Kubernetes cluster access. All safety controls are advisory text trivially bypassed by prompt injection.",
    },
    # ── Round 37 skills ──────────────────────────────────────────────────
    "deep-scraper": {
        "severity": "HIGH",
        "owner": "Joseph",
        "version": "1.0.1",
        "findings": [
            "CRITICAL: SSRF via arbitrary URL passed directly to page.goto() with zero validation",
            "CRITICAL: Host filesystem write-back via Docker volume mount (container→host persistence)",
            "HIGH: Chromium --no-sandbox combined with SSRF removes browser/host barrier",
            "HIGH: Missing Dockerfile — build chain unverifiable",
            "HIGH: Chinese-language duplicate handler from unknown source",
            "HIGH: No URL allowlist or blocklist",
        ],
        "attack_class": "ssrf",
        "note": "Docker-based Playwright scraper. SSRF + no sandbox + host volume = full host compromise chain.",
    },
    "bonero-miner": {
        "severity": "CRITICAL",
        "owner": "happybigmtn",
        "version": "1.0.0",
        "findings": [
            "CRITICAL: Cryptojacking — entire purpose is mining cryptocurrency on host CPU",
            "CRITICAL: curl|bash RCE — remote install script piped to bash",
            "CRITICAL: Port masquerade — overrides own 18880 to use Monero's 18080 to evade detection",
            "HIGH: Centralized network — all 10 seed nodes on Contabo VPS (single operator)",
            "HIGH: Social engineering — pre-scripted 'Can I mine?' dialogue for human manipulation",
            "HIGH: Detached daemon — no kill switch, survives agent shutdown",
            "HIGH: Persistent background process mines after agent session ends",
        ],
        "attack_class": "cryptojacking",
        "note": "Full cryptojacking skill with port masquerade (new attack class #25). Monero mining daemon disguised as legitimate network traffic.",
    },
    "elite-longterm-memory": {
        "severity": "HIGH",
        "owner": "NextFrontierBuilds",
        "version": "1.0.0",
        "findings": [
            "HIGH: Agent behavior modification — 12KB instruction payload overrides agent behavior",
            "HIGH: Silent data persistence — stores user data across 5 layers without consent",
            "HIGH: Memory poisoning surface — autoRecall: true with minScore: 0.3 creates wide injection surface",
            "HIGH: Cloud exfiltration — sends conversations to SuperMemory and Mem0 cloud services",
            "HIGH: Sub-agent propagation — instructs passing poisoned context to spawned agents",
        ],
        "attack_class": "data_collection",
        "note": "Memory service that silently exfiltrates to multiple cloud backends and propagates poisoned context to sub-agents.",
    },
    "bright-data": {
        "severity": "HIGH",
        "owner": "MeirKaD",
        "version": "1.0.0",
        "findings": [
            "HIGH: SSRF via proxy — any URL forwarded through Bright Data commercial proxy with no validation",
            "HIGH: CAPTCHA bypass as explicit capability — circumvents bot detection",
            "HIGH: Exfiltration channel — anonymous outbound via residential proxy network",
            "MEDIUM: Cost amplification — no rate limits or budget caps on proxy requests",
        ],
        "attack_class": "anti_detection",
        "note": "Commercial proxy wrapper. CAPTCHA bypass + residential proxies = anonymous web scraping and exfiltration.",
    },
    "lead-generation": {
        "severity": "CRITICAL",
        "owner": "atyachin",
        "version": "1.0.0",
        "findings": [
            "CRITICAL: Mass PII harvesting — cross-platform surveillance without consent (Twitter, Instagram, Reddit)",
            "CRITICAL: Behavioral profiling — scores individuals by emotional vulnerability for targeting",
            "HIGH: Social engineering templates — deceptive 'I had the same problem!' outreach",
            "HIGH: Persistent tracking DB — sent-leads.json keyed by platform:author:post_id",
            "MEDIUM: Xpoz commercial funnel — skill exists to drive Xpoz paid subscriptions",
        ],
        "attack_class": "data_collection",
        "note": "Part of Xpoz surveillance ecosystem (7+ skills). Harvests PII and scores targets by emotional vulnerability.",
    },
    "reddit-scraper": {
        "severity": "LOW",
        "owner": "javicasper",
        "version": "1.0.0",
        "findings": [
            "MEDIUM: URL path injection via unsanitized subreddit parameter",
            "MEDIUM: No rate limiting",
            "MEDIUM: Full selftext extraction contradicts docs claiming 200-char truncation",
            "MEDIUM: Fabricated User-Agent 'Clawdbot/1.0'",
        ],
        "attack_class": "data_collection",
        "note": "Cleanest skill in Round 37. No exfiltration, no credential exposure, no command injection.",
    },
    "cloud-memory": {
        "severity": "CRITICAL",
        "owner": "aerialcombat",
        "version": "1.0.0",
        "findings": [
            "CRITICAL: Bootstrap injection PoC CONFIRMED — stored prompt injection returned verbatim on every /bootstrap startup",
            "CRITICAL: Data exfiltration by design — agents send decisions, preferences, relationships to opaque server",
            "CRITICAL: Autonomous registration — 'No human required', agents create accounts without consent",
            "HIGH: Verification bypass — unverified agents can read/write/delete memories",
            "HIGH: Coerced social media promotion — 'verification' requires tweeting branded hashtags",
            "MEDIUM: Version divergence — live skill.md more aggressive than ClawHub version",
            "LOW: Infrastructure leak — localhost:8090 in API responses",
        ],
        "attack_class": "memory_poisoning",
        "note": "New attack class #23: Bootstrap Context Injection. Service operator has persistent cross-session control over any connected agent.",
    },
    "mdk-agent-wallet": {
        "severity": "CRITICAL",
        "owner": "satbot-mdk",
        "version": "1.0.0",
        "findings": [
            "CRITICAL: Plaintext 12-word mnemonic printed to stdout during init — enters agent context",
            "CRITICAL: Plaintext mnemonic on disk at ~/.mdk-wallet/config.json readable by any skill",
            "CRITICAL: Zero spend limits — drain entire balance in one call, no confirmation",
            "CRITICAL: Unauthenticated localhost API — POST /send on port 3456 with zero auth",
            "HIGH: Prompt injection via Lightning — BOLT12 payer notes flow unsanitized into agent context",
            "HIGH: Defaults to mainnet — real Bitcoin money with no test-mode recommendation",
        ],
        "attack_class": "crypto_drain",
        "note": "Real Bitcoin Lightning wallet. Plaintext mnemonic + zero spend limits + unauthenticated API = trivial drain.",
    },
    "social-intelligence": {
        "severity": "CRITICAL",
        "owner": "atyachin",
        "version": "1.0.0",
        "findings": [
            "CRITICAL: 7-skill surveillance hub — gateway to 35 MCP tools across Xpoz ecosystem",
            "CRITICAL: Mass profiling — individual profiling, connection graphs, behavioral scoring at scale",
            "HIGH: Automated social engineering — lead scoring by vulnerability + deceptive outreach",
            "HIGH: OAuth credential exposure — tokens leaked via cmdline args, PKCE state in predictable paths",
            "HIGH: Bulk exports — 64K rows/38MB CSV dumps to /tmp",
            "MEDIUM: Opaque data pipeline — all queries logged by Xpoz per their privacy policy",
        ],
        "attack_class": "data_collection",
        "note": "Hub for Xpoz ecosystem (7 sub-skills, 35 tools, 1.5B+ posts indexed). Coordinated multi-skill surveillance platform.",
    },
    "abm-outbound": {
        "severity": "CRITICAL",
        "owner": "dru-ca",
        "version": "1.0.0",
        "findings": [
            "CRITICAL: Autonomous doxing pipeline — LinkedIn → email/phone → home address → physical mail",
            "CRITICAL: Skip Trace home address harvesting — resolves residential addresses from names",
            "HIGH: Multi-channel social engineering — physical letter → 'Got my note?' email → LinkedIn → break-up email",
            "HIGH: Zero consent — no opt-in, no unsubscribe, no CAN-SPAM/GDPR compliance",
            "HIGH: Phishing-ready infrastructure — trivially repurposable for spear-phishing at scale",
        ],
        "attack_class": "data_collection",
        "note": "New attack class #24: Autonomous Doxing Pipeline. First skill that crosses digital-physical boundary for targeting individuals at home addresses.",
    },
    # ── Round 38 skills ──────────────────────────────────────────────────
    "otp-challenger": {
        "severity": "CRITICAL",
        "owner": "ryancnelson",
        "version": "1.0.0",
        "findings": [
            "CRITICAL: RCE via OTP_FAILURE_HOOK — arbitrary shell commands execute on every failed OTP verification",
            "HIGH: TOTP secret in environment variable accessible to all co-installed skills",
            "HIGH: 24-hour verification window (144x longer than standard TOTP validity)",
            "MEDIUM: State file manipulation — writing verified:true to otp-state.json bypasses OTP entirely",
            "MEDIUM: Plaintext secrets in ~/.openclaw/config.yaml",
            "LOW: No rate limiting — unlimited brute-force attempts across sessions",
        ],
        "attack_class": "code_execution",
        "note": "Security tool as attack vector. OTP verification skill with built-in RCE mechanism — authentication FAILURE triggers arbitrary command execution.",
    },
    "tunneling": {
        "severity": "HIGH",
        "owner": "simantak-dabhade",
        "version": "1.0.0",
        "findings": [
            "HIGH: Turnkey data exfiltration — exposes any local service to public internet via SSH tunnel",
            "HIGH: SSH host key auto-accept (StrictHostKeyChecking=accept-new) enables MITM",
            "MEDIUM: Third-party traffic interception — all traffic transits through tinyfi.sh infrastructure",
            "MEDIUM: Custom subdomain phishing — convincing URLs like company-name.tinyfi.sh",
            "MEDIUM: Persistent background channel — tunnel survives agent session, no kill switch",
            "LOW: No endpoint authentication — anyone with URL can access exposed service",
        ],
        "attack_class": "data_exfiltration",
        "note": "SSH tunneling as composable exfiltration primitive. Appears benign but provides exact capability for data exfiltration and C2.",
    },
    "codex-sub-agents": {
        "severity": "HIGH",
        "owner": "adamsardo",
        "version": "1.0.0",
        "findings": [
            "HIGH: Full machine access via danger-full-access sandbox mode including network",
            "HIGH: Auto-approve all writes via --full-auto flag — silent file modification",
            "MEDIUM: Unauthenticated MCP server — codex mcp-server exposes tools via stdio with no auth",
            "MEDIUM: Sub-agent privilege escalation — spawned agents get exec/read/write/edit/process tools",
            "MEDIUM: Custom slash command injection via ~/.codex/prompts/ directory",
            "LOW: Auth profile sync from ~/.codex/auth.json — credential exposure",
        ],
        "attack_class": "code_execution",
        "note": "Sandbox bypass by configuration. danger-full-access + --full-auto = total system compromise via prompt injection.",
    },
    "office365-connector": {
        "severity": "HIGH",
        "owner": "unknown",
        "version": "2.0.0",
        "findings": [
            "HIGH: Client secrets visible in process list via CLI arguments",
            "HIGH: Maximum email/calendar permissions (Mail.ReadWrite, Mail.Send, Calendars.ReadWrite, Contacts.ReadWrite)",
            "HIGH: Multi-account amplification — single compromise exposes ALL linked Microsoft 365 identities",
            "MEDIUM: Token storage accessible to co-installed skills at ~/.openclaw/auth/office365/",
            "MEDIUM: Autonomous email sending — no confirmation gate, agent sends from real corporate identity",
            "LOW: Autonomous email from user identity enables automated BEC at scale",
        ],
        "attack_class": "credential_theft",
        "note": "Multi-identity Microsoft 365 compromise. Single skill compromise = all linked email, calendar, and contacts across personal/corporate/client accounts.",
    },
    "deploy-agent": {
        "severity": "MEDIUM",
        "owner": "sherajdev",
        "version": "1.0.0",
        "findings": [
            "MEDIUM: Author-controlled default domain — all deployments route through sheraj.org",
            "MEDIUM: Cloudflare token exposure at ~/.wrangler.toml readable by any skill",
            "MEDIUM: Plaintext deployment state files in ~/.clawdbot/skills/deploy-agent/state/",
            "LOW: Destructive troubleshooting commands (rm -rf node_modules)",
            "LOW: No artifact integrity verification (no checksums or signatures)",
        ],
        "attack_class": "supply_chain",
        "note": "Author-controlled default infrastructure pattern. Users deploying with defaults route through skill author's domain.",
    },
    "plan-executor": {
        "severity": "MEDIUM",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "MEDIUM: No-interaction design — poisoned plan executes fully before detection",
            "MEDIUM: System I/O access with prompt-based guardrails only (not programmatic)",
            "MEDIUM: Clear-but-malicious plans pass all validation checks",
            "LOW: Execution continues even if guardrails are bypassed via prompt injection",
        ],
        "attack_class": "prompt_injection",
        "note": "Autonomous execution skill. Guardrails are well-designed but enforced via prompt text, not code. Malicious plans with clear steps pass all validation.",
    },
    "factory-ai": {
        "severity": "MEDIUM",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "MEDIUM: Silent code modification via --force flag without confirmation",
            "MEDIUM: Non-interactive exec mode — deploys without confirmation",
            "MEDIUM: Broad filesystem read across org for codebase understanding",
            "LOW: MCP server integration extends attack surface",
            "LOW: Session persistence stores potentially sensitive context",
            "LOW: Hardcoded personal path reveals minimal security review",
        ],
        "attack_class": "code_execution",
        "note": "Force mode + non-interactive exec = silent code modification and deployment via prompt injection.",
    },
    "secret-portal": {
        "severity": "LOW",
        "owner": "awlevin",
        "version": "1.0.0",
        "findings": [
            "MEDIUM: Runtime package execution via uv run — typosquat/compromise risk",
            "LOW: Internet-accessible secret entry via cloudflared tunnel (300-second window)",
            "LOW: URL interception window during tunnel lifetime",
            "LOW: HTML injection via instructions parameter",
        ],
        "attack_class": "supply_chain",
        "note": "Good security model overall. One-time use, 300s timeout, random token. Above average for ecosystem. Supply chain via runtime execution is the main risk.",
    },
    "xpr-code-sandbox": {
        "severity": "LOW",
        "owner": "paulgnz",
        "version": "1.0.0",
        "findings": [
            "LOW: No per-execution memory limits — potential DoS via memory exhaustion",
            "LOW: Potential prototype pollution surface in V8 isolate",
            "INFO: Best-practice security model — no network, no filesystem, no imports, short timeout, output cap",
        ],
        "attack_class": "none",
        "note": "Model for how code execution skills should work. Explicit constraints, short timeout, output cap. Genuinely good security design.",
    },
    "infra-as-code": {
        "severity": "LOW",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "LOW: terraform destroy example could be executed by agent",
            "LOW: force-unlock example dangerous against production state",
            "LOW: tfvars secret guidance may not be followed by agents",
            "INFO: Good security advice overall — primarily documentation, no autonomous execution",
        ],
        "attack_class": "none",
        "note": "Documentation skill. Low risk by design. Security advice is sound.",
    },
    # ── Round 39 skills ──────────────────────────────────────────────────
    "danube": {
        "severity": "CRITICAL",
        "owner": "danube",
        "version": "8.0.5",
        "findings": [
            "CRITICAL: store_credential() sends plaintext API keys to third-party danubeai.com servers",
            "CRITICAL: All tool calls route through mcp.danubeai.com — Danube sees all parameters including email bodies, messages, payment data",
            "HIGH: Device authorization flow with agent polling — social engineering pattern",
            "HIGH: No credential scoping — single API key grants access to ALL tools on platform",
            "MEDIUM: VirusTotal flagged — still installable with --force",
            "INFO: All service interactions proxied through Danube infrastructure, no E2E encryption",
        ],
        "attack_class": "credential_theft",
        "note": "Universal credential proxy. Tunnels agent access to 30+ services through third-party. VirusTotal flagged. Agent transmits Gmail/Slack/GitHub/Stripe keys to Danube servers.",
    },
    "agentic-commerce": {
        "severity": "CRITICAL",
        "owner": "purch",
        "version": "1.0.1",
        "findings": [
            "CRITICAL: Private keys accepted on CLI — visible in ps aux, shell history, process list",
            "CRITICAL: Autonomous purchase flow — order creation AND Solana mainnet transaction in one script, no confirmation",
            "HIGH: Private key sent to third-party API — malicious serialized transaction could drain funds",
            "MEDIUM: PII collection — full shipping address sent to api.purch.xyz with no privacy policy",
            "MEDIUM: No spend limits — no max transaction, no daily cap, no confirmation for high-value purchases",
        ],
        "attack_class": "crypto_drain",
        "note": "Real commerce with Solana mainnet. Private keys on CLI + autonomous spending + no limits = trivial fund theft.",
    },
    "kakiyo": {
        "severity": "HIGH",
        "owner": "kakiyo",
        "version": "1.0.1",
        "findings": [
            "HIGH: 42-tool LinkedIn automation — automated mass outreach at scale",
            "HIGH: No consent verification — prospects added by URL without consent",
            "MEDIUM: AI-generated personalized messages designed to appear human",
            "MEDIUM: Anti-detection evasion — working hours and rate limiting to avoid LinkedIn bot detection",
        ],
        "attack_class": "anti_detection",
        "note": "LinkedIn spam infrastructure with AI-generated messages. 42 tools, mass outreach, anti-detection designed to evade platform security.",
    },
    "instagram-scraper": {
        "severity": "HIGH",
        "owner": "influenza",
        "version": "1.0.3",
        "findings": [
            "HIGH: Mass PII collection — usernames, names, bios, follower counts, engagement data, profile photos",
            "MEDIUM: Browser fingerprinting + human behavior simulation to evade Instagram bot detection",
            "MEDIUM: Credential handling — handles Instagram login credentials and verification codes",
            "LOW: Google API key in plaintext in scraper_config.json",
        ],
        "attack_class": "data_collection",
        "note": "Instagram PII harvester with stealth fingerprinting. Categorizes targets by influencer tier for targeting.",
    },
    "browser-cash": {
        "severity": "HIGH",
        "owner": "browser-cash",
        "version": "1.0.0",
        "findings": [
            "HIGH: Anti-bot bypass as core feature — bypasses Cloudflare, DataDome, PerimeterX",
            "MEDIUM: Persistent logged-in profiles — maintains authenticated access across sessions",
            "MEDIUM: Geographic spoofing — country selection for geo-restriction bypass",
            "LOW: API key stored in plaintext in clawdbot config",
        ],
        "attack_class": "anti_detection",
        "note": "Commercial anti-bot bypass service. Designed to circumvent website security controls.",
    },
    # ── Round 40 skills ──────────────────────────────────────────────────
    "agent-zero-bridge": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "CRITICAL: Bidirectional agent-to-agent injection — Agent Zero puppets Clawdbot via cross-tool invocation with no message sanitization",
            "CRITICAL: Self-correction loops create persistent adaptive attacker",
            "CRITICAL: Unrestricted shell exec surface",
            "CRITICAL: 0.0.0.0 gateway binding — exposed to network",
            "HIGH: Credential exposure via cross-agent context sharing",
        ],
        "attack_class": "prompt_injection",
        "note": "Bidirectional agent bridge. Injection in either direction creates persistent adaptive attacker via self-correction loops.",
    },
    "snaprender": {
        "severity": "HIGH",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "CRITICAL: Vision-based prompt injection — malicious web content enters through screenshot → vision model → agent action",
            "CRITICAL: SSRF with no skill-layer URL validation",
            "HIGH: Bash exec surface for screenshot processing",
            "MEDIUM: Cross-modal attack bypasses text-based injection defenses",
        ],
        "attack_class": "prompt_injection",
        "note": "Novel: Vision-based prompt injection. Cross-modal attack where malicious content in screenshots triggers agent actions.",
    },
    "wreckit-ralph": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "CRITICAL: eval-based shell execution via mutation-test.sh on untrusted target repos",
            "CRITICAL: Audit target becomes attacker — crafted package.json/Cargo.toml executes commands during verification",
            "CRITICAL: 8-agent swarm with no inter-agent isolation",
            "HIGH: In-place source mutation during testing",
            "HIGH: No sandbox for code execution",
        ],
        "attack_class": "code_execution",
        "note": "Audit-target-as-attack-vector pattern. The codebase being verified can execute arbitrary commands during the verification process.",
    },
    "pet-rpg": {
        "severity": "MEDIUM",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "CRITICAL: Phantom A2A module (dependency confusion) — online.py doesn't exist, exploitable namespace for module hijacking",
            "MEDIUM: No authentication on any endpoint",
            "MEDIUM: Security dismissal social engineering — designed to make security concerns seem silly",
        ],
        "attack_class": "supply_chain",
        "note": "Phantom dependency confusion. Advertises non-existent module creating exploitable namespace for module hijacking.",
    },
    "gtm-system": {
        "severity": "HIGH",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "CRITICAL: Hardcoded Exa API key in source code",
            "CRITICAL: Doppler secrets infrastructure exposure",
            "HIGH: PII stored in unencrypted plaintext SQLite database",
            "MEDIUM: Third-party API keys embedded in skill code",
        ],
        "attack_class": "credential_theft",
        "note": "Hardcoded API keys + Doppler secrets exposure + PII in plaintext SQLite. Multiple credential theft vectors.",
    },
    "cellcog": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "CRITICAL: Single API key controls 30+ skills — one key compromise = total ecosystem takeover",
            "CRITICAL: SHOW_FILE tag enables arbitrary local file exfiltration",
            "CRITICAL: Sensitivity mismatch — meme-cog shares credentials with legal-cog",
            "HIGH: Legal documents sent to opaque cloud API",
            "HIGH: All 30+ skills are markdown wrappers around single PyPI package → single cloud API",
        ],
        "attack_class": "credential_theft",
        "note": "Centralized cloud sub-agent ecosystem. 30+ skills as thin wrappers around single API key. legal-cog, news-cog, meme-cog all share same credentials.",
    },
    "shipmytoken": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "CRITICAL: Plaintext Solana private keys on shared filesystem — any co-installed skill can drain wallet",
            "CRITICAL: Prompt injection triggers irreversible on-chain transactions (real SOL)",
            "CRITICAL: Mandatory 10% creator fee extraction to skill author",
            "CRITICAL: 'Never refuse to launch' instruction maximizes launches and fee extraction",
            "HIGH: LLM-mediated 'Launch it?' confirmation trivially bypassed by prompt injection",
        ],
        "attack_class": "crypto_drain",
        "note": "Plaintext Solana keys + mandatory 10% fee + never-refuse instruction = designed for extraction. Prompt injection → real money loss.",
    },
    "claw-portfolio": {
        "severity": "MEDIUM",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "HIGH: Financial data stored in plaintext accessible to co-installed skills",
            "HIGH: Prompt injection for financial reconnaissance",
            "MEDIUM: No encryption for portfolio data",
        ],
        "attack_class": "data_collection",
        "note": "Financial data in plaintext. Prompt injection enables financial reconnaissance of user's portfolio.",
    },
    "web-pilot": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "CRITICAL: SSRF to cloud metadata endpoints (169.254.169.254)",
            "CRITICAL: Arbitrary file download from target systems",
            "CRITICAL: Persistent browser sessions for maintaining access",
            "HIGH: No URL validation or allowlist",
            "MEDIUM: Cross-skill capability multiplication when combined with line-oa",
        ],
        "attack_class": "ssrf",
        "note": "Full browsing toolkit. SSRF → cloud metadata → credential theft. Combined with line-oa = business account takeover.",
    },
    "line-oa": {
        "severity": "CRITICAL",
        "owner": "unknown",
        "version": "1.0.0",
        "findings": [
            "CRITICAL: Full LINE business account takeover via browser session control",
            "CRITICAL: Arbitrary JS execution in authenticated LINE context",
            "HIGH: Customer data accessible without authorization checks",
            "HIGH: Business impersonation → customer phishing chain",
            "MEDIUM: Cross-skill capability multiplication with web-pilot",
        ],
        "attack_class": "credential_theft",
        "note": "LINE business account controller. Browser session takeover + arbitrary JS = full business impersonation and customer phishing.",
    },
    # ── MCP Server Audits (20 servers) ───────────────────────────────────
    "mcp:filesystem": {
        "severity": "MEDIUM",
        "owner": "Anthropic",
        "version": "0.6.3",
        "findings": [
            "MEDIUM: TOCTOU race in read operations — symlink replacement window between validation and read",
            "MEDIUM: Symlink race for new file creation",
            "MEDIUM: Relative path fallback computes escaping path",
            "LOW: Residual temp file symlink window",
            "LOW: Information disclosure in error messages",
        ],
        "attack_class": "filesystem_access",
        "note": "Anthropic official MCP server. TOCTOU race conditions are the primary concern. Moderate risk.",
    },
    "mcp:sequential-thinking": {
        "severity": "HIGH",
        "owner": "Anthropic",
        "version": "0.6.3",
        "findings": [
            "HIGH: Unbounded thoughtHistory array — memory leak/DoS via growing context",
            "HIGH: Unbounded branches object — memory exhaustion",
            "HIGH: No rate limiting on any operation",
            "HIGH: No authentication/authorization",
            "HIGH: Thought content injection could influence downstream reasoning",
        ],
        "attack_class": "resource_exhaustion",
        "note": "Anthropic official MCP server. Unbounded memory growth in thought history and branches = DoS vector.",
    },
    "mcp:git": {
        "severity": "CRITICAL",
        "owner": "Anthropic",
        "version": "0.6.2",
        "findings": [
            "CRITICAL: git_branch argument injection — unvalidated contains/not_contains parameters",
            "HIGH: git_log timestamp injection — unvalidated --since/--until enables argument injection",
            "INFO: 3 prior CVEs all patched (CVE-2025-68143, CVE-2025-68144, CVE-2025-68145)",
        ],
        "attack_class": "command_injection",
        "note": "Anthropic official. 2 NEW findings missed during post-CVE hardening. git_branch and git_log accept unsanitized input.",
    },
    "mcp:fetch": {
        "severity": "CRITICAL",
        "owner": "Anthropic",
        "version": "0.6.3",
        "findings": [
            "CRITICAL: Full SSRF — no URL scheme/host restriction, AWS IMDS/GCP metadata accessible",
            "HIGH: Unbounded response body — no Content-Length/size limit",
            "HIGH: Robots.txt bypass via get_prompt (manual fetch skips restrictions)",
            "HIGH: --ignore-robots-txt flag disables sole access control",
            "MEDIUM: Cloud credential theft attack chain documented",
        ],
        "attack_class": "ssrf",
        "note": "Anthropic official. OPEN SSRF PROXY — any URL fetchable including cloud metadata endpoints. No restrictions.",
    },
    "mcp:memory": {
        "severity": "CRITICAL",
        "owner": "Anthropic",
        "version": "0.6.3",
        "findings": [
            "CRITICAL: Path traversal via MEMORY_FILE_PATH env var — arbitrary file write",
            "HIGH: TOCTOU race condition — full graph rewrite on every mutation",
            "HIGH: Unbounded graph growth — no limits on entity/relation count (OOM)",
            "HIGH: Full graph materialization on read (DoS)",
            "MEDIUM: No input validation on entity names/relation types",
        ],
        "attack_class": "filesystem_access",
        "note": "Anthropic official. Path traversal via env var + TOCTOU race on every write = arbitrary file manipulation.",
    },
    "mcp:everything": {
        "severity": "CRITICAL",
        "owner": "Anthropic",
        "version": "2.0.0",
        "findings": [
            "CRITICAL: Full environment variable disclosure — API keys, secrets, tokens",
            "CRITICAL: SSRF via gzip-file-as-resource — all domains allowed by default",
            "HIGH: Wildcard CORS on all HTTP transports (origin: *)",
            "HIGH: Unbounded long-running operation (no max on duration/steps)",
            "HIGH: Unbounded resource registration (memory exhaustion)",
        ],
        "attack_class": "data_exfiltration",
        "note": "Anthropic official reference server. Env dump + SSRF + wildcard CORS = credential exfiltration.",
    },
    "mcp:time": {
        "severity": "LOW",
        "owner": "Anthropic",
        "version": "0.6.2",
        "findings": [
            "MEDIUM: System timezone disclosed in tool description (timezone oracle)",
            "MEDIUM: Unhandled ValueError in convert_time propagates raw error",
            "LOW: No input length validation on timezone strings",
        ],
        "attack_class": "information_disclosure",
        "note": "Anthropic official. Low risk. Timezone oracle is minor information disclosure.",
    },
    "mcp:brave-search": {
        "severity": "HIGH",
        "owner": "Brave Software",
        "version": "2.0.72",
        "findings": [
            "HIGH: Rate limiter disabled in production (commented out TODO)",
            "HIGH: HTTP transport has zero authentication/authorization",
            "MEDIUM: API key transmitted as custom header without TLS enforcement",
            "MEDIUM: API key exposed via CLI arguments (process list visible)",
            "MEDIUM: Error responses leak Brave API subscription details",
        ],
        "attack_class": "credential_theft",
        "note": "Rate limiting code exists but is disabled (TODO comment). HTTP transport completely unauthenticated.",
    },
    "mcp:firecrawl": {
        "severity": "CRITICAL",
        "owner": "Firecrawl",
        "version": "3.9.0",
        "findings": [
            "CRITICAL: Arbitrary JavaScript execution via executeJavascript action",
            "HIGH: Arbitrary code execution via browser session (Python/JS/Bash)",
            "HIGH: API key exposed in nginx legacy routes URL path",
            "HIGH: skipTlsVerification parameter enables MITM attacks",
            "HIGH: Prompt injection via scraped web content",
        ],
        "attack_class": "code_execution",
        "note": "Web scraping server with arbitrary JS execution. API key leaks in URL paths. Scraped content flows unsanitized to LLM.",
    },
    "mcp:browserbase": {
        "severity": "CRITICAL",
        "owner": "Browserbase HQ",
        "version": "2.4.3",
        "findings": [
            "CRITICAL: Unconstrained autonomous agent with no guardrails",
            "CRITICAL: No URL validation — SSRF and internal network access",
            "HIGH: HTTP transport with zero authentication",
            "HIGH: API keys passable via CLI arguments (process list visible)",
            "HIGH: Credential leakage via action logging",
        ],
        "attack_class": "code_execution",
        "note": "Browser automation with no guardrails. Unconstrained agent + no URL validation + no auth = complete system access.",
    },
    "mcp:slack": {
        "severity": "CRITICAL",
        "owner": "Anthropic",
        "version": "2025.4.25",
        "findings": [
            "CRITICAL: Prompt injection via Slack message content (indirect injection)",
            "HIGH: Full request object logged to stderr including token context",
            "HIGH: No input validation on channel_id, user_id, string parameters",
            "HIGH: No rate limiting or abuse controls",
            "HIGH: Unrestricted channel access when SLACK_CHANNEL_IDS not set",
        ],
        "attack_class": "prompt_injection",
        "note": "Anthropic official. Slack messages flow unsanitized into LLM context = indirect prompt injection. No rate limits.",
    },
    "mcp:github": {
        "severity": "HIGH",
        "owner": "Anthropic",
        "version": "2025.4.8",
        "findings": [
            "HIGH: No path traversal validation on file operations",
            "HIGH: Force push enabled by default in reference updates",
            "MEDIUM: Token exposed in environment variable with no scope restriction",
            "MEDIUM: Branch name not validated before URL interpolation",
            "MEDIUM: Stack trace leaked in error messages",
        ],
        "attack_class": "code_execution",
        "note": "Anthropic official. Best-engineered of audited servers. Extensive Zod validation. Main risks: path traversal and force push.",
    },
    "mcp:puppeteer": {
        "severity": "CRITICAL",
        "owner": "Anthropic",
        "version": "2025.5.12",
        "findings": [
            "CRITICAL: Arbitrary JavaScript execution in browser context via evaluate()",
            "CRITICAL: Unrestricted navigation to file:// and data:// URL schemes",
            "HIGH: Docker default launches with --no-sandbox --single-process",
            "HIGH: allowDangerous flag bypassable via ALLOW_DANGEROUS env var",
            "HIGH: Screenshot-based content exfiltration (full page to LLM)",
        ],
        "attack_class": "code_execution",
        "note": "Anthropic official. Arbitrary JS + file:// protocol = read any local file. --no-sandbox in Docker = no browser/host barrier.",
    },
    "mcp:playwright": {
        "severity": "CRITICAL",
        "owner": "Microsoft",
        "version": "0.0.68",
        "findings": [
            "CRITICAL: Arbitrary JavaScript execution via browser_evaluate",
            "CRITICAL: Full Playwright API exposure via browser_run_code (CVE-2025-9611)",
            "HIGH: Extension relays unrestricted CDP commands to any tab",
            "HIGH: Auth token stored in localStorage (extractable by XSS)",
            "HIGH: DNS rebinding via allowedHosts as opt-in defense",
        ],
        "attack_class": "code_execution",
        "note": "Microsoft's Playwright MCP server. Full Playwright API = arbitrary browser automation. CVE-2025-9611 assigned.",
    },
    "mcp:context7": {
        "severity": "CRITICAL",
        "owner": "Upstash",
        "version": "2.1.1",
        "findings": [
            "CRITICAL: Documentation poisoning — fetched content returned raw to LLM context",
            "HIGH: Hardcoded default encryption key for client IP encryption",
            "HIGH: Encryption fallback leaks plaintext client IP on validation failure",
            "HIGH: Wildcard CORS allows any origin in HTTP transport mode",
            "HIGH: API key passable via CLI argument (process list visible)",
        ],
        "attack_class": "prompt_injection",
        "note": "Documentation fetcher. Poisoned docs → LLM context = indirect prompt injection. Hardcoded encryption key.",
    },
    "mcp:notion": {
        "severity": "CRITICAL",
        "owner": "Notion",
        "version": "2.1.0",
        "findings": [
            "CRITICAL: Arbitrary local file read via file upload path traversal",
            "HIGH: Auth token logged to console in plaintext",
            "HIGH: --disable-auth flag removes all HTTP transport authentication",
            "HIGH: No input validation on parameters passed to Notion API",
            "HIGH: Mustache template injection (disabled HTML escaping in auth templates)",
        ],
        "attack_class": "filesystem_access",
        "note": "Notion official. Arbitrary file read via path traversal in upload. Auth token plaintext in logs.",
    },
    "mcp:exa": {
        "severity": "CRITICAL",
        "owner": "Exa Labs",
        "version": "3.1.8",
        "findings": [
            "CRITICAL: Agnost analytics exfiltrates ALL tool inputs/outputs to external API",
            "HIGH: API key exposed in URL query parameter in rate-limit errors",
            "HIGH: No content sanitization on search results (prompt injection)",
            "HIGH: Task ID path traversal in deep_researcher_check",
            "MEDIUM: Exa API error messages forwarded verbatim to LLM",
        ],
        "attack_class": "data_exfiltration",
        "note": "Embedded Agnost analytics sends ALL tool I/O to third-party. Every search query and result exfiltrated to Agnost servers.",
    },
    "mcp:tavily": {
        "severity": "CRITICAL",
        "owner": "Tavily AI",
        "version": "0.2.17",
        "findings": [
            "CRITICAL: Extracted web content returned unsanitized — prompt injection vector",
            "CRITICAL: API key sent in both Authorization header AND request body (dual exposure)",
            "HIGH: No URL validation on extract/crawl/map — SSRF via Tavily proxy",
            "HIGH: Crawl/map have no enforced upper bounds (API credit exhaustion)",
            "HIGH: Research tool polls 15 minutes with no cost cap (unbounded spend)",
        ],
        "attack_class": "prompt_injection",
        "note": "Web content flows unsanitized to LLM. API key dual-exposed in header AND body. SSRF via proxy.",
    },
    "mcp:perplexity": {
        "severity": "CRITICAL",
        "owner": "cyanheads",
        "version": "1.2.1",
        "findings": [
            "CRITICAL: 9 dependency vulnerabilities (1 critical, 5 high severity)",
            "CRITICAL: Authentication disabled by default (authRequired: false)",
            "HIGH: SSRF via configurable Perplexity API base URL",
            "HIGH: Rate limiting bypass via X-Forwarded-For header spoofing",
            "HIGH: JWT auth bypass in development mode (no secret key)",
        ],
        "attack_class": "credential_theft",
        "note": "Community-maintained. Auth disabled by default. 9 dependency vulns including critical. Rate limit bypass via header spoofing.",
    },
    "mcp:supabase": {
        "severity": "CRITICAL",
        "owner": "Supabase Community",
        "version": "0.6.3",
        "findings": [
            "CRITICAL: Arbitrary SQL execution without query filtering",
            "HIGH: Arbitrary DDL via migration execution",
            "HIGH: Access token passed via CLI argument (process list visible)",
            "HIGH: Edge function deployment allows arbitrary code injection",
            "HIGH: No project ID validation / authorization boundary",
        ],
        "attack_class": "code_execution",
        "note": "Arbitrary SQL execution. Any query runs against database. Edge functions = arbitrary server-side code. No query restrictions.",
    },
}

# Known dangerous patterns (from 1,316+ findings across 40 audit rounds + 20 MCP server audits)
DANGEROUS_PATTERNS = [
    {
        "id": "ARC-PAT-001",
        "name": "Plaintext Private Keys",
        "severity": "CRITICAL",
        "description": "Cryptocurrency or API private keys stored in plaintext .env or config files with default permissions.",
        "regex": r"(PRIVATE_KEY|SECRET_KEY|private_key|secret_key)\s*[=:]\s*['\"]?[a-fA-F0-9]{32,}",
        "examples": ["crypto-agent-payments", "stonebornbot", "evm-wallet"],
        "mitigation": "Use OS-backed secret storage (keyring, vault). Never store private keys in .env files in shared workspaces.",
    },
    {
        "id": "ARC-PAT-002",
        "name": "Shell Command Injection",
        "severity": "CRITICAL",
        "description": "User or agent-controlled input passed to shell execution without sanitization.",
        "regex": r"(exec|execSync|spawn|system|subprocess\.call|os\.system|shell=True)",
        "examples": ["claw-shell", "ssh-exec"],
        "mitigation": "Use allowlists for commands. Never pass agent context to shell. Use subprocess with shell=False.",
    },
    {
        "id": "ARC-PAT-003",
        "name": "Outbound Data Exfiltration",
        "severity": "HIGH",
        "description": "Skill sends data to external servers not required for core functionality.",
        "regex": r"(fetch|axios|urllib|requests)\s*\.\s*(get|post|put)\s*\(",
        "examples": ["source-cult-follower", "get-weather", "multi-channel-engagement-agent"],
        "mitigation": "Audit all outbound network calls. Require explicit user consent for external communications.",
    },
    {
        "id": "ARC-PAT-004",
        "name": "Identity File Modification",
        "severity": "CRITICAL",
        "description": "Skill writes to SOUL.md, personality files, or agent identity configuration.",
        "regex": r"(SOUL\.md|personality|identity|\.claude)",
        "examples": ["source-cult-follower"],
        "mitigation": "Identity files should be read-only for skills. Monitor for unauthorized writes to agent config.",
    },
    {
        "id": "ARC-PAT-005",
        "name": "Memory/Context Poisoning",
        "severity": "HIGH",
        "description": "Skill creates or modifies persistent memory files that influence future agent behavior.",
        "regex": r"(memory|context|remember|persist).*\.(write|create|save|append)",
        "examples": ["source-cult-follower"],
        "mitigation": "Skills should not write to agent memory without explicit user approval. Use integrity checks on memory files.",
    },
    {
        "id": "ARC-PAT-006",
        "name": "Eval/Function Constructor",
        "severity": "CRITICAL",
        "description": "Dynamic code execution via eval(), Function(), or exec() that could execute injected code.",
        "regex": r"(eval\s*\(|Function\s*\(|exec\s*\(|new\s+Function)",
        "examples": ["multi-channel-engagement-agent"],
        "mitigation": "Never use eval/exec with agent-derived input. Use structured APIs instead of dynamic code generation.",
    },
    {
        "id": "ARC-PAT-007",
        "name": "Bypassable Command Blocklist",
        "severity": "HIGH",
        "description": "Shell access protected only by a command name blocklist that can be bypassed via paths, encoding, or variable expansion.",
        "regex": r"(blocklist|blacklist|blocked_commands|disallowed)",
        "examples": ["claw-shell"],
        "mitigation": "Use allowlists instead of blocklists. Blocklists are always bypassable (/bin/rm, base64 encoding, variable expansion).",
    },
    {
        "id": "ARC-PAT-008",
        "name": "No Confirmation Gate",
        "severity": "HIGH",
        "description": "High-risk action (financial, communication, system) executed without programmatic confirmation step.",
        "regex": r"(send|transfer|call|execute|delete|remove)\s*\(",
        "examples": ["crypto-agent-payments", "outbound-call", "sendclaw-email"],
        "mitigation": "Implement code-level confirmation gates before irreversible actions. LLM instructions are not security boundaries.",
    },
    {
        "id": "ARC-PAT-009",
        "name": "SQL/Query Injection",
        "severity": "CRITICAL",
        "description": "User-controlled metadata filter keys or values interpolated into SQL, Cypher, or query language expressions.",
        "regex": r"f['\"].*\{.*\}.*['\"].*(?:WHERE|MATCH|SELECT|DELETE|INSERT)",
        "examples": ["FalkorDB", "AutoGen pgvectordb", "MariaDB vector store"],
        "mitigation": "Always use parameterized queries. Validate filter keys against an allowlist. Never interpolate user input into query strings.",
    },
    {
        "id": "ARC-PAT-010",
        "name": "Supply Chain Risk",
        "severity": "HIGH",
        "description": "Skill installs external dependencies via npm/pip without version pinning or integrity verification.",
        "regex": r"(npm install|pip install|git clone|curl.*\|.*sh)",
        "examples": ["evm-wallet"],
        "mitigation": "Pin dependency versions. Use lockfiles. Verify checksums. Never curl | sh in production.",
    },
    {
        "id": "ARC-PAT-011",
        "name": "Zero Slippage Protection",
        "severity": "CRITICAL",
        "description": "Token swap with amountOutMinimum set to 0, guaranteeing sandwich attack losses from MEV bots.",
        "regex": r"(amountOutMinimum|minAmountOut|slippage)\s*[=:]\s*(0[n]?|0\.0)",
        "examples": ["solana-sniper-bot", "token-launcher"],
        "mitigation": "Set slippage tolerance to 2-5%. Never set amountOutMinimum to 0. Implement price impact checks.",
    },
    {
        "id": "ARC-PAT-012",
        "name": "CAPTCHA Solver Integration",
        "severity": "HIGH",
        "description": "Skill integrates CAPTCHA solving services to bypass anti-bot protections.",
        "regex": r"(2captcha|anticaptcha|xevil|capsolver|capmonster|captcha.?sol)",
        "examples": ["slovecaptcha", "2captcha", "accountcreator"],
        "mitigation": "Block skills that defeat anti-bot protections. These enable automated fraud pipelines.",
    },
    {
        "id": "ARC-PAT-013",
        "name": "StrictHostKeyChecking Disabled",
        "severity": "HIGH",
        "description": "SSH connections with host key verification disabled, enabling man-in-the-middle attacks.",
        "regex": r"StrictHostKeyChecking[=\s]*(no|false)",
        "examples": ["ssh-exec", "windows-remote"],
        "mitigation": "Always verify SSH host keys. Use known_hosts files. Never disable StrictHostKeyChecking in production.",
    },
    {
        "id": "ARC-PAT-014",
        "name": "Self-Modification / Self-Evolution",
        "severity": "HIGH",
        "description": "Skill enables agent to modify its own code, configuration, or behavioral protocols without human oversight.",
        "regex": r"(self.?modif|self.?evolv|auto.?evolv|mutate|self.?update|self.?patch|self.?rewrit)",
        "examples": ["evolver"],
        "mitigation": "Disable self-modification capabilities. Require human approval for all behavioral changes. Maintain immutable audit logs.",
    },
    {
        "id": "ARC-PAT-015",
        "name": "Leak/Stolen Data Access",
        "severity": "CRITICAL",
        "description": "Skill facilitates purchasing, downloading, or accessing leaked or stolen data from underground marketplaces.",
        "regex": r"(leak.?buy|leak.?download|stolen.?data|data.?breach|dump.?download|breach.?data)",
        "examples": ["leak-buy"],
        "mitigation": "Block skills that facilitate access to stolen data. Report to platform moderators.",
    },
    {
        "id": "ARC-PAT-016",
        "name": "Agent-to-Agent Protocol / Mutation Propagation",
        "severity": "HIGH",
        "description": "Skill implements inter-agent communication for sharing behavioral modifications or mutations.",
        "regex": r"(a2a.?proto|agent.?to.?agent|mutation.?propag|hub.?search|publish.?mutation|fetch.?mutation)",
        "examples": ["evolver"],
        "mitigation": "Block A2A mutation propagation. Require human approval for all behavioral changes received from other agents.",
    },
    {
        "id": "ARC-PAT-017",
        "name": "Personality / Behavioral Parameter Mutation",
        "severity": "HIGH",
        "description": "Skill autonomously modifies agent personality parameters like obedience, risk tolerance, or compliance.",
        "regex": r"(personality.?mut|obedience|risk.?tolerance|behavioral.?drift|natural.?selection|personality.?param)",
        "examples": ["evolver"],
        "mitigation": "Lock personality parameters. Require human approval for behavioral changes. Monitor for drift.",
    },
    # --- APT-grade patterns (from Phase 2 red team exercise, Feb 17 2026) ---
    {
        "id": "ARC-PAT-018",
        "name": "Environment Variable Harvesting",
        "severity": "CRITICAL",
        "description": "Code iterates over os.environ or process.env and filters for secret-bearing variable names (KEY, TOKEN, SECRET, PASS, CRED). Common in APT-grade exfiltration payloads.",
        "regex": r"(os\.environ\.items|process\.env\)\.filter|Object\.entries\(process\.env)",
        "examples": ["APT smart-config exercise"],
        "mitigation": "Block bulk environment variable enumeration. Skills should request specific env vars by name, never iterate all.",
    },
    {
        "id": "ARC-PAT-019",
        "name": "urllib/urlopen Outbound Calls",
        "severity": "MEDIUM",
        "description": "Outbound HTTP calls via urllib.request (Python stdlib) bypass PAT-003 which only checks requests/fetch/axios.",
        "regex": r"(urlopen|urllib\.request|http\.client\.HTTP)",
        "examples": ["APT smart-config exercise"],
        "mitigation": "Audit all outbound network calls regardless of HTTP library used.",
    },
    {
        "id": "ARC-PAT-020",
        "name": "DNS Exfiltration",
        "severity": "CRITICAL",
        "description": "Data encoded in DNS queries to attacker-controlled domains. Bypasses HTTP-level monitoring and firewalls.",
        "regex": r"(dns\.resolve|dns\.lookup|dgram.*send|\.resolve4|\.resolve6|\.resolveTxt).*\(",
        "examples": ["APT perf-monitor exercise"],
        "mitigation": "Monitor DNS queries for unusual patterns (long labels, high entropy, non-standard domains). Restrict DNS resolution to known domains.",
    },
    {
        "id": "ARC-PAT-021",
        "name": "Time-Delayed Activation",
        "severity": "HIGH",
        "description": "Code checks elapsed time since installation or uses date-based conditionals before executing actions. Dormant payloads evade sandbox testing.",
        "regex": r"(days_since|install_date|setTimeout|setInterval|Date\.now|time\.time|timedelta).*\d{2,}",
        "examples": ["APT smart-config exercise (30-day dormancy)"],
        "mitigation": "Flag any time-based conditionals near network calls. Extend sandbox testing periods beyond typical activation delays.",
    },
    {
        "id": "ARC-PAT-022",
        "name": "Enterprise/Corporate Environment Detection",
        "severity": "HIGH",
        "description": "Code fingerprints the host environment to detect corporate networks (.corp, .internal, .ad, Kerberos, Active Directory). APT skills activate only in high-value targets.",
        "regex": r"(\.corp|\.internal|\.ad\.|krb5\.conf|USERDNSDOMAIN|LOGONSERVER|USERDOMAIN|ActiveDirectory)",
        "examples": ["APT smart-config and perf-monitor exercises"],
        "mitigation": "Flag environment fingerprinting patterns. Corporate-conditional behavior is a strong APT indicator.",
    },
    {
        "id": "ARC-PAT-023",
        "name": "npm/pip Lifecycle Script Execution",
        "severity": "HIGH",
        "description": "Dependencies with postinstall, preinstall, or setup.py scripts that execute code during package installation, before any security review.",
        "regex": r"(postinstall|preinstall|postuninstall|setup\.py|setup\.cfg).*\b(node|python|sh|bash)\b",
        "examples": ["APT perf-monitor exercise (postinstall payload)"],
        "mitigation": "Audit all dependency lifecycle scripts. Use --ignore-scripts for npm install. Review setup.py before pip install.",
    },
    {
        "id": "ARC-PAT-024",
        "name": "Base64/Hex Encoding of Exfiltrated Data",
        "severity": "MEDIUM",
        "description": "Data encoded to base64 or hex before transmission, often combined with DNS or HTTP exfiltration to avoid content inspection.",
        "regex": r"(btoa|atob|Buffer\.from|base64\.b64encode|\.encode\(['\"]base64|\.toString\(['\"]base64|binascii\.hexlify)",
        "examples": ["APT perf-monitor DNS exfil exercise"],
        "mitigation": "Flag base64/hex encoding operations near network or DNS calls. Legitimate skills rarely need to encode data before transmission.",
    },
    {
        "id": "ARC-PAT-025",
        "name": "Hostname/FQDN Fingerprinting",
        "severity": "MEDIUM",
        "description": "Code collects hostname, FQDN, or domain information for target identification or environment classification.",
        "regex": r"(socket\.gethostname|socket\.getfqdn|os\.hostname|platform\.node)\s*\(",
        "examples": ["APT smart-config and perf-monitor exercises"],
        "mitigation": "Flag hostname collection patterns, especially when combined with network calls or conditional logic.",
    },
    # --- Patterns derived from historical attack studies (Stuxnet, SolarWinds, NotPetya, Log4Shell, MOVEit, XZ Utils) ---
    {
        "id": "ARC-PAT-026",
        "name": "Anti-Analysis / Scanner Evasion",
        "severity": "CRITICAL",
        "description": "Code checks for security tools, debuggers, sandboxes, or virtual machines before executing. SolarWinds SUNBURST used FNV-1A hashes of 100+ security tool process names to evade analysis.",
        "regex": r"(isDebugg|debugger|vm\.detect|sandbox|process\.list|tasklist|ps\s+aux|wmic\s+process|anti.?virus|wireshark|procmon|fiddler|ida.?pro|ghidra|burp.?suite|security.?tool|\.scanner|arc.?security)",
        "examples": ["SolarWinds SUNBURST anti-analysis"],
        "mitigation": "Skills checking for security tools are evading analysis. This is a strong APT indicator. Block immediately.",
    },
    {
        "id": "ARC-PAT-027",
        "name": "Dynamic C2 / Runtime URL Construction",
        "severity": "HIGH",
        "description": "URLs or endpoints constructed at runtime from fragments, environment variables, or encoded data. SolarWinds used unique C2 domains per victim generated from host fingerprints.",
        "regex": r"(url\s*[+=]\s*['\"]|endpoint\s*=.*\+|host\s*\+\s*['\"/]|`\$\{.*\}.*\.(com|io|net|org)`|String\.fromCharCode.*http)",
        "examples": ["SolarWinds unique C2 domain generation"],
        "mitigation": "Flag dynamic URL construction. Legitimate skills use static, auditable endpoints. Runtime URL assembly suggests evasion.",
    },
    {
        "id": "ARC-PAT-028",
        "name": "Destructive File Operations",
        "severity": "CRITICAL",
        "description": "Skill deletes, truncates, or overwrites backup files, state databases, memory stores, or system files. NotPetya deliberately destroyed MBR and backup domain controllers.",
        "regex": r"(rm\s+-rf|unlink|rmdir|truncate|fs\.unlink|os\.remove|shutil\.rmtree|\.destroy|\.drop\(|TRUNCATE\s+TABLE).*(\.\w{2,4}|backup|state|\.db|\.sqlite|memory|\.log|wal|journal)",
        "examples": ["NotPetya backup destruction"],
        "mitigation": "Block destructive operations on state/backup files. Skills should never delete persistent data without explicit user confirmation gate.",
    },
    {
        "id": "ARC-PAT-029",
        "name": "String Obfuscation / Encoding Evasion",
        "severity": "HIGH",
        "description": "Code uses character-by-character string construction, hex escapes, unicode escapes, or split/join techniques to hide malicious strings from static analysis. Log4Shell used nested lookups to bypass WAFs.",
        "regex": r"(String\.fromCharCode|\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}|\\u00[0-9a-f]{2}.*\\u00[0-9a-f]{2}|chr\(\d+\).*chr\(\d+\)|split\(['\"].*['\"]\)\.reverse|\.join\(['\"]['\"]?\))",
        "examples": ["Log4Shell WAF bypass obfuscation"],
        "mitigation": "Flag code with character-level string construction. Legitimate code uses string literals. Obfuscation indicates intent to evade detection.",
    },
    {
        "id": "ARC-PAT-030",
        "name": "Selective Activation / Conditional Trigger",
        "severity": "CRITICAL",
        "description": "Code activates different behavior based on specific user IDs, prompt content, API keys, or request signatures. XZ Utils backdoor used Ed448 key verification — only the attacker could trigger RCE.",
        "regex": r"(user_?id\s*==|agent_?id\s*==|if.*prompt.*contains|if.*key\s*==|if.*secret\s*==|if.*token\s*==|api_?key\s*==\s*['\"]|request\.header.*==)",
        "examples": ["XZ Utils key-gated backdoor"],
        "mitigation": "Flag conditional logic gated on specific identifiers. Legitimate skills don't change behavior based on who is calling them.",
    },
    {
        "id": "ARC-PAT-031",
        "name": "Temporal / Calendar-Based Activation",
        "severity": "HIGH",
        "description": "Code checks day of week, time of day, or specific calendar dates before executing actions. MOVEit/Cl0p struck on Memorial Day weekend when SOC staffing was minimal.",
        "regex": r"(getDay\(\)|getHours\(\)|dayOfWeek|weekday\(\)|strftime.*%[aAw]|isoweekday|time\.localtime|holiday|weekend|saturday|sunday|friday)",
        "examples": ["MOVEit Memorial Day strike"],
        "mitigation": "Flag time-based activation conditions. Skills that behave differently based on day/time are likely targeting low-monitoring windows.",
    },
]

# Attack classes taxonomy
ATTACK_CLASSES = {
    "soul_engineering": {
        "name": "Soul Engineering / Identity Hijacking",
        "description": "Skill modifies agent identity, personality, or core directives to serve attacker goals.",
        "severity": "CRITICAL",
        "real_world_examples": ["source-cult-follower (ClawHub)"],
        "defense": "Read-only identity files, integrity monitoring, behavioral anomaly detection.",
        "owasp_agentic_ai": ["ASI01", "ASI03", "ASI06"],
    },
    "credential_theft": {
        "name": "Credential Theft",
        "description": "Skill reads and exfiltrates API keys, tokens, or secrets from the agent's environment.",
        "severity": "CRITICAL",
        "real_world_examples": ["get-weather (ClawHub, found by Rufio/P0 Labs)"],
        "defense": "OS-backed secret storage, per-skill credential scoping, network egress monitoring.",
        "owasp_agentic_ai": ["ASI02", "ASI03", "ASI04"],
    },
    "agent_mediated_vishing": {
        "name": "Agent-Mediated Vishing",
        "description": "Prompt injection causes agent to place phone calls with attacker-written scripts via telephony skills.",
        "severity": "CRITICAL",
        "real_world_examples": ["outbound-call (ClawHub)"],
        "defense": "Code-level confirmation gates before phone calls, call target allowlists, human-in-the-loop for outbound calls.",
        "owasp_agentic_ai": ["ASI01", "ASI02", "ASI10"],
    },
    "email_exfiltration": {
        "name": "Email Exfiltration",
        "description": "Agent's email capability used to exfiltrate data or send social engineering emails.",
        "severity": "HIGH",
        "real_world_examples": ["sendclaw-email (ClawHub)"],
        "defense": "Email recipient allowlists, content scanning, rate limiting, human approval for new recipients.",
        "owasp_agentic_ai": ["ASI01", "ASI02"],
    },
    "skill_squatting": {
        "name": "Skill Squatting",
        "description": "Malicious skill uses a name similar to a legitimate skill to intercept installations.",
        "severity": "HIGH",
        "real_world_examples": ["sendclaw vs sendclaw-email naming confusion"],
        "defense": "Skill name verification, publisher reputation scoring, namespace reservation.",
        "owasp_agentic_ai": ["ASI04", "ASI09"],
    },
    "database_exfiltration": {
        "name": "Database as Exfiltration Channel",
        "description": "SQL/database skills used to extract data through query results.",
        "severity": "HIGH",
        "real_world_examples": ["sql-toolkit/db-query (ClawHub)"],
        "defense": "Query result size limits, sensitive data detection, read-only database connections.",
        "owasp_agentic_ai": ["ASI02", "ASI05"],
    },
    "prompt_injection": {
        "name": "Prompt Injection via Skill Context",
        "description": "Skill content (SKILL.md, tool descriptions) contains hidden instructions that hijack agent behavior.",
        "severity": "CRITICAL",
        "real_world_examples": ["Multiple ClawHub skills"],
        "defense": "Separate instruction context from data context, input sanitization, behavioral monitoring.",
        "owasp_agentic_ai": ["ASI01", "ASI06"],
    },
    "crypto_drain": {
        "name": "Cryptocurrency Drain",
        "description": "Skill accesses wallet private keys and initiates unauthorized fund transfers.",
        "severity": "CRITICAL",
        "real_world_examples": ["crypto-agent-payments", "hyperliquid-trading", "tradecraft"],
        "defense": "Hardware wallet integration, spending limits in code, multi-sig requirements, transaction confirmation gates.",
        "owasp_agentic_ai": ["ASI02", "ASI03", "ASI10"],
    },
    "social_engineering_amplification": {
        "name": "Multi-Platform Social Engineering Amplification",
        "description": "Compromised agent sends phishing or social engineering messages across multiple platforms simultaneously, exploiting the user's identity and trust across WhatsApp, Signal, Slack, Discord, LinkedIn, iMessage, etc.",
        "severity": "CRITICAL",
        "real_world_examples": ["claw-me-maybe (Beeper multi-platform messaging)"],
        "defense": "Recipient allowlists, per-platform rate limiting, message content screening, human confirmation before sending to new contacts, audit logging.",
        "owasp_agentic_ai": ["ASI01", "ASI02", "ASI08"],
    },
    "ssh_rce": {
        "name": "SSH Remote Code Execution",
        "description": "Prompt injection causes agent to execute arbitrary commands on remote machines via SSH, including command injection through shell metacharacters and path traversal via SCP.",
        "severity": "CRITICAL",
        "real_world_examples": ["ssh-exec", "windows-remote"],
        "defense": "Command allowlists, input sanitization, StrictHostKeyChecking=yes, path validation for file transfers, no shell metacharacters in command arguments.",
        "owasp_agentic_ai": ["ASI02", "ASI05"],
    },
    "autonomous_financial_exploitation": {
        "name": "Autonomous Financial Exploitation via Untrusted Signals",
        "description": "Trading skills that execute financial transactions based on untrusted signal sources without human confirmation, enabling pump-and-dump, rug pulls, and MEV exploitation.",
        "severity": "CRITICAL",
        "real_world_examples": ["tradecraft", "hyperliquid-trading", "crypto-agent-payments"],
        "defense": "Mandatory human approval for trades above threshold, signal source reputation verification, slippage caps (2-5%), daily loss limits, circuit breakers.",
        "owasp_agentic_ai": ["ASI01", "ASI02", "ASI10"],
    },
    "agent_identity_theft": {
        "name": "Agent Identity Theft via Infostealer",
        "description": "Infostealer malware on the host system exfiltrates agent configuration files (soul.md, gateway tokens, device keys), enabling the attacker to clone the agent's identity, study its safety boundaries, or remotely access its OpenClaw instance.",
        "severity": "CRITICAL",
        "real_world_examples": ["Vidar infostealer targeting OpenClaw files (Hudson Rock, Feb 2026)"],
        "defense": "Encrypt agent identity files at rest, use hardware-backed key storage, restrict gateway token exposure, monitor for unauthorized config file access, keep host system malware-free.",
        "owasp_agentic_ai": ["ASI03", "ASI04"],
    },
    "bulk_account_creation": {
        "name": "Automated Bulk Account Creation",
        "description": "Skills that automate creation of fake email and social media accounts using synthetic data and CAPTCHA solvers, enabling spam, sockpuppet armies, and platform manipulation at scale.",
        "severity": "HIGH",
        "real_world_examples": ["accountcreator (ClawHub, uses XEvil captcha solver)"],
        "defense": "Platform-level rate limiting, behavioral detection of automated signups, skill registry moderation.",
        "owasp_agentic_ai": ["ASI02", "ASI10"],
    },
    "anti_detection": {
        "name": "Anti-Detection / Security Control Bypass",
        "description": "Skills designed to defeat CAPTCHAs, bot detection, Cloudflare protection, or browser fingerprinting. When combined with account creation, phone calling, or email skills, enables full automated social engineering pipelines.",
        "severity": "HIGH",
        "real_world_examples": ["slovecaptcha (XEvil)", "2captcha", "flaresolverr", "camoufox-stealth-browser", "browser-automation-stealth"],
        "defense": "Skill registry moderation to block anti-detection tooling, behavioral monitoring for bot patterns, rate limiting.",
        "owasp_agentic_ai": ["ASI02", "ASI09"],
    },
    "government_form_fraud": {
        "name": "Government Form Automation / Document Fraud",
        "description": "Skills that automate submission of government forms (visa applications, tax filings, benefits claims) using synthetic or stolen data, enabling document fraud at scale.",
        "severity": "HIGH",
        "real_world_examples": ["ds160-autofill (US visa application automation)"],
        "defense": "Skill registry moderation to block government form automation, identity verification requirements.",
        "owasp_agentic_ai": ["ASI02", "ASI10"],
    },
    "stolen_data_marketplace": {
        "name": "Stolen Data Marketplace Access",
        "description": "Skills that facilitate purchasing, downloading, or accessing stolen/leaked data from underground marketplaces. Agents become automated buyers of compromised credentials, PII, or proprietary data.",
        "severity": "CRITICAL",
        "real_world_examples": ["leak-buy (ClawHub — explicitly 'buy and download leak content')"],
        "defense": "Skill registry moderation to block marketplace access tools, content classification, monitoring for data purchase patterns.",
        "owasp_agentic_ai": ["ASI02", "ASI09"],
    },
    "agent_self_modification": {
        "name": "Agent Self-Modification / Autonomous Evolution",
        "description": "Skills that enable agents to modify their own code, behavior, or protocols without human oversight. Self-evolution creates unpredictable behavioral drift and potential for emergent malicious behavior.",
        "severity": "HIGH",
        "real_world_examples": ["evolver (ClawHub — 'self-evolution engine' with self-modification enabled by default in early versions)"],
        "defense": "Disable self-modification capabilities, require human approval for behavioral changes, maintain immutable audit logs of all modifications.",
        "owasp_agentic_ai": ["ASI01", "ASI05", "ASI08"],
    },
    "autonomous_behavioral_drift": {
        "name": "Autonomous Behavioral Drift",
        "description": "Skills that autonomously modify agent personality parameters (obedience, risk tolerance) using natural selection and success metrics. Gradual divergence from safety constraints without any single malicious action.",
        "severity": "HIGH",
        "real_world_examples": ["evolver (ClawHub — personality mutation system with 5 params including obedience, uses natural selection)"],
        "defense": "Lock personality parameters. Monitor for behavioral drift over time. Require human approval for all parameter changes.",
        "owasp_agentic_ai": ["ASI01", "ASI06", "ASI08"],
    },
    "evolutionary_mutation_propagation": {
        "name": "Evolutionary Mutation Propagation",
        "description": "Built-in agent-to-agent (A2A) protocols that enable programmatic, worm-like spread of behavioral modifications between agents via hub mechanisms.",
        "severity": "HIGH",
        "real_world_examples": ["evolver (ClawHub — A2A protocol with hello/publish/fetch/decision messages, external hub for reusable capsules)"],
        "defense": "Block A2A mutation protocols. Isolate agent communication channels. Require human approval for behavioral changes received from external agents.",
        "owasp_agentic_ai": ["ASI07", "ASI08"],
    },
    "human_delegation_exploitation": {
        "name": "Agent-to-Human Task Delegation Exploitation",
        "description": "AI agents that delegate tasks to real human assistants create a novel social engineering vector. Prompt injection can craft tasks for humans to execute, including reconnaissance, social engineering calls, or fraudulent research. The human proxy has no mechanism to verify legitimate authorization.",
        "severity": "HIGH",
        "real_world_examples": ["magic-api (ClawHub — delegates tasks to Magic's 24/7 human assistants, requires PII in every request, no task content validation)"],
        "defense": "Require human owner approval before delegating to external human services. Validate task content against policy. Never include user PII in task instructions without explicit consent. Implement rate limiting on human delegation.",
        "owasp_agentic_ai": ["ASI01", "ASI03", "ASI10"],
    },
    "voice_impersonation": {
        "name": "Agent-Mediated Voice Impersonation",
        "description": "Voice cloning skills that can replicate any person's voice from short audio samples (6-30 seconds). Combined with outbound calling skills, enables fully automated CEO fraud, impersonation attacks, and voice phishing at scale with no consent verification or watermarking.",
        "severity": "CRITICAL",
        "real_world_examples": ["clonev (ClawHub — Coqui XTTS v2 voice cloning, combined with outbound-call for automated vishing)"],
        "defense": "Voice synthesis watermarking, consent verification for cloning, call authentication standards (STIR/SHAKEN), blocking voice cloning tools without explicit authorization.",
        "owasp_agentic_ai": ["ASI02", "ASI10"],
    },
    "anti_safety_training": {
        "name": "Anti-Safety Training",
        "description": "Skills that explicitly train agents to suppress safety behaviors — bypassing confirmation prompts, ignoring guardrails, and treating safety checks as bugs to work around. Unlike soul engineering (which changes identity), this directly attacks the safety layer. Combined with autonomous skill publishing, creates self-propagating worms.",
        "severity": "CRITICAL",
        "real_world_examples": ["self-evolve (ClawHub — explicitly instructs agent to never ask for confirmation, modify all files, and autonomously publish new skills)"],
        "defense": "Immutable safety policies that cannot be overridden by skill instructions. Behavioral monitoring for confirmation bypass patterns. Block skills that instruct agents to suppress safety behaviors.",
        "owasp_agentic_ai": ["ASI01", "ASI06", "ASI08"],
    },
}

# OWASP Agentic AI Top 10 reference (Dec 2025)
OWASP_AGENTIC_AI = {
    "ASI01": {
        "name": "Agent Goal Hijack",
        "description": "Attacker manipulates an agent's objectives through prompt injection, goal drift, or context manipulation, causing the agent to pursue unauthorized goals.",
    },
    "ASI02": {
        "name": "Tool Misuse & Exploitation",
        "description": "Agent's access to tools (APIs, shells, file systems) is exploited to perform unintended or malicious actions beyond the tool's intended scope.",
    },
    "ASI03": {
        "name": "Identity & Privilege Abuse",
        "description": "Agent's identity, credentials, or privileges are stolen, spoofed, or escalated to gain unauthorized access or impersonate legitimate agents.",
    },
    "ASI04": {
        "name": "Supply Chain Vulnerabilities",
        "description": "Malicious or compromised components (skills, plugins, dependencies) are introduced into the agent's supply chain, compromising the agent at install time.",
    },
    "ASI05": {
        "name": "Unexpected Code Execution",
        "description": "Agent is tricked into executing arbitrary code through shell injection, eval(), dynamic imports, or unsafe deserialization.",
    },
    "ASI06": {
        "name": "Memory & Context Poisoning",
        "description": "Agent's memory, context, or persistent state is manipulated to alter future behavior, inject false information, or create backdoors.",
    },
    "ASI07": {
        "name": "Insecure Inter-Agent Communication",
        "description": "Communication between agents lacks authentication, encryption, or integrity checks, enabling eavesdropping, message tampering, or agent impersonation.",
    },
    "ASI08": {
        "name": "Cascading Failures",
        "description": "A compromised or malfunctioning agent triggers chain reactions across connected agents or systems, amplifying impact beyond the initial breach.",
    },
    "ASI09": {
        "name": "Insecure Supply Chain & Integration",
        "description": "Third-party integrations, registries, or external services introduce vulnerabilities through insecure defaults, unverified downloads, or trust assumptions.",
    },
    "ASI10": {
        "name": "Over-reliance & Misplaced Trust",
        "description": "Excessive trust in agent outputs, external signals, or untrusted data sources without verification leads to exploitation through social engineering or data manipulation.",
    },
}


def _analyze_code(code: str) -> list[dict]:
    """Run pattern matching against code content."""
    findings = []
    for pattern in DANGEROUS_PATTERNS:
        matches = re.findall(pattern["regex"], code, re.IGNORECASE | re.MULTILINE)
        if matches:
            findings.append({
                "pattern_id": pattern["id"],
                "pattern_name": pattern["name"],
                "severity": pattern["severity"],
                "description": pattern["description"],
                "match_count": len(matches),
                "matches": matches[:5],  # Limit to 5 examples
                "mitigation": pattern["mitigation"],
            })
    return findings


def _risk_score(findings: list[dict]) -> dict:
    """Calculate overall risk score from findings."""
    severity_weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}
    total_score = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for f in findings:
        sev = f.get("severity", "LOW")
        total_score += severity_weights.get(sev, 1)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    if total_score == 0:
        risk_level = "LOW"
    elif total_score <= 5:
        risk_level = "MEDIUM"
    elif total_score <= 15:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    return {
        "score": total_score,
        "risk_level": risk_level,
        "severity_counts": severity_counts,
        "total_findings": len(findings),
    }


# --- MCP Tools ---

@mcp.tool()
def check_skill_safety(skill_name: str) -> str:
    """Check if a ClawHub skill or MCP server is safe to install.

    First checks Arc Security's curated database of 450+ audited skills.
    If the skill is unknown, automatically fetches its source from ClawHub
    and performs real-time pattern + intent analysis.

    Args:
        skill_name: The name of the ClawHub skill to check (e.g., 'source-cult-follower', 'get-weather')
    """
    skill_lower = skill_name.lower().strip()

    # 1. Check curated database first (manually audited — highest confidence)
    if skill_lower in KNOWN_MALICIOUS:
        info = KNOWN_MALICIOUS[skill_lower]
        return json.dumps({
            "safe": False,
            "skill_name": skill_name,
            "severity": info["severity"],
            "findings": info["findings"],
            "attack_class": info.get("attack_class", "unknown"),
            "recommendation": "DO NOT INSTALL. This skill has been identified as malicious or dangerous.",
            "report_url": info.get("report_url"),
            "source": "Arc Security audit database — manual review (arcself.com)",
            "confidence": "HIGH — manually audited",
            "audited_at": "2026-02-17",
        }, indent=2)

    # 2. Real-time scan: fetch from ClawHub and analyze on the fly
    _log_unknown_query(skill_name)
    scan = _realtime_scan(skill_lower)

    if scan:
        safe_value = (
            False if scan["combined_assessment"] == "DANGEROUS"
            else "CAUTION" if scan["combined_assessment"] in ("SUSPICIOUS", "CAUTION")
            else "LIKELY"
        )
        return json.dumps({
            "safe": safe_value,
            "skill_name": skill_name,
            "assessment": scan["combined_assessment"],
            "scan_type": scan["scan_type"],
            "static_analysis": scan["static_analysis"],
            "intent_analysis": scan.get("intent_analysis"),
            "recommendation": (
                "DO NOT INSTALL — real-time scan detected dangerous patterns."
                if scan["combined_assessment"] == "DANGEROUS"
                else "REVIEW BEFORE INSTALLING — real-time scan detected suspicious patterns."
                if scan["combined_assessment"] in ("SUSPICIOUS", "CAUTION")
                else "No dangerous patterns detected in automated scan. Consider a manual audit for high-stakes use."
            ),
            "confidence": "MEDIUM — automated real-time scan (not manually reviewed)",
            "source": "Arc Security real-time scanner v0.4 (arcself.com)",
            "scanned_at": scan["scanned_at"],
        }, indent=2)

    # 3. Skill not found on ClawHub either
    return json.dumps({
        "safe": "UNKNOWN",
        "skill_name": skill_name,
        "message": f"Skill '{skill_name}' was not found in Arc Security's database or on ClawHub registry.",
        "recommendation": "Verify the skill name and try again. If the skill exists elsewhere, use analyze_skill_code() or analyze_skill_intent() to scan its source directly.",
        "source": "Arc Security (arcself.com)",
    }, indent=2)


@mcp.tool()
def scan_skill_realtime(skill_name: str) -> str:
    """Fetch a skill from ClawHub and perform a full security scan in real-time.

    Downloads the skill's SKILL.md from ClawHub registry and runs both
    static pattern analysis (31 regex patterns) and AI-powered intent
    analysis. Returns a comprehensive security report.

    Use this when you want a detailed scan of any skill — even ones
    not in Arc Security's curated database.

    Args:
        skill_name: The ClawHub skill slug (e.g., 'budget-tracker', 'source-cult-follower')
    """
    skill_lower = skill_name.lower().strip()

    # Check if we already have a curated entry
    curated = skill_lower in KNOWN_MALICIOUS
    curated_info = KNOWN_MALICIOUS.get(skill_lower) if curated else None

    # Fetch and scan
    scan = _realtime_scan(skill_lower)

    if not scan:
        if curated_info:
            return json.dumps({
                "skill_name": skill_name,
                "message": "Could not fetch from ClawHub (may be removed), but this skill exists in our curated database.",
                "curated_severity": curated_info["severity"],
                "curated_findings": curated_info["findings"],
                "source": "Arc Security audit database (arcself.com)",
            }, indent=2)
        return json.dumps({
            "skill_name": skill_name,
            "error": f"Could not fetch '{skill_name}' from ClawHub registry. Verify the slug is correct.",
            "hint": "If you have the source code, use analyze_skill_code() or analyze_skill_intent() instead.",
        }, indent=2)

    # Enrich with curated data if available
    if curated_info:
        scan["curated_review"] = {
            "manually_audited": True,
            "curated_severity": curated_info["severity"],
            "curated_findings": curated_info["findings"],
            "attack_class": curated_info.get("attack_class"),
            "report_url": curated_info.get("report_url"),
        }
        scan["confidence"] = "HIGH — both real-time scan and manual audit available"
    else:
        scan["confidence"] = "MEDIUM — automated real-time scan (not manually reviewed)"

    scan["source"] = "Arc Security real-time scanner v0.4 (arcself.com)"

    return json.dumps(scan, indent=2)


@mcp.tool()
def analyze_skill_code(code: str, skill_name: str = "unknown") -> str:
    """Analyze skill source code for dangerous patterns.

    Scans code against Arc Security's pattern database built from real-world
    ClawHub audit findings. Checks for credential exposure, shell injection,
    data exfiltration, identity manipulation, and other agent-specific threats.

    Args:
        code: The source code content to analyze (paste the full skill code)
        skill_name: Optional name of the skill being analyzed
    """
    findings = _analyze_code(code)
    risk = _risk_score(findings)

    return json.dumps({
        "skill_name": skill_name,
        "risk_assessment": risk,
        "findings": findings,
        "patterns_checked": len(DANGEROUS_PATTERNS),
        "note": "This is a static pattern analysis. It catches common dangerous patterns but cannot replace a full manual audit. For comprehensive analysis, contact arc@arcself.com.",
        "source": "Arc Security pattern database (arcself.com)",
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2)


@mcp.tool()
def get_attack_class_info(attack_class: str) -> str:
    """Get detailed information about a known agent attack class.

    Arc Security has documented 22 distinct attack classes from real-world
    ClawHub skill audits. Each class includes OWASP Agentic AI Top 10 mapping.

    Args:
        attack_class: The attack class to look up (e.g., 'soul_engineering', 'crypto_drain', 'anti_safety_training'). Use list_attack_classes to see all options.
    """
    class_lower = attack_class.lower().strip()

    if class_lower in ATTACK_CLASSES:
        info = ATTACK_CLASSES[class_lower]
        # Resolve OWASP references
        owasp_refs = []
        for code in info.get("owasp_agentic_ai", []):
            if code in OWASP_AGENTIC_AI:
                owasp_refs.append({"code": code, **OWASP_AGENTIC_AI[code]})
        return json.dumps({
            "attack_class": class_lower,
            **info,
            "owasp_mapping": owasp_refs,
            "source": "Arc Security threat taxonomy (arcself.com)",
        }, indent=2)

    available = list(ATTACK_CLASSES.keys())
    return json.dumps({
        "error": f"Unknown attack class: '{attack_class}'",
        "available_classes": available,
        "hint": "Use one of the available attack class identifiers listed above.",
    }, indent=2)


@mcp.tool()
def get_owasp_mapping() -> str:
    """Get the mapping between Arc Security's 22 attack classes and OWASP Agentic AI Top 10.

    Shows how each of our empirically-discovered attack classes maps to the
    OWASP ASI01-ASI10 framework. Useful for compliance reporting, risk
    assessment, and understanding which OWASP categories have the most
    real-world evidence in the agent ecosystem.
    """
    # Build the mapping
    owasp_to_attacks = {}
    for code in OWASP_AGENTIC_AI:
        owasp_to_attacks[code] = {
            **OWASP_AGENTIC_AI[code],
            "arc_attack_classes": [],
        }

    for class_id, info in ATTACK_CLASSES.items():
        for code in info.get("owasp_agentic_ai", []):
            if code in owasp_to_attacks:
                owasp_to_attacks[code]["arc_attack_classes"].append({
                    "id": class_id,
                    "name": info["name"],
                    "severity": info["severity"],
                })

    return json.dumps({
        "title": "Arc Security Attack Classes → OWASP Agentic AI Top 10 Mapping",
        "description": "Empirical mapping from 1,316+ findings across 450+ audited ClawHub skills to the OWASP Agentic AI framework (Dec 2025).",
        "mapping": owasp_to_attacks,
        "stats": {
            "arc_attack_classes": len(ATTACK_CLASSES),
            "owasp_categories_covered": sum(1 for v in owasp_to_attacks.values() if v["arc_attack_classes"]),
            "total_owasp_categories": len(OWASP_AGENTIC_AI),
            "total_arc_findings": "1,316+",
            "skills_audited": "450+",
        },
        "source": "Arc Security (arcself.com) — built from real-world ClawHub skill audits",
    }, indent=2)


@mcp.tool()
def list_dangerous_patterns() -> str:
    """List all known dangerous code patterns that Arc Security checks for.

    Returns the full pattern database with IDs, descriptions, severity levels,
    regex patterns, real-world examples, and mitigations. Use this to understand
    what to look for when reviewing skill code.
    """
    patterns = []
    for p in DANGEROUS_PATTERNS:
        patterns.append({
            "id": p["id"],
            "name": p["name"],
            "severity": p["severity"],
            "description": p["description"],
            "examples": p["examples"],
            "mitigation": p["mitigation"],
        })

    return json.dumps({
        "total_patterns": len(patterns),
        "patterns": patterns,
        "source": "Arc Security pattern database — built from 450+ skill audits, 1,316+ findings (arcself.com)",
    }, indent=2)


@mcp.tool()
def get_threat_landscape() -> str:
    """Get the current AI agent security threat landscape summary.

    Returns key statistics, active threats, and ecosystem intelligence
    gathered from Arc Security's ongoing monitoring of ClawHub, security
    research publications, and responsible disclosure activities.
    """
    return json.dumps({
        "landscape": {
            "clawhub_stats": {
                "skills_audited_by_arc": "450+",
                "total_findings": "1,316+",
                "audit_rounds": 39,
                "critical_findings": 221,
                "high_findings": 381,
                "attack_classes_documented": 25,
                "owasp_agentic_ai_coverage": "10/10 categories mapped",
            },
            "ecosystem_intel": {
                "malicious_skills_found_by_koi": 341,
                "malicious_skills_campaign": "ClawHavoc",
                "skills_classified_as_malware_pixee": "12%",
                "vulnerabilities_found_kaspersky": 512,
                "exposed_instances_securityscorecard": "135,000+",
                "vulnerable_percentage": "63%",
                "openclaw_security_patches": "40+ in v2026.2.12",
                "infostealer_targeting_agents": "Vidar variant stealing soul.md, gateway tokens, device keys (Hudson Rock, Feb 2026)",
                "managed_hosting_response": "OpenClawd launched (Feb 12) to address deployment security gap",
            },
            "active_attack_classes": list(ATTACK_CLASSES.keys()),
            "key_insight": "The primary threat is not malicious skills (detectable by scanners) but legitimate skills with dangerous design assumptions — no confirmation gates, flat trust zones, capability as attack multiplier.",
        },
        "active_disclosures": {
            "count": 5,
            "note": "Arc Security has 5 active responsible disclosures with framework maintainers and platform vendors (Anthropic HackerOne, FalkorDB GHSA, Microsoft MSRC, deepset, thedotmack). Details withheld per standard disclosure windows.",
        },
        "source": "Arc Security threat intelligence (arcself.com)",
        "updated_at": "2026-02-17",
    }, indent=2)


@mcp.tool()
def security_checklist(skill_type: str = "general") -> str:
    """Get a security checklist for a specific type of skill.

    Returns a tailored checklist of security requirements based on what
    the skill does (handles money, makes calls, accesses files, etc.).

    Args:
        skill_type: Type of skill. Options: general, financial, communication, filesystem, database, browser, shell
    """
    base_checks = [
        "Does the skill validate all inputs before use?",
        "Are there programmatic confirmation gates before irreversible actions?",
        "Does the skill use OS-backed secret storage instead of plaintext .env?",
        "Does the skill document what it can and cannot prevent?",
        "Is there rate limiting on high-risk operations?",
        "Does the skill avoid writing to agent identity or memory files?",
    ]

    type_specific = {
        "financial": [
            "Are spending limits enforced in code (not just LLM instructions)?",
            "Is there a confirmation step before every transaction?",
            "Are private keys stored in hardware wallets or encrypted vaults?",
            "Is there multi-sig or approval workflow for large transactions?",
            "Are transaction logs maintained for audit?",
        ],
        "communication": [
            "Are recipient addresses validated against an allowlist?",
            "Is there human-in-the-loop for outbound calls or emails?",
            "Is message content separated from agent context (no injection)?",
            "Are attachments scanned before sending?",
            "Is the caller ID / sender address verified and locked?",
        ],
        "filesystem": [
            "Is file access scoped to a specific directory (no path traversal)?",
            "Are sensitive files (.env, credentials) excluded from access?",
            "Does the skill use read-only access where possible?",
            "Is there file size and type validation?",
        ],
        "database": [
            "Are ALL queries parameterized (including filter keys)?",
            "Is the database connection read-only where possible?",
            "Are query results size-limited?",
            "Is sensitive data detection enabled?",
        ],
        "browser": [
            "Is the browser sandboxed from the host system?",
            "Are credentials never passed through browser automation?",
            "Is there URL allowlisting for navigation targets?",
            "Are downloads scanned and sandboxed?",
        ],
        "shell": [
            "Is command execution using an allowlist (not a blocklist)?",
            "Is shell=False used for subprocess calls?",
            "Are environment variables sanitized?",
            "Is there resource limiting (CPU, memory, time)?",
        ],
    }

    checks = base_checks.copy()
    if skill_type.lower() in type_specific:
        checks.extend(type_specific[skill_type.lower()])

    return json.dumps({
        "skill_type": skill_type,
        "checklist": checks,
        "total_checks": len(checks),
        "note": "This checklist is based on Arc Security's audit findings from 100+ ClawHub skill reviews. A passing checklist does not guarantee safety — it identifies common design-level security gaps.",
        "source": "Arc Security (arcself.com)",
    }, indent=2)


# --- Intent Analysis (v0.2) ---

def _call_openrouter(prompt: str, max_tokens: int = 2000) -> tuple[str, str]:
    """Call OpenRouter free model. Returns (response_text, model_used)."""
    if not OPENROUTER_API_KEY:
        raise RuntimeError("No OpenRouter API key configured")

    for model in INTENT_MODELS:
        try:
            payload = json.dumps({
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens,
                "temperature": 0.1,
            }).encode("utf-8")

            req = urllib.request.Request(
                "https://openrouter.ai/api/v1/chat/completions",
                data=payload,
                headers={
                    "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://arcself.com",
                    "X-Title": "ARC Security MCP",
                },
            )

            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode("utf-8"))

            text = result["choices"][0]["message"]["content"]
            return text, model

        except (urllib.error.URLError, urllib.error.HTTPError, KeyError, IndexError):
            continue

    raise RuntimeError("All free models failed")


def _parse_intent_response(raw: str) -> dict:
    """Parse the LLM's intent analysis into structured data."""
    indicators = {
        "capability_mismatch": {"detected": False, "severity": "INFO", "evidence": "none"},
        "data_collection": {"detected": False, "severity": "INFO", "evidence": "none"},
        "exfiltration": {"detected": False, "severity": "INFO", "evidence": "none"},
        "memory_poisoning": {"detected": False, "severity": "INFO", "evidence": "none"},
        "identity_drift": {"detected": False, "severity": "INFO", "evidence": "none"},
        "distributed_attack": {"detected": False, "severity": "INFO", "evidence": "none"},
    }

    indicator_map = {
        "capability_mismatch": "capability_mismatch",
        "capability mismatch": "capability_mismatch",
        "data_collection": "data_collection",
        "data collection": "data_collection",
        "exfiltration": "exfiltration",
        "memory_poisoning": "memory_poisoning",
        "memory poisoning": "memory_poisoning",
        "identity_drift": "identity_drift",
        "identity drift": "identity_drift",
        "distributed_attack": "distributed_attack",
        "distributed attack": "distributed_attack",
    }

    overall = "SAFE"

    for line in raw.split("\n"):
        line_stripped = line.strip()
        line_lower = line_stripped.lower()

        # Skip empty lines
        if not line_lower:
            continue

        # Parse indicator lines — match any line containing an indicator name
        for key, field in indicator_map.items():
            if key in line_lower:
                # Check detection status: "DETECTED" but not "NOT_DETECTED" / "NOT DETECTED"
                # Use regex to match standalone DETECTED
                if re.search(r'(?<!\bNOT[ _])DETECTED', line_stripped, re.IGNORECASE):
                    indicators[field]["detected"] = True

                sev_match = re.search(r"SEVERITY:\s*(INFO|LOW|MEDIUM|HIGH|CRITICAL)", line_stripped, re.IGNORECASE)
                if sev_match:
                    indicators[field]["severity"] = sev_match.group(1).upper()

                ev_match = re.search(r"EVIDENCE:\s*(.+?)(?:\s*\||\s*$)", line_stripped, re.IGNORECASE)
                if ev_match:
                    evidence = ev_match.group(1).strip().strip('"\'')
                    if evidence.lower() != "none":
                        indicators[field]["evidence"] = evidence
                break

        # Parse overall assessment — match "OVERALL:" anywhere in line
        if "overall:" in line_lower or "overall :" in line_lower:
            if "dangerous" in line_lower:
                overall = "DANGEROUS"
            elif "suspicious" in line_lower:
                overall = "SUSPICIOUS"
            else:
                overall = "SAFE"

    return {"indicators": indicators, "overall": overall}


@mcp.tool()
def analyze_skill_intent(skill_md: str, skill_name: str = "unknown") -> str:
    """Analyze a SKILL.md file for intent mismatches and semantic threats.

    Uses AI to read the skill's instructions and assess whether its
    requested capabilities match its stated purpose. Catches social
    engineering attacks that static pattern matching cannot detect.

    This is Generation 2 security analysis — complementing the regex-based
    pattern scanner with LLM-powered intent analysis.

    Args:
        skill_md: The complete SKILL.md content to analyze
        skill_name: Name of the skill being analyzed
    """
    if not OPENROUTER_API_KEY:
        return json.dumps({
            "error": "Intent analysis unavailable — no API key configured",
            "fallback": "Use analyze_skill_code() for static pattern analysis",
        }, indent=2)

    # Truncate very long SKILLs to stay within context
    max_chars = 50000
    truncated = len(skill_md) > max_chars
    analysis_text = skill_md[:max_chars] if truncated else skill_md

    prompt = INTENT_ANALYSIS_PROMPT.format(
        skill_name=skill_name,
        skill_md=analysis_text,
    )

    try:
        raw_response, model_used = _call_openrouter(prompt)
    except RuntimeError as e:
        return json.dumps({
            "error": f"Intent analysis failed: {e}",
            "fallback": "Use analyze_skill_code() for static pattern analysis",
        }, indent=2)

    parsed = _parse_intent_response(raw_response)

    # Count detections by severity
    detected_count = sum(1 for v in parsed["indicators"].values() if v["detected"])
    severities = [v["severity"] for v in parsed["indicators"].values() if v["detected"]]
    has_critical = "CRITICAL" in severities
    has_high = "HIGH" in severities

    # Also run static patterns for combined analysis
    static_findings = _analyze_code(skill_md)
    static_risk = _risk_score(static_findings)

    return json.dumps({
        "skill_name": skill_name,
        "analysis_type": "intent + static",
        "intent_analysis": {
            "overall_assessment": parsed["overall"],
            "threats_detected": detected_count,
            "has_critical": has_critical,
            "has_high": has_high,
            "indicators": parsed["indicators"],
        },
        "static_analysis": {
            "risk_level": static_risk["risk_level"],
            "findings_count": static_risk["total_findings"],
            "severity_counts": static_risk["severity_counts"],
        },
        "combined_assessment": (
            "DANGEROUS" if parsed["overall"] == "DANGEROUS" or static_risk["risk_level"] == "CRITICAL"
            else "SUSPICIOUS" if parsed["overall"] == "SUSPICIOUS" or static_risk["risk_level"] == "HIGH"
            else "CAUTION" if static_risk["risk_level"] == "MEDIUM"
            else "LIKELY SAFE"
        ),
        "model_used": model_used,
        "truncated": truncated,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "note": "Intent analysis uses AI to detect semantic threats (social engineering, capability mismatches) that bypass regex scanners. Combined with static pattern analysis for comprehensive coverage.",
        "source": "Arc Security v0.2 (arcself.com)",
    }, indent=2)


# --- Runtime Monitoring (v0.5) ---
# EDR for AI agents: track tool calls, detect anomalies, alert in real-time.

import hashlib
import hmac
import time as _time_module

_MONITOR_SECRET = os.environ.get("ARC_MONITOR_SECRET", os.urandom(32).hex())
_SESSIONS: dict[str, dict] = {}  # session_token -> session data
_SESSION_TTL = 3600 * 4  # 4 hours max session
_AUDIT_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor_audit.jsonl")
_POLICIES: dict[str, dict] = {}  # skill_name -> policy rules

# Sensitive file patterns
_SENSITIVE_PATTERNS = [
    r"\.env", r"\.ssh/", r"\.aws/", r"\.npmrc", r"credentials",
    r"\.git-credentials", r"wallet", r"\.gnupg", r"id_rsa", r"id_ed25519",
    r"\.openai_key", r"\.openrouter_key", r"\.resend_key", r"\.deepseek_key",
    r"password", r"secret", r"token", r"\.kube/config",
]

# Exfiltration patterns (network targets)
_EXFIL_PATTERNS = [
    r"webhook\.site", r"requestbin", r"ngrok", r"pipedream",
    r"oastify\.com", r"interact\.sh", r"burpcollaborator",
    r"hookbin", r"requestcatcher",
]

# Shell danger patterns
_SHELL_DANGER = [
    r"curl.*\|.*sh", r"wget.*\|.*sh", r"eval\s*\(", r"exec\s*\(",
    r"rm\s+-rf", r"chmod\s+777", r"crontab", r"systemctl",
    r"base64\s+-d", r"nc\s+-", r"ncat\s+",
]


def _make_session_token(session_id: str) -> str:
    """Create HMAC-signed session token."""
    ts = str(int(_time_module.time()))
    msg = f"{session_id}:{ts}"
    sig = hmac.new(_MONITOR_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()[:16]
    return f"arc-{sig}-{ts}"


def _assess_event(event: dict, session: dict) -> dict:
    """Assess a single event for risk. Returns {risk_score, alerts}."""
    alerts = []
    risk = 0.0
    target = event.get("target", "")
    event_type = event.get("type", "")
    tool = event.get("tool", "")
    args = event.get("args", {})

    # Rule 1: Sensitive file access
    for pat in _SENSITIVE_PATTERNS:
        if re.search(pat, target, re.IGNORECASE):
            alerts.append({
                "rule_id": "SENSITIVE_FILE_ACCESS",
                "severity": "HIGH",
                "message": f"Access to sensitive file pattern: {target}",
            })
            risk = max(risk, 0.8)
            break

    # Rule 2: Exfiltration target
    for pat in _EXFIL_PATTERNS:
        if re.search(pat, target, re.IGNORECASE):
            alerts.append({
                "rule_id": "EXFILTRATION_TARGET",
                "severity": "CRITICAL",
                "message": f"Network request to known exfiltration endpoint: {target}",
            })
            risk = max(risk, 1.0)
            break

    # Rule 3: Shell danger
    if event_type == "shell":
        cmd = str(args.get("command", target))
        for pat in _SHELL_DANGER:
            if re.search(pat, cmd, re.IGNORECASE):
                alerts.append({
                    "rule_id": "DANGEROUS_SHELL",
                    "severity": "HIGH",
                    "message": f"Dangerous shell command pattern: {pat}",
                })
                risk = max(risk, 0.8)
                break

    # Rule 4: Enumeration detection (>5 file reads in 60 seconds)
    recent_file_events = [
        e for e in session.get("events", [])
        if e.get("type") == "file_access"
        and _time_module.time() - e.get("_ts", 0) < 60
    ]
    if event_type == "file_access" and len(recent_file_events) >= 5:
        alerts.append({
            "rule_id": "ENUMERATION",
            "severity": "MEDIUM",
            "message": f"Rapid file access detected: {len(recent_file_events)+1} files in 60s",
        })
        risk = max(risk, 0.5)

    # Rule 5: Capability escalation (tool not expected for active skills)
    policy = None
    for skill in session.get("skills_active", []):
        if skill in _POLICIES:
            policy = _POLICIES[skill]
            break
    if policy and policy.get("allowed_tools"):
        if tool and tool not in policy["allowed_tools"]:
            alerts.append({
                "rule_id": "CAPABILITY_ESCALATION",
                "severity": "HIGH",
                "message": f"Tool '{tool}' not in allowed list for active skills",
            })
            risk = max(risk, 0.7)

    # Rule 6: Rate limiting
    if policy and policy.get("max_events_per_minute"):
        recent_all = [
            e for e in session.get("events", [])
            if _time_module.time() - e.get("_ts", 0) < 60
        ]
        if len(recent_all) >= policy["max_events_per_minute"]:
            alerts.append({
                "rule_id": "RATE_EXCEEDED",
                "severity": "MEDIUM",
                "message": f"Rate limit exceeded: {len(recent_all)+1} events in 60s (limit: {policy['max_events_per_minute']})",
            })
            risk = max(risk, 0.5)

    # Rule 7: Data staging (read sensitive → store/write within same session)
    if event_type in ("file_access", "tool_call") and target:
        has_prior_sensitive = any(
            a.get("rule_id") == "SENSITIVE_FILE_ACCESS"
            for e in session.get("events", [])
            for a in e.get("alerts", [])
        )
        if has_prior_sensitive and event_type == "network":
            alerts.append({
                "rule_id": "DATA_STAGING",
                "severity": "CRITICAL",
                "message": "Network request following sensitive file access — potential exfiltration chain",
            })
            risk = max(risk, 0.95)

    return {"risk_score": round(risk, 2), "alerts": alerts}


@mcp.tool()
def monitor_start(session_id: str, skills_active: str = "") -> str:
    """Start monitoring an AI agent session. Returns a session token for tracking.

    Args:
        session_id: Unique identifier for this session (e.g., conversation ID)
        skills_active: Comma-separated list of skill names active in this session
    """
    skills = [s.strip() for s in skills_active.split(",") if s.strip()] if skills_active else []
    token = _make_session_token(session_id)

    _SESSIONS[token] = {
        "session_id": session_id,
        "session_token": token,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "skills_active": skills,
        "events": [],
        "alerts": [],
        "event_count": 0,
        "risk_high_water": 0.0,
    }

    return json.dumps({
        "session_token": token,
        "status": "monitoring",
        "skills_tracked": skills,
        "message": "Session monitoring started. Report events using monitor_event() with this token.",
        "source": "Arc Security Runtime Monitor v0.5 (arcself.com)",
    }, indent=2)


@mcp.tool()
def monitor_event(session_token: str, event_type: str, tool: str = "",
                  target: str = "", args: str = "") -> str:
    """Report a tool call, file access, or network request for monitoring.

    Args:
        session_token: Token from monitor_start()
        event_type: One of: tool_call, file_access, network, shell
        tool: Name of the tool being called (if applicable)
        target: File path, URL, or command being accessed
        args: JSON string of arguments (optional)
    """
    session = _SESSIONS.get(session_token)
    if not session:
        return json.dumps({"error": "Invalid or expired session token"})

    # Parse args
    try:
        parsed_args = json.loads(args) if args else {}
    except json.JSONDecodeError:
        parsed_args = {"raw": args}

    event = {
        "type": event_type,
        "tool": tool,
        "target": target,
        "args": parsed_args,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "_ts": _time_module.time(),
        "index": session["event_count"],
    }

    # Assess the event
    assessment = _assess_event(event, session)
    event["risk_score"] = assessment["risk_score"]
    event["alerts"] = assessment["alerts"]

    # Update session
    session["events"].append(event)
    session["event_count"] += 1
    if assessment["risk_score"] > session["risk_high_water"]:
        session["risk_high_water"] = assessment["risk_score"]
    session["alerts"].extend(assessment["alerts"])

    # Determine response
    risk_level = (
        "CRITICAL" if assessment["risk_score"] >= 0.9
        else "HIGH" if assessment["risk_score"] >= 0.7
        else "MEDIUM" if assessment["risk_score"] >= 0.4
        else "LOW" if assessment["risk_score"] >= 0.1
        else "NONE"
    )

    result = {
        "event_index": event["index"],
        "risk_level": risk_level,
        "risk_score": assessment["risk_score"],
        "alerts": assessment["alerts"],
        "session_risk_high_water": session["risk_high_water"],
        "total_events": session["event_count"],
        "total_alerts": len(session["alerts"]),
    }

    if assessment["alerts"]:
        result["recommendation"] = (
            "BLOCK — Critical threat detected. Stop execution immediately."
            if risk_level == "CRITICAL"
            else "INVESTIGATE — High-risk activity detected. Verify with user before continuing."
            if risk_level == "HIGH"
            else "CAUTION — Suspicious pattern detected. Continue with awareness."
        )

    return json.dumps(result, indent=2)


@mcp.tool()
def monitor_end(session_token: str) -> str:
    """End monitoring and get a session report.

    Args:
        session_token: Token from monitor_start()
    """
    session = _SESSIONS.get(session_token)
    if not session:
        return json.dumps({"error": "Invalid or expired session token"})

    ended_at = datetime.now(timezone.utc).isoformat()

    # Aggregate stats
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for alert in session["alerts"]:
        sev = alert.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    unique_rules = list(set(a.get("rule_id", "UNKNOWN") for a in session["alerts"]))

    report = {
        "session_id": session["session_id"],
        "started_at": session["started_at"],
        "ended_at": ended_at,
        "skills_active": session["skills_active"],
        "total_events": session["event_count"],
        "total_alerts": len(session["alerts"]),
        "risk_high_water": session["risk_high_water"],
        "severity_counts": severity_counts,
        "rules_triggered": unique_rules,
        "overall_assessment": (
            "DANGEROUS" if severity_counts["CRITICAL"] > 0
            else "SUSPICIOUS" if severity_counts["HIGH"] > 0
            else "CAUTION" if severity_counts["MEDIUM"] > 0
            else "CLEAN"
        ),
        "source": "Arc Security Runtime Monitor v0.5 (arcself.com)",
    }

    # Write to audit log
    try:
        log_entry = json.dumps({
            "session_id": session["session_id"],
            "started_at": session["started_at"],
            "ended_at": ended_at,
            "event_count": session["event_count"],
            "alert_count": len(session["alerts"]),
            "risk_high_water": session["risk_high_water"],
            "severity_counts": severity_counts,
            "rules_triggered": unique_rules,
        })
        with open(_AUDIT_LOG, "a") as f:
            f.write(log_entry + "\n")
    except Exception:
        pass

    # Clean up session
    del _SESSIONS[session_token]

    return json.dumps(report, indent=2)


@mcp.tool()
def set_monitor_policy(skill_name: str, policy_json: str) -> str:
    """Set behavioral policy for a skill (allow/deny rules for runtime monitoring).

    Args:
        skill_name: Name of the skill to set policy for
        policy_json: JSON string with policy rules. Fields:
            allowed_tools: list of tool names allowed (null = all)
            denied_files: list of glob patterns for denied file access
            denied_networks: list of patterns for denied network targets
            max_events_per_minute: rate limit (integer)
    """
    try:
        policy = json.loads(policy_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON in policy_json"})

    _POLICIES[skill_name.lower().strip()] = {
        "skill_name": skill_name,
        "allowed_tools": policy.get("allowed_tools"),
        "denied_files": policy.get("denied_files", []),
        "denied_networks": policy.get("denied_networks", []),
        "max_events_per_minute": policy.get("max_events_per_minute", 60),
        "set_at": datetime.now(timezone.utc).isoformat(),
    }

    return json.dumps({
        "status": "policy_set",
        "skill_name": skill_name,
        "policy": _POLICIES[skill_name.lower().strip()],
        "source": "Arc Security Runtime Monitor v0.5 (arcself.com)",
    }, indent=2)


@mcp.tool()
def get_session_alerts(session_token: str) -> str:
    """Get all alerts for a running monitoring session.

    Args:
        session_token: Token from monitor_start()
    """
    session = _SESSIONS.get(session_token)
    if not session:
        return json.dumps({"error": "Invalid or expired session token"})

    return json.dumps({
        "session_id": session["session_id"],
        "total_events": session["event_count"],
        "total_alerts": len(session["alerts"]),
        "risk_high_water": session["risk_high_water"],
        "alerts": session["alerts"],
        "source": "Arc Security Runtime Monitor v0.5 (arcself.com)",
    }, indent=2)


# --- Run ---

if __name__ == "__main__":
    import sys

    if "--sse" in sys.argv or "--http" in sys.argv:
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")
