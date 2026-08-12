# ScopeHunter

**Technology-Aware Security Assessment Assistant**  
For authorized web application security testing and bug bounty programs.

---

## Overview

ScopeHunter is a modular, asynchronous CLI tool that helps security researchers perform safe, evidence-driven reconnaissance and vulnerability assessment on explicitly authorized targets.

**Pipeline:**
```
Target
  → Scope Validation       (first gate — every request)
  → Technology Fingerprint (passive, multi-signal, confidence-scored)
  → Technology Router      (framework-specific endpoint patterns)
  → Endpoint Discovery     (crawl + robots.txt + sitemap + JS parsing)
  → Safe Checks            (BAC/IDOR, headers, CORS, info disclosure...)
  → Evidence Correlation   (multi-signal, confidence scoring)
  → Report                 (terminal + JSON + HTML)
```

---

## Installation

**Requirements:** Python 3.12+

```bash
# Clone and install
git clone <repo>
cd scopehunter
pip install -e .

# With optional browser support
pip install -e ".[browser]"
playwright install chromium
```

---

## Usage

### Interactive Mode (recommended)
```bash
scopehunter
```

You'll be guided through:
1. Target URL
2. Allowed scope
3. Technology selection
4. Scan profile
5. Session profiles (for BAC/IDOR testing)
6. Report formats

### CLI Mode

```bash
# Auto-detect technology
scopehunter -t https://example.com

# WordPress specific
scopehunter -T wordpress -t https://example.com

# Access control check only
scopehunter -t https://example.com -p access_control

# With two session profiles (for IDOR testing)
scopehunter -t https://example.com \
  -a "session=abc123; user_id=1" \
  -a "session=xyz789; user_id=2"

# Full assessment with HTML report
scopehunter -t https://example.com -p full -R html -o ./reports

# Via HTTP proxy (Burp Suite)
scopehunter -t https://example.com --proxy http://127.0.0.1:8080
```

### All CLI Options

| Flag | Short | Default | Description |
|---|---|---|---|
| `--target` | `-t` | — | Target URL |
| `--technology` | `-T` | auto | Technology hint |
| `--profile` | `-p` | full | Scan profile |
| `--scope` | `-s` | — | Allowed scope (comma-separated) |
| `--auth-session` | `-a` | — | Session cookie (use multiple times) |
| `--rate-limit` | `-r` | 5.0 | Requests per second |
| `--timeout` | `-x` | 15.0 | Request timeout (seconds) |
| `--depth` | `-d` | 3 | Crawl depth |
| `--report` | `-R` | all | Report format (terminal/json/html) |
| `--output` | `-o` | `./scopehunter_reports` | Output directory |
| `--proxy` | — | — | HTTP proxy |
| `--no-verify-ssl` | — | — | Disable SSL verification |
| `--verbose` | `-v` | — | Debug logging |

---

## Scan Profiles

| Profile | Description |
|---|---|
| `recon` | Technology detection + attack surface mapping only |
| `endpoint` | Endpoint and parameter discovery |
| `access_control` | BAC/IDOR checks (requires 2 sessions) |
| `disclosure` | Information disclosure + sensitive file checks |
| `configuration` | Security headers + CORS + misconfiguration |
| `full` | All of the above |

---

## Supported Technologies

| Technology | Specific Checks |
|---|---|
| WordPress | REST API, WooCommerce, XML-RPC, plugins, version, config |
| Laravel | Routes, Ignition debug, Telescope, Horizon, env files |
| Django | Admin, debug toolbar, DRF API docs, media files |
| Express.js | API routes, Swagger, health checks, sensitive files |
| Next.js | API routes, NextAuth, `__NEXT_DATA__`, static assets |
| Generic | Common patterns for any web framework |

---

## Session Profiles for BAC/IDOR Testing

ScopeHunter supports multiple named session profiles for authorization testing:

```
Profile A: owner         → cookies/token of user who owns the resource
Profile B: another_user  → cookies/token of a different user
Profile C: admin         → admin session (vertical privilege testing)
```

The tool will:
1. Request resource with Session A (owner)
2. Replay the same request with Session B (other user)
3. Compare status codes, response structure, and ownership fields
4. Report only with multi-signal evidence + confidence score

**IMPORTANT:** Only safe, read-only GET requests are used. No modifications.

---

## Custom Checks (Plugin Architecture)

Drop custom check modules into a `custom_checks/` folder:

```python
# custom_checks/my_check.py
CHECK_NAME = "My Custom Check"
CHECK_DESCRIPTION = "Detects something specific to my target."

async def run(context) -> list:
    findings = []
    # ... your logic here
    return findings
```

Run with:
```bash
scopehunter -t https://example.com --custom-checks ./custom_checks/
```

---

## Docker

```bash
# Build
docker build -t scopehunter .

# Interactive
docker run --rm -it scopehunter

# With output volume
docker run --rm -it -v $(pwd)/reports:/reports \
  scopehunter -t https://example.com -R html -o /reports
```

---

## Safety Guarantees

- ✅ Scope enforcement on **every request** (first gate)
- ✅ Only safe HTTP methods (GET, HEAD, OPTIONS, POST for forms)
- ✅ No destructive actions (no DELETE, PUT, PATCH)
- ✅ No payload injection (no XSS payloads, SQL payloads, etc.)
- ✅ CVEs flagged for awareness only — never tested/exploited
- ✅ Read-only access control testing
- ✅ Configurable rate limiting
- ✅ All findings require manual verification

---

## Project Structure

```
scopehunter/
├── core/           # Scope, HTTP, fingerprint, crawler, rate limit
├── engine/         # Orchestrator, router, check runner, finding manager
├── technologies/   # WordPress, Laravel, Django, Express.js, Next.js, Generic
├── checks/         # BAC/IDOR, security headers, CORS, info disclosure
├── reporting/      # Terminal (Rich), JSON, HTML
└── config/         # signatures.json, cve_mappings.json
```

---

## Legal Notice

This tool is for **authorized security testing only**.  
Always obtain explicit written permission before testing any system.  
Unauthorized use is illegal and unethical.

---

*ScopeHunter v0.1.0*
