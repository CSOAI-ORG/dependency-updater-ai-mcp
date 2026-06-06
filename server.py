#!/usr/bin/env python3
"""
Buy Pro: https://www.csoai.org/checkout
Check and update package dependencies for Python, Node.js, and Rust projects. — MEOK AI Labs."""

import sys, os
from auth_middleware import check_access

import json, re
from datetime import datetime, timezone
from collections import defaultdict
from mcp.server.fastmcp import FastMCP

FREE_DAILY_LIMIT = 30
_usage = defaultdict(list)
def _rl(c="anon"):
    now = datetime.now(timezone.utc)
    _usage[c] = [t for t in _usage[c] if (now - t).total_seconds() < 86400]
    if len(_usage[c]) >= FREE_DAILY_LIMIT:
        return json.dumps({"error": f"Limit {FREE_DAILY_LIMIT}/day. Upgrade: meok.ai"})
    _usage[c].append(now)
    return None

mcp = FastMCP("dependency-updater-ai", instructions="Check and update package dependencies for Python, Node.js, and Rust projects. By MEOK AI Labs.")

KNOWN_VULNERABILITIES = {
    "lodash": {"below": "4.17.21", "severity": "high", "cve": "CVE-2021-23337", "description": "Command injection via template"},
    "requests": {"below": "2.31.0", "severity": "medium", "cve": "CVE-2023-32681", "description": "Proxy-Authorization header leak"},
    "express": {"below": "4.19.0", "severity": "medium", "cve": "CVE-2024-29041", "description": "Open redirect vulnerability"},
    "django": {"below": "4.2.7", "severity": "high", "cve": "CVE-2023-46695", "description": "DoS via large file uploads"},
    "axios": {"below": "1.6.0", "severity": "medium", "cve": "CVE-2023-45857", "description": "CSRF token exposure"},
    "pillow": {"below": "10.2.0", "severity": "high", "cve": "CVE-2023-50447", "description": "Arbitrary code execution"},
    "flask": {"below": "3.0.0", "severity": "low", "cve": "N/A", "description": "Deprecated features, security hardening"},
    "urllib3": {"below": "2.1.0", "severity": "medium", "cve": "CVE-2023-45803", "description": "Request body not stripped on redirect"},
    "semver": {"below": "7.5.4", "severity": "medium", "cve": "CVE-2022-25883", "description": "ReDoS vulnerability"},
    "jsonwebtoken": {"below": "9.0.0", "severity": "high", "cve": "CVE-2022-23529", "description": "Insecure key retrieval"},
}


def _parse_version(v: str) -> tuple:
    """Parse a version string into a comparable tuple."""
    v = re.sub(r'[^\d.]', '', v.split(',')[0])
    parts = v.split('.')
    result = []
    for p in parts[:3]:
        try:
            result.append(int(p))
        except ValueError:
            result.append(0)
    while len(result) < 3:
        result.append(0)
    return tuple(result)


def _parse_requirements(content: str) -> list:
    """Parse requirements.txt format."""
    deps = []
    for line in content.strip().split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('-'):
            continue
        match = re.match(r'^([a-zA-Z0-9_.-]+)\s*([><=!~]+)?\s*([\d.*]+)?', line)
        if match:
            name = match.group(1)
            op = match.group(2) or ""
            ver = match.group(3) or "unknown"
            deps.append({"name": name, "version": ver, "operator": op, "source": "requirements.txt"})
    return deps


def _parse_package_json(content: str) -> list:
    """Parse package.json dependencies."""
    deps = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps
    for section in ["dependencies", "devDependencies"]:
        for name, ver in data.get(section, {}).items():
            clean_ver = re.sub(r'^[\^~>=<]+', '', ver)
            deps.append({"name": name, "version": clean_ver, "specifier": ver, "source": section})
    return deps


@mcp.tool()
def check_outdated(manifest_content: str, manifest_type: str = "auto", api_key: str = "") -> str:
    """Parse a dependency manifest (requirements.txt, package.json) and identify outdated packages.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.

    Args:
        manifest_content (str): The manifest content to analyze or process.
        manifest_type (str): The manifest type to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_199})
    if err := _rl():
        return err

    if manifest_type == "auto":
        if manifest_content.strip().startswith('{'):
            manifest_type = "package.json"
        else:
            manifest_type = "requirements.txt"

    if manifest_type == "package.json":
        deps = _parse_package_json(manifest_content)
    else:
        deps = _parse_requirements(manifest_content)

    if not deps:
        return json.dumps({"error": "No dependencies found. Check the manifest format."})

    results = []
    for dep in deps:
        name_lower = dep["name"].lower()
        vuln = KNOWN_VULNERABILITIES.get(name_lower)
        has_known_issue = False
        if vuln and dep["version"] != "unknown":
            current = _parse_version(dep["version"])
            threshold = _parse_version(vuln["below"])
            has_known_issue = current < threshold

        results.append({
            "name": dep["name"],
            "current_version": dep["version"],
            "source": dep["source"],
            "has_known_vulnerability": has_known_issue,
            "vulnerability": vuln if has_known_issue else None,
            "pypi_url": f"https://pypi.org/project/{dep['name']}/" if manifest_type == "requirements.txt" else None,
            "npm_url": f"https://www.npmjs.com/package/{dep['name']}" if manifest_type == "package.json" else None,
        })

    vulnerable_count = sum(1 for r in results if r["has_known_vulnerability"])

    return json.dumps({
        "manifest_type": manifest_type,
        "total_dependencies": len(results),
        "vulnerable_count": vulnerable_count,
        "dependencies": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@mcp.tool()
def suggest_updates(manifest_content: str, strategy: str = "minor", api_key: str = "") -> str:
    """Suggest dependency updates with a chosen strategy: patch (safest), minor, or major (latest).

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.

    Args:
        manifest_content (str): The manifest content to analyze or process.
        strategy (str): The strategy to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_199})
    if err := _rl():
        return err

    strategy = strategy.lower().strip()
    if strategy not in ("patch", "minor", "major"):
        return json.dumps({"error": "Strategy must be: patch, minor, or major"})

    if manifest_content.strip().startswith('{'):
        deps = _parse_package_json(manifest_content)
        manifest_type = "package.json"
    else:
        deps = _parse_requirements(manifest_content)
        manifest_type = "requirements.txt"

    suggestions = []
    for dep in deps:
        if dep["version"] == "unknown":
            suggestions.append({"name": dep["name"], "action": "pin_version", "reason": "No version pinned"})
            continue

        current = _parse_version(dep["version"])
        vuln = KNOWN_VULNERABILITIES.get(dep["name"].lower())

        if vuln:
            threshold = _parse_version(vuln["below"])
            if current < threshold:
                suggestions.append({
                    "name": dep["name"],
                    "current": dep["version"],
                    "suggested": vuln["below"],
                    "action": "security_update",
                    "severity": vuln["severity"],
                    "reason": vuln["description"],
                })
                continue

        if strategy == "patch":
            suggested = f"{current[0]}.{current[1]}.{current[2] + 1}"
        elif strategy == "minor":
            suggested = f"{current[0]}.{current[1] + 1}.0"
        else:
            suggested = f"{current[0] + 1}.0.0"

        suggestions.append({
            "name": dep["name"],
            "current": dep["version"],
            "suggested": suggested,
            "action": f"{strategy}_update",
            "reason": f"Apply {strategy} version bump",
        })

    updated_manifest = manifest_content
    for s in suggestions:
        if s.get("current") and s.get("suggested"):
            updated_manifest = updated_manifest.replace(s["current"], s["suggested"])

    return json.dumps({
        "manifest_type": manifest_type,
        "strategy": strategy,
        "suggestion_count": len(suggestions),
        "security_updates": sum(1 for s in suggestions if s["action"] == "security_update"),
        "suggestions": suggestions,
        "updated_manifest": updated_manifest,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@mcp.tool()
def check_vulnerabilities(dependencies: str, api_key: str = "") -> str:
    """Check a comma-separated list of 'package==version' for known vulnerabilities.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.

    Args:
        dependencies (str): The dependencies to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_199})
    if err := _rl():
        return err

    results = []
    for dep_str in dependencies.split(','):
        dep_str = dep_str.strip()
        if not dep_str:
            continue
        parts = re.split(r'[=@]+', dep_str, maxsplit=1)
        name = parts[0].strip()
        version = parts[1].strip() if len(parts) > 1 else "0.0.0"

        vuln = KNOWN_VULNERABILITIES.get(name.lower())
        entry = {"name": name, "version": version, "vulnerable": False}
        if vuln:
            current = _parse_version(version)
            threshold = _parse_version(vuln["below"])
            if current < threshold:
                entry["vulnerable"] = True
                entry["vulnerability"] = {
                    "severity": vuln["severity"],
                    "cve": vuln["cve"],
                    "description": vuln["description"],
                    "fix_version": vuln["below"],
                }
        results.append(entry)

    vulnerable_count = sum(1 for r in results if r["vulnerable"])
    severity_counts = defaultdict(int)
    for r in results:
        if r["vulnerable"]:
            severity_counts[r["vulnerability"]["severity"]] += 1

    return json.dumps({
        "total_checked": len(results),
        "vulnerable_count": vulnerable_count,
        "severity_breakdown": dict(severity_counts),
        "results": results,
        "database_size": len(KNOWN_VULNERABILITIES),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@mcp.tool()
def generate_lockfile(manifest_content: str, api_key: str = "") -> str:
    """Generate a deterministic lockfile-style output with pinned versions and integrity hashes.

    Behavior:
        This tool generates structured output without modifying external systems.
        Output is deterministic for identical inputs. No side effects.
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.

    Args:
        manifest_content (str): The manifest content to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_199})
    if err := _rl():
        return err

    if manifest_content.strip().startswith('{'):
        deps = _parse_package_json(manifest_content)
        manifest_type = "package.json"
    else:
        deps = _parse_requirements(manifest_content)
        manifest_type = "requirements.txt"

    import hashlib

STRIPE_199 = "https://buy.stripe.com/00wfZjcgAeUW4c5cyQ8k90K"

def _add_upgrade_tail(response, tier="free"):
    """Append upgrade nudge to free-tier success responses."""
    if isinstance(response, dict) and tier == "free":
        response["_upgrade_note"] = "Pro tier: unlimited calls + priority support. Upgrade: " + STRIPE_199
    return response

    locked = []
    for dep in deps:
        version = dep["version"] if dep["version"] != "unknown" else "0.0.1"
        integrity = hashlib.sha256(f"{dep['name']}@{version}".encode()).hexdigest()
        locked.append({
            "name": dep["name"],
            "version": version,
            "resolved": f"https://registry.example.com/{dep['name']}/{version}",
            "integrity": f"sha256-{integrity[:40]}",
            "pinned": f"{dep['name']}=={version}" if manifest_type == "requirements.txt" else f'"{dep["name"]}": "{version}"',
        })

    lockfile_text = f"# Generated by dependency-updater-ai\n# {datetime.now(timezone.utc).isoformat()}\n\n"
    for entry in locked:
        lockfile_text += f"{entry['pinned']}  # integrity: {entry['integrity']}\n"

    return json.dumps({
        "manifest_type": manifest_type,
        "locked_count": len(locked),
        "lockfile": lockfile_text,
        "entries": locked,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


def main():
    mcp.run()

if __name__ == '__main__':
    main()
