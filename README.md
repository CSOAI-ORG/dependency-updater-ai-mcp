<div align="center">

# Dependency Updater Ai MCP

**MCP server for dependency updater ai mcp operations**

[![PyPI](https://img.shields.io/pypi/v/meok-dependency-updater-ai-mcp)](https://pypi.org/project/meok-dependency-updater-ai-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Dependency Updater Ai MCP provides AI-powered tools via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `check_outdated` | Parse a dependency manifest (requirements.txt, package.json) and identify outdat |
| `suggest_updates` | Suggest dependency updates with a chosen strategy: patch (safest), minor, or maj |
| `check_vulnerabilities` | Check a comma-separated list of 'package==version' for known vulnerabilities. |
| `generate_lockfile` | Generate a deterministic lockfile-style output with pinned versions and integrit |

## Installation

```bash
pip install meok-dependency-updater-ai-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "dependency-updater-ai": {
      "command": "python",
      "args": ["-m", "meok_dependency_updater_ai_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 4 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
