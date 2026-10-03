from __future__ import annotations

from typing import Any

import httpx
from mcp.server import MCPServer

from h1_hacker_mcp.config import MissingCredentials, load_settings
from h1_hacker_mcp.hackerone import HackerOneClient, HackerOneError, safe_http_error

mcp = MCPServer(
    "h1-hacker-mcp",
    version="0.1.0",
    instructions=(
        "Write some detailed agent instructions here."
    ),
)


@mcp.tool()
def test_key() -> dict[str, Any]:
    """Check stored HackerOne credentials."""
    try:
        settings = load_settings()
    except MissingCredentials as exc:
        return {"ok": False, "error": str(exc)}

    try:
        with HackerOneClient(settings) as client:
            return client.ping_programs()
    except httpx.HTTPStatusError as exc:
        return {
            "ok": False,
            "status": exc.response.status_code,
            "error": safe_http_error(exc),
        }
    except HackerOneError as exc:
        return {"ok": False, "error": str(exc)}
    except httpx.HTTPError as exc:
        return {"ok": False, "error": type(exc).__name__}


# pytest collects callables named test_*; this is an MCP tool, not a unit test.
test_key.__test__ = False  # type: ignore[attr-defined]


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
