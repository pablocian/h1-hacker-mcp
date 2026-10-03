from __future__ import annotations

import json
from typing import Any

import httpx

from h1_hacker_mcp.config import Settings

USER_AGENT = "h1-hacker-mcp/0.1"
PROGRAMS_PATH = "/programs"


class HackerOneClient:

    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        self._settings = settings
        self._owns_client = client is None
        self._http = client or httpx.Client(
            base_url=settings.api_base,
            auth=(settings.identifier, settings.token),
            headers={
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
            timeout=20.0,
        )

    def close(self) -> None:
        if self._owns_client:
            self._http.close()

    def __enter__(self) -> HackerOneClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def ping_programs(self) -> dict[str, Any]:
        """GET /programs?page[size]=1 — proves the token can see the pool."""
        response = self._http.get(PROGRAMS_PATH, params={"page[size]": 1})
        response.raise_for_status()
        try:
            body = response.json()
        except json.JSONDecodeError as exc:
            raise HackerOneError("HackerOne returned a non-JSON body.") from exc
        data = body.get("data") if isinstance(body, dict) else None
        sample = data if isinstance(data, list) else []
        return {
            "ok": True,
            "status": response.status_code,
            "sample_count": len(sample),
        }


class HackerOneError(Exception):
    """HackerOne Error"""


def safe_http_error(exc: httpx.HTTPStatusError) -> str:
    status = exc.response.status_code
    if status in (401, 403):
        return "HackerOne rejected the credentials or they lack access."
    if status == 429:
        return "HackerOne rate limit hit. Try again later."
    return f"HackerOne returned HTTP {status}."
