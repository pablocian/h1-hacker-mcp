from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from h1_hacker_mcp.config import MISSING_CREDENTIALS_MESSAGE
from h1_hacker_mcp.hackerone import HackerOneError
from h1_hacker_mcp.server import (
    INSTRUCTIONS,
    check_credentials,
    get_program,
    list_programs,
    mcp,
)


class _FakeClient:
    def __init__(self, result: dict[str, Any] | None = None, error: Exception | None = None) -> None:
        self.result = result if result is not None else {"data": [], "links": {}}
        self.error = error
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def _respond(self, name: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
        self.calls.append((name, args, kwargs))
        if self.error is not None:
            raise self.error
        return self.result

    def ping_programs(self) -> dict[str, Any]:
        return self._respond("ping_programs")

    def list_programs(self, **kwargs: Any) -> dict[str, Any]:
        return self._respond("list_programs", **kwargs)

    def get_program(self, handle: str) -> dict[str, Any]:
        return self._respond("get_program", handle)


@pytest.fixture
def credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HACKERONE_API_IDENTIFIER", "identifier")
    monkeypatch.setenv("HACKERONE_API_TOKEN", "token")


def _patch_client(monkeypatch: pytest.MonkeyPatch, fake: _FakeClient) -> None:
    monkeypatch.setattr(
        "h1_hacker_mcp.server.HackerOneClient",
        lambda settings: fake,
    )


def test_list_programs_strips_policy_and_get_program_keeps_it(
    monkeypatch: pytest.MonkeyPatch, credentials: None
) -> None:
    program = {
        "id": "9",
        "attributes": {
            "handle": "acme",
            "policy": "full policy text",
            "offers_bounties": True,
            "open_scope": False,
        },
    }
    listed = _FakeClient({"data": [program], "links": {"self": "https://example.test"}})
    _patch_client(monkeypatch, listed)
    page = list_programs(page_number=2, page_size=10)
    assert page["policy_omitted"] is True
    assert "policy" not in page["data"][0]["attributes"]
    assert page["data"][0]["attributes"]["offers_bounties"] is True
    assert listed.calls == [("list_programs", (), {"page_number": 2, "page_size": 10})]

    detailed = _FakeClient({"data": program})
    _patch_client(monkeypatch, detailed)
    full = get_program("acme")
    assert full["data"]["attributes"]["policy"] == "full policy text"
    assert "policy_omitted" not in full


def test_check_credentials_reports_a_successful_ping(
    monkeypatch: pytest.MonkeyPatch, credentials: None
) -> None:
    fake = _FakeClient({"ok": True, "sample_count": 1})
    _patch_client(monkeypatch, fake)
    assert check_credentials() == {"ok": True, "sample_count": 1}


def test_missing_credentials_are_a_tool_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HACKERONE_API_IDENTIFIER", raising=False)
    monkeypatch.delenv("HACKERONE_API_TOKEN", raising=False)
    result = check_credentials()
    assert result["ok"] is False
    assert result["error"] == MISSING_CREDENTIALS_MESSAGE


def test_http_errors_stay_json_results(
    monkeypatch: pytest.MonkeyPatch, credentials: None
) -> None:
    request = httpx.Request("GET", "https://api.hackerone.com/v1/hackers/programs")
    fake = _FakeClient(
        error=httpx.HTTPStatusError(
            "limited",
            request=request,
            response=httpx.Response(429, request=request),
        )
    )
    _patch_client(monkeypatch, fake)
    assert list_programs() == {
        "ok": False,
        "status": 429,
        "error": "HackerOne rate limit hit. Try again later.",
    }

    fake = _FakeClient(error=HackerOneError("page_size must be an integer from 1 to 100."))
    _patch_client(monkeypatch, fake)
    assert list_programs()["ok"] is False


def test_every_tool_is_read_only() -> None:
    tools = asyncio.run(mcp.list_tools())
    names = {tool.name for tool in tools}
    assert names == {
        "check_credentials",
        "list_programs",
        "get_program",
        "list_structured_scopes",
        "list_scope_exclusions",
        "list_weaknesses",
        "list_my_reports",
        "get_report",
        "search_hacktivity",
        "get_balance",
        "list_earnings",
        "list_payouts",
        "list_report_intents",
        "get_report_intent",
        "list_report_intent_attachments",
    }
    for tool in tools:
        assert tool.annotations is not None
        assert tool.annotations.read_only_hint is True
        assert tool.annotations.destructive_hint is False
        assert tool.annotations.idempotent_hint is True
        assert tool.annotations.open_world_hint is True
    assert "read-only" in INSTRUCTIONS.lower()
    assert "get_program" in INSTRUCTIONS
    assert "list_structured_scopes" in INSTRUCTIONS
    assert "get_report" in INSTRUCTIONS
