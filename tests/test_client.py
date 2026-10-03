from __future__ import annotations

import inspect
from typing import Any

import httpx
import pytest

from h1_hacker_mcp.config import Settings
from h1_hacker_mcp.hackerone import (
    HackerOneClient,
    HackerOneError,
    omit_program_policies,
    safe_http_error,
)


def _client(handler: httpx.MockTransport | Any) -> tuple[HackerOneClient, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    http = httpx.Client(
        transport=httpx.MockTransport(record),
        base_url="https://api.hackerone.com/v1/hackers",
    )
    settings = Settings(identifier="identifier", token="token")
    return HackerOneClient(settings, client=http), seen


def _json_handler(body: dict[str, Any] | list[Any] | None = None, status: int = 200):
    payload = {"data": [], "links": {}} if body is None else body

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=payload)

    return handler


def test_every_read_method_issues_the_documented_get() -> None:
    client, seen = _client(_json_handler())
    calls: list[tuple[str, dict[str, str]]] = []

    def run(method: str, args: tuple[Any, ...] = (), kwargs: dict[str, Any] | None = None) -> None:
        before = len(seen)
        getattr(client, method)(*args, **(kwargs or {}))
        request = seen[before]
        calls.append((request.url.path, dict(request.url.params)))
        assert request.method == "GET"

    run("ping_programs")
    run("list_programs", kwargs={"page_number": 2, "page_size": 10})
    run("get_program", args=("acme",))
    run(
        "list_structured_scopes",
        args=("acme",),
        kwargs={
            "page_number": 3,
            "page_size": 50,
            "id_gt": 100,
            "created_after": "2024-01-01T00:00:00Z",
            "updated_after": "2024-06-01T00:00:00Z",
        },
    )
    run("list_scope_exclusions", args=("acme",))
    run("list_weaknesses", args=("acme",), kwargs={"page_number": 1, "page_size": 25})
    run("list_my_reports", kwargs={"page_number": 4, "page_size": 5})
    run("get_report", args=(1337,))
    run(
        "search_hacktivity",
        kwargs={"query": "severity_rating:critical", "sort": "-votes", "page_number": 1, "page_size": 25},
    )
    run("get_balance")
    run("list_earnings", kwargs={"page_number": 1, "page_size": 25})
    run("list_payouts", kwargs={"page_number": 1, "page_size": 25})
    run("list_report_intents")
    run("get_report_intent", args=(23,))
    run("list_report_intent_attachments", args=(23,))

    assert calls == [
        ("/v1/hackers/programs", {"page[size]": "1"}),
        ("/v1/hackers/programs", {"page[number]": "2", "page[size]": "10"}),
        ("/v1/hackers/programs/acme", {}),
        (
            "/v1/hackers/programs/acme/structured_scopes",
            {
                "page[number]": "3",
                "page[size]": "50",
                "filter[id__gt]": "100",
                "filter[created_at__gt]": "2024-01-01T00:00:00Z",
                "filter[updated_at__gt]": "2024-06-01T00:00:00Z",
            },
        ),
        ("/v1/hackers/programs/acme/scope_exclusions", {}),
        ("/v1/hackers/programs/acme/weaknesses", {"page[number]": "1", "page[size]": "25"}),
        ("/v1/hackers/me/reports", {"page[number]": "4", "page[size]": "5"}),
        ("/v1/hackers/reports/1337", {}),
        (
            "/v1/hackers/hacktivity",
            {
                "queryString": "severity_rating:critical",
                "sort": "-votes",
                "page[number]": "1",
                "page[size]": "25",
            },
        ),
        ("/v1/hackers/payments/balance", {}),
        ("/v1/hackers/payments/earnings", {"page[number]": "1", "page[size]": "25"}),
        ("/v1/hackers/payments/payouts", {"page[number]": "1", "page[size]": "25"}),
        ("/v1/hackers/report_intents", {}),
        ("/v1/hackers/report_intents/23", {}),
        ("/v1/hackers/report_intents/23/attachments", {}),
    ]
    assert all(request.method == "GET" for request in seen)


def test_client_source_has_no_write_methods() -> None:
    source = inspect.getsource(HackerOneClient)
    for call in (".post(", ".put(", ".patch(", ".delete(", ".request("):
        assert call not in source


@pytest.mark.parametrize(
    ("handle",),
    [("bad/handle",), ("../acme",), ("",), (" has space",), ("-leading",)],
)
def test_rejects_invalid_handles_without_a_request(handle: str) -> None:
    client, seen = _client(_json_handler())
    with pytest.raises(HackerOneError):
        client.get_program(handle)
    assert seen == []


@pytest.mark.parametrize("report_id", [0, -1, True])
def test_rejects_invalid_report_ids(report_id: int) -> None:
    client, seen = _client(_json_handler())
    with pytest.raises(HackerOneError):
        client.get_report(report_id)
    assert seen == []


def test_rejects_invalid_page_size_and_sort() -> None:
    client, seen = _client(_json_handler())
    with pytest.raises(HackerOneError):
        client.list_programs(page_size=101)
    with pytest.raises(HackerOneError):
        client.search_hacktivity(sort="title")
    assert seen == []


def test_safe_http_error_maps_auth_and_rate_limit() -> None:
    request = httpx.Request("GET", "https://api.hackerone.com/v1/hackers/programs")
    unauthorized = httpx.HTTPStatusError(
        "no", request=request, response=httpx.Response(401, request=request)
    )
    forbidden = httpx.HTTPStatusError(
        "no", request=request, response=httpx.Response(403, request=request)
    )
    limited = httpx.HTTPStatusError(
        "no", request=request, response=httpx.Response(429, request=request)
    )
    missing = httpx.HTTPStatusError(
        "no", request=request, response=httpx.Response(404, request=request)
    )
    assert safe_http_error(unauthorized) == "HackerOne rejected the credentials or they lack access."
    assert safe_http_error(forbidden) == "HackerOne rejected the credentials or they lack access."
    assert safe_http_error(limited) == "HackerOne rate limit hit. Try again later."
    assert safe_http_error(missing) == "HackerOne returned HTTP 404."


def test_get_json_raises_for_http_errors_and_non_json() -> None:
    client, _seen = _client(lambda request: httpx.Response(429, json={"errors": []}))
    with pytest.raises(httpx.HTTPStatusError) as limited:
        client.get_balance()
    assert limited.value.response.status_code == 429

    client, _seen = _client(lambda request: httpx.Response(200, content=b"not-json"))
    with pytest.raises(HackerOneError, match="non-JSON"):
        client.get_balance()

    client, _seen = _client(_json_handler([]))
    with pytest.raises(HackerOneError, match="unexpected"):
        client.get_balance()


def test_omit_program_policies_drops_policy_without_mutating_the_source() -> None:
    body = {
        "data": [
            {"id": "9", "attributes": {"handle": "acme", "policy": "long policy", "offers_bounties": True}},
            {"id": "10", "attributes": {"handle": "other"}},
            "not-a-program",
        ],
        "links": {"next": "https://example.test/next"},
    }
    result = omit_program_policies(body)
    assert result["policy_omitted"] is True
    assert "policy" not in result["data"][0]["attributes"]
    assert result["data"][0]["attributes"]["offers_bounties"] is True
    assert result["data"][1]["attributes"]["handle"] == "other"
    assert result["data"][2] == "not-a-program"
    assert result["links"]["next"].endswith("/next")
    assert body["data"][0]["attributes"]["policy"] == "long policy"
    assert "policy_omitted" not in body
