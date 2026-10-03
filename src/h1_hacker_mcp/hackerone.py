from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import quote

import httpx

from h1_hacker_mcp.config import Settings

USER_AGENT = "h1-hacker-mcp/0.1"
HANDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,254}$")
HACKTIVITY_SORTS = frozenset(
    {
        "latest_disclosable_activity_at",
        "-latest_disclosable_activity_at",
        "disclosed_at",
        "-disclosed_at",
        "total_awarded_amount",
        "-total_awarded_amount",
        "votes",
        "-votes",
    }
)


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

    def get_json(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """GET a JSON:API document. This client has no other HTTP method."""
        response = self._http.get(path, params=_drop_none(params))
        response.raise_for_status()
        try:
            body = response.json()
        except json.JSONDecodeError as exc:
            raise HackerOneError("HackerOne returned a non-JSON body.") from exc
        if not isinstance(body, dict):
            raise HackerOneError("HackerOne returned an unexpected JSON body.")
        return body

    def ping_programs(self) -> dict[str, Any]:
        """GET /programs?page[size]=1 — proves the token can see the pool."""
        body = self.get_json("/programs", {"page[size]": 1})
        data = body.get("data")
        sample = data if isinstance(data, list) else []
        return {"ok": True, "sample_count": len(sample)}

    def list_programs(self, *, page_number: int = 1, page_size: int = 25) -> dict[str, Any]:
        return self.get_json("/programs", _page_params(page_number, page_size))

    def get_program(self, handle: str) -> dict[str, Any]:
        return self.get_json(_program_path(handle))

    def list_structured_scopes(
        self,
        handle: str,
        *,
        page_number: int = 1,
        page_size: int = 25,
        id_gt: int | None = None,
        created_after: str | None = None,
        updated_after: str | None = None,
    ) -> dict[str, Any]:
        params = _page_params(page_number, page_size)
        if id_gt is not None:
            params["filter[id__gt]"] = _non_negative_int(id_gt, "id_gt")
        if created_after is not None:
            params["filter[created_at__gt]"] = _timestamp(created_after, "created_after")
        if updated_after is not None:
            params["filter[updated_at__gt]"] = _timestamp(updated_after, "updated_after")
        return self.get_json(f"{_program_path(handle)}/structured_scopes", params)

    def list_scope_exclusions(self, handle: str) -> dict[str, Any]:
        return self.get_json(f"{_program_path(handle)}/scope_exclusions")

    def list_weaknesses(
        self, handle: str, *, page_number: int = 1, page_size: int = 25
    ) -> dict[str, Any]:
        return self.get_json(
            f"{_program_path(handle)}/weaknesses",
            _page_params(page_number, page_size),
        )

    def list_my_reports(self, *, page_number: int = 1, page_size: int = 25) -> dict[str, Any]:
        return self.get_json("/me/reports", _page_params(page_number, page_size))

    def get_report(self, report_id: int) -> dict[str, Any]:
        return self.get_json(f"/reports/{_positive_int(report_id, 'report_id')}")

    def search_hacktivity(
        self,
        *,
        query: str | None = None,
        sort: str | None = None,
        page_number: int = 1,
        page_size: int = 25,
    ) -> dict[str, Any]:
        params = _page_params(page_number, page_size)
        if query is not None:
            params["queryString"] = query
        if sort is not None:
            if sort not in HACKTIVITY_SORTS:
                allowed = ", ".join(sorted(HACKTIVITY_SORTS))
                raise HackerOneError(f"sort must be one of: {allowed}.")
            params["sort"] = sort
        return self.get_json("/hacktivity", params)

    def get_balance(self) -> dict[str, Any]:
        return self.get_json("/payments/balance")

    def list_earnings(self, *, page_number: int = 1, page_size: int = 25) -> dict[str, Any]:
        return self.get_json("/payments/earnings", _page_params(page_number, page_size))

    def list_payouts(self, *, page_number: int = 1, page_size: int = 25) -> dict[str, Any]:
        return self.get_json("/payments/payouts", _page_params(page_number, page_size))

    def list_report_intents(self) -> dict[str, Any]:
        return self.get_json("/report_intents")

    def get_report_intent(self, report_intent_id: int) -> dict[str, Any]:
        intent_id = _positive_int(report_intent_id, "report_intent_id")
        return self.get_json(f"/report_intents/{intent_id}")

    def list_report_intent_attachments(self, report_intent_id: int) -> dict[str, Any]:
        intent_id = _positive_int(report_intent_id, "report_intent_id")
        return self.get_json(f"/report_intents/{intent_id}/attachments")


class HackerOneError(Exception):
    """HackerOne Error"""


def safe_http_error(exc: httpx.HTTPStatusError) -> str:
    status = exc.response.status_code
    if status in (401, 403):
        return "HackerOne rejected the credentials or they lack access."
    if status == 429:
        return "HackerOne rate limit hit. Try again later."
    return f"HackerOne returned HTTP {status}."


def omit_program_policies(body: dict[str, Any]) -> dict[str, Any]:
    """Copy a program list and drop attributes.policy from each item."""
    result = dict(body)
    data = result.get("data")
    if isinstance(data, list):
        cleaned: list[Any] = []
        for item in data:
            if isinstance(item, dict):
                item = dict(item)
                attributes = item.get("attributes")
                if isinstance(attributes, dict) and "policy" in attributes:
                    attributes = dict(attributes)
                    del attributes["policy"]
                    item["attributes"] = attributes
            cleaned.append(item)
        result["data"] = cleaned
    result["policy_omitted"] = True
    return result


def _program_path(handle: str) -> str:
    handle = handle.strip()
    if not HANDLE_RE.fullmatch(handle):
        raise HackerOneError(
            "Program handle must start with a letter or digit and contain only "
            "letters, digits, underscores, or hyphens."
        )
    return f"/programs/{quote(handle, safe='')}"


def _positive_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise HackerOneError(f"{name} must be a positive integer.")
    return value


def _non_negative_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise HackerOneError(f"{name} must be an integer greater than or equal to 0.")
    return value


def _timestamp(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HackerOneError(f"{name} must be an ISO-8601 timestamp.")
    return value.strip()


def _page_params(page_number: int, page_size: int) -> dict[str, int]:
    page_number = _positive_int(page_number, "page_number")
    if isinstance(page_size, bool) or not isinstance(page_size, int) or not 1 <= page_size <= 100:
        raise HackerOneError("page_size must be an integer from 1 to 100.")
    return {"page[number]": page_number, "page[size]": page_size}


def _drop_none(params: dict[str, Any] | None) -> dict[str, Any] | None:
    if not params:
        return None
    return {key: value for key, value in params.items() if value is not None}
