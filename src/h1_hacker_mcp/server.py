from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from h1_hacker_mcp.config import MissingCredentials, load_settings
from h1_hacker_mcp.hackerone import (
    HackerOneClient,
    HackerOneError,
    omit_program_policies,
    safe_http_error,
)

READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=True,
)

INSTRUCTIONS = """\
This server is read-only access to the HackerOne Hacker API for the authenticated \
hacker account. It cannot create, update, comment on, or submit reports, and it \
cannot change programs, bounties, or payouts. Do not invent a submit, comment, or \
bounty action.

Use list_programs to see programs the account can access. Policies are omitted from \
that list. Call get_program for the full policy and the declaration flags \
offers_bounties, open_scope, fast_payments, gold_standard_safe_harbor, and \
allows_bounty_splitting.

Use list_structured_scopes for in-scope assets. That endpoint allows 50 requests per \
minute, and page offsets stop after 10,000 rows; continue with id_gt instead. Use \
list_scope_exclusions for report categories excluded from rewards, and list_weaknesses \
for the weakness types the program accepts.

Use list_my_reports for the account's submitted reports, then get_report for the full \
report, including activity, severity, bounties, and attachment metadata. Attachment \
tools return an expiring download URL and do not fetch file bytes.

search_hacktivity searches publicly disclosed reports. get_balance, list_earnings, and \
list_payouts read the account's payments. list_report_intents and get_report_intent \
read unsubmitted draft report intents only.

List tools return one page plus the JSON:API links object. Pass the next page_number \
to continue. Credentials are the HACKERONE_API_IDENTIFIER and HACKERONE_API_TOKEN \
environment variables.\
"""

mcp = MCPServer(
    "h1-hacker-mcp",
    version="0.1.0",
    instructions=INSTRUCTIONS,
)


def _call(action: Callable[[HackerOneClient], dict[str, Any]]) -> dict[str, Any]:
    try:
        settings = load_settings()
    except MissingCredentials as exc:
        return {"ok": False, "error": str(exc)}

    try:
        with HackerOneClient(settings) as client:
            return action(client)
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


@mcp.tool(annotations=READ_ONLY)
def check_credentials() -> dict[str, Any]:
    """Check the stored HackerOne API token by requesting one program."""
    return _call(lambda client: client.ping_programs())


@mcp.tool(annotations=READ_ONLY)
def list_programs(page_number: int = 1, page_size: int = 25) -> dict[str, Any]:
    """List programs the hacker account can access.

    Program policies are omitted from this list. Call get_program for the policy
    and declaration flags. page_number starts at 1. page_size is 1-100.
    """
    return _call(
        lambda client: omit_program_policies(
            client.list_programs(page_number=page_number, page_size=page_size)
        )
    )


@mcp.tool(annotations=READ_ONLY)
def get_program(handle: str) -> dict[str, Any]:
    """Get one program, including its policy and declaration flags.

    Declaration flags are offers_bounties, open_scope, fast_payments,
    gold_standard_safe_harbor, and allows_bounty_splitting. handle is the
    program handle from list_programs, such as "security".
    """
    return _call(lambda client: client.get_program(handle))


@mcp.tool(annotations=READ_ONLY)
def list_structured_scopes(
    handle: str,
    page_number: int = 1,
    page_size: int = 25,
    id_gt: int | None = None,
    created_after: str | None = None,
    updated_after: str | None = None,
) -> dict[str, Any]:
    """List a program's structured scope (in-scope and submission-eligible assets).

    Each asset includes asset_identifier, asset_type, eligible_for_submission,
    eligible_for_bounty, max_severity, and instruction. Limited to 50 requests
    per minute. Page offsets cover at most 10,000 rows; pass id_gt (the last
    seen scope id) to continue, and prefer that over high page numbers.
    created_after and updated_after are ISO-8601 timestamps.
    """
    return _call(
        lambda client: client.list_structured_scopes(
            handle,
            page_number=page_number,
            page_size=page_size,
            id_gt=id_gt,
            created_after=created_after,
            updated_after=updated_after,
        )
    )


@mcp.tool(annotations=READ_ONLY)
def list_scope_exclusions(handle: str) -> dict[str, Any]:
    """List report categories a program excludes from rewards, beyond core ineligible findings."""
    return _call(lambda client: client.list_scope_exclusions(handle))


@mcp.tool(annotations=READ_ONLY)
def list_weaknesses(
    handle: str, page_number: int = 1, page_size: int = 25
) -> dict[str, Any]:
    """List weakness types a program accepts. page_number starts at 1. page_size is 1-100."""
    return _call(
        lambda client: client.list_weaknesses(
            handle, page_number=page_number, page_size=page_size
        )
    )


@mcp.tool(annotations=READ_ONLY)
def list_my_reports(page_number: int = 1, page_size: int = 25) -> dict[str, Any]:
    """List reports submitted by the authenticated hacker.

    This page does not include report activity. Call get_report for the full
    report. page_number starts at 1. page_size is 1-100.
    """
    return _call(
        lambda client: client.list_my_reports(page_number=page_number, page_size=page_size)
    )


@mcp.tool(annotations=READ_ONLY)
def get_report(report_id: int) -> dict[str, Any]:
    """Get one report the account can view, including activity.

    Includes reporter, program, weakness, severity, bounties, swag, activities,
    attachment metadata (with expiring download URLs), structured scope, and
    summaries. vulnerability_information is present when the hacker owns the
    report. This tool does not download attachment bytes.
    """
    return _call(lambda client: client.get_report(report_id))


@mcp.tool(annotations=READ_ONLY)
def search_hacktivity(
    query: str | None = None,
    sort: str | None = None,
    page_number: int = 1,
    page_size: int = 25,
) -> dict[str, Any]:
    """Search publicly disclosed hacktivity reports.

    query is an Apache Lucene query. Filters: severity_rating, asset_type,
    substate, cwe, cve_ids, reporter, team, total_awarded_amount, disclosed_at,
    has_collaboration, disclosed. Example:
    severity_rating:critical AND disclosed_at:>=01-01-1970.
    sort is latest_disclosable_activity_at, disclosed_at, total_awarded_amount,
    or votes. Prefix with - for descending order. The API default is
    -latest_disclosable_activity_at.
    """
    return _call(
        lambda client: client.search_hacktivity(
            query=query, sort=sort, page_number=page_number, page_size=page_size
        )
    )


@mcp.tool(annotations=READ_ONLY)
def get_balance() -> dict[str, Any]:
    """Get the authenticated hacker's current payments balance."""
    return _call(lambda client: client.get_balance())


@mcp.tool(annotations=READ_ONLY)
def list_earnings(page_number: int = 1, page_size: int = 25) -> dict[str, Any]:
    """List earnings (bounties, retests, and pentests) for the authenticated hacker."""
    return _call(
        lambda client: client.list_earnings(page_number=page_number, page_size=page_size)
    )


@mcp.tool(annotations=READ_ONLY)
def list_payouts(page_number: int = 1, page_size: int = 25) -> dict[str, Any]:
    """List payouts sent to the authenticated hacker."""
    return _call(
        lambda client: client.list_payouts(page_number=page_number, page_size=page_size)
    )


@mcp.tool(annotations=READ_ONLY)
def list_report_intents() -> dict[str, Any]:
    """List unsubmitted report-intent drafts owned by the authenticated hacker.

    This does not submit them.
    """
    return _call(lambda client: client.list_report_intents())


@mcp.tool(annotations=READ_ONLY)
def get_report_intent(report_intent_id: int) -> dict[str, Any]:
    """Get one report-intent draft. This does not submit or update it."""
    return _call(lambda client: client.get_report_intent(report_intent_id))


@mcp.tool(annotations=READ_ONLY)
def list_report_intent_attachments(report_intent_id: int) -> dict[str, Any]:
    """List attachment metadata for a report-intent draft, including expiring download URLs.

    This does not download file bytes or upload attachments.
    """
    return _call(lambda client: client.list_report_intent_attachments(report_intent_id))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
