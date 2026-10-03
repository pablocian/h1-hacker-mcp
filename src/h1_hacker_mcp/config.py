from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_API_BASE = "https://api.hackerone.com/v1/hackers"
IDENTIFIER_ENV = "HACKERONE_API_IDENTIFIER"
TOKEN_ENV = "HACKERONE_API_TOKEN"

MISSING_CREDENTIALS_MESSAGE = (
    f"Set {IDENTIFIER_ENV} and {TOKEN_ENV} "
    "(HackerOne Settings → API Token)."
)


class MissingCredentials(Exception):
    """Raised when HackerOne API env vars are absent or blank."""


@dataclass(frozen=True)
class Settings:
    identifier: str
    token: str = field(repr=False)
    api_base: str = DEFAULT_API_BASE


def load_settings() -> Settings:
    identifier = os.environ.get(IDENTIFIER_ENV, "").strip()
    token = os.environ.get(TOKEN_ENV, "").strip()
    if not identifier or not token:
        raise MissingCredentials(MISSING_CREDENTIALS_MESSAGE)
    return Settings(identifier=identifier, token=token)
