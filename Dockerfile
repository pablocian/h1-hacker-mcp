FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY src ./src

RUN uv sync --frozen --no-dev --no-editable \
    && useradd --create-home --uid 1000 --shell /usr/sbin/nologin app \
    && chown -R app:app /app

USER app

ENTRYPOINT ["uv", "run", "--frozen", "--no-dev", "h1-hacker-mcp"]
