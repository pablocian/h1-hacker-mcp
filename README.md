# h1-hacker-mcp

Read-only MCP server for the [HackerOne Hacker API](https://api.hackerone.com/hacker-resources/). An agent can read the programs, policies, scope, reports, and payments the authenticated hacker account can already see. It cannot create, update, or submit reports.

## Credentials

Create an API token in HackerOne under Settings → API Token, then set:

```bash
export HACKERONE_API_IDENTIFIER="your-api-token-identifier"
export HACKERONE_API_TOKEN="your-api-token"
```

## Cursor

Add this to your MCP config. The process needs the two environment variables above.

```json
{
  "mcpServers": {
    "h1-hacker": {
      "command": "uv",
      "args": ["run", "--directory", "/absolute/path/to/h1-hacker-mcp", "h1-hacker-mcp"]
    }
  }
}
```

## Run

```bash
uv run h1-hacker-mcp
```
