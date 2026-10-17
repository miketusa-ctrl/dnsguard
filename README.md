# DnsGuard

Check a domain's email authentication: SPF, DKIM, DMARC, BIMI, MX, MTA-STS, TLS-RPT. Score + fixes.

## Live service

- Web app and API: https://dnsguard.mike-tusa.workers.dev/
- Pricing and plans: https://dnsguard.mike-tusa.workers.dev/
- Support: digitalpromohub.support@gmail.com

## Use it from an AI assistant (MCP)

DnsGuard is a remote MCP server (Streamable HTTP) at `https://dnsguard.mike-tusa.workers.dev/mcp`. Tools: `check_domain`.

Most MCP clients (Claude Desktop, Cursor, Cline, Windsurf) accept this config:

```json
{
  "mcpServers": {
    "dnsguard": {
      "type": "http",
      "url": "https://dnsguard.mike-tusa.workers.dev/mcp"
    }
  }
}
```

Clients that only support stdio can bridge with `npx mcp-remote https://dnsguard.mike-tusa.workers.dev/mcp`. VS Code uses a `servers` key instead of `mcpServers`.

The `server.json` file is the [MCP Registry](https://registry.modelcontextprotocol.io) manifest for this server.

## Run your own copy

Requires Node.js 20+ and a Cloudflare account.

```bash
npm install
npx wrangler dev        # local dev server
```

`wrangler.toml` is a template: create your own KV namespaces / D1 databases / rate-limit namespaces and replace the `<PLACEHOLDER>` values before `npx wrangler deploy`. Any secrets the Worker reads go in `wrangler secret put` (or `.dev.vars` locally), never in the repo.

## License

MIT (c) Digital Promo Hub. See [LICENSE](LICENSE).
