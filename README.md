# cert-expiry-action

A tiny Go CLI **and** GitHub Action that checks a list of hosts for TLS certificate expiry and fails the job when any are too close to the edge.

> Built by [TigerTrust](https://tigertrust.io). Apache-2.0.

## Why

Expired certs are the kind of outage that used to happen to other people — until short-lived (30-, 47-, 90-day) issuance makes it happen to everyone. This action runs on a schedule, writes a job-summary table, and exits non-zero so the alert routes through your existing CI channels.

## Install (local CLI)

```sh
go install github.com/tigertrust/cert-expiry-action/cmd/cert-expiry@latest
```

Or:

```sh
git clone https://github.com/tigertrust/cert-expiry-action
cd cert-expiry-action
go run ./cmd/cert-expiry --hosts-file hosts.txt
```

## CLI

### Inline hosts

```sh
cert-expiry --hosts "api.example.com, www.example.com:8443"
```

```
api.example.com                     71 days  ok     DigiCert Global G2 TLS RSA SHA256 2020 CA1
www.example.com                     12 days  fail   DigiCert Global G2 TLS RSA SHA256 2020 CA1
```

### Hosts file

```sh
cat > hosts.txt <<'EOF'
# Production endpoints
api.tigertrust.io
app.tigertrust.io
# Internal, non-standard port
vault.internal:8443
EOF

cert-expiry --hosts-file hosts.txt --warn-days 30 --fail-days 14
```

### JSON output (filter the bad ones with jq)

```sh
cert-expiry --hosts-file hosts.txt --json | jq '.[] | select(.status != "ok")'
```

### Markdown table (good for Slack / PR comments)

```sh
cert-expiry --hosts-file hosts.txt --markdown
```

### Generic webhook on warn/fail

```sh
cert-expiry --hosts-file hosts.txt \
  --webhook-url https://hooks.slack.com/services/XXX/YYY/ZZZ
```

### TigerTrust webhook with bearer token (never logged)

```sh
export TIGERTRUST_WEBHOOK_TOKEN=tt_live_abc123
cert-expiry --hosts-file hosts.txt \
  --tigertrust-webhook https://api.tigertrust.io/hooks/cert-expiry
```

### From a Go source checkout

```sh
go run ./cmd/cert-expiry --hosts-file hosts.txt
```

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--hosts STR` | — | Comma/newline-separated hosts (`host` or `host:port`) |
| `--hosts-file PATH` | — | File of hosts, one per line, `#` comments allowed |
| `--warn-days N` | `30` | Classify as `warn` when days-left < N |
| `--fail-days N` | `14` | Classify as `fail` (exit 1) when days-left < N |
| `--timeout DUR` | `10s` | Per-host TLS dial timeout |
| `--json` | — | Emit JSON array of results |
| `--markdown` | — | Emit a markdown table (also written to `$GITHUB_STEP_SUMMARY` when set) |
| `--allow-errors` | `false` | Treat dial errors as non-fatal |
| `--webhook-url URL` | — | POST a JSON summary when any `warn`/`fail` |
| `--tigertrust-webhook URL` | — | POST with `Authorization: Bearer $TIGERTRUST_WEBHOOK_TOKEN` |

### Exit codes

| Code | Meaning |
|-----:|---------|
| `0` | Every host is `ok` or `warn` |
| `1` | At least one host is `fail` — or `error` without `--allow-errors` |
| `2` | Usage error |

### Webhook payload

```json
{
  "generatedAt": "2026-11-04T06:00:00Z",
  "worst": "fail",
  "results": [
    {"host":"api.example.com","port":443,"issuer":"R10","notAfter":"2026-11-10T00:00:00Z","days":6,"status":"fail"}
  ]
}
```

The `TIGERTRUST_WEBHOOK_TOKEN` is never printed and never included in the generic `--webhook-url` POST.

## GitHub Action

Pin the action and let it run weekly:

```yaml
name: TLS expiry
on:
  schedule:
    - cron: '0 6 * * 1'
  workflow_dispatch:

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: tigertrust/cert-expiry-action@v0.1
        with:
          hosts: |
            tigertrust.io
            api.tigertrust.io
          warn_days: '30'
          fail_days: '14'
```

### Action inputs

| Input | Default | Meaning |
|-------|---------|---------|
| `hosts` | — | Multiline or comma-separated host list |
| `warn_days` | `30` | — |
| `fail_days` | `14` | — |
| `timeout` | `10s` | — |
| `allow_errors` | `false` | — |
| `webhook_url` | — | Generic webhook |
| `tigertrust_webhook` | — | TigerTrust webhook. Pass token as env `TIGERTRUST_WEBHOOK_TOKEN` via `env:` on the step. |

### Secrets

Pass the TigerTrust token through the action step's `env`:

```yaml
- uses: tigertrust/cert-expiry-action@v0.1
  env:
    TIGERTRUST_WEBHOOK_TOKEN: ${{ secrets.TIGERTRUST_WEBHOOK_TOKEN }}
  with:
    hosts: tigertrust.io
    tigertrust_webhook: https://api.tigertrust.io/hooks/cert-expiry
```

## Related

- [`aia-chain-check`](https://github.com/tigertrust/aia-chain-check) — fail CI when a server does not send its full chain
- [`47-day-readiness-score`](https://github.com/tigertrust/47-day-readiness-score) — overall short-lived-cert readiness score

## License

Apache-2.0. See [LICENSE](./LICENSE) and [SECURITY.md](./SECURITY.md).
