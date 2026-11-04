# Security policy

## Supported versions

The `main` branch and the latest tagged release receive security fixes.

## Reporting a vulnerability

Please email **security@tigertrust.io** with a description of the issue, steps
to reproduce, and any proof-of-concept. We acknowledge reports within 3
business days and aim to ship fixes within 30 days for critical findings.

Do **not** file public GitHub issues for vulnerabilities.

## Handling of secrets

- `TIGERTRUST_WEBHOOK_TOKEN` is read from the process environment and sent as
  `Authorization: Bearer <token>` to the `--tigertrust-webhook` URL only.
- The token is never written to stdout, stderr, the step summary, or the
  generic `--webhook-url` payload.
- GitHub masks the value for you when passed via the standard Actions
  `secrets` mechanism; do not log it yourself.
