// Command cert-expiry checks TLS certificate expiry for a list of hosts and
// classifies each as ok / warn / fail / error. Designed to run both locally
// and as a GitHub Action.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/tigertrust/cert-expiry-action/internal/checker"
)

const usage = `cert-expiry — TigerTrust TLS certificate expiry check

Usage:
  cert-expiry --hosts "host[:port], host2" [flags]
  cert-expiry --hosts-file hosts.txt [flags]

Examples:
  # Inline hosts
  cert-expiry --hosts "api.example.com, www.example.com:8443"

  # Hosts file (blank lines and '#' comments ignored)
  cert-expiry --hosts-file hosts.txt --warn-days 30 --fail-days 14

  # JSON output (filter the bad ones with jq)
  cert-expiry --hosts-file hosts.txt --json | jq '.[] | select(.status != "ok")'

  # Markdown table (also emitted to $GITHUB_STEP_SUMMARY when set)
  cert-expiry --hosts-file hosts.txt --markdown

  # Generic webhook on warn/fail
  cert-expiry --hosts-file hosts.txt \
    --webhook-url https://hooks.slack.com/services/XXX/YYY/ZZZ

  # TigerTrust webhook with bearer from env (never logged)
  TIGERTRUST_WEBHOOK_TOKEN=tt_live_abc123 \
    cert-expiry --hosts-file hosts.txt \
    --tigertrust-webhook https://api.tigertrust.io/hooks/cert-expiry

Exit codes:
  0  every host is ok or warn
  1  at least one host is fail, or error (unless --allow-errors)
  2  usage error

Flags:
`

func main() {
	fs := flag.NewFlagSet("cert-expiry", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		fs.PrintDefaults()
	}
	hostsInline := fs.String("hosts", "", "hosts, comma- or newline-separated")
	hostsFile := fs.String("hosts-file", "", "file with one host per line (# comments ok)")
	warnDays := fs.Int("warn-days", 30, "warn when a cert expires within N days")
	failDays := fs.Int("fail-days", 14, "fail (exit 1) when a cert expires within N days")
	timeout := fs.Duration("timeout", 10*time.Second, "TLS dial timeout")
	jsonOut := fs.Bool("json", false, "emit JSON")
	markdownOut := fs.Bool("markdown", false, "emit markdown table")
	allowErrors := fs.Bool("allow-errors", false, "treat dial errors as non-fatal")
	webhookURL := fs.String("webhook-url", "", "POST JSON summary to this URL on any warn/fail")
	tigertrustWebhook := fs.String("tigertrust-webhook", "", "POST to TigerTrust webhook (uses env TIGERTRUST_WEBHOOK_TOKEN)")

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	var hosts []string
	if *hostsInline != "" {
		hosts = append(hosts, checker.ParseHostsString(*hostsInline)...)
	}
	if *hostsFile != "" {
		fromFile, err := checker.ParseHostsFile(*hostsFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "hosts-file:", err)
			os.Exit(2)
		}
		hosts = append(hosts, fromFile...)
	}
	if len(hosts) == 0 {
		fs.Usage()
		os.Exit(2)
	}

	opts := checker.DefaultOptions()
	opts.WarnDays = *warnDays
	opts.FailDays = *failDays
	opts.Timeout = *timeout

	results := checker.CheckAll(hosts, opts)

	// Primary output.
	switch {
	case *jsonOut:
		if err := checker.WriteJSON(os.Stdout, results); err != nil {
			fmt.Fprintln(os.Stderr, "json:", err)
			os.Exit(2)
		}
	case *markdownOut:
		checker.WriteMarkdown(os.Stdout, results)
	default:
		for _, r := range results {
			fmt.Printf("%-40s %6d days  %-5s  %s\n", r.Host, r.Days, r.Status, r.Issuer)
			if r.Status == checker.StatusError {
				fmt.Printf("  error: %s\n", r.Error)
			}
		}
	}

	// GitHub step summary.
	if summaryPath := os.Getenv("GITHUB_STEP_SUMMARY"); summaryPath != "" {
		var buf bytes.Buffer
		buf.WriteString("# TLS certificate expiry\n\n")
		checker.WriteMarkdown(&buf, results)
		if err := appendFile(summaryPath, buf.Bytes()); err != nil {
			fmt.Fprintln(os.Stderr, "warning: GITHUB_STEP_SUMMARY:", err)
		}
	}

	// Webhooks.
	worst := checker.WorstStatus(results)
	if *webhookURL != "" && worst != checker.StatusOK {
		if err := checker.PostWebhook(*webhookURL, "", results, nil); err != nil {
			fmt.Fprintln(os.Stderr, "warning: webhook:", err)
		}
	}
	if *tigertrustWebhook != "" {
		token := os.Getenv("TIGERTRUST_WEBHOOK_TOKEN")
		if err := checker.PostWebhook(*tigertrustWebhook, token, results, nil); err != nil {
			fmt.Fprintln(os.Stderr, "warning: tigertrust webhook:", err)
		}
	}

	// Exit code.
	if worst == checker.StatusFail {
		os.Exit(1)
	}
	if worst == checker.StatusError && !*allowErrors {
		os.Exit(1)
	}
}

func appendFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}
