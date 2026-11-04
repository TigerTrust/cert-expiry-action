package checker

import (
	"encoding/json"
	"fmt"
	"io"
)

// WriteMarkdown writes a GitHub-flavored markdown table of results.
func WriteMarkdown(w io.Writer, results []Result) {
	fmt.Fprintln(w, "| Host | Port | Issuer | NotAfter | Days | Status |")
	fmt.Fprintln(w, "|------|-----:|--------|----------|-----:|--------|")
	for _, r := range results {
		issuer := r.Issuer
		if issuer == "" {
			issuer = "—"
		}
		notAfter := r.NotAfter
		if notAfter == "" {
			notAfter = "—"
		}
		mark := statusEmoji(r.Status)
		detail := string(r.Status)
		if r.Status == StatusError {
			detail = "error: " + r.Error
		}
		fmt.Fprintf(w, "| `%s` | %d | %s | %s | %d | %s %s |\n", r.Host, r.Port, issuer, notAfter, r.Days, mark, detail)
	}
}

// WriteJSON writes results as a pretty-printed JSON array.
func WriteJSON(w io.Writer, results []Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func statusEmoji(s Status) string {
	switch s {
	case StatusOK:
		return ":white_check_mark:"
	case StatusWarn:
		return ":warning:"
	case StatusFail:
		return ":x:"
	case StatusError:
		return ":boom:"
	}
	return ""
}
