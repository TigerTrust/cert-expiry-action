// Package checker inspects TLS certificate expiry across a list of hosts
// and classifies each one as ok / warn / fail / error.
package checker

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// Status is the classification bucket for a single host.
type Status string

const (
	StatusOK    Status = "ok"
	StatusWarn  Status = "warn"
	StatusFail  Status = "fail"
	StatusError Status = "error"
)

// Result is the outcome of checking one host.
type Result struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Issuer   string `json:"issuer,omitempty"`
	NotAfter string `json:"notAfter,omitempty"`
	Days     int    `json:"days"`
	Status   Status `json:"status"`
	Error    string `json:"error,omitempty"`
}

// Options drives the batch check.
type Options struct {
	WarnDays int
	FailDays int
	Timeout  time.Duration
	// Now is overridable for deterministic tests.
	Now func() time.Time
	// Dial is overridable for deterministic tests.
	Dial func(host string, port int, timeout time.Duration) (*x509.Certificate, error)
}

// DefaultOptions returns the stock options set.
func DefaultOptions() Options {
	return Options{
		WarnDays: 30,
		FailDays: 14,
		Timeout:  10 * time.Second,
		Now:      time.Now,
		Dial:     DialLeaf,
	}
}

// DialLeaf performs a TLS handshake and returns the server's leaf cert.
func DialLeaf(host string, port int, timeout time.Duration) (*x509.Certificate, error) {
	d := &net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no peer certificates")
	}
	return certs[0], nil
}

// Check inspects a single host:port and returns a classified result.
func Check(host string, opts Options) Result {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Dial == nil {
		opts.Dial = DialLeaf
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	h, port, err := splitHostPort(host)
	if err != nil {
		return Result{Host: host, Status: StatusError, Error: err.Error()}
	}

	cert, err := opts.Dial(h, port, opts.Timeout)
	if err != nil {
		return Result{Host: h, Port: port, Status: StatusError, Error: err.Error()}
	}

	days := int(cert.NotAfter.Sub(opts.Now()).Hours() / 24)
	status := classify(days, opts.WarnDays, opts.FailDays)

	return Result{
		Host:     h,
		Port:     port,
		Issuer:   cert.Issuer.CommonName,
		NotAfter: cert.NotAfter.UTC().Format(time.RFC3339),
		Days:     days,
		Status:   status,
	}
}

// CheckAll runs Check over a list of hosts sequentially.
func CheckAll(hosts []string, opts Options) []Result {
	out := make([]Result, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, Check(h, opts))
	}
	return out
}

func classify(days, warn, fail int) Status {
	if days < fail {
		return StatusFail
	}
	if days < warn {
		return StatusWarn
	}
	return StatusOK
}

func splitHostPort(spec string) (string, int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", 0, fmt.Errorf("empty host")
	}
	if !strings.Contains(spec, ":") {
		return spec, 443, nil
	}
	h, p, err := net.SplitHostPort(spec)
	if err != nil {
		return "", 0, err
	}
	var port int
	if _, err := fmt.Sscanf(p, "%d", &port); err != nil {
		return "", 0, fmt.Errorf("bad port %q", p)
	}
	return h, port, nil
}

// ParseHostsString splits comma- and newline-separated host specs.
func ParseHostsString(s string) []string {
	// Replace newlines with commas, then split and trim.
	s = strings.ReplaceAll(s, "\n", ",")
	s = strings.ReplaceAll(s, "\r", ",")
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}
		out = append(out, p)
	}
	return out
}

// ParseHostsFile reads `path` line-by-line, stripping blank and `#`-prefixed lines.
func ParseHostsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseHostsReader(f)
}

func parseHostsReader(r io.Reader) ([]string, error) {
	var hosts []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hosts = append(hosts, line)
	}
	return hosts, sc.Err()
}

// WorstStatus returns the most severe status across a set of results.
func WorstStatus(results []Result) Status {
	worst := StatusOK
	rank := map[Status]int{StatusOK: 0, StatusWarn: 1, StatusFail: 2, StatusError: 3}
	for _, r := range results {
		if rank[r.Status] > rank[worst] {
			worst = r.Status
		}
	}
	return worst
}
