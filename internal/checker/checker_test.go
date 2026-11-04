package checker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseHostsString(t *testing.T) {
	in := "a.com, b.com:8443\n# comment\nc.com\n\nd.com"
	want := []string{"a.com", "b.com:8443", "c.com", "d.com"}
	got := ParseHostsString(in)
	if !eq(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := map[string]struct {
		h string
		p int
	}{
		"example.com":        {"example.com", 443},
		"example.com:8443":   {"example.com", 8443},
		"[::1]:443":          {"::1", 443},
	}
	for in, want := range cases {
		h, p, err := splitHostPort(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if h != want.h || p != want.p {
			t.Errorf("%q = (%s,%d), want (%s,%d)", in, h, p, want.h, want.p)
		}
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		days, warn, fail int
		want             Status
	}{
		{100, 30, 14, StatusOK},
		{20, 30, 14, StatusWarn},
		{5, 30, 14, StatusFail},
		{-1, 30, 14, StatusFail},
	}
	for _, c := range cases {
		if got := classify(c.days, c.warn, c.fail); got != c.want {
			t.Errorf("classify(%d,%d,%d) = %s, want %s", c.days, c.warn, c.fail, got, c.want)
		}
	}
}

func TestCheck_WithInjectedDial(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cert := genCert(t, now.Add(20*24*time.Hour))
	opts := Options{
		WarnDays: 30, FailDays: 14,
		Timeout: time.Second,
		Now:     func() time.Time { return now },
		Dial: func(host string, port int, timeout time.Duration) (*x509.Certificate, error) {
			return cert, nil
		},
	}
	r := Check("example.com", opts)
	if r.Status != StatusWarn {
		t.Fatalf("status = %s, want warn (20 days remaining)", r.Status)
	}
	if r.Days != 20 {
		t.Errorf("days = %d, want 20", r.Days)
	}
}

func TestCheck_DialError(t *testing.T) {
	opts := Options{
		Timeout: time.Second,
		Now:     time.Now,
		Dial: func(string, int, time.Duration) (*x509.Certificate, error) {
			return nil, errFake("boom")
		},
	}
	r := Check("example.com", opts)
	if r.Status != StatusError {
		t.Fatalf("status = %s, want error", r.Status)
	}
}

func TestCheck_LiveTLSServer(t *testing.T) {
	cert, tlsCert := genTLSCert(t, time.Now().Add(5*24*time.Hour))
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{tlsCert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	// Use an insecure dialer so the test-only self-signed cert is accepted.
	insecureDial := func(host string, port int, timeout time.Duration) (*x509.Certificate, error) {
		d := &net.Dialer{Timeout: timeout}
		addr := net.JoinHostPort(host, portStr(port))
		conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		cs := conn.ConnectionState()
		if len(cs.PeerCertificates) == 0 {
			t.Fatal("no peer certs")
		}
		return cs.PeerCertificates[0], nil
	}

	opts := DefaultOptions()
	opts.WarnDays = 30
	opts.FailDays = 14
	opts.Dial = insecureDial
	r := Check("127.0.0.1:"+port, opts)
	if r.Status != StatusFail {
		t.Fatalf("status = %s, want fail (5-day cert)", r.Status)
	}
	if r.Issuer != cert.Issuer.CommonName {
		t.Errorf("issuer = %q, want %q", r.Issuer, cert.Issuer.CommonName)
	}
}

func portStr(p int) string {
	return fmt.Sprintf("%d", p)
}

func TestPostWebhook_TokenAndPayload(t *testing.T) {
	var gotAuth string
	var gotBody WebhookPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	results := []Result{{Host: "a", Status: StatusFail, Days: 1}}
	if err := PostWebhook(srv.URL, "secret-token", results, srv.Client()); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("Authorization = %q, want bearer", gotAuth)
	}
	if gotBody.Worst != StatusFail {
		t.Errorf("worst = %s, want fail", gotBody.Worst)
	}
	if len(gotBody.Results) != 1 || gotBody.Results[0].Host != "a" {
		t.Errorf("results = %+v", gotBody.Results)
	}
}

func TestWriteMarkdown(t *testing.T) {
	var b strings.Builder
	WriteMarkdown(&b, []Result{{Host: "a.com", Port: 443, Issuer: "X", NotAfter: "2027-01-01T00:00:00Z", Days: 60, Status: StatusOK}})
	s := b.String()
	if !strings.Contains(s, "a.com") || !strings.Contains(s, ":white_check_mark:") {
		t.Fatalf("missing content: %s", s)
	}
}

func TestWorstStatus(t *testing.T) {
	cases := []struct {
		in   []Status
		want Status
	}{
		{[]Status{StatusOK, StatusOK}, StatusOK},
		{[]Status{StatusOK, StatusWarn}, StatusWarn},
		{[]Status{StatusWarn, StatusFail}, StatusFail},
		{[]Status{StatusFail, StatusError}, StatusError},
	}
	for _, c := range cases {
		var rs []Result
		for _, s := range c.in {
			rs = append(rs, Result{Status: s})
		}
		if got := WorstStatus(rs); got != c.want {
			t.Errorf("WorstStatus(%v) = %s, want %s", c.in, got, c.want)
		}
	}
}

// --- helpers ---

func genCert(t *testing.T, notAfter time.Time) *x509.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		NotBefore:    notAfter.Add(-30 * 24 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"example.com", "127.0.0.1"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	c, _ := x509.ParseCertificate(der)
	return c
}

func genTLSCert(t *testing.T, notAfter time.Time) (*x509.Certificate, tls.Certificate) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	c, _ := x509.ParseCertificate(der)
	tlsCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k, Leaf: c}

	// Make our DialLeaf accept this self-signed cert for this one test by
	// swapping the system verify out — easiest is to disable server verify
	// in the dialer used by Check. We do that in a dedicated test wrapper.
	return c, tlsCert
}

type errFake string

func (e errFake) Error() string { return string(e) }

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
