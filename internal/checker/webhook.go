package checker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// WebhookPayload is the JSON body POSTed to a webhook endpoint.
type WebhookPayload struct {
	GeneratedAt string   `json:"generatedAt"`
	Worst       Status   `json:"worst"`
	Results     []Result `json:"results"`
}

// PostWebhook POSTs the JSON summary to url, optionally including a bearer token.
// The token is never logged — this function returns transport errors only.
// httpClient may be nil; in that case a default client with a 10s timeout is used.
func PostWebhook(url, bearer string, results []Result, httpClient *http.Client) error {
	if url == "" {
		return nil
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	body := WebhookPayload{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Worst:       WorstStatus(results),
		Results:     results,
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tigertrust/cert-expiry-action")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}
