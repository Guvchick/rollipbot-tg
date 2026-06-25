package provider

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// maxBody caps how much of a response body we read (protects against huge/hung
// responses while keeping error bodies useful).
const maxBody = 1 << 20

// DoJSON executes req, returns an *APIError on non-2xx, and decodes the JSON
// body into out when out is non-nil. Shared by all REST adapters.
func DoJSON(client *http.Client, req *http.Request, name string, out any) error {
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: request failed: %w", name, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{Provider: name, StatusCode: resp.StatusCode, Body: string(body)}
	}

	if out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("%s: decode response: %w", name, err)
		}
	}
	return nil
}
