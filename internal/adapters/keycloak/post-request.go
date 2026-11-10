package keycloak

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
)

func (a *keycloack) postRequest(ctx context.Context, endpoint, contentType, bearer string, body io.Reader, result any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	decoder := json.NewDecoder(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		response := &responseError{status: res.StatusCode}
		_ = decoder.Decode(response)
		return response
	}
	if result == nil {
		return nil
	}
	return decoder.Decode(result)
}
