package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/vald3mare/rudstock-auth/internal/models"
)

func (e *responseError) Error() string {
	return fmt.Sprintf("Keycloak returned HTTP %d", e.status)
}

func hasErrorCode(err error, code string) bool {
	var response *responseError
	return errors.As(err, &response) && response.Code == code
}

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

func (a *keycloack) postForm(ctx context.Context, endpoint string, form url.Values, result any) error {
	form.Set("client_id", a.clientID)
	form.Set("client_secret", a.clientSecret)
	return a.postRequest(ctx, a.issuer+"/protocol/openid-connect/"+endpoint,
		"application/x-www-form-urlencoded", "", strings.NewReader(form.Encode()), result)
}

func (a *keycloack) requestTokens(ctx context.Context, form url.Values) (models.Tokens, error) {
	var result tokenResponse
	if err := a.postForm(ctx, "token", form, &result); err != nil {
		return models.Tokens{}, err
	}
	if result.Access == "" || result.Refresh == "" {
		return models.Tokens{}, errors.New("Keycloak did not return an access and refresh token pair")
	}
	return models.Tokens{Access: result.Access, Refresh: result.Refresh}, nil
}
