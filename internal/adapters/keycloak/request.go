package keycloak

import (
	"encoding/json"
	"io"
	"net/http"
)

const maxResponseBody = 1 << 20

func (a *keycloack) send(req *http.Request) (*http.Response, error) {
	res, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		return res, nil
	}
	defer res.Body.Close()

	response := &responseError{status: res.StatusCode}
	_ = json.NewDecoder(io.LimitReader(res.Body, maxResponseBody)).Decode(response)
	return nil, response
}

func decodeJSON[T any](res *http.Response) (T, error) {
	defer res.Body.Close()

	var result T
	err := json.NewDecoder(io.LimitReader(res.Body, maxResponseBody)).Decode(&result)
	return result, err
}
