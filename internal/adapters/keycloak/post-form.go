package keycloak

import (
	"context"
	"net/url"
	"strings"
)

const (
	clientIDKey     = "client_id"
	clientSecretKey = "client_secret"
)

func (a *keycloack) postForm(ctx context.Context, endpoint string, encodedForm string, result any) error {
	credentials := url.Values{
		clientIDKey:     {a.clientID},
		clientSecretKey: {a.clientSecret},
	}
	body := credentials.Encode()
	if encodedForm != "" {
		body += "&" + encodedForm
	}
	return a.postRequest(ctx, a.issuer+"/protocol/openid-connect/"+endpoint,
		"application/x-www-form-urlencoded", "", strings.NewReader(body), result)
}
