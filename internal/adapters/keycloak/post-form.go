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

// резалт убрать в возврат
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

func (a *keycloack) postFormClientCrenedtials(ctx context.Context) (result any, err error) {
	credentials := url.Values{
		clientIDKey:     {a.clientID},
		clientSecretKey: {a.clientSecret},
		grantTypeKey: {a.grantTypeClientCredentials}
	}
	//body := credentials.Encode()


	//tokenEndpoint, url.Values{grantTypeKey: {grantTypeClientCredentials}}.Encode(), &admin); err != nil {
	//	return models.User{}, models.Tokens{}, fmt.Errorf("get Keycloak service account token: %w", err)


	// return a.postRequest(ctx, a.issuer+"/protocol/openid-connect/"+endpoint,
	// 	"application/x-www-form-urlencoded", "", strings.NewReader(body), result)
	return nil, nil
}
