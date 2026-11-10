package keycloak

import (
	"errors"
	"net/url"
	"strings"
)

func (conf Config) validate() (*url.URL, error) {
	base, err := url.Parse(conf.BaseURL)
	if err != nil {
		return nil, errors.New("could not parse Keycloak base URL")
	}
	if (base.Scheme != "https" && base.Scheme != "http") || base.Hostname() == "" ||
		base.User != nil || base.ForceQuery || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("Keycloak base URL must be an HTTP(S) URL without credentials, a query, or a fragment")
	}
	if conf.Realm == "" || conf.Realm == "." || conf.Realm == ".." ||
		strings.ContainsAny(conf.Realm, "/\\") {
		return nil, errors.New("invalid Keycloak realm")
	}
	if conf.ClientID == "" || conf.ClientSecret == "" {
		return nil, errors.New("Keycloak client ID and client secret are required")
	}
	return base, nil
}
