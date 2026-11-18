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
	if (base.Scheme != "https" && base.Scheme != "http") || base.Hostname() == "" {
		return nil, errors.New("Keycloak base URL must use http or https and include a host")
	}
	if base.User != nil {
		return nil, errors.New("Keycloak base URL must not include user info")
	}
	if base.ForceQuery || base.RawQuery != "" {
		return nil, errors.New("Keycloak base URL must not include a query")
	}
	if base.Fragment != "" {
		return nil, errors.New("Keycloak base URL must not include a fragment")
	}

	switch conf.Realm {
	case "", ".", "..":
		return nil, errors.New("invalid Keycloak realm")
	}
	if strings.ContainsAny(conf.Realm, "/\\") {
		return nil, errors.New("Keycloak realm must be a single path segment")
	}
	if conf.ClientID == "" {
		return nil, errors.New("Keycloak client ID is required")
	}
	if conf.ClientSecret == "" {
		return nil, errors.New("Keycloak client secret is required")
	}
	return base, nil
}
