package adapters

import (
	"fmt"

	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vald3mare/rudstock-auth/internal/adapters/dummycloak"
	"github.com/vald3mare/rudstock-auth/internal/adapters/dummycloak/tokens"
	"github.com/vald3mare/rudstock-auth/internal/adapters/keycloak"
	"github.com/vald3mare/rudstock-auth/internal/config"
	authRepo "github.com/vald3mare/rudstock-auth/internal/repositories/auth"
	"github.com/vald3mare/rudstock-auth/internal/repositories/session"
	"github.com/vald3mare/rudstock-auth/internal/repositories/user"
)

func NewCloak(pool *pgxpool.Pool, conf *config.Config) (authRepo.Cloak, error) {
	switch conf.KeyCloak {
	case "dummycloak":
		users := user.NewUserRepo(pool)
		sessions := session.NewSessionRepo(pool)
		emitter, err := tokens.NewEmitter([]byte(conf.JWTSecret), conf.JWTIssuer, conf.AccessTTL, conf.RefreshTokenBytes)
		if err != nil {
			return nil, fmt.Errorf("create dummycloak token emitter: %w", err)
		}

		return dummycloak.New(users, sessions, emitter, dummycloak.Config{
			RefreshTTL:    conf.RefreshTTL,
			RefreshMaxTTL: conf.RefreshMaxTTL,
			Argon2: argon2id.Params{
				Memory:      conf.Argon2Memory,
				Iterations:  conf.Argon2Iterations,
				Parallelism: conf.Argon2Parallelism,
				SaltLength:  conf.Argon2SaltLength,
				KeyLength:   conf.Argon2KeyLength,
			},
		})
	case "keycloak":
		return keycloak.New(keycloak.Config{
			BaseURL:      conf.KeycloakURL,
			Realm:        conf.KeycloakRealm,
			ClientID:     conf.KeycloakClientID,
			ClientSecret: conf.KeycloakClientSecret,
		})
	default:
		return nil, fmt.Errorf("unknown auth provider %q", conf.KeyCloak)
	}
}
