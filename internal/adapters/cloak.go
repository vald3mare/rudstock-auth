package adapters

import (
	"context"
	"fmt"

	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vald3mare/rudstock-auth/internal/adapters/dummycloak"
	"github.com/vald3mare/rudstock-auth/internal/adapters/dummycloak/tokens"
	"github.com/vald3mare/rudstock-auth/internal/adapters/keycloak"
	"github.com/vald3mare/rudstock-auth/internal/config"
	"github.com/vald3mare/rudstock-auth/internal/models"
	"github.com/vald3mare/rudstock-auth/internal/repositories/session"
	"github.com/vald3mare/rudstock-auth/internal/repositories/user"
)

type Cloak interface {
	Register(ctx context.Context, email, password string) (user models.User, tokens models.Tokens, err error)
	Login(ctx context.Context, email, password string) (user models.User, tokens models.Tokens, err error)
	Logout(ctx context.Context, refresh string) error
	Refresh(ctx context.Context, refresh string) (models.Tokens, error)
	CheckExpire(ctx context.Context, access string) (models.Identity, error)
}

func NewCloak(pool *pgxpool.Pool, conf *config.Config) (Cloak, error) {
	switch conf.KeyCloak {
	case config.ProviderDummycloak:
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
	case config.ProviderKeycloak:
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
