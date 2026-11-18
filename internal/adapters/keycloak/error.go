package keycloak

import (
	"errors"
	"fmt"
)

func (e *responseError) Error() string {
	return fmt.Sprintf("Keycloak returned HTTP %d", e.status)
}

func hasErrorCode(err error, code string) bool {
	var response *responseError
	return errors.As(err, &response) && response.Code == code
}
