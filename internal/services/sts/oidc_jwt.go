package sts

import (
	"errors"

	"stackd/internal/awswire"
	"stackd/internal/jwt"
)

func invalidOIDCToken(message string) *awswire.Error {
	return &awswire.Error{Code: "InvalidIdentityToken", StatusCode: 400, Message: message}
}
func oidcProviderError(message string) *awswire.Error {
	return &awswire.Error{Code: "IDPCommunicationError", StatusCode: 400, Message: message}
}

func parseOIDCJWT(raw string) (jwt.Token, *awswire.Error) {
	token, err := jwt.Parse(raw, func(algorithm string) bool {
		_, ok := oidcAlgorithms[algorithm]
		return ok
	})
	if errors.Is(err, jwt.ErrAlgorithm) {
		return jwt.Token{}, invalidOIDCToken("The token's signing algorithm is not supported.")
	}
	if err != nil {
		return jwt.Token{}, invalidOIDCToken("The web identity token is not a valid signed JWT.")
	}
	return token, nil
}
