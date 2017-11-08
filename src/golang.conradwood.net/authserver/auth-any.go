package main

// TODO: how/when do we close database connections? (pooling?)

import (
	"golang.conradwood.net/auth"
)

type AnyAuthenticator struct {
	auth.Authenticator
}

func (pga *AnyAuthenticator) Authenticate(token string) (string, error) {
	return "1", nil
}