// Package extension defines the versioned API for registering AWS service providers.
package extension

import (
	"context"
	"net/http"

	"stackd/internal/awsctx"
)

const APIVersion = 1

type Protocol string

const (
	Query  Protocol = "query"
	JSON10 Protocol = "json1.0"
	JSON11 Protocol = "json1.1"
)

// Service registers a provider for an otherwise unregistered AWS signing name.
// Its handler receives authenticated requests with AWS scope in their context.
// The caller must finish configuring the handler before creating the emulator.
type Service struct {
	APIVersion   int
	Name         string
	SigningName  string
	Protocol     Protocol
	QueryVersion string
	Namespace    string
	TargetPrefix string
	Operations   []string
	Handler      http.Handler
}

// Scope is the AWS scope available to extension handlers. No secret credentials
// or mutable internal service state are exposed through the extension API.
type Scope struct {
	AccountID    string
	Region       string
	Partition    string
	RequestID    string
	PrincipalARN string
	PrincipalID  string
}

func RequestScope(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{AccountID: m.AccountID, Region: m.Region, Partition: m.Partition, RequestID: m.RequestID, PrincipalARN: m.PrincipalARN, PrincipalID: m.PrincipalID}
}
