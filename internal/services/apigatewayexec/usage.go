package apigatewayexec

import "context"

// APIKeyIdentity projects the supplied API key and its recognized identifier.
// An optional HEADER method can expose an unknown value without an identifier.
type APIKeyIdentity struct {
	ID, Value string
}

// UsagePlans admits a REST request against the resolved API owner's key state.
// Keys mapped to the stage enforce plan limits, even disabled keys on optional
// methods. Required methods reject missing, disabled or unmapped keys. Accounting commits
// before backend invocation.
type UsagePlans interface {
	AdmitUsage(context.Context, *Route, string) (APIKeyIdentity, error)
}
