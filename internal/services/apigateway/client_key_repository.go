package apigateway

import "time"

// ClientKey identifies a usage-plan API key, independently of any REST API.
// APIKey identifies the REST API itself.
type ClientKey struct {
	Scope
	ID string
}

type ClientKeyRecord struct {
	Key                           ClientKey
	Name, Description, CustomerID *string
	Value                         string
	Enabled                       bool
	Created, Updated              time.Time
	Tags                          map[string]string
	StageKeys                     []StageKey
}
