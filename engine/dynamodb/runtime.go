// Package dynamodb defines the external engine boundary used by the DynamoDB
// control plane. Tables sharing a database can participate in native atomic
// transactions. AWS identity, table names, policy and service time belong to Go.
package dynamodb

import "context"

// Runtime prepares or reopens an owned regional database. Open succeeds only
// after a real DynamoDB API request succeeds; process creation is not readiness.
// Remove destroys the database, including partially prepared resources.
type Runtime interface {
	Open(context.Context, Specification) (Database, error)
	Remove(context.Context, Specification) error
}

// Specification is retained by the control plane. ID identifies one database
// independently of table names and client credentials, across process restarts.
// All tables in a transaction must belong to this same account and region.
type Specification struct {
	ID                           string
	Partition, AccountID, Region string
}

// Database carries actual DynamoDB and Streams protocol calls. Target is the
// complete AWS JSON target, not an HTTP URL. Calls run outside repository
// transactions. Close detaches this process without destroying retained data;
// Runtime.Remove owns destruction.
type Database interface {
	Request(context.Context, string, []byte) (Response, error)
	Close() error
}

// Response preserves modeled AWS errors and their HTTP status alongside success
// documents. Engine transport and process failures are returned as Go errors.
type Response struct {
	StatusCode int
	Body       []byte
}
