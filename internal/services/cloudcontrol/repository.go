// Package cloudcontrol owns asynchronous resource requests over CloudFormation's
// owner-backed resource adapters. Resource state remains in each service owner.
package cloudcontrol

import (
	"context"
	"errors"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
)

var ErrNotFound = errors.New("cloudcontrol request not found")

type Scope = cloudformation.Scope

// RequestRecord is retained execution intent and progress, never a resource
// database. Before and Desired are immutable admitted update inputs; Model is a
// historical progress projection. GetResource always reads the service owner.
type RequestRecord struct {
	Scope                                                      Scope
	Token, ClientToken, RequestHash                            string
	TypeName, Identifier, Operation, Status, Phase             string
	RoleARN, Desired, Before, Patch, Model, ErrorCode, Message string
	Caller                                                     awsctx.Metadata
	Created, EventTime, Due                                    time.Time
	Revision                                                   uint64
}

type Reader interface {
	Context() context.Context
	Request(string) (RequestRecord, error)
	Requests(Scope) ([]RequestRecord, error)
	NextRequest() (RequestRecord, bool, error)
}
type Transaction interface {
	Reader
	PutRequest(RequestRecord) error
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
}
