// Package route53 owns hosted zones and authoritative DNS records.
package route53

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("Route53 resource not found")

// Route53 control resources are global within a partition and account.
type Scope struct{ Partition, AccountID string }
type AliasTarget struct{ HostedZoneID, DNSName string }
type RecordSet struct {
	Name, Type, Identifier string
	TTL                    int64
	Values                 []string
	Weighted               bool
	Weight                 int64
	MultiValue             bool
	Alias                  *AliasTarget
	// Owner is an internal CloudFormation incarnation claim, absent from the public API.
	Owner string
}
type Zone struct {
	Scope
	ID, Name, CallerReference, Comment string
	Created                            time.Time
	Records                            []RecordSet
}
type Change struct {
	Scope
	ID, ZoneID, Comment string
	Submitted, Ready    time.Time
}
type Reader interface {
	Context() context.Context
	Zone(string) (Zone, error)
	Zones() ([]Zone, error)
	Change(string) (Change, error)
}
type Transaction interface {
	Reader
	PutZone(Zone) error
	DeleteZone(string) error
	PutChange(Change) error
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
