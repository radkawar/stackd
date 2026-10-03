// Package opensearch owns OpenSearch and legacy ES domain identity and controls.
package opensearch

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("opensearch domain not found")

type Scope struct{ Partition, AccountID, Region string }
type Key struct {
	Scope
	Name string
}

func (k Key) ARN() string {
	return "arn:" + k.Partition + ":es:" + k.Region + ":" + k.AccountID + ":domain/" + k.Name
}

// Domain is typed control intent. Native indices and documents live only in the
// engine volume. Incarnation and Version fence work and stale public endpoints.
type Domain struct {
	Key                                                           Key
	Incarnation, EngineVersion, Status, NativeEndpoint, LastError string
	AccessPolicy                                                  string
	InstanceType                                                  string
	InstanceCount                                                 int32
	AdvancedOptions                                               map[string]string
	PolicyPrincipals                                              map[string]string
	Tags                                                          map[string]string
	Created, Updated, Due                                         time.Time
	Version, ConfigVersion                                        int64
}

type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
type Reader interface {
	Context() context.Context
	Domain(Key) (Domain, error)
	Domains(Scope) ([]Domain, error)
	AllDomains() ([]Domain, error)
}
type Transaction interface {
	Reader
	PutDomain(Domain) error
	DeleteDomain(Key) error
}

// NativeSpecification contains no customer document bytes or ambient identity.
// ID is a fresh immutable incarnation, never a reusable customer domain name.
type NativeSpecification struct {
	ID, EngineVersion string
	AdvancedOptions   map[string]string
}
type NativeStatistics struct {
	Nodes, Documents, StoreBytes int64
	JVMPercent                   float64
	Health                       string
}

// Runtime is the consumer-owned native boundary. Ensure returns only after an
// actual OpenSearch protocol readiness response. Close detaches; Delete removes
// precisely owned process and data. Endpoints are private controller targets.
type Runtime interface {
	Ensure(context.Context, NativeSpecification) (string, error)
	Delete(context.Context, string) error
	Statistics(context.Context, NativeSpecification) (NativeStatistics, error)
	Close() error
}

type Metric struct {
	Domain Key
	Name   string
	Value  float64
	At     time.Time
}
type MetricPublisher interface {
	PublishOpenSearchMetric(context.Context, Metric) error
}
