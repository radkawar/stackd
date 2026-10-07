// Package elbv2 owns Application Load Balancer control and retained runtime intent.
package elbv2

import (
	"context"
	"errors"
	api "stackd/internal/awsapi/elbv2"
	"time"
)

var ErrNotFound = errors.New("ELBv2 resource not found")

type Scope struct{ Partition, AccountID, Region string }
type LoadBalancerRecord struct {
	Scope
	Ownership             string
	Data                  api.LoadBalancer
	Tags                  api.TagList
	DeletionProtection    bool
	IdleTimeout           time.Duration
	AttachmentIDs         map[string]string
	AttachmentGenerations map[string]uint64
	Deleting              bool
	NextReconcile         time.Time
	NextMetricAt          time.Time
	Version               uint64
}
type TargetGroupRecord struct {
	Scope
	Ownership           string
	Data                api.TargetGroup
	Tags                api.TagList
	DeregistrationDelay time.Duration
}
type ListenerRecord struct {
	Scope
	Ownership     string
	Data          api.Listener
	Tags          api.TagList
	CertificateID string
}
type RuleRecord struct {
	Scope
	Ownership   string
	Data        api.Rule
	ListenerARN string
	Tags        api.TagList
}
type TargetRecord struct {
	Scope
	TargetGroupARN                                    string
	Data                                              api.TargetDescription
	OwnerARN, Incarnation, State, Reason, Description string
	Successes, Failures                               int
	NextCheck, DrainUntil                             time.Time
	Version                                           uint64
}

// Callbacks share the repository transaction with authorization and audit. Native
// networking and socket effects must occur outside these callbacks.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
type Reader interface {
	MetricReader
	Context() context.Context
	LoadBalancer(Scope, string) (LoadBalancerRecord, error)
	LoadBalancers(Scope) ([]LoadBalancerRecord, error)
	TargetGroup(Scope, string) (TargetGroupRecord, error)
	TargetGroups(Scope) ([]TargetGroupRecord, error)
	Listener(Scope, string) (ListenerRecord, error)
	Listeners(Scope) ([]ListenerRecord, error)
	Rule(Scope, string) (RuleRecord, error)
	Rules(Scope) ([]RuleRecord, error)
	Target(Scope, string, string, int32) (TargetRecord, error)
	Targets(Scope, string) ([]TargetRecord, error)
}
type Transaction interface {
	Reader
	MetricWriter
	NextID() (uint64, error)
	PutLoadBalancer(LoadBalancerRecord) error
	DeleteLoadBalancer(Scope, string) error
	PutTargetGroup(TargetGroupRecord) error
	DeleteTargetGroup(Scope, string) error
	PutListener(ListenerRecord) error
	DeleteListener(Scope, string) error
	PutRule(RuleRecord) error
	DeleteRule(Scope, string) error
	PutTarget(TargetRecord) error
	DeleteTarget(Scope, string, string, int32) error
}
