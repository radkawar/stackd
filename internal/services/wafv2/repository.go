// Package wafv2 owns regional AWS WAF web ACLs, IP sets, resource associations
// and the request inspection applied by associated API Gateway REST stages.
package wafv2

import (
	"context"
	"errors"
	"time"

	metricsapi "stackd/internal/awsapi/cloudwatch"
	api "stackd/internal/awsapi/wafv2"
)

var ErrNotFound = errors.New("WAFv2 resource not found")

type Scope struct{ Partition, AccountID, Region string }

// Definition is the validated web ACL configuration in the authoritative AWS
// model shape. Only configuration whose request effects are implemented is
// admitted; ARN, capacity and label namespace are derived, never stored here.
type Definition struct {
	DefaultAction        api.DefaultAction        `json:"DefaultAction"`
	Rules                api.Rules                `json:"Rules,omitempty"`
	VisibilityConfig     api.VisibilityConfig     `json:"VisibilityConfig"`
	CustomResponseBodies api.CustomResponseBodies `json:"CustomResponseBodies,omitempty"`
	AssociationConfig    *api.AssociationConfig   `json:"AssociationConfig,omitempty"`
}

type WebACL struct {
	Scope
	Name, ID, ARN, Description, LockToken string
	Definition                            Definition
	Capacity                              int64
	Created, Updated                      time.Time
	Tags                                  map[string]string
	Owner                                 ResourceOwner
}

type IPSet struct {
	Scope
	Name, ID, ARN, Description, LockToken string
	IPAddressVersion                      string
	Addresses                             []string
	Created, Updated                      time.Time
	Tags                                  map[string]string
	Owner                                 ResourceOwner
}

// AssociationOwner identifies a trusted in-process owner of one association.
// The zero value denotes a natively created association.
type AssociationOwner struct{ StackID, LogicalID, Token string }

// Association binds one protected resource incarnation to one web ACL. A
// protected resource recreated under the same ARN is a different incarnation
// and is not protected by a retained association.
type Association struct {
	Scope
	ResourceARN, WebACLARN string
	ResourceIncarnation    string
	Owner                  AssociationOwner
	Created                time.Time
}

// MetricKey owns one AWS/WAFV2 dimension set {Region, Rule, WebACL} for one
// UTC minute. Pending observations survive web ACL deletion.
type MetricKey struct {
	Scope
	WebACL, Rule string
	Minute       time.Time
}

type MetricSample struct {
	Name  string
	Count int64
}

// SampledRequest is a retained request observation for GetSampledRequests.
type SampledRequest struct {
	Scope
	WebACLARN, MetricName string
	At                    time.Time
	Sequence              int64
	Sample                api.SampledHTTPRequest
}

type Reader interface {
	Context() context.Context
	WebACL(Scope, string) (WebACL, error) // by ARN
	WebACLs(Scope) ([]WebACL, error)
	IPSet(Scope, string) (IPSet, error) // by ARN
	IPSets(Scope) ([]IPSet, error)
	Association(Scope, string) (Association, error)    // by resource ARN
	Associations(Scope, string) ([]Association, error) // by web ACL ARN
	NextMetricPublication() (MetricKey, error)
	MetricSamples(MetricKey) ([]MetricSample, error)
	SampledRequests(Scope, string, string, time.Time, time.Time, int) ([]SampledRequest, error)
	SamplePopulation(Scope, string, string, time.Time, time.Time) (int64, error)
	SampleCount(Scope, string, string, time.Time) (int64, error)
}

type Transaction interface {
	Reader
	PutWebACL(WebACL) error
	DeleteWebACL(Scope, string) error
	PutIPSet(IPSet) error
	DeleteIPSet(Scope, string) error
	PutAssociation(Association) error
	DeleteAssociation(Scope, string) error
	AddMetricSample(MetricKey, MetricSample) error
	DeleteMetricPublication(MetricKey) error
	PutSampledRequest(SampledRequest) error
	AddSamplePopulation(Scope, string, string, time.Time, int64) error
	PruneSamples(time.Time) error
}

type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}

// ProtectedResources resolves the current opaque private incarnation of a
// protected resource from its owning service. The identity must change on
// every creation, even when the service clock has not advanced. Missing
// resources return ErrNotFound.
type ProtectedResources interface {
	RESTStageIncarnation(ctx context.Context, scope Scope, apiID, stage string) (string, error)
}

// MetricPublisher publishes service-owned AWS/WAFV2 observations; it does not
// borrow the customer's cloudwatch:PutMetricData permission.
type MetricPublisher interface {
	Publish(context.Context, string, []metricsapi.MetricDatum) error
}
