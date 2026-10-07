// Package awsctx carries immutable AWS request identity and routing metadata.
package awsctx

import (
	"context"
	"maps"
	"slices"
	"time"

	"stackd/journal"
)

// Metadata describes the request's local AWS scope. Global services deliberately
// ignore Region when choosing their resource store.
type Metadata struct {
	AccountID     string
	Region        string
	Partition     string
	AccessKeyID   string
	RequestID     string
	ParentEventID string
	// TraceHeader is AWS X-Ray request metadata, not an authorization or causal ID.
	// Services own its validation, precedence and downstream propagation.
	TraceHeader       string
	PrincipalARN      string
	PrincipalID       string
	UserName          string
	SessionType       string
	IssuerARN         string
	IssuerID          string
	SessionPolicies   []string
	SessionPolicyARNs []string
	HasSessionPolicy  bool
	// SessionContext contains authenticated federation or service-issued source claims.
	SessionContext     map[string][]string
	FederatedProvider  string
	SessionTags        map[string]string
	TransitiveTagKeys  []string
	SourceIdentity     string
	MFAPresent         bool
	MFAAuthenticatedAt time.Time
	TokenIssueTime     time.Time
	// CalledVia is the ordered chain of services using the original caller
	// credentials. Only internal service adapters add hops.
	CalledVia []string
	// TransportKnown distinguishes an observed HTTP connection from internal
	// calls that have only identity metadata. SourceIP never trusts proxy headers.
	TransportKnown  bool
	SourceIP        string
	SecureTransport bool
	UserAgent       string
	// These describe the verified public signature, not an internal service hop.
	SignatureVersion     string
	AuthenticationMethod string
	// ServicePrincipal is set by internal delivery adapters, never HTTP auth.
	ServicePrincipal ServicePrincipal
	// InvokedBy supplies the audit service origin without changing the
	// authenticated principal or CalledVia authorization chain.
	// Only internal service adapters set this field.
	InvokedBy string
	// InScopeOf is public audit scope supplied by internal EC2 identity
	// authorities, never inferred from an ARN or accepted from HTTP.
	InScopeOf journal.APIIdentityScope
	// EndpointRegionImplicit marks an unsigned public request whose endpoint
	// carries no region. Region is then the configured default, and an owner
	// may resolve a bearer identifier (such as a Cognito app client) partition-wide.
	EndpointRegionImplicit bool
}

// ServicePrincipal describes an AWS service, optionally acting for a source resource.
// An absent SourceARN omits source-resource condition keys rather than inventing them.
// Type is the observed IAM condition value, which can differ from CloudTrail's
// identity type (EventBridge SQS delivery uses User, for example).
type ServicePrincipal struct {
	Name, SourceARN, Type string
	// Aliases are additional verified policy identities of this service instance.
	// Name remains the canonical audit identity and aws:PrincipalServiceName.
	// Only trusted internal adapters may supply aliases.
	Aliases []string
}

type contextKey struct{}

func WithMetadata(ctx context.Context, metadata Metadata) context.Context {
	return context.WithValue(ctx, contextKey{}, Clone(metadata))
}

func FromContext(ctx context.Context) Metadata {
	metadata, _ := ctx.Value(contextKey{}).(Metadata)
	return Clone(metadata)
}

// Clone returns a detached caller snapshot, including all session collections.
func Clone(m Metadata) Metadata {
	m.CalledVia = slices.Clone(m.CalledVia)
	m.ServicePrincipal.Aliases = slices.Clone(m.ServicePrincipal.Aliases)
	m.SessionPolicies = slices.Clone(m.SessionPolicies)
	m.SessionPolicyARNs = slices.Clone(m.SessionPolicyARNs)
	m.SessionContext = cloneSessionContext(m.SessionContext)
	m.SessionTags = maps.Clone(m.SessionTags)
	m.TransitiveTagKeys = slices.Clone(m.TransitiveTagKeys)
	return m
}

func cloneSessionContext(values map[string][]string) map[string][]string {
	if values == nil {
		return nil
	}
	result := make(map[string][]string, len(values))
	for key, value := range values {
		result[key] = slices.Clone(value)
	}
	return result
}

// WithViaService forwards the authenticated caller through a service principal.
// The IAM/STS identity and public endpoint transport context remain unchanged.
func WithViaService(ctx context.Context, principal string) context.Context {
	m := FromContext(ctx)
	m.CalledVia = append(m.CalledVia, principal)
	return WithMetadata(ctx, m)
}

// WithServicePrincipal starts a service request in the current routing scope.
// The originating user's credentials, session and network attributes do not
// authenticate the service's delivery.
func WithServicePrincipal(ctx context.Context, principal ServicePrincipal) context.Context {
	m := FromContext(ctx)
	return WithMetadata(ctx, Metadata{AccountID: m.AccountID, Region: m.Region,
		Partition: m.Partition, RequestID: m.RequestID, ParentEventID: m.ParentEventID, ServicePrincipal: principal})
}
