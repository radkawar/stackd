// Package apievents supplies common identity and origin handling for committed
// API outcomes. Services retain command transactions and native event projections.
package apievents

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"stackd/internal/awsctx"
	"stackd/journal"
)

// Recorder completes public caller metadata and appends the outcome. It joins
// ctx's native write transaction; without one the sink owns the audit transaction.
// The source supplies resource-owner scope and completion time. Successful
// mutations must abort if Record fails. Read-only and rejected calls record after
// their resource transaction has closed, never through a borrowed read context.
// A source may reserve EventID before invoking another service so independently
// committed child calls can reference their originating API outcome.
// A source-supplied identity takes precedence for native federation and
// cross-account recipient records; it must contain only verified public fields.
type Recorder interface {
	Record(context.Context, journal.Envelope, journal.APICallCompleted) error
}

// Sink participates in the source's native transaction. It does not perform
// external delivery or publish records before that transaction commits.
type Sink interface {
	AppendAPICallCompleted(context.Context, journal.Envelope, journal.APICallCompleted) error
}

type recorder struct{ sink Sink }

// New connects shared completion handling to the instance journal. A nil sink
// leaves recording disabled for standalone consumers.
func New(sink Sink) Recorder {
	if sink == nil {
		return nil
	}
	return recorder{sink: sink}
}

type eventIDKey struct{}

// Reserve gives one API call a fresh outcome identity before it invokes child
// services. It always replaces an inherited reservation. The owner explicitly
// assigns EventID(ctx) to its outcome; child recorders do not inherit it.
func Reserve(ctx context.Context) (context.Context, error) {
	id, err := newEventID()
	if err != nil {
		return nil, err
	}
	return context.WithValue(ctx, eventIDKey{}, id), nil
}

// EventID returns the identity reserved by the current API call, or empty.
func EventID(ctx context.Context) string {
	id, _ := ctx.Value(eventIDKey{}).(string)
	return id
}

func newEventID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	h := hex.EncodeToString(id[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// CompletionContext gives a finished source call bounded time to record its
// outcome even if its caller disconnected. Pass the original request context,
// only after the command's resource transactions have closed, never a borrowed
// transaction context. Context values retain verified identity and causal origin;
// successful mutation recording must instead use its original native transaction.
func CompletionContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
}

// WithOrigin combines trusted request/causal identity with the source's resource
// scope and service instant. Service principals remain distinct from actor ARNs.
// It is shared by API outcomes, EventBridge acceptance and SQS message commits.
func WithOrigin(ctx context.Context, scope journal.Envelope) journal.Envelope {
	m := awsctx.FromContext(ctx)
	scope.At = scope.At.UTC()
	scope.RequestID = m.RequestID
	scope.ParentEventID = m.ParentEventID
	scope.ActorARN = m.PrincipalARN
	scope.ActorService = m.ServicePrincipal.Name
	if scope.ActorService == "" {
		scope.ActorService = m.InvokedBy
	}
	return scope
}

func (r recorder) Record(ctx context.Context, scope journal.Envelope, call journal.APICallCompleted) error {
	m := awsctx.FromContext(ctx)
	origin := WithOrigin(ctx, scope)
	if call.ServiceEvent {
		call.Identity = journal.APIIdentity{AccountID: scope.AccountID}
		call.SourceIPAddress, call.UserAgent = call.EventSource, call.EventSource
		origin.ActorARN, origin.ActorService = "", call.EventSource
		origin.ParentEventID = EventID(ctx)
		var err error
		origin.RequestID, err = newEventID()
		if err != nil {
			return err
		}
	} else {
		if call.Identity.Type == "" {
			call.Identity = publicIdentity(m)
		}
		call.SourceIPAddress, call.UserAgent = m.SourceIP, m.UserAgent
	}
	if call.EventID == "" {
		var err error
		call.EventID, err = newEventID()
		if err != nil {
			return err
		}
	}
	return r.sink.AppendAPICallCompleted(ctx, origin, call)
}

func publicIdentity(m awsctx.Metadata) journal.APIIdentity {
	id := journal.APIIdentity{Type: "IAMUser", PrincipalID: m.PrincipalID, AccountID: m.AccountID, AccessKeyID: m.AccessKeyID, UserName: m.UserName, SessionCreatedAt: m.TokenIssueTime, MFAAuthenticated: m.MFAPresent, SourceIdentity: m.SourceIdentity}
	id.InScopeOf = m.InScopeOf
	if values := m.SessionContext["ec2:roledelivery"]; len(values) == 1 {
		id.EC2RoleDelivery = values[0]
	}
	switch {
	case m.ServicePrincipal.Name != "":
		id.Type = "AWSService"
	case strings.HasSuffix(m.PrincipalARN, ":root"):
		// TODO: Comeback include configured account aliases in root audit identities and root federation issuers.
		id.Type, id.UserName = "Root", "root"
	case strings.Contains(m.PrincipalARN, ":assumed-role/"):
		id.Type = "AssumedRole"
		id.UserName = m.PrincipalARN[strings.LastIndex(m.PrincipalARN, "/")+1:]
		id.IssuerID, id.IssuerARN = m.IssuerID, m.IssuerARN
		id.IssuerUserName = m.IssuerARN[strings.LastIndex(m.IssuerARN, "/")+1:]
	case strings.Contains(m.PrincipalARN, ":federated-user/"):
		id.Type = "FederatedUser"
		id.UserName = m.PrincipalARN[strings.LastIndex(m.PrincipalARN, "/")+1:]
		id.IssuerID, id.IssuerARN = m.IssuerID, m.IssuerARN
		if !strings.HasSuffix(m.IssuerARN, ":root") {
			id.IssuerUserName = m.IssuerARN[strings.LastIndex(m.IssuerARN, "/")+1:]
		}
	}
	return id
}
