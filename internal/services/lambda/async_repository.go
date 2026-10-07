package lambda

import (
	"strings"
	"time"

	"stackd/internal/scheduler"
)

// EventInvokeConfig separates API-visible options from applied queue settings.
// Deleted hides a pending reset from the API; omission still uses service defaults.
type EventInvokeConfig struct {
	Key                        FunctionReference
	Owner                      AdditionalOwner
	Modified                   time.Time
	MaxAgeSeconds, MaxRetries  int
	HasMaxAge, HasMaxRetries   bool
	OnSuccessARN, OnFailureARN string
	Effective                  EventInvokeSettings
	AppliesAt                  *time.Time
	Version                    uint64
	Deleted                    bool
}

// EventInvokeSettings contains resolved values used by asynchronous workers.
type EventInvokeSettings struct {
	MaxAgeSeconds, MaxRetries  int
	OnSuccessARN, OnFailureARN string
}

// InvocationRecord owns acceptance, retries and the terminal result. Attempts
// refresh applied controls and delivery authority while the target exists; their
// last values survive target deletion so accepted failures still have an owner.
// ResponseStatus is zero until a runtime or modeled pre-execution response exists.
type InvocationRecord struct {
	ID                        string
	Key                       FunctionKey
	FunctionARN               string
	Payload                   []byte
	RequestID, ParentEventID  string
	TraceHeader               string
	Accepted, Due             time.Time
	Version                   uint64
	State                     string
	InvokeCount, SystemErrors int
	ResponsePayload           []byte
	ResponseError             string
	ResponseStatus            int
	ResponseVersion           string
	Completed                 time.Time
	Completion, RoleARN       string
	Settings                  EventInvokeSettings
	// Whole-function deletion detaches applied queue controls, not runtime identity.
	// Explicitly applied replacement configuration reattaches these controls.
	SettingsDetached bool
	DeadLetterARN    string
}

// Reference retains the requested alias/version independently of each attempt's
// resolved deployment. FunctionARN was parsed at durable admission.
func (v InvocationRecord) Reference() FunctionReference {
	_, resource, _ := strings.Cut(v.FunctionARN, ":function:")
	_, qualifier, _ := strings.Cut(resource, ":")
	return FunctionReference{FunctionKey: v.Key, Qualifier: qualifier}
}

type AsyncReader interface {
	EventInvokeConfig(FunctionReference) (EventInvokeConfig, error)
	EventInvokeConfigs(FunctionKey) ([]EventInvokeConfig, error)
	NextEventInvokeConfigChange() (scheduler.Job, bool, error)
	Invocation(string) (InvocationRecord, error)
	NextInvocation() (scheduler.Job, bool, error)
	InFlightInvocations() ([]InvocationRecord, error)
}
type AsyncWriter interface {
	PutEventInvokeConfig(EventInvokeConfig) error
	DeleteEventInvokeConfig(FunctionReference) error
	PutInvocation(InvocationRecord) error
	DeleteInvocation(string) error
	ReattachInvocationSettings(FunctionReference) error
}

func defaultEventInvokeSettings() EventInvokeSettings {
	return EventInvokeSettings{MaxAgeSeconds: 21600, MaxRetries: 2}
}

func configuredEventInvokeSettings(v EventInvokeConfig) EventInvokeSettings {
	out := defaultEventInvokeSettings()
	if !v.Deleted {
		if v.HasMaxAge {
			out.MaxAgeSeconds = v.MaxAgeSeconds
		}
		if v.HasMaxRetries {
			out.MaxRetries = v.MaxRetries
		}
		out.OnSuccessARN, out.OnFailureARN = v.OnSuccessARN, v.OnFailureARN
	}
	return out
}

func effectiveEventInvokeConfig(r Reader, key FunctionReference) (EventInvokeSettings, error) {
	v, err := r.EventInvokeConfig(key)
	if err == ErrNotFound {
		return defaultEventInvokeSettings(), nil
	}
	return v.Effective, err
}
