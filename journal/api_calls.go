package journal

import (
	"encoding/json"
	"slices"
	"time"
)

// APICallCategory distinguishes API management activity from data-plane calls.
// Sources own classification; an absent category is not management activity.
type APICallCategory string

const (
	CategoryManagement APICallCategory = "Management"
	CategoryData       APICallCategory = "Data"
)

// APICallEventType is the native CloudTrail type when a documented service
// uses neither AwsApiCall nor AwsServiceEvent. Empty preserves those defaults.
type APICallEventType string

const EventTypeRDSData APICallEventType = "Rds Data Service"

// APICallCompleted is a sanitized API outcome. Successful mutations
// append it in their resource transaction. Rejected calls append separately,
// after the failed resource transaction has rolled back.
type APICallCompleted struct {
	EventID           string           `json:"event_id"`
	SharedEventID     string           `json:"shared_event_id,omitempty"`
	EventSource       string           `json:"event_source"`
	EventName         string           `json:"event_name"`
	EventType         APICallEventType `json:"event_type,omitempty"`
	APIVersion        string           `json:"api_version,omitempty"`
	Category          APICallCategory  `json:"event_category"`
	ReadOnly          bool             `json:"read_only"`
	Identity          APIIdentity      `json:"identity"`
	SourceIPAddress   string           `json:"source_ip_address"`
	UserAgent         string           `json:"user_agent"`
	ErrorCode         string           `json:"error_code,omitempty"`
	ErrorMessage      string           `json:"error_message,omitempty"`
	RequestParameters json.RawMessage  `json:"request_parameters"`
	ResponseElements  json.RawMessage  `json:"response_elements"`
	// Resources are CloudTrail LookupEvents search terms, which can include
	// multiple names for a resource. They are not the event's resources field.
	Resources []APIResource `json:"lookup_resources"`
	// EventResources are native CloudTrail resource identities, independently
	// of LookupEvents search terms. Selectors match these types and ARNs.
	EventResources      []APIEventResource `json:"event_resources,omitempty"`
	AdditionalEventData json.RawMessage    `json:"additional_event_data,omitempty"`
	// ServiceEvent marks a native service-generated outcome rather than a call
	// to a public API. Its sanitized details are owned by the producing service.
	ServiceEvent        bool            `json:"service_event,omitempty"`
	ServiceEventDetails json.RawMessage `json:"service_event_details,omitempty"`
}

// APIIdentity retains public caller identity; no signing or session secrets are
// permitted. The actor ARN is owned by the event envelope.
type APIIdentity struct {
	Type             string           `json:"type"`
	PrincipalID      string           `json:"principal_id"`
	AccountID        string           `json:"account_id"`
	AccessKeyID      string           `json:"access_key_id"`
	UserName         string           `json:"user_name"`
	IssuerID         string           `json:"issuer_id,omitempty"`
	IssuerARN        string           `json:"issuer_arn,omitempty"`
	IssuerUserName   string           `json:"issuer_user_name,omitempty"`
	IdentityProvider string           `json:"identity_provider,omitempty"`
	SessionCreatedAt time.Time        `json:"session_created_at,omitzero"`
	MFAAuthenticated bool             `json:"mfa_authenticated"`
	SourceIdentity   string           `json:"source_identity,omitempty"`
	EC2RoleDelivery  string           `json:"ec2_role_delivery,omitempty"`
	InScopeOf        APIIdentityScope `json:"in_scope_of,omitzero"`
}

// APIIdentityScope is the native source-resource scope of an EC2 identity.
// It contains public audit identity, not credentials or authorization. Only the
// identity authority supplies it; ARNs alone do not.
type APIIdentityScope struct {
	IssuerType          string `json:"issuerType"`
	CredentialsIssuedTo string `json:"credentialsIssuedTo"`
}

type APIResource struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type APIEventResource struct {
	AccountID string `json:"accountId,omitempty"`
	Type      string `json:"type,omitempty"`
	ARN       string `json:"ARN,omitempty"`
	ARNPrefix string `json:"ARNPrefix,omitempty"`
}

// APICallCursor selects entries preceding an already returned event in descending
// completion-time, sequence order. Sequence breaks ties in virtual time.
type APICallCursor struct {
	At       time.Time
	Sequence int64
}

// APICallQuery is the validated CloudTrail history query. Start and End are
// inclusive. Limit includes any look-ahead row requested by the caller.
// MaxSequence zero selects the current committed prefix; subsequent pages reuse
// the returned prefix so newly committed events cannot shift the traversal.
type APICallQuery struct {
	Partition, AccountID, Region string
	Start, End                   time.Time
	AttributeKey, AttributeValue string
	Before                       *APICallCursor
	MaxSequence                  int64
	Limit                        int
}

type APICallPage struct {
	Events      []Event
	MaxSequence int64
}

func cloneEvent(event Event) Event {
	event.LambdaSourceBatchAccepted.RecordIDs = slices.Clone(event.LambdaSourceBatchAccepted.RecordIDs)
	if event.KubernetesAuditObserved != nil {
		audit := CloneKubernetesAudit(*event.KubernetesAuditObserved)
		event.KubernetesAuditObserved = &audit
	}
	if event.APICallCompleted != nil {
		call := *event.APICallCompleted
		call.RequestParameters = slices.Clone(call.RequestParameters)
		call.ResponseElements = slices.Clone(call.ResponseElements)
		call.Resources = slices.Clone(call.Resources)
		call.EventResources = slices.Clone(call.EventResources)
		call.AdditionalEventData = slices.Clone(call.AdditionalEventData)
		call.ServiceEventDetails = slices.Clone(call.ServiceEventDetails)
		event.APICallCompleted = &call
	}
	return event
}
