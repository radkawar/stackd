package apievents

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"stackd/journal"
)

type eventIdentity struct {
	Type             string                   `json:"type,omitempty"`
	PrincipalID      string                   `json:"principalId,omitempty"`
	ARN              string                   `json:"arn,omitempty"`
	AccountID        string                   `json:"accountId,omitempty"`
	AccessKeyID      string                   `json:"accessKeyId,omitempty"`
	UserName         string                   `json:"userName,omitempty"`
	InvokedBy        string                   `json:"invokedBy,omitempty"`
	IdentityProvider string                   `json:"identityProvider,omitempty"`
	SessionContext   *sessionContext          `json:"sessionContext,omitempty"`
	InScopeOf        journal.APIIdentityScope `json:"inScopeOf,omitzero"`
}
type sessionContext struct {
	SessionIssuer   *sessionIssuer    `json:"sessionIssuer,omitempty"`
	Attributes      sessionAttributes `json:"attributes"`
	SourceIdentity  string            `json:"sourceIdentity,omitempty"`
	EC2RoleDelivery string            `json:"ec2RoleDelivery,omitempty"`
}
type sessionIssuer struct {
	Type        string `json:"type"`
	PrincipalID string `json:"principalId"`
	ARN         string `json:"arn"`
	AccountID   string `json:"accountId"`
	UserName    string `json:"userName,omitempty"`
}
type sessionAttributes struct {
	CreationDate     string `json:"creationDate"`
	MFAAuthenticated string `json:"mfaAuthenticated"`
}
type eventDocument struct {
	EventVersion        string                     `json:"eventVersion"`
	UserIdentity        eventIdentity              `json:"userIdentity"`
	EventTime           string                     `json:"eventTime"`
	EventSource         string                     `json:"eventSource"`
	EventName           string                     `json:"eventName"`
	APIVersion          string                     `json:"apiVersion,omitempty"`
	AWSRegion           string                     `json:"awsRegion"`
	SourceIPAddress     string                     `json:"sourceIPAddress"`
	UserAgent           string                     `json:"userAgent,omitempty"`
	RequestParameters   json.RawMessage            `json:"requestParameters"`
	ResponseElements    json.RawMessage            `json:"responseElements"`
	ErrorCode           string                     `json:"errorCode,omitempty"`
	ErrorMessage        string                     `json:"errorMessage,omitempty"`
	RequestID           string                     `json:"requestID"`
	EventID             string                     `json:"eventID"`
	SharedEventID       string                     `json:"sharedEventID,omitempty"`
	ReadOnly            bool                       `json:"readOnly"`
	EventType           string                     `json:"eventType"`
	ManagementEvent     bool                       `json:"managementEvent"`
	RecipientAccountID  string                     `json:"recipientAccountId"`
	EventCategory       string                     `json:"eventCategory"`
	Resources           []journal.APIEventResource `json:"resources,omitempty"`
	AdditionalEventData json.RawMessage            `json:"additionalEventData,omitempty"`
	ServiceEventDetails json.RawMessage            `json:"serviceEventDetails,omitempty"`
}

// CloudTrailRecord is the shared native document used by history, configured
// trail delivery and EventBridge's AWS API Call via CloudTrail detail. Sources
// retain ownership of event category, resource identities and sanitized fields.
func CloudTrailRecord(e journal.Event) ([]byte, error) {
	call := e.APICallCompleted
	id := call.Identity
	identity := eventIdentity{Type: id.Type, PrincipalID: id.PrincipalID, ARN: e.ActorARN, AccountID: id.AccountID, AccessKeyID: id.AccessKeyID, IdentityProvider: id.IdentityProvider}
	identity.InvokedBy = e.ActorService
	identity.InScopeOf = id.InScopeOf
	switch id.Type {
	case "IAMUser":
		identity.UserName = id.UserName
	case "SAMLUser", "WebIdentityUser":
		identity.UserName, identity.ARN = id.UserName, ""
	case "AWSAccount":
		identity.ARN = ""
	}
	if !id.SessionCreatedAt.IsZero() {
		identity.SessionContext = &sessionContext{Attributes: sessionAttributes{CreationDate: id.SessionCreatedAt.UTC().Format(time.RFC3339), MFAAuthenticated: strconv.FormatBool(id.MFAAuthenticated)}, SourceIdentity: id.SourceIdentity, EC2RoleDelivery: id.EC2RoleDelivery}
		if id.IssuerARN != "" {
			issuerType := "Role"
			if id.Type == "FederatedUser" {
				issuerType = "IAMUser"
				if strings.HasSuffix(id.IssuerARN, ":root") {
					issuerType = "Root"
				}
			}
			identity.SessionContext.SessionIssuer = &sessionIssuer{Type: issuerType, PrincipalID: id.IssuerID, ARN: id.IssuerARN, AccountID: id.AccountID, UserName: id.IssuerUserName}
		}
	}
	sourceIP, agent := call.SourceIPAddress, call.UserAgent
	if id.Type == "AWSService" {
		identity = eventIdentity{Type: id.Type, InvokedBy: e.ActorService}
		if sourceIP == "" {
			sourceIP = e.ActorService
		}
		if agent == "" {
			agent = e.ActorService
		}
	}
	eventType := string(call.EventType)
	if eventType == "" {
		eventType = "AwsApiCall"
		if call.ServiceEvent {
			eventType = "AwsServiceEvent"
		}
	}
	return json.Marshal(eventDocument{EventVersion: "1.11", UserIdentity: identity, EventTime: e.At.UTC().Format(time.RFC3339), EventSource: call.EventSource, EventName: call.EventName, APIVersion: call.APIVersion, AWSRegion: e.Region, SourceIPAddress: sourceIP, UserAgent: agent, RequestParameters: call.RequestParameters, ResponseElements: call.ResponseElements, ErrorCode: call.ErrorCode, ErrorMessage: call.ErrorMessage, RequestID: e.RequestID, EventID: call.EventID, SharedEventID: call.SharedEventID, ReadOnly: call.ReadOnly, EventType: eventType, ManagementEvent: call.Category == journal.CategoryManagement, RecipientAccountID: e.AccountID, EventCategory: string(call.Category), Resources: call.EventResources, AdditionalEventData: call.AdditionalEventData, ServiceEventDetails: call.ServiceEventDetails})
}
