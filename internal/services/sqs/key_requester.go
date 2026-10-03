package sqs

import (
	"bytes"
	"context"
	"encoding/json"

	"stackd/internal/awsctx"
	"stackd/internal/identity"
)

// keyRequester identifies the principal and the session policy scope that may
// reuse KMS authorization. Role session names, tags and source identity do not
// create new requesters. Native EventBridge deliveries also share a service
// requester across source rules; SourceArn still constrains cold KMS authorization.
// Queue authorization checks the current caller on every command.
func keyRequester(ctx context.Context) string {
	m := awsctx.FromContext(ctx)
	principal := m.PrincipalID
	if m.SessionType == string(identity.SessionTypeAssumeRole) {
		principal = m.IssuerID
	}
	// Native captures share whitespace variants, but distinguish reordered
	// statements and managed-policy ARN lists. Preserve their supplied order.
	for i, document := range m.SessionPolicies {
		var compact bytes.Buffer
		// Session issuance validates these documents before authentication can
		// expose them here. This only removes insignificant JSON whitespace.
		_ = json.Compact(&compact, []byte(document))
		m.SessionPolicies[i] = compact.String()
	}
	encoded, _ := json.Marshal(struct {
		Partition, Account, Principal, Issuer string
		Restricted                            bool
		Service                               string `json:",omitempty"`
		// Empty lists have one scope, including after relational recovery.
		Policies   []string `json:",omitempty"`
		PolicyARNs []string `json:",omitempty"`
	}{m.Partition, m.AccountID, principal, m.IssuerID, m.HasSessionPolicy, m.ServicePrincipal.Name, m.SessionPolicies, m.SessionPolicyARNs})
	return string(encoded)
}
