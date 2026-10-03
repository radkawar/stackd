package ssm

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/ssm"
)

// Parameter policy wire documents deliberately exclude retained scheduler state.
type policyDocument struct {
	Type       string            `json:"Type"`
	Version    string            `json:"Version"`
	Attributes map[string]string `json:"Attributes"`
}

// parsePolicies replaces policies only when the PutParameter caller supplies the
// field. Both [] and the documented [{}] remove existing policies.
func parsePolicies(raw string, now time.Time) ([]ParameterPolicy, error) {
	var documents []json.RawMessage
	if len(raw) > 4096 || json.Unmarshal([]byte(raw), &documents) != nil || strings.TrimSpace(raw) == "null" {
		return nil, failure("ValidationException", "Policies must be a JSON array of parameter policy objects.")
	}
	if len(documents) > 10 {
		return nil, failure("PoliciesLimitExceededException", "A parameter can have at most 10 policies.")
	}
	policies := make([]ParameterPolicy, 0, len(documents))
	for _, document := range documents {
		document = bytes.TrimSpace(document)
		if len(document) < 2 || document[0] != '{' {
			return nil, failure("InvalidPolicyAttributeException", "Each parameter policy must be a JSON object.")
		}
		if len(documents) == 1 && len(bytes.TrimSpace(document[1:len(document)-1])) == 0 {
			return policies, nil
		}
		var p policyDocument
		decoder := json.NewDecoder(bytes.NewReader(document))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&p) != nil {
			return nil, failure("InvalidPolicyAttributeException", "The parameter policy contains invalid attributes.")
		}
		if p.Type != "Expiration" && p.Type != "ExpirationNotification" && p.Type != "NoChangeNotification" {
			return nil, failure("InvalidPolicyTypeException", "The parameter policy type is not supported.")
		}
		if p.Version != "1.0" {
			return nil, failure("InvalidPolicyAttributeException", "The parameter policy version must be 1.0.")
		}
		policies = append(policies, ParameterPolicy{Type: p.Type, Version: p.Version, Attributes: p.Attributes})
	}
	return refreshPolicies(policies, now)
}

// refreshPolicies re-arms only the inactivity policy on an ordinary value update;
// expiration deadlines and already-delivered expiration notices remain unchanged.
func refreshPolicies(policies []ParameterPolicy, modified time.Time) ([]ParameterPolicy, error) {
	result := make([]ParameterPolicy, len(policies))
	var expiration time.Time
	for i, p := range policies {
		result[i] = p
		if p.Type != "Expiration" {
			continue
		}
		if len(p.Attributes) != 1 || p.Attributes["Timestamp"] == "" {
			return nil, failure("InvalidPolicyAttributeException", "Exactly one Timestamp is required for an Expiration policy.")
		}
		due, err := time.Parse(time.RFC3339Nano, p.Attributes["Timestamp"])
		if err != nil {
			due, err = time.Parse("2006-01-02T15:04:05.999999999Z07:00:00", p.Attributes["Timestamp"])
		}
		if err != nil {
			return nil, failure("InvalidPolicyAttributeException", "Expiration Timestamp must be an ISO-8601 timestamp.")
		}
		result[i].Due = due.UTC()
		if expiration.IsZero() || due.Before(expiration) {
			expiration = due
		}
	}
	for i := range result {
		p := &result[i]
		switch p.Type {
		case "Expiration":
		case "ExpirationNotification", "NoChangeNotification":
			attribute := "Before"
			if p.Type == "NoChangeNotification" {
				attribute = "After"
			}
			seconds, err := policyInterval(p.Attributes, attribute)
			if err != nil {
				return nil, err
			}
			if p.Type == "ExpirationNotification" {
				if expiration.IsZero() {
					return nil, failure("InvalidPolicyAttributeException", "ExpirationNotification requires an Expiration policy.")
				}
				p.Due = time.Unix(expiration.Unix()-seconds, int64(expiration.Nanosecond())).UTC()
			} else {
				p.Due, p.Fired = time.Unix(modified.Unix()+seconds, int64(modified.Nanosecond())).UTC(), false
			}
		default:
			return nil, failure("InvalidPolicyTypeException", "The parameter policy type is not supported.")
		}
	}
	return result, nil
}

func policyInterval(attributes map[string]string, field string) (int64, error) {
	unit := int64(3600)
	if attributes["Unit"] == "Days" {
		unit *= 24
	} else if attributes["Unit"] != "Hours" {
		return 0, failure("InvalidPolicyAttributeException", "Policy Unit must be Days or Hours.")
	}
	n, err := strconv.ParseInt(attributes[field], 10, 64)
	if len(attributes) != 2 || err != nil || n <= 0 || n >= 8760000 {
		return 0, failure("InvalidPolicyAttributeException", field+" must be a positive integer smaller than 8760000.")
	}
	return n * unit, nil
}

func policyOutput(policies []ParameterPolicy) api.ParameterPolicyList {
	out := policyHistoryOutput(policies)
	for i, p := range policies {
		status := "Pending"
		if p.Fired {
			status = "Finished"
		}
		out[i].PolicyStatus = new(api.String(status))
	}
	return out
}

func policyHistoryOutput(policies []ParameterPolicy) api.ParameterPolicyList {
	out := make(api.ParameterPolicyList, 0, len(policies))
	for _, p := range policies {
		text, _ := json.Marshal(policyDocument{Type: p.Type, Version: p.Version, Attributes: p.Attributes})
		out = append(out, api.ParameterInlinePolicy{PolicyText: new(api.String(text)), PolicyType: new(api.String(p.Type))})
	}
	return out
}
