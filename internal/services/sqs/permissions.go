package sqs

import (
	"encoding/json"
	"net/http"
	"regexp"
	"slices"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/sqs"
	"stackd/internal/awswire"
)

var accountPattern = regexp.MustCompile(`^[0-9]{12}$`)

type queuePolicy struct {
	Version    string            `json:"Version"`
	ID         string            `json:"Id,omitempty"`
	Statements []json.RawMessage `json:"Statement"`
}
type permissionStatement struct {
	SID       string              `json:"Sid"`
	Effect    string              `json:"Effect"`
	Principal permissionPrincipal `json:"Principal"`
	Actions   []string            `json:"Action"`
	Resource  string              `json:"Resource"`
}
type permissionPrincipal struct {
	AWS []string `json:"AWS"`
}

func readPolicy(raw string) (queuePolicy, error) {
	if raw == "" {
		return queuePolicy{Version: "2012-10-17"}, nil
	}
	var input struct {
		Version   string          `json:"Version"`
		ID        string          `json:"Id"`
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		return queuePolicy{}, err
	}
	out := queuePolicy{Version: input.Version, ID: input.ID}
	if len(input.Statement) > 0 && input.Statement[0] == '[' {
		if err := json.Unmarshal(input.Statement, &out.Statements); err != nil {
			return queuePolicy{}, err
		}
	} else {
		out.Statements = []json.RawMessage{input.Statement}
	}
	return out, nil
}
func statementSID(raw json.RawMessage) string {
	var sid struct {
		SID string `json:"Sid"`
	}
	_ = json.Unmarshal(raw, &sid)
	return sid.SID
}
func (s *Service) registerPermissions() {
	register(s, "AddPermission", true, s.addPermission)
	register(s, "RemovePermission", true, s.removePermission)
}
func (s *Service) addPermission(r *http.Request, in *api.AddPermissionInput) (*api.AddPermissionOutput, *awswire.Error) {
	q, err := s.queueFor(r, value(in.QueueUrl))
	if err != nil {
		return nil, err
	}
	label := value(in.Label)
	if len(label) == 0 || len(label) > 80 || !queueNamePattern.MatchString(label) {
		return nil, failure("InvalidParameterValue", "Invalid permission label.")
	}
	if len(in.Actions) == 0 || len(in.Actions) > 7 || len(in.AWSAccountIds) == 0 || len(in.AWSAccountIds) > 50 {
		return nil, failure("OverLimit", "A permission requires 1 to 7 actions and 1 to 50 principals.")
	}
	statement := permissionStatement{SID: label, Effect: "Allow", Resource: q.key.arn()}
	for _, account := range in.AWSAccountIds {
		if !accountPattern.MatchString(string(account)) {
			return nil, failure("InvalidParameterValue", "Invalid AWS account ID.")
		}
		statement.Principal.AWS = append(statement.Principal.AWS, "arn:"+q.key.partition+":iam::"+string(account)+":root")
	}
	for _, action := range in.Actions {
		if action != "*" && !slices.Contains(s.Operations(), string(action)) {
			return nil, failure("InvalidParameterValue", "Invalid permission action.")
		}
		statement.Actions = append(statement.Actions, "sqs:"+string(action))
	}
	doc, parseErr := readPolicy(q.config.policy)
	if parseErr != nil {
		return nil, failure("InvalidAttributeValue", "The queue policy is invalid.")
	}
	for _, st := range doc.Statements {
		if statementSID(st) == label {
			return nil, failure("InvalidParameterValue", "A permission with this label already exists.")
		}
	}
	if len(doc.Statements) >= 20 {
		return nil, failure("OverLimit", "A queue policy can contain at most 20 statements.")
	}
	encoded, _ := json.Marshal(statement)
	doc.Statements = append(doc.Statements, encoded)
	encoded, _ = json.Marshal(doc)
	if len(encoded) > 8192 {
		return nil, failure("OverLimit", "The queue policy exceeds 8192 bytes.")
	}
	if err := authorization.ValidateResourcePolicy(encoded); err != nil {
		return nil, failure("InvalidAttributeValue", err.Error())
	}
	q.config.policy = string(encoded)
	q.policyOwner = ""
	q.modified = s.now()
	return &api.AddPermissionOutput{}, nil
}
func (s *Service) removePermission(r *http.Request, in *api.RemovePermissionInput) (*api.RemovePermissionOutput, *awswire.Error) {
	q, err := s.queueFor(r, value(in.QueueUrl))
	if err != nil {
		return nil, err
	}
	label := value(in.Label)
	if len(label) == 0 || len(label) > 80 || !queueNamePattern.MatchString(label) {
		return nil, failure("InvalidParameterValue", "Invalid permission label.")
	}
	doc, parseErr := readPolicy(q.config.policy)
	if parseErr != nil {
		return nil, failure("InvalidAttributeValue", "The queue policy is invalid.")
	}
	kept := doc.Statements[:0]
	for _, statement := range doc.Statements {
		if statementSID(statement) != label {
			kept = append(kept, statement)
		}
	}
	doc.Statements = kept
	if len(kept) == 0 {
		q.config.policy = ""
		q.config.policyPrincipals = nil
	} else {
		encoded, _ := json.Marshal(doc)
		q.config.policy = string(encoded)
	}
	q.policyOwner = ""
	q.modified = s.now()
	return &api.RemovePermissionOutput{}, nil
}
