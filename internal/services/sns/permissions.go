package sns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"regexp"
	"slices"
	"strings"

	"stackd/iam/policy"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/sns"
	"stackd/internal/awswire"
	"stackd/internal/iam/catalog"
)

var permissionLabelPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`)

// These eight actions are SNS's native default policy, not its admission catalog.
func defaultTopicPolicy(key TopicKey) string {
	return `{"Version":"2008-10-17","Id":"__default_policy_ID","Statement":[{"Sid":"__default_statement_ID","Effect":"Allow","Principal":{"AWS":"*"},"Action":["SNS:GetTopicAttributes","SNS:SetTopicAttributes","SNS:AddPermission","SNS:RemovePermission","SNS:DeleteTopic","SNS:Subscribe","SNS:ListSubscriptionsByTopic","SNS:Publish"],"Resource":"` + key.ARN() + `","Condition":{"StringEquals":{"AWS:SourceOwner":"` + key.AccountID + `"}}}]}`
}

// This is only the presentation shape for statement editing. The shared IAM
// parser and principal binder own policy language and authorization semantics.
type topicPolicy struct {
	Version    string            `json:"Version,omitempty"`
	ID         string            `json:"Id,omitempty"`
	Statements []json.RawMessage `json:"Statement"`
}

func readTopicPolicy(document string) (topicPolicy, error) {
	var raw struct {
		Version   string
		ID        string `json:"Id"`
		Statement json.RawMessage
	}
	if err := json.Unmarshal([]byte(document), &raw); err != nil {
		return topicPolicy{}, err
	}
	out := topicPolicy{Version: raw.Version, ID: raw.ID}
	if bytes.HasPrefix(bytes.TrimSpace(raw.Statement), []byte("[")) {
		if err := json.Unmarshal(raw.Statement, &out.Statements); err != nil {
			return topicPolicy{}, err
		}
	} else {
		out.Statements = []json.RawMessage{raw.Statement}
	}
	return out, nil
}

func topicPolicyStrings(raw json.RawMessage) []string {
	var scalar string
	if json.Unmarshal(raw, &scalar) == nil {
		return []string{scalar}
	}
	var values []string
	_ = json.Unmarshal(raw, &values)
	return values
}

func validateTopicPolicy(document string, key TopicKey) (string, error) {
	if len(document) > 30720 {
		return "", failure("InvalidParameter", "Invalid parameter: Policy exceeds the maximum size of 30 KB.")
	}
	parsed, err := policy.ParseResource([]byte(document))
	if err != nil {
		return "", failure("InvalidParameter", "Invalid parameter: Policy Error: null")
	}
	presentation, err := readTopicPolicy(document)
	if err != nil {
		return "", err
	}
	actions, err := catalog.Load()
	if err != nil {
		return "", err
	}
	for _, raw := range presentation.Statements {
		var statement struct {
			Action, Resource, NotAction, NotResource, NotPrincipal json.RawMessage
		}
		if err := json.Unmarshal(raw, &statement); err != nil {
			return "", err
		}
		if statement.NotAction != nil || statement.NotResource != nil || statement.NotPrincipal != nil {
			return "", failure("InvalidParameter", "Invalid parameter: Policy contains a prohibited negative field.")
		}
		for _, action := range topicPolicyStrings(statement.Action) {
			if !strings.HasPrefix(strings.ToLower(action), "sns:") || strings.ContainsAny(action, "*?") {
				return "", failure("InvalidParameter", "Invalid parameter: Policy statement action out of service scope!")
			}
			if _, ok := actions.LookupAction(action); !ok {
				return "", failure("InvalidParameter", "Invalid parameter: Policy statement action out of service scope!")
			}
		}
		for _, resource := range topicPolicyStrings(statement.Resource) {
			if resource != "*" && resource != key.ARN() {
				return "", failure("InvalidParameter", "Invalid parameter: Policy statement must apply to this topic.")
			}
		}
	}
	replacements := map[string]string{}
	for _, principal := range parsed.AWSPrincipals() {
		if accountPattern.MatchString(principal) {
			replacements[principal] = "arn:" + key.Partition + ":iam::" + principal + ":root"
		}
	}
	canonical, err := policy.RewriteResourcePrincipals([]byte(document), replacements)
	if err != nil {
		return "", err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, canonical); err != nil {
		return "", err
	}
	return compact.String(), nil
}

func (s *Service) bindTopicPolicy(ctx context.Context, document string, key TopicKey) (authorization.BoundPolicy, error) {
	canonical, err := validateTopicPolicy(document, key)
	if err != nil {
		return authorization.BoundPolicy{}, err
	}
	if s.binder == nil {
		return authorization.BoundPolicy{}, unsupported("Topic policy principal binding is not configured.")
	}
	bound, err := s.binder.BindResourcePolicy(ctx, canonical, authorization.ResourcePolicyOptions{})
	if errors.Is(err, authorization.ErrInvalidPrincipal) {
		return authorization.BoundPolicy{}, failure("InvalidParameter", "Invalid parameter: Policy contains an invalid principal.")
	}
	return bound, err
}

func permissionSID(raw json.RawMessage) string {
	var statement struct {
		SID string `json:"Sid"`
	}
	_ = json.Unmarshal(raw, &statement)
	return statement.SID
}

func (s *Service) registerPermissions() {
	register(s, "AddPermission", s.addPermission)
	register(s, "RemovePermission", s.removePermission)
}

func (s *Service) addPermission(ctx context.Context, in *api.AddPermissionInput) (out *api.AddPermissionOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "AddPermission", in, &out, &rejected, false)
	key, wire := topicKey(ctx, value(in.TopicArn))
	if wire != nil {
		return nil, wire
	}
	if !permissionLabelPattern.MatchString(value(in.Label)) || len(in.AWSAccountId) == 0 || len(in.ActionName) == 0 {
		return nil, failure("InvalidParameter", "Invalid parameter: Label, AWSAccountId or ActionName")
	}
	principals := make([]string, 0, len(in.AWSAccountId))
	for _, account := range in.AWSAccountId {
		if !accountPattern.MatchString(string(account)) {
			return nil, failure("InvalidParameter", "Invalid parameter: AWSAccountId")
		}
		principals = append(principals, "arn:"+key.Partition+":iam::"+string(account)+":root")
	}
	actions := make([]string, 0, len(in.ActionName))
	for _, action := range in.ActionName {
		actions = append(actions, "SNS:"+string(action))
	}
	statement, err := json.Marshal(struct {
		SID       string              `json:"Sid"`
		Effect    string              `json:"Effect"`
		Principal map[string][]string `json:"Principal"`
		Action    []string            `json:"Action"`
		Resource  string              `json:"Resource"`
	}{value(in.Label), "Allow", map[string][]string{"AWS": principals}, actions, key.ARN()})
	if err != nil {
		return nil, wireError(err)
	}
	incoming, err := json.Marshal(topicPolicy{Version: "2008-10-17", Statements: []json.RawMessage{statement}})
	if err != nil {
		return nil, wireError(err)
	}
	if _, err := validateTopicPolicy(string(incoming), key); err != nil {
		return nil, wireError(err)
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		topic, err := tx.Topic(key)
		if err != nil {
			return err
		}
		if err := s.authorize(tx, "AddPermission", key.ARN(), topic.Tags, nil, topic.Policy); err != nil {
			return err
		}
		document, err := readTopicPolicy(topic.Policy.Document)
		if err != nil {
			return err
		}
		replaced := false
		for i, old := range document.Statements {
			if permissionSID(old) == value(in.Label) {
				document.Statements[i], replaced = statement, true
				break
			}
		}
		if !replaced {
			document.Statements = append(document.Statements, statement)
		}
		if err := s.storeEditedTopicPolicy(tx, &topic, document); err != nil {
			return err
		}
		out = &api.AddPermissionOutput{}
		return s.recordCall(tx.Context(), "AddPermission", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) removePermission(ctx context.Context, in *api.RemovePermissionInput) (out *api.RemovePermissionOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "RemovePermission", in, &out, &rejected, false)
	key, wire := topicKey(ctx, value(in.TopicArn))
	if wire != nil {
		return nil, wire
	}
	if !permissionLabelPattern.MatchString(value(in.Label)) {
		return nil, failure("InvalidParameter", "Invalid parameter: Label")
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		topic, err := tx.Topic(key)
		if err != nil {
			return err
		}
		if err := s.authorize(tx, "RemovePermission", key.ARN(), topic.Tags, nil, topic.Policy); err != nil {
			return err
		}
		document, err := readTopicPolicy(topic.Policy.Document)
		if err != nil {
			return err
		}
		found := false
		for i, old := range document.Statements {
			if permissionSID(old) == value(in.Label) {
				if len(document.Statements) == 1 {
					return failure("InvalidParameter", "Invalid parameter: "+value(in.Label)+" Reason: Policy must include at least one statement")
				}
				document.Statements = append(document.Statements[:i], document.Statements[i+1:]...)
				found = true
				break
			}
		}
		if found {
			if err := s.storeEditedTopicPolicy(tx, &topic, document); err != nil {
				return err
			}
		}
		out = &api.RemovePermissionOutput{}
		return s.recordCall(tx.Context(), "RemovePermission", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) storeEditedTopicPolicy(tx Transaction, topic *TopicRecord, document topicPolicy) error {
	data, err := json.Marshal(document)
	if err != nil {
		return err
	}
	if len(data) > 30720 {
		return failure("InvalidParameter", "Invalid parameter: Policy exceeds the maximum size of 30 KB.")
	}
	// Shorthand adds account principals, which are not identity-bound. Preserve
	// every surviving ARN's immutable ID rather than rebinding a deleted identity.
	retained := maps.Clone(topic.Policy.PrincipalIDs)
	if len(retained) != 0 {
		parsed, err := policy.ParseResource(data)
		if err != nil {
			return err
		}
		principals := parsed.AWSPrincipals()
		for arn := range retained {
			if !slices.Contains(principals, arn) {
				delete(retained, arn)
			}
		}
	}
	topic.Policy = authorization.BoundPolicy{Document: string(data), PrincipalIDs: retained}
	clearCloudFormationPolicyClaim(topic)
	topic.Updated = s.clock.Now()
	return tx.PutTopic(*topic)
}
