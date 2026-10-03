package secretsmanager

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"stackd/iam/policy"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/iam/catalog"
)

const (
	policyPublicMessage  = "You can not attach a resource policy that grants Public access to your secret."
	policyLockoutMessage = "This resource policy will not allow you to manage this secret in the future."
)

func (s *Service) getResourcePolicy(tx Transaction, in *api.GetResourcePolicyInput) (*api.GetResourcePolicyOutput, error) {
	secret, err := resolveSecret(tx, value(in.SecretId))
	if err != nil {
		return nil, err
	}
	if err = s.authorize(tx, "GetResourcePolicy", secret, nil); err != nil {
		return nil, err
	}
	out := &api.GetResourcePolicyOutput{ARN: str[api.SecretARNType](secret.ARN), Name: str[api.NameType](secret.Key.Name)}
	if secret.Policy.Document == "" {
		return out, nil
	}
	if s.binder == nil {
		return nil, failure("InternalServiceError", "Resource policy principal binding is not configured.")
	}
	document, err := s.binder.RenderResourcePolicy(tx.Context(), secret.Policy)
	if err != nil {
		return nil, err
	}
	out.ResourcePolicy = str[api.NonEmptyResourcePolicyType](document)
	return out, nil
}

func (s *Service) putResourcePolicy(tx Transaction, in *api.PutResourcePolicyInput) (*api.PutResourcePolicyOutput, error) {
	secret, err := resolveSecret(tx, value(in.SecretId))
	if err != nil {
		return nil, err
	}
	conditions := map[string][]string{}
	if in.BlockPublicPolicy != nil {
		conditions["secretsmanager:BlockPublicPolicy"] = []string{strconv.FormatBool(bool(*in.BlockPublicPolicy))}
	}
	if err = s.authorize(tx, "PutResourcePolicy", secret, conditions); err != nil {
		return nil, err
	}
	if err = checkWritable(tx.Context(), secret); err != nil {
		return nil, err
	}
	bound, err := s.bindSecretPolicy(tx, value(in.ResourcePolicy))
	if err != nil {
		return nil, err
	}
	if in.BlockPublicPolicy != nil && bool(*in.BlockPublicPolicy) {
		public, err := publicSecretPolicy(tx.Context(), bound.Document, secret.ARN)
		if err != nil {
			return nil, err
		}
		if public {
			return nil, failure("PublicPolicyException", policyPublicMessage)
		}
	}
	secret.Policy = bound
	if err = tx.PutSecret(secret); err != nil {
		return nil, err
	}
	if err = s.refreshReplicas(tx, secret); err != nil {
		return nil, err
	}
	return &api.PutResourcePolicyOutput{ARN: str[api.SecretARNType](secret.ARN), Name: str[api.NameType](secret.Key.Name)}, nil
}

func (s *Service) deleteResourcePolicy(tx Transaction, in *api.DeleteResourcePolicyInput) (*api.DeleteResourcePolicyOutput, error) {
	secret, err := resolveSecret(tx, value(in.SecretId))
	if err != nil {
		return nil, err
	}
	if err = s.authorize(tx, "DeleteResourcePolicy", secret, nil); err != nil {
		return nil, err
	}
	if err = checkWritable(tx.Context(), secret); err != nil {
		return nil, err
	}
	secret.Policy = authorization.BoundPolicy{}
	if err = tx.PutSecret(secret); err != nil {
		return nil, err
	}
	if err = s.refreshReplicas(tx, secret); err != nil {
		return nil, err
	}
	return &api.DeleteResourcePolicyOutput{ARN: str[api.SecretARNType](secret.ARN), Name: str[api.NameType](secret.Key.Name)}, nil
}

func (s *Service) validateResourcePolicy(tx Transaction, in *api.ValidateResourcePolicyInput) (*api.ValidateResourcePolicyOutput, error) {
	var secret SecretRecord
	var err error
	if in.SecretId != nil {
		secret, err = resolveSecret(tx, value(in.SecretId))
		if err != nil {
			return nil, err
		}
	}
	for _, action := range []string{"ValidateResourcePolicy", "PutResourcePolicy"} {
		if err = s.authorize(tx, action, secret, nil); err != nil {
			return nil, err
		}
	}
	if err = checkNotDeleted(secret); err != nil {
		return nil, err
	}
	bound, err := s.bindSecretPolicy(tx, value(in.ResourcePolicy))
	if err != nil {
		return nil, err
	}
	public, err := publicSecretPolicy(tx.Context(), bound.Document, secret.ARN)
	if err != nil {
		return nil, err
	}
	out := &api.ValidateResourcePolicyOutput{ValidationErrors: api.ValidationErrorsType{}}
	if public {
		out.ValidationErrors = append(out.ValidationErrors, policyValidationError("BlockPublicPolicyCheck", policyPublicMessage))
	}
	// Re-evaluate the caller against the proposed bound policy, rather than
	// requiring an Allow in that policy. Existing identity grants still count;
	// a direct session grant retains its different IAM ceiling semantics.
	secret.Policy = bound
	if err = s.authorize(tx, "PutResourcePolicy", secret, nil); err != nil {
		if wireError(err).Code != "AccessDeniedException" {
			return nil, err
		}
		out.ValidationErrors = append(out.ValidationErrors, policyValidationError("LockOutCheck", policyLockoutMessage))
	}
	out.PolicyValidationPassed = ptr(api.BooleanType(len(out.ValidationErrors) == 0))
	return out, nil
}

func policyValidationError(check, message string) api.ValidationErrorsEntry {
	return api.ValidationErrorsEntry{CheckName: str[api.NameType](check), ErrorMessage: str[api.ErrorMessage](message)}
}

func (s *Service) bindSecretPolicy(r Reader, document string) (authorization.BoundPolicy, error) {
	if n := utf8.RuneCountInString(document); n < 1 || n > 20480 {
		return authorization.BoundPolicy{}, failure("InvalidParameterException", "ResourcePolicy must contain between 1 and 20480 characters.")
	}
	if s.binder == nil {
		return authorization.BoundPolicy{}, failure("InternalServiceError", "Resource policy principal binding is not configured.")
	}
	bound, err := s.binder.BindResourcePolicy(r.Context(), document, authorization.ResourcePolicyOptions{})
	if err != nil {
		if errors.Is(err, authorization.ErrInvalidPrincipal) {
			return authorization.BoundPolicy{}, failure("MalformedPolicyDocumentException", "This resource policy contains an unsupported principal.")
		}
		if errors.Is(err, policy.ErrInvalidPolicy) || errors.Is(err, policy.ErrUnsupported) {
			return authorization.BoundPolicy{}, failure("MalformedPolicyDocumentException", "This resource policy contains a syntax error.")
		}
		return authorization.BoundPolicy{}, err
	}
	return bound, nil
}

// Public classification analyzes possible grants, not the current caller. The
// shared IAM parser owns syntax, and its permission algebra handles overlapping
// Action/NotAction and Resource/NotResource sets. These trust restrictions are
// Secrets Manager's documented Source* keys, not S3's bucket/access-point rules.
type secretPolicyStatement struct {
	Effect       string
	Principal    json.RawMessage                       `json:",omitempty"`
	NotPrincipal json.RawMessage                       `json:",omitempty"`
	Action       json.RawMessage                       `json:",omitempty"`
	NotAction    json.RawMessage                       `json:",omitempty"`
	Resource     json.RawMessage                       `json:",omitempty"`
	NotResource  json.RawMessage                       `json:",omitempty"`
	Condition    map[string]map[string]json.RawMessage `json:",omitempty"`
}

var secretPolicyActions = sync.OnceValues(func() ([]string, error) {
	c, err := catalog.Load()
	if err != nil {
		return nil, err
	}
	service, ok := c.LookupService("secretsmanager")
	if !ok {
		return nil, failure("InternalServiceError", "Secrets Manager authorization metadata is unavailable.")
	}
	var actions []string
	for _, action := range service.Actions {
		if slices.Contains(action.Resources, "Secret") {
			actions = append(actions, action.Name)
		}
	}
	return actions, nil
})

func publicSecretPolicy(ctx context.Context, document, resource string) (bool, error) {
	var raw struct{ Statement json.RawMessage }
	if err := json.Unmarshal([]byte(document), &raw); err != nil {
		return false, err
	}
	var statements []secretPolicyStatement
	if len(raw.Statement) > 0 && raw.Statement[0] == '[' {
		if err := json.Unmarshal(raw.Statement, &statements); err != nil {
			return false, err
		}
	} else {
		var statement secretPolicyStatement
		if err := json.Unmarshal(raw.Statement, &statement); err != nil {
			return false, err
		}
		statements = []secretPolicyStatement{statement}
	}
	actions, err := secretPolicyActions()
	if err != nil {
		return false, err
	}
	if resource == "" {
		resource = "arn:*:secretsmanager:*:*:secret:*"
	}
	resources := make(map[string][]string, len(actions))
	for _, action := range actions {
		resources[action] = []string{resource}
	}
	for _, allow := range statements {
		if allow.Effect != "Allow" || !secretPolicyUniversal(allow.Principal) || secretPolicyTrustCondition(allow.Condition) {
			continue
		}
		projection := []secretPolicyStatement{secretPolicySelectors(allow)}
		for _, deny := range statements {
			if deny.Effect != "Deny" {
				continue
			}
			// A universal denial cancels the selected public scope. A
			// NotPrincipal denial excluding only fixed identities likewise
			// leaves access confined to those identities, never the public.
			universal := secretPolicyUniversal(deny.Principal)
			fixedRemainder := len(deny.NotPrincipal) != 0 && !secretPolicyUniversal(deny.NotPrincipal)
			if (universal || fixedRemainder) && secretPolicyDenyRestricts(deny.Condition, allow.Condition) {
				projection = append(projection, secretPolicySelectors(deny))
			}
		}
		data, err := json.Marshal(struct{ Statement []secretPolicyStatement }{projection})
		if err != nil {
			return false, err
		}
		summary, err := policy.ParsePermissionSummary(data)
		if err != nil {
			return false, err
		}
		possible, err := policy.PotentialActions(ctx, [][]*policy.PermissionSummary{{summary}}, resources)
		if err != nil {
			return false, err
		}
		if len(possible) != 0 {
			return true, nil
		}
	}
	return false, nil
}

func secretPolicySelectors(statement secretPolicyStatement) secretPolicyStatement {
	statement.Principal, statement.NotPrincipal, statement.Condition = nil, nil, nil
	return statement
}

func secretPolicyStrings(raw json.RawMessage) []string {
	var values []string
	if json.Unmarshal(raw, &values) == nil {
		return values
	}
	var value string
	if json.Unmarshal(raw, &value) == nil {
		return []string{value}
	}
	return nil
}

func secretPolicyUniversal(raw json.RawMessage) bool {
	if slices.Contains(secretPolicyStrings(raw), "*") {
		return true
	}
	var principals map[string]json.RawMessage
	return json.Unmarshal(raw, &principals) == nil && slices.Contains(secretPolicyStrings(principals["AWS"]), "*")
}

func secretPolicyTrustCondition(conditions map[string]map[string]json.RawMessage) bool {
	for operator, keys := range conditions {
		base := strings.TrimPrefix(strings.TrimPrefix(operator, "ForAllValues:"), "ForAnyValue:")
		base = strings.TrimSuffix(base, "IfExists")
		for key, raw := range keys {
			if (strings.HasPrefix(operator, "ForAllValues:") || strings.HasSuffix(operator, "IfExists")) && !secretPolicyRequiresPresence(conditions, key) {
				continue
			}
			if secretPolicyTrustValues(base, key, secretPolicyStrings(raw)) {
				return true
			}
		}
	}
	return false
}

func secretPolicyRequiresPresence(conditions map[string]map[string]json.RawMessage, key string) bool {
	for candidate, raw := range conditions["Null"] {
		if !strings.EqualFold(candidate, key) {
			continue
		}
		var value bool
		if json.Unmarshal(raw, &value) == nil {
			return !value
		}
		values := secretPolicyStrings(raw)
		return len(values) == 1 && strings.EqualFold(values[0], "false")
	}
	return false
}

func secretPolicyTrustValues(operator, key string, values []string) bool {
	if len(values) == 0 {
		return false
	}
	key = strings.ToLower(key)
	if operator == "IpAddress" && key == "aws:sourceip" {
		for _, value := range values {
			if _, err := netip.ParseAddr(value); err == nil {
				continue
			}
			prefix, err := netip.ParsePrefix(value)
			if err != nil || prefix.Bits() == 0 {
				return false
			}
		}
		return true
	}
	if operator != "StringEquals" && operator != "StringLike" && operator != "ArnEquals" && operator != "ArnLike" {
		return false
	}
	switch key {
	case "aws:sourcearn", "aws:sourcevpc", "aws:sourcevpce", "aws:sourceaccount":
	default:
		return false
	}
	for _, value := range values {
		if value == "" || strings.Contains(value, "${") || operator != "StringEquals" && strings.ContainsAny(value, "*?") {
			return false
		}
	}
	return true
}

func secretPolicyDenyRestricts(deny, allow map[string]map[string]json.RawMessage) bool {
	implied := true
	for operator, keys := range deny {
		for key, raw := range keys {
			matched := false
			for candidate, other := range allow[operator] {
				if strings.EqualFold(candidate, key) {
					var left, right any
					matched = json.Unmarshal(raw, &left) == nil && json.Unmarshal(other, &right) == nil && reflect.DeepEqual(left, right)
					break
				}
			}
			implied = implied && matched
		}
	}
	if implied {
		return true
	}
	// The complement of one negated, fixed Source* restriction is a bounded
	// trust domain. Multiple predicates are a conjunction: none may be
	// discarded when determining what the denial actually excludes.
	if len(deny) != 1 {
		return false
	}
	for operator, keys := range deny {
		if len(keys) != 1 {
			return false
		}
		var positive string
		switch operator {
		case "StringNotEquals", "StringNotEqualsIfExists":
			positive = "StringEquals"
		case "StringNotLike", "StringNotLikeIfExists":
			positive = "StringLike"
		case "ArnNotEquals", "ArnNotEqualsIfExists":
			positive = "ArnEquals"
		case "ArnNotLike", "ArnNotLikeIfExists":
			positive = "ArnLike"
		case "NotIpAddress", "NotIpAddressIfExists":
			positive = "IpAddress"
		default:
			return false
		}
		for key, raw := range keys {
			return secretPolicyTrustValues(positive, key, secretPolicyStrings(raw))
		}
	}
	return false
}
