package ssm

import (
	"context"
	"maps"
	"regexp"
	"strings"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

var parameterNamePattern = regexp.MustCompile(`^/?[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*$`)

func parameterARN(key ParameterKey) string {
	return "arn:" + key.Partition + ":ssm:" + key.Region + ":" + key.AccountID + ":parameter/" + strings.TrimPrefix(key.Name, "/")
}
func parameterKey(ctx context.Context, name string, allowARN bool) (ParameterKey, error) {
	scope := scopeFor(ctx)
	name = strings.TrimSpace(name)
	if strings.HasPrefix(name, "arn:") {
		parts := strings.SplitN(name, ":", 6)
		if !allowARN || len(parts) != 6 || parts[1] != scope.Partition || parts[2] != "ssm" || parts[3] != scope.Region || parts[4] == "" || !strings.HasPrefix(parts[5], "parameter/") {
			return ParameterKey{}, failure("ValidationException", "The parameter ARN is invalid.")
		}
		scope.AccountID = parts[4]
		name = "/" + strings.TrimPrefix(parts[5], "parameter/")
	}
	if !parameterNamePattern.MatchString(name) || strings.Contains(name, "/") && !strings.HasPrefix(name, "/") {
		return ParameterKey{}, failure("ValidationException", "Parameter name must be a fully qualified path and contain only letters, numbers and .-_ characters.")
	}
	if len(strings.Split(strings.TrimPrefix(name, "/"), "/")) > 15 {
		return ParameterKey{}, failure("HierarchyLevelLimitExceededException", "A parameter hierarchy can have a maximum of 15 levels.")
	}
	key := ParameterKey{Scope: scope, Name: name}
	if len(parameterARN(key)) > 1011 {
		return ParameterKey{}, failure("ValidationException", "The parameter name exceeds the maximum length.")
	}
	return key, nil
}
func (s *Service) authorize(r Reader, action string, p ParameterRecord, conditions map[string][]string) error {
	context := make(map[string][]string, len(conditions)+2*len(p.Tags))
	maps.Copy(context, conditions)
	for k, v := range p.Tags {
		context["aws:ResourceTag/"+k] = []string{v}
		context["ssm:resourceTag/"+k] = []string{v}
	}
	if p.Key.AccountID != "" && p.Key.AccountID != awsctx.FromContext(r.Context()).AccountID && action != "GetParameter" && action != "GetParameters" && action != "GetParameterHistory" && action != "DescribeParameters" {
		return failure("AccessDeniedException", "Shared parameters are read-only.")
	}
	resource := p.ARN
	if resource == "" {
		resource = "*"
	}
	now := s.clock.Now()
	request := authorization.Request{Action: "ssm:" + strings.TrimPrefix(action, "ssm:"), ResourceARN: resource, ResourceAccountID: p.Key.AccountID, Context: context, EvaluationTime: &now}
	// Only advanced parameters can be shared. The same evaluator retains identity,
	// permissions boundaries, explicit denies and immutable principal bindings.
	if p.Tier == "Advanced" {
		for _, policy := range p.ResourcePolicies {
			request.ResourcePolicies = append(request.ResourcePolicies, policy.Policy)
		}
		if s.sharing != nil && p.CurrentVersion != 0 {
			policies, err := s.sharing.Policies(r.Context(), SharedParameter{ARN: p.ARN})
			if err != nil {
				return err
			}
			request.ResourcePolicies = append(request.ResourcePolicies, policies...)
		}
	}
	if denied := s.authorizer.Authorize(r.Context(), request); denied != nil {
		return wireError(denied)
	}
	return nil
}
