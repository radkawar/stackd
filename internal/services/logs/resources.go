package logs

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func enabled[T ~bool](p *T) bool { return p != nil && bool(*p) }
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}

var groupNamePattern = regexp.MustCompile(`^[.\-_/#A-Za-z0-9]{1,512}$`)

func groupKey(ctx context.Context, reference string) (GroupKey, *awswire.Error) {
	k := GroupKey{Scope: scopeFor(ctx), Name: reference}
	if strings.HasPrefix(reference, "arn:") {
		parts := strings.SplitN(reference, ":", 6)
		if len(parts) != 6 || parts[2] != "logs" || !strings.HasPrefix(parts[5], "log-group:") {
			return k, invalid("The log group ARN is invalid.")
		}
		if parts[1] != k.Partition || parts[3] != k.Region || parts[4] != k.AccountID {
			return k, unsupported("Cross-account or cross-Region log access requires linked-account observability, which is not configured.")
		}
		k.Name = strings.TrimSuffix(strings.TrimPrefix(parts[5], "log-group:"), ":*")
	}
	if !groupNamePattern.MatchString(k.Name) {
		return k, invalid("The log group name is invalid.")
	}
	return k, nil
}
func reference(name *api.LogGroupName, id *api.LogGroupIdentifier) (string, *awswire.Error) {
	if (name == nil) == (id == nil) {
		return "", invalid("Specify exactly one of logGroupName and logGroupIdentifier.")
	}
	if name != nil {
		return value(name), nil
	}
	return value(id), nil
}
func resourceName(name, kind string) *awswire.Error {
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) < 1 || utf8.RuneCountInString(name) > 512 || strings.ContainsAny(name, ":*") {
		return invalid("The " + kind + " name is invalid.")
	}
	return nil
}
func (s *Service) authorize(r Reader, action string, g GroupRecord, stream string, tags map[string]string, keys []string) *awswire.Error {
	arn := g.Key.ARN() + ":*"
	switch action {
	case "TagResource", "UntagResource", "ListTagsForResource", "PutSubscriptionFilter":
		arn = g.Key.ARN()
	case "CreateLogStream", "DeleteLogStream", "PutLogEvents", "GetLogEvents":
		arn = g.Key.ARN() + ":log-stream:" + stream
	case "DescribeLogGroups", "ListLogGroups", "TestMetricFilter":
		arn = "*"
	case "DescribeResourcePolicies":
		arn = "*"
	case "PutResourcePolicy", "DeleteResourcePolicy", "DescribeMetricFilters":
		if g.Key.Name == "" {
			arn = "*"
		}
	}
	conditions := map[string][]string{}
	if action != "DescribeLogGroups" && action != "ListLogGroups" && action != "CreateLogGroup" {
		for k, v := range g.Tags {
			conditions["aws:ResourceTag/"+k] = []string{v}
		}
	}
	for k, v := range tags {
		conditions["aws:RequestTag/"+k] = []string{v}
		keys = append(keys, k)
	}
	if len(keys) > 0 {
		conditions["aws:TagKeys"] = keys
	}
	var policies []authorization.BoundPolicy
	if (action == "CreateLogStream" || action == "PutLogEvents") && awsctx.FromContext(r.Context()).ServicePrincipal.Name != "" {
		rows, err := r.ResourcePolicies(PolicyQuery{Scope: g.Key.Scope, PolicyScope: PolicyScopeAccount, Limit: maxAccountResourcePolicies})
		if err != nil {
			return wireError(err)
		}
		policies = make([]authorization.BoundPolicy, 0, len(rows)+1)
		for _, p := range rows {
			policies = append(policies, authorization.BoundPolicy{Document: p.Document})
		}
		p, err := r.ResourcePolicy(PolicyKey{Scope: g.Key.Scope, PolicyScope: PolicyScopeResource, Name: g.Key.ARN()})
		if err != nil && !errors.Is(err, ErrNotFound) {
			return wireError(err)
		}
		if err == nil && p.GroupID == g.ID {
			policies = append(policies, authorization.BoundPolicy{Document: p.Document})
		}
	}
	err := s.authorizer.Authorize(r.Context(), authorization.Request{Action: "logs:" + action, ResourceARN: arn, ResourceAccountID: g.Key.AccountID, ResourcePolicies: policies, Context: conditions})
	if err != nil && err.Code == "AccessDenied" {
		copy := *err
		copy.Code = "AccessDeniedException"
		copy.StatusCode = 400
		return &copy
	}
	return err
}
func (s *Service) loadGroup(r Reader, ref, action, stream string) (GroupRecord, *awswire.Error) {
	k, w := groupKey(r.Context(), ref)
	if w != nil {
		return GroupRecord{}, w
	}
	g, err := r.Group(k)
	if err != nil {
		if wire := s.authorize(r, action, GroupRecord{Key: k}, stream, nil, nil); wire != nil {
			return g, wire
		}
		return g, wireError(err)
	}
	if w := s.authorize(r, action, g, stream, nil, nil); w != nil {
		return g, w
	}
	return g, nil
}
func (s *Service) retainedAfter(g GroupRecord) int64 {
	// Visibility/accounting use the current policy independently of the worker's
	// physical deletion, so increasing retention can recover not-yet-deleted data.
	if g.RetentionDays > 0 {
		return s.clock.Now().UnixMilli() - int64(g.RetentionDays)*86400000
	}
	return 0
}
