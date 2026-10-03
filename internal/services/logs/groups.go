package logs

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awswire"
)

// EnsureLogGroup creates a missing group through the ordinary authorized
// command. Existing groups require no CreateLogGroup permission, and this
// existence check grants no authority to append events.
func (s *Service) EnsureLogGroup(ctx context.Context, groupName string) *awswire.Error {
	err := s.repository.View(ctx, func(r Reader) error {
		_, err := r.Group(GroupKey{Scope: scopeFor(ctx), Name: groupName})
		return err
	})
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrNotFound) {
		return wireError(err)
	}
	_, wire := s.CreateLogGroup(ctx, &api.CreateLogGroupRequest{LogGroupName: new(api.LogGroupName(groupName))})
	if wire != nil && wire.Code == "ResourceAlreadyExistsException" {
		return nil
	}
	return wire
}

func (s *Service) createLogGroup(tx Transaction, in *api.CreateLogGroupRequest) (*api.Unit, *awswire.Error) {
	if in == nil {
		return nil, invalid("A request is required.")
	}
	name := value(in.LogGroupName)
	if strings.HasPrefix(name, "arn:") || strings.HasPrefix(name, "aws/") {
		return nil, invalid("The log group name is invalid.")
	}
	k, w := groupKey(tx.Context(), name)
	if w != nil {
		return nil, w
	}
	// TODO: Comeback implement KMS-backed encryption, non-STANDARD storage classes and deletion protection.
	if value(in.KmsKeyId) != "" {
		return nil, unsupported("KMS log encryption is not configured.")
	}
	if value(in.LogGroupClass) != "" && value(in.LogGroupClass) != "STANDARD" {
		return nil, unsupported("Only STANDARD log group storage is implemented.")
	}
	if enabled(in.DeletionProtectionEnabled) {
		return nil, unsupported("Log group deletion protection is not implemented.")
	}
	tags, w := tagValues(in.Tags)
	if w != nil {
		return nil, w
	}
	g := GroupRecord{Key: k, ID: uuid.NewString(), Created: s.clock.Now().UnixMilli(), Tags: tags}
	if w := s.authorize(tx, "CreateLogGroup", g, "", tags, nil); w != nil {
		return nil, w
	}
	if len(tags) > 0 {
		uncreated := GroupRecord{Key: k}
		if denied := s.authorize(tx, "TagResource", uncreated, "", tags, nil); denied != nil {
			if legacy := s.authorize(tx, "TagLogGroup", uncreated, "", tags, nil); legacy != nil {
				return nil, denied
			}
		}
	}
	if _, err := tx.Group(k); err == nil {
		return nil, failure("ResourceAlreadyExistsException", "The specified log group already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, wireError(err)
	}
	if err := tx.PutGroup(g); err != nil {
		return nil, wireError(err)
	}
	return &api.Unit{}, nil
}
func (s *Service) deleteLogGroup(tx Transaction, in *api.DeleteLogGroupRequest) (*api.Unit, *awswire.Error) {
	g, w := s.loadGroup(tx, value(in.LogGroupName), "DeleteLogGroup", "")
	if w != nil {
		return nil, w
	}
	if err := tx.DeleteGroup(g.Key); err != nil {
		return nil, wireError(err)
	}
	return &api.Unit{}, nil
}
func groupOutput(g GroupRecord, pattern bool) api.LogGroup {
	out := api.LogGroup{LogGroupName: new(api.LogGroupName(g.Key.Name)), Arn: new(api.Arn(g.Key.ARN() + ":*")), CreationTime: new(api.Timestamp(g.Created))}
	if pattern {
		return out
	}
	out.LogGroupArn = new(api.Arn(g.Key.ARN()))
	out.LogGroupClass = new(api.LogGroupClass("STANDARD"))
	out.MetricFilterCount = new(api.FilterCount(0))
	out.StoredBytes = new(api.StoredBytes(0))
	out.DeletionProtectionEnabled = new(api.DeletionProtectionEnabled(false))
	out.BearerTokenAuthenticationEnabled = new(api.BearerTokenAuthenticationEnabled(false))
	if g.RetentionDays > 0 {
		out.RetentionInDays = new(api.Days(g.RetentionDays))
	}
	return out
}
func (s *Service) describeLogGroups(tx Transaction, in *api.DescribeLogGroupsRequest) (*api.DescribeLogGroupsResponse, *awswire.Error) {
	if enabled(in.IncludeLinkedAccounts) || len(in.AccountIdentifiers) > 0 {
		return nil, unsupported("Linked-account observability is not configured.")
	}
	if in.LogGroupNamePrefix != nil && in.LogGroupNamePattern != nil {
		return nil, invalid("logGroupNamePrefix and logGroupNamePattern are mutually exclusive.")
	}
	if len(in.LogGroupIdentifiers) > 0 && (in.LogGroupNamePrefix != nil || in.LogGroupNamePattern != nil || in.LogGroupClass != nil) {
		return nil, invalid("logGroupIdentifiers cannot be combined with other log group filters.")
	}
	n, w := pageLimit(in.Limit, 50, 50)
	if w != nil {
		return nil, w
	}
	scope := scopeFor(tx.Context())
	if w := s.authorize(tx, "DescribeLogGroups", GroupRecord{Key: GroupKey{Scope: scope}}, "", nil, nil); w != nil {
		return nil, w
	}
	names := []string{}
	for _, id := range in.LogGroupIdentifiers {
		if strings.HasPrefix(string(id), "arn:") {
			return nil, unsupported("ARN logGroupIdentifiers require monitoring-account observability, which is not configured.")
		}
		k, w := groupKey(tx.Context(), string(id))
		if w != nil {
			return nil, w
		}
		names = append(names, k.Name)
	}
	slices.Sort(names)
	query := queryIdentity("DescribeLogGroups", scope, value(in.LogGroupNamePrefix), value(in.LogGroupNamePattern), value(in.LogGroupClass), names)
	token, w := s.decodeToken(value(in.NextToken), query)
	if w != nil {
		return nil, w
	}
	out := &api.DescribeLogGroupsResponse{LogGroups: api.LogGroups{}}
	q := GroupQuery{Scope: scope, After: token.Name, Prefix: value(in.LogGroupNamePrefix), Contains: value(in.LogGroupNamePattern), Class: value(in.LogGroupClass), Limit: n + 1}
	for {
		rows, err := tx.Groups(q)
		if err != nil {
			return nil, wireError(err)
		}
		for _, g := range rows {
			q.After = g.Key.Name
			if len(names) > 0 && !slices.Contains(names, g.Key.Name) {
				continue
			}
			if len(out.LogGroups) == n {
				out.NextToken = encodeToken(token)
				return out, nil
			}
			item := groupOutput(g, in.LogGroupNamePattern != nil)
			if in.LogGroupNamePattern == nil {
				bytes, err := tx.StoredBytes(g.ID, s.retainedAfter(g))
				if err != nil {
					return nil, wireError(err)
				}
				item.StoredBytes = new(api.StoredBytes(bytes))
			}
			out.LogGroups = append(out.LogGroups, item)
			token.Name = g.Key.Name
		}
		if len(rows) < q.Limit {
			return out, nil
		}
	}
}
func (s *Service) listLogGroups(tx Transaction, in *api.ListLogGroupsRequest) (*api.ListLogGroupsResponse, *awswire.Error) {
	if enabled(in.IncludeLinkedAccounts) || len(in.AccountIdentifiers) > 0 {
		return nil, unsupported("Linked-account observability is not configured.")
	}
	if len(in.DataSources) > 0 || len(in.FieldIndexNames) > 0 {
		return nil, unsupported("Data-source and field-index filtering require unimplemented Logs integrations.")
	}
	n, w := pageLimit(in.Limit, 50, 1000)
	if w != nil {
		return nil, w
	}
	scope := scopeFor(tx.Context())
	if w := s.authorize(tx, "ListLogGroups", GroupRecord{Key: GroupKey{Scope: scope}}, "", nil, nil); w != nil {
		return nil, w
	}
	var pattern *regexp.Regexp
	if in.LogGroupNamePattern != nil {
		var err error
		pattern, err = regexp.Compile(value(in.LogGroupNamePattern))
		if err != nil {
			return nil, invalid("The log group name pattern is invalid.")
		}
	}
	query := queryIdentity("ListLogGroups", scope, value(in.LogGroupNamePattern), value(in.LogGroupClass), in.LogGroupTags)
	token, w := s.decodeToken(value(in.NextToken), query)
	if w != nil {
		return nil, w
	}
	out := &api.ListLogGroupsResponse{LogGroups: api.LogGroupSummaries{}}
	q := GroupQuery{Scope: scope, After: token.Name, Class: value(in.LogGroupClass), Limit: n + 1}
	for {
		rows, err := tx.Groups(q)
		if err != nil {
			return nil, wireError(err)
		}
		for _, g := range rows {
			q.After = g.Key.Name
			if pattern != nil && !pattern.MatchString(g.Key.Name) || !matchesTags(g.Tags, in.LogGroupTags) {
				continue
			}
			if len(out.LogGroups) == n {
				out.NextToken = encodeToken(token)
				return out, nil
			}
			out.LogGroups = append(out.LogGroups, api.LogGroupSummary{LogGroupName: new(api.LogGroupName(g.Key.Name)), LogGroupArn: new(api.Arn(g.Key.ARN())), LogGroupClass: new(api.LogGroupClass("STANDARD"))})
			token.Name = g.Key.Name
		}
		if len(rows) < q.Limit {
			return out, nil
		}
	}
}
func matchesTags(tags map[string]string, filters api.TagFilters) bool {
	for _, f := range filters {
		v, ok := tags[value(f.Key)]
		if !ok {
			return false
		}
		if len(f.Values) > 0 && !slices.Contains(f.Values, api.TagFilterValue(v)) {
			return false
		}
	}
	return true
}
