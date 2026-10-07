package xray

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"slices"
	"strings"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/xray"
)

// The regional quota includes the always-present Default group.
const groupLimit = 25

func defaultGroup(scope Scope) GroupRecord {
	return GroupRecord{Key: GroupKey{Scope: scope, Name: "Default"}, Version: 1, Tags: map[string]string{}}
}

func validGroupName(name string) bool {
	if len(name) < 1 || len(name) > 32 {
		return false
	}
	for _, c := range name {
		if c != '-' && !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func groupKey(scope Scope, name, arn string) (GroupKey, error) {
	key := GroupKey{Scope: scope, Name: name}
	if name == "" && arn == "" || name != "" && arn != "" {
		return key, failure("InvalidRequestException", "Provide either GroupName or GroupARN")
	}
	if arn != "" {
		prefix := (GroupKey{Scope: scope}).ARN()
		if !strings.HasPrefix(arn, prefix) {
			return key, failure("InvalidRequestException", "Invalid group ARN")
		}
		parts := strings.Split(strings.TrimPrefix(arn, prefix), "/")
		if len(parts) == 1 && parts[0] == "Default" {
			key.Name = "Default"
		} else if len(parts) == 2 && parts[0] != "Default" && parts[1] != "" {
			key.Name, key.ID = parts[0], parts[1]
		} else {
			return key, failure("InvalidRequestException", "Invalid group ARN")
		}
	}
	if !validGroupName(key.Name) {
		return key, failure("InvalidRequestException", "Invalid group name")
	}
	return key, nil
}

// resolveGroup preserves the requested key on ErrNotFound so callers can
// authorize before reporting absence.
func resolveGroup(r Reader, name, arn string) (GroupRecord, error) {
	key, err := groupKey(scopeFor(r.Context()), name, arn)
	if err != nil {
		return GroupRecord{}, err
	}
	if arn != "" || key.Name == "Default" {
		row, err := r.Group(key)
		if errors.Is(err, ErrNotFound) && key.Name == "Default" {
			return defaultGroup(key.Scope), nil
		}
		if errors.Is(err, ErrNotFound) {
			return GroupRecord{Key: key}, ErrNotFound
		}
		return row, err
	}
	rows, err := r.Groups(key.Scope)
	if err != nil {
		return GroupRecord{}, err
	}
	for _, row := range rows {
		if row.Key.Name == key.Name {
			return row, nil
		}
	}
	return GroupRecord{Key: key}, ErrNotFound
}

// Expressions use the current configuration, never retained graph membership.
func groupExpressions(rows []GroupRecord) map[string]string {
	result := make(map[string]string, len(rows)*2+1)
	result["Default"] = ""
	for _, row := range rows {
		result[row.Key.Name] = row.FilterExpression
		result[row.Key.ARN()] = row.FilterExpression
		result[(GroupKey{Scope: row.Key.Scope, Name: "Default"}).ARN()] = ""
	}
	return result
}

func groupOutput(row GroupRecord) *api.Group {
	out := &api.Group{GroupARN: new(api.String(row.Key.ARN())), GroupName: new(api.String(row.Key.Name)), InsightsConfiguration: &api.InsightsConfiguration{InsightsEnabled: new(api.NullableBoolean(false)), NotificationsEnabled: new(api.NullableBoolean(false))}}
	if row.Key.Name != "Default" {
		out.FilterExpression = new(api.String(row.FilterExpression))
	}
	return out
}

func validateGroupInsights(in *api.InsightsConfiguration) error {
	if in != nil && (in.InsightsEnabled != nil && bool(*in.InsightsEnabled) || in.NotificationsEnabled != nil && bool(*in.NotificationsEnabled)) {
		// TODO: Comeback implement real Insights detection and notification
		// dependencies before accepting enabled group Insights configuration.
		return failure("NotImplementedException", "X-Ray Insights and Insights notifications are not implemented", 501)
	}
	return nil
}

func (s *Service) createGroup(tx Transaction, in *api.CreateGroupRequest) (*api.CreateGroupResult, error) {
	name := value(in.GroupName)
	if !validGroupName(name) {
		return nil, failure("InvalidRequestException", "Invalid group name")
	}
	scope := scopeFor(tx.Context())
	rows, err := tx.Groups(scope)
	if err != nil {
		return nil, err
	}
	key := GroupKey{Scope: scope, Name: name}
	var currentTags map[string]string
	for _, row := range rows {
		if row.Key.Name == name {
			key, currentTags = row.Key, row.Tags
			break
		}
	}
	if key.ID == "" && !cloudFormationRecovering(tx.Context()) {
		var random [32]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, err
		}
		key.ID = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(random[:])
	}
	tags, err := validateTags(in.Tags)
	if err != nil {
		return nil, err
	}
	request := authorization.Request{Action: "xray:CreateGroup", ResourceARN: key.ARN(), Context: tagContext(currentTags, tags, nil), ContextTypes: map[string]string{"aws:TagKeys": "stringList"}}
	if err := s.authorizeResource(tx, request); err != nil {
		return nil, err
	}
	if len(tags) != 0 {
		request.Action = "xray:TagResource"
		if err := s.authorizeResource(tx, request); err != nil {
			return nil, err
		}
	}
	if name == "Default" {
		return nil, failure("InvalidRequestException", "Default is a reserved group name")
	}
	if err := validateGroupInsights(in.InsightsConfiguration); err != nil {
		return nil, err
	}
	count := 1
	for _, row := range rows {
		if row.Key.Name == name {
			if _, ok := tx.Context().Value(cloudFormationOwnerKey{}).(cloudFormationOwner); !ok {
				return nil, failure("InvalidRequestException", name+" already exists")
			}
			if _, err := cloudFormationClaim(tx.Context(), row.CFNOwner, true); err != nil {
				return nil, err
			}
			return &api.CreateGroupResult{Group: groupOutput(row)}, nil
		}
		if row.Key.Name != "Default" {
			count++
		}
	}
	if cloudFormationRecovering(tx.Context()) {
		return nil, failure("ResourceNotFoundException", "Group not found", 404)
	}
	claim, err := cloudFormationClaim(tx.Context(), "", false)
	if err != nil {
		return nil, err
	}
	if count >= groupLimit {
		return nil, failure("InvalidRequestException", "The maximum number of groups has been reached")
	}
	if strings.TrimSpace(value(in.FilterExpression)) == "" {
		return nil, failure("InvalidRequestException", "Filter Expression is empty")
	}
	row := GroupRecord{Key: key, FilterExpression: value(in.FilterExpression), Version: 1, Tags: tags, CFNOwner: claim}
	if _, err := compileTraceFilter(row.FilterExpression, groupExpressions(append(rows, row))); err != nil {
		return nil, err
	}
	if err := tx.PutGroup(row); err != nil {
		return nil, err
	}
	return &api.CreateGroupResult{Group: groupOutput(row)}, nil
}

func (s *Service) updateGroup(tx Transaction, in *api.UpdateGroupRequest) (*api.UpdateGroupResult, error) {
	row, err := resolveGroup(tx, value(in.GroupName), value(in.GroupARN))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if authErr := s.authorizeResource(tx, authorization.Request{Action: "xray:UpdateGroup", ResourceARN: row.Key.ARN(), Context: tagContext(row.Tags, nil, nil)}); authErr != nil {
		return nil, authErr
	}
	if err != nil {
		return nil, failure("InvalidRequestException", "Group not found")
	}
	if _, err := cloudFormationClaim(tx.Context(), row.CFNOwner, true); err != nil {
		return nil, err
	}
	if err := validateGroupInsights(in.InsightsConfiguration); err != nil {
		return nil, err
	}
	if row.Key.Name == "Default" {
		return nil, failure("InvalidRequestException", "The Default group filter expression cannot be changed")
	}
	if strings.TrimSpace(value(in.FilterExpression)) == "" {
		return nil, failure("InvalidRequestException", "Filter Expression is empty")
	}
	rows, err := tx.Groups(row.Key.Scope)
	if err != nil {
		return nil, err
	}
	expressions := groupExpressions(rows)
	expressions[row.Key.Name], expressions[row.Key.ARN()] = value(in.FilterExpression), value(in.FilterExpression)
	if _, err := compileTraceFilter(value(in.FilterExpression), expressions); err != nil {
		return nil, err
	}
	if row.FilterExpression != value(in.FilterExpression) {
		row.FilterExpression = value(in.FilterExpression)
		row.Version++
		if err := tx.PutGroup(row); err != nil {
			return nil, err
		}
	}
	return &api.UpdateGroupResult{Group: groupOutput(row)}, nil
}

func (s *Service) deleteGroup(tx Transaction, in *api.DeleteGroupRequest) (*api.DeleteGroupResult, error) {
	row, err := resolveGroup(tx, value(in.GroupName), value(in.GroupARN))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if authErr := s.authorizeResource(tx, authorization.Request{Action: "xray:DeleteGroup", ResourceARN: row.Key.ARN(), Context: tagContext(row.Tags, nil, nil)}); authErr != nil {
		return nil, authErr
	}
	if err != nil {
		return nil, failure("InvalidRequestException", "Group not found")
	}
	if _, err := cloudFormationClaim(tx.Context(), row.CFNOwner, true); err != nil {
		return nil, err
	}
	if row.Key.Name == "Default" {
		return nil, failure("InvalidRequestException", "The Default group cannot be deleted")
	}
	if err := tx.DeleteGroup(row.Key); err != nil {
		return nil, err
	}
	if audit, ok := tx.Context().Value(groupAuditKey{}).(*groupAudit); ok {
		audit.ARN = row.Key.ARN()
	}
	return &api.DeleteGroupResult{}, nil
}

func (s *Service) getGroup(tx Transaction, in *api.GetGroupRequest) (*api.GetGroupResult, error) {
	row, err := resolveGroup(tx, value(in.GroupName), value(in.GroupARN))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if authErr := s.authorizeResource(tx, authorization.Request{Action: "xray:GetGroup", ResourceARN: row.Key.ARN(), Context: tagContext(row.Tags, nil, nil)}); authErr != nil {
		return nil, authErr
	}
	if err != nil {
		return nil, failure("InvalidRequestException", "Group not found")
	}
	return &api.GetGroupResult{Group: groupOutput(row)}, nil
}

func (s *Service) getGroups(tx Transaction, in *api.GetGroupsRequest) (*api.GetGroupsResult, error) {
	if err := s.authorizeResource(tx, authorization.Request{Action: "xray:GetGroups", ResourceARN: "*"}); err != nil {
		return nil, err
	}
	// Native rejects continuation tokens; the bounded active set is one page.
	if value(in.NextToken) != "" {
		return nil, failure("InvalidRequestException", "Next Token not supported")
	}
	scope := scopeFor(tx.Context())
	rows, err := tx.Groups(scope)
	if err != nil {
		return nil, err
	}
	foundDefault := false
	for _, row := range rows {
		foundDefault = foundDefault || row.Key.Name == "Default"
	}
	if !foundDefault {
		rows = append(rows, defaultGroup(scope))
	}
	slices.SortFunc(rows, func(a, b GroupRecord) int {
		if a.Key.Name == b.Key.Name {
			return strings.Compare(a.Key.ID, b.Key.ID)
		}
		if a.Key.Name == "Default" {
			return -1
		}
		if b.Key.Name == "Default" {
			return 1
		}
		return strings.Compare(a.Key.Name, b.Key.Name)
	})
	out := &api.GetGroupsResult{Groups: make(api.GroupSummaryList, 0, len(rows))}
	for _, row := range rows {
		group := groupOutput(row)
		out.Groups = append(out.Groups, api.GroupSummary{FilterExpression: group.FilterExpression, GroupARN: group.GroupARN, GroupName: group.GroupName, InsightsConfiguration: group.InsightsConfiguration})
	}
	return out, nil
}
