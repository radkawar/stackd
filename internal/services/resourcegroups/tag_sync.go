package resourcegroups

import (
	"encoding/base32"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/resourcegroups"
)

var tagSyncTaskARN = regexp.MustCompile(`^arn:aws(-[a-z]+)*:resource-groups:[a-z]{2}(-[a-z]+)+-[0-9]:[0-9]{12}:group/[a-zA-Z0-9_.-]{1,150}/[a-z0-9]{26}/tag-sync-task/[a-z0-9]{26}$`)

func (s *Service) startTagSyncTask(tx Transaction, in *api.StartTagSyncTaskInput) (*api.StartTagSyncTaskOutput, error) {
	g, err := s.loadGroup(tx, value(in.Group), "StartTagSyncTask")
	if err != nil {
		return nil, err
	}
	if g.ManagedType != applicationGroupType {
		return nil, failure("BadRequestException", "Tag synchronization requires an application group.")
	}
	if in.ResourceQuery != nil && (in.TagKey != nil || in.TagValue != nil) {
		return nil, failure("BadRequestException", "Specify ResourceQuery or TagKey and TagValue, not both.")
	}
	query := in.ResourceQuery
	usesTag := query == nil
	if usesTag {
		if in.TagKey == nil || in.TagValue == nil || value(in.TagKey) == "" {
			return nil, failure("BadRequestException", "Specify ResourceQuery or both TagKey and TagValue.")
		}
		document, _ := json.Marshal(resourceQuery{ResourceTypeFilters: []string{"AWS::AllSupported"}, TagFilters: []tagFilter{{Key: value(in.TagKey), Values: []string{value(in.TagValue)}}}})
		query = &api.ResourceQuery{Type: new(api.QueryTypeTAG_FILTERS_1_0), Query: new(api.Query(document))}
	}
	if _, err := parseQuery(query); err != nil {
		return nil, err
	}
	if value(query.Type) != string(api.QueryTypeTAG_FILTERS_1_0) {
		return nil, failure("BadRequestException", "Tag synchronization requires a tag-based ResourceQuery.")
	}
	role, err := arn.Parse(value(in.RoleArn))
	if err != nil || role.Partition != g.Partition || role.AccountID != g.AccountID || role.Service != "iam" || role.Region != "" || !strings.HasPrefix(role.Resource, "role/") {
		return nil, failure("BadRequestException", "RoleArn must identify an IAM role in this account and partition.")
	}
	if err := s.authorize(tx.Context(), "CreateGroup", nil, nil, nil); err != nil {
		return nil, err
	}
	now := s.clock.Now()
	if denied := s.authorizer.Authorize(tx.Context(), authorization.Request{Action: "iam:PassRole", ResourceARN: role.String(), Context: map[string][]string{"iam:PassedToService": {"resource-groups.amazonaws.com"}}, EvaluationTime: &now}); denied != nil {
		return nil, denied
	}
	if s.roles == nil || s.applicationResources == nil {
		return nil, failure("NotImplementedException", "Tag synchronization requires current owner tagging and delegated IAM role authority.")
	}
	if _, err := s.roles.AssumeTagSyncRole(tx.Context(), role.String(), g.ARN); err != nil {
		return nil, err
	}
	id := uuid.New()
	suffix := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(id[:]))
	t := TagSyncTask{Scope: g.Scope, ARN: g.ARN + "/tag-sync-task/" + suffix, GroupARN: g.ARN, GroupName: g.Name, RoleARN: role.String(), Query: *query, UsesTag: usesTag, TagKey: value(in.TagKey), TagValue: value(in.TagValue), Status: "ACTIVE", Created: now, NextCheck: now, Version: 1}
	if err := tx.PutTagSyncTask(t); err != nil {
		return nil, err
	}
	out := &api.StartTagSyncTaskOutput{GroupArn: new(api.GroupArnV2(t.GroupARN)), GroupName: new(api.GroupName(t.GroupName)), TaskArn: new(api.TagSyncTaskArn(t.ARN)), RoleArn: in.RoleArn}
	if usesTag {
		out.TagKey = in.TagKey
		out.TagValue = in.TagValue
	} else {
		out.ResourceQuery = query
	}
	return out, nil
}

func (s *Service) getTagSyncTask(tx Transaction, in *api.GetTagSyncTaskInput) (*api.GetTagSyncTaskOutput, error) {
	t, err := s.loadTagSyncTask(tx, value(in.TaskArn), "GetTagSyncTask")
	if err != nil {
		return nil, err
	}
	item := taskItem(t)
	return &api.GetTagSyncTaskOutput{CreatedAt: item.CreatedAt, ErrorMessage: item.ErrorMessage, GroupArn: item.GroupArn, GroupName: item.GroupName, ResourceQuery: item.ResourceQuery, RoleArn: item.RoleArn, Status: item.Status, TagKey: item.TagKey, TagValue: item.TagValue, TaskArn: item.TaskArn}, nil
}

func (s *Service) cancelTagSyncTask(tx Transaction, in *api.CancelTagSyncTaskInput) (*api.CancelTagSyncTaskOutput, error) {
	t, err := s.loadTagSyncTask(tx, value(in.TaskArn), "CancelTagSyncTask")
	if err != nil {
		return nil, err
	}
	if err := s.authorizeTagSyncGroup(tx, t.GroupARN, "DeleteGroup"); err != nil {
		return nil, err
	}
	// Cancellation deletes the task, not the resources or their current tags.
	// Neither the API nor the guide promises retroactive awsApplication removal.
	if err := tx.DeleteTagSyncTask(t.ARN); err != nil {
		return nil, err
	}
	return &api.CancelTagSyncTaskOutput{}, nil
}
func (s *Service) loadTagSyncTask(tx Reader, taskARN, action string) (TagSyncTask, error) {
	if !tagSyncTaskARN.MatchString(taskARN) {
		return TagSyncTask{}, failure("BadRequestException", "TaskArn must be a valid tag-sync task ARN.")
	}
	groupARN, _, _ := strings.Cut(taskARN, "/tag-sync-task/")
	if err := s.authorizeTagSyncGroup(tx, groupARN, action); err != nil {
		return TagSyncTask{}, err
	}
	rows, err := tx.TagSyncTasks()
	if err != nil {
		return TagSyncTask{}, err
	}
	for _, t := range rows {
		if t.ARN == taskARN && t.Scope == scopeFor(tx.Context()) {
			return t, nil
		}
	}
	return TagSyncTask{}, failure("NotFoundException", "Cannot find task: "+taskARN)
}

// Task lookup authorizes the group even when it no longer exists.
func (s *Service) authorizeTagSyncGroup(tx Reader, id, action string) error {
	scope := scopeFor(tx.Context())
	g, ok, err := tx.Group(scope, id)
	if err != nil {
		return err
	}
	if !ok {
		if !strings.HasPrefix(id, "arn:") {
			id = groupARN(scope, id)
		}
		g = Group{Scope: scope, ARN: id}
	}
	return s.authorize(tx.Context(), action, &g, nil, nil)
}
func taskItem(t TagSyncTask) api.TagSyncTaskItem {
	out := api.TagSyncTaskItem{CreatedAt: &t.Created, GroupArn: new(api.GroupArnV2(t.GroupARN)), GroupName: new(api.GroupName(t.GroupName)), TaskArn: new(api.TagSyncTaskArn(t.ARN)), RoleArn: new(api.RoleArn(t.RoleARN)), Status: new(api.TagSyncTaskStatus(t.Status))}
	if t.ErrorMessage != "" {
		out.ErrorMessage = new(api.ErrorMessage(t.ErrorMessage))
	}
	if t.UsesTag {
		out.TagKey = new(api.TagKey(t.TagKey))
		out.TagValue = new(api.TagValue(t.TagValue))
	} else {
		out.ResourceQuery = &t.Query
	}
	return out
}
func (s *Service) listTagSyncTasks(tx Transaction, in *api.ListTagSyncTasksInput) (*api.ListTagSyncTasksOutput, error) {
	if len(in.Filters) == 0 {
		if err := s.authorize(tx.Context(), "ListTagSyncTasks", nil, nil, nil); err != nil {
			return nil, err
		}
	}
	for _, filter := range in.Filters {
		arn, name := value(filter.GroupArn), value(filter.GroupName)
		if arn == "" && name == "" {
			return nil, failure("BadRequestException", "Filters parameter must contain GroupArn or GroupName")
		}
		if arn != "" && name != "" {
			return nil, failure("BadRequestException", "Filters parameter can only contain a GroupArn or GroupName, not both")
		}
		id := arn
		if id == "" {
			id = name
		}
		if err := s.authorizeTagSyncGroup(tx, id, "ListTagSyncTasks"); err != nil {
			return nil, err
		}
	}
	rows, err := tx.TagSyncTasks()
	if err != nil {
		return nil, err
	}
	items := []api.TagSyncTaskItem{}
	for _, t := range rows {
		if t.Scope != scopeFor(tx.Context()) {
			continue
		}
		matches := len(in.Filters) == 0
		for _, f := range in.Filters {
			if value(f.GroupArn) == t.GroupARN || value(f.GroupName) == t.GroupName {
				matches = true
			}
		}
		if matches {
			items = append(items, taskItem(t))
		}
	}
	request := *in
	request.NextToken = nil
	request.MaxResults = nil
	items, token, err := paginate(tx.Context(), "ListTagSyncTasks", request, in.NextToken, in.MaxResults, items, func(t api.TagSyncTaskItem) string { return value(t.TaskArn) })
	if err != nil {
		return nil, err
	}
	return &api.ListTagSyncTasksOutput{TagSyncTasks: items, NextToken: token}, nil
}
