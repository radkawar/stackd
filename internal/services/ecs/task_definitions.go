package ecs

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awsctx"
	"strconv"
	"strings"
	"time"
)

func (s *Service) registerTaskDefinition(ctx context.Context, tx Transaction, in *api.RegisterTaskDefinitionInput) (*api.RegisterTaskDefinitionOutput, error) {
	definition, rejected := normalizeTaskDefinition(in)
	if rejected != nil {
		return nil, rejected
	}
	tags, conditions, rejected := admitTags(in.Tags, "ClientException")
	if rejected != nil {
		return nil, rejected
	}
	family := FamilyKey{scopeFor(ctx), value(in.Family)}
	revision, err := tx.NextTaskDefinitionRevision(family)
	if err != nil {
		return nil, err
	}
	key := TaskDefinitionKey{family, revision}
	// Allocation and authorization share the transaction, so a denial cannot
	// consume a revision. The generated IAM catalog owns resource-level support.
	if definition.Cpu != nil {
		conditions["ecs:task-cpu"] = []string{value(definition.Cpu)}
	}
	if definition.Memory != nil {
		conditions["ecs:task-memory"] = []string{value(definition.Memory)}
	}
	for _, compatibility := range definition.RequiresCompatibilities {
		conditions["ecs:compute-compatibility"] = append(conditions["ecs:compute-compatibility"], string(compatibility))
	}
	privileged := false
	for _, container := range definition.ContainerDefinitions {
		privileged = privileged || container.Privileged != nil && bool(*container.Privileged)
	}
	conditions["ecs:privileged"] = []string{strconv.FormatBool(privileged)}
	if err := s.authorize(ctx, "RegisterTaskDefinition", key.ARN(), nil, conditions); err != nil {
		return nil, err
	}
	for _, role := range []*api.String{definition.TaskRoleArn, definition.ExecutionRoleArn} {
		if role == nil {
			continue
		}
		arn := value(role)
		parts := strings.SplitN(arn, ":", 6)
		if len(parts) != 6 || parts[0] != "arn" || parts[1] != family.Partition || parts[2] != "iam" || parts[3] != "" || parts[4] != family.AccountID || !strings.HasPrefix(parts[5], "role/") {
			return nil, failure("ClientException", "Role is not valid")
		}
		now := s.clock.Now()
		if err := s.authorizer.Authorize(ctx, authorization.Request{Action: "iam:PassRole", ResourceARN: arn, Context: map[string][]string{"iam:PassedToService": {"ecs-tasks.amazonaws.com"}}, EvaluationTime: &now}); err != nil {
			return nil, err
		}
	}
	if len(tags) > 0 {
		conditions["ecs:CreateAction"] = []string{"RegisterTaskDefinition"}
		if err := s.authorize(ctx, "TagResource", key.ARN(), nil, conditions); err != nil {
			return nil, err
		}
	}
	if err := s.reapTaskDefinitions(tx, family.Scope); err != nil {
		return nil, err
	}
	definition.Revision = new(api.Integer(revision))
	definition.TaskDefinitionArn = new(api.String(key.ARN()))
	definition.Status = new(api.TaskDefinitionStatus("ACTIVE"))
	definition.RegisteredAt = new(s.clock.Now().Truncate(time.Millisecond))
	definition.RegisteredBy = new(api.String(awsctx.FromContext(ctx).PrincipalARN))
	if err := tx.PutTaskDefinition(TaskDefinitionRecord{Key: key, Data: definition}); err != nil {
		return nil, err
	}
	if err := tx.PutTags(TagRecord{TagKey{family.Scope, key.ARN()}, tags}); err != nil {
		return nil, err
	}
	out := &api.RegisterTaskDefinitionOutput{TaskDefinition: &definition}
	if in.Tags != nil {
		out.Tags = tags
	}
	return out, nil
}
func (s *Service) describeTaskDefinition(ctx context.Context, tx Transaction, in *api.DescribeTaskDefinitionInput) (*api.DescribeTaskDefinitionOutput, error) {
	key, rejected := definitionKey(ctx, value(in.TaskDefinition), false)
	if rejected != nil {
		return nil, rejected
	}
	// DescribeTaskDefinition is an unscoped IAM action even when a revision is supplied.
	if err := s.authorize(ctx, "DescribeTaskDefinition", "*", nil, nil); err != nil {
		return nil, err
	}
	if err := s.reapTaskDefinitions(tx, key.Scope); err != nil {
		return nil, err
	}
	record, err := loadDefinition(tx, key)
	if errors.Is(err, ErrNotFound) {
		return nil, failure("ClientException", "Unable to describe task definition.")
	}
	if err != nil {
		return nil, err
	}
	record.Data.DeleteRequestedAt = nil
	out := &api.DescribeTaskDefinitionOutput{TaskDefinition: &record.Data, Tags: api.Tags{}}
	if slices.Contains(in.Include, api.TaskDefinitionField("TAGS")) {
		out.Tags, err = tagsFor(tx, key.Scope, record.Key.ARN())
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (s *Service) deregisterTaskDefinition(ctx context.Context, tx Transaction, in *api.DeregisterTaskDefinitionInput) (*api.DeregisterTaskDefinitionOutput, error) {
	key, rejected := definitionKey(ctx, value(in.TaskDefinition), true)
	if rejected != nil {
		return nil, rejected
	}
	if err := s.authorize(ctx, "DeregisterTaskDefinition", "*", nil, nil); err != nil {
		return nil, err
	}
	if err := s.reapTaskDefinitions(tx, key.Scope); err != nil {
		return nil, err
	}
	record, err := tx.TaskDefinition(key)
	if errors.Is(err, ErrNotFound) {
		return nil, failure("ClientException", "Unable to deregister task definition.")
	}
	if err != nil {
		return nil, err
	}
	if value(record.Data.Status) == "DELETE_IN_PROGRESS" {
		return nil, failure("ClientException", "The task definition could not be deregistered because it is in the process of being deleted.")
	}
	previous := record.Data.Status
	if value(record.Data.Status) == "ACTIVE" {
		record.Data.Status = new(api.TaskDefinitionStatus("INACTIVE"))
		record.Data.DeregisteredAt = new(s.clock.Now().Truncate(time.Millisecond))
		if err := tx.PutTaskDefinition(record); err != nil {
			return nil, err
		}
		record.Data.DeregisteredAt = nil
	}
	record.Data.PreviousStatus = previous
	return &api.DeregisterTaskDefinitionOutput{TaskDefinition: &record.Data}, nil
}
func (s *Service) deleteTaskDefinitions(ctx context.Context, tx Transaction, in *api.DeleteTaskDefinitionsInput) (*api.DeleteTaskDefinitionsOutput, error) {
	if len(in.TaskDefinitions) < 1 || len(in.TaskDefinitions) > 10 {
		return nil, failure("InvalidParameterException", "taskDefinitions must contain between 1 and 10 entries.")
	}
	if err := s.reapTaskDefinitions(tx, scopeFor(ctx)); err != nil {
		return nil, err
	}
	out := &api.DeleteTaskDefinitionsOutput{TaskDefinitions: api.TaskDefinitionList{}, Failures: api.Failures{}}
	for _, id := range in.TaskDefinitions {
		key, rejected := definitionKey(ctx, string(id), true)
		if rejected != nil {
			out.Failures = append(out.Failures, api.Failure{Arn: new(id), Reason: new(api.String("The specified task definition identifier is invalid. Specify a valid name or ARN and try again."))})
			continue
		}
		tags, err := tagsFor(tx, key.Scope, key.ARN())
		if err != nil {
			return nil, err
		}
		if err := s.authorize(ctx, "DeleteTaskDefinitions", key.ARN(), tags, nil); err != nil {
			return nil, err
		}
		record, err := tx.TaskDefinition(key)
		if errors.Is(err, ErrNotFound) {
			out.Failures = append(out.Failures, api.Failure{Arn: new(id), Reason: new(api.String("The specified task definition does not exist. Specify a valid account, family, revision and try again."))})
			continue
		}
		if err != nil {
			return nil, err
		}
		if value(record.Data.Status) == "ACTIVE" {
			out.Failures = append(out.Failures, api.Failure{Arn: new(id), Reason: new(api.String("The specified task definition is still in ACTIVE status. Please deregister the target and try again."))})
			continue
		}
		previous := record.Data.Status
		if record.Data.DeleteRequestedAt == nil {
			record.Data.DeleteRequestedAt = new(s.clock.Now().Truncate(time.Millisecond))
		}
		record.Data.Status = new(api.TaskDefinitionStatus("DELETE_IN_PROGRESS"))
		if err := tx.PutTaskDefinition(record); err != nil {
			return nil, err
		}
		record.Data.PreviousStatus = previous
		record.Data.DeleteRequestedAt = nil
		out.TaskDefinitions = append(out.TaskDefinitions, record.Data)
	}
	return out, nil
}
func (s *Service) listTaskDefinitions(ctx context.Context, tx Transaction, in *api.ListTaskDefinitionsInput) (*api.ListTaskDefinitionsOutput, error) {
	if err := s.authorize(ctx, "ListTaskDefinitions", "*", nil, nil); err != nil {
		return nil, err
	}
	status := value(in.Status)
	if status == "" {
		status = "ACTIVE"
	}
	if status != "ACTIVE" && status != "INACTIVE" && status != "DELETE_IN_PROGRESS" {
		return nil, failure("ClientException", "Invalid task definition status.")
	}
	order := value(in.Sort)
	if order == "" {
		order = "ASC"
	}
	if order != "ASC" && order != "DESC" {
		return nil, failure("InvalidParameterException", "Invalid sort order.")
	}
	limit, rejected := pageSize(in.MaxResults)
	if rejected != nil {
		return nil, rejected
	}
	scope := scopeFor(ctx)
	if err := s.reapTaskDefinitions(tx, scope); err != nil {
		return nil, err
	}
	query := TaskDefinitionQuery{Scope: scope, Family: value(in.FamilyPrefix), Status: status, Descending: order == "DESC", Limit: limit + 1}
	// ECS's native revision cursor is an observable family::zero-padded revision,
	// not a generic opaque page offset. Scope comes from the authenticated request.
	if in.NextToken != nil {
		family, revision, ok := strings.Cut(value(in.NextToken), "::")
		n, err := strconv.ParseInt(revision, 10, 32)
		if !ok || !resourceName.MatchString(family) || err != nil || n < 1 || query.Family != "" && family != query.Family {
			return nil, failure("InvalidParameterException", "Invalid next token.")
		}
		query.AfterFamily = family
		query.AfterRevision = int32(n)
	}
	rows, err := tx.TaskDefinitions(query)
	if err != nil {
		return nil, err
	}
	out := &api.ListTaskDefinitionsOutput{TaskDefinitionArns: api.StringList{}}
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1].Key
		out.NextToken = new(api.String(fmt.Sprintf("%s::%010d", last.Family, last.Revision)))
	}
	for _, row := range rows {
		out.TaskDefinitionArns = append(out.TaskDefinitionArns, api.String(row.Key.ARN()))
	}
	return out, nil
}
func (s *Service) listTaskDefinitionFamilies(ctx context.Context, tx Transaction, in *api.ListTaskDefinitionFamiliesInput) (*api.ListTaskDefinitionFamiliesOutput, error) {
	if err := s.authorize(ctx, "ListTaskDefinitionFamilies", "*", nil, nil); err != nil {
		return nil, err
	}
	status := value(in.Status)
	if status == "" {
		status = "ALL"
	}
	if status != "ALL" && status != "ACTIVE" && status != "INACTIVE" {
		return nil, failure("ClientException", "Invalid task definition family status.")
	}
	limit, rejected := pageSize(in.MaxResults)
	if rejected != nil {
		return nil, rejected
	}
	scope := scopeFor(ctx)
	if err := s.reapTaskDefinitions(tx, scope); err != nil {
		return nil, err
	}
	identity := collection(scope, "families", value(in.FamilyPrefix), status)
	after, rejected := page(in.NextToken, identity)
	if rejected != nil {
		return nil, rejected
	}
	rows, err := tx.TaskDefinitions(TaskDefinitionQuery{Scope: scope, FamilyPrefix: value(in.FamilyPrefix)})
	if err != nil {
		return nil, err
	}
	type familyState struct{ active, inactive bool }
	states := map[string]familyState{}
	families := []string{}
	for _, row := range rows {
		state, exists := states[row.Key.Family]
		if !exists {
			families = append(families, row.Key.Family)
		}
		switch value(row.Data.Status) {
		case "ACTIVE":
			state.active = true
		case "INACTIVE", "DELETE_IN_PROGRESS":
			state.inactive = true
		}
		states[row.Key.Family] = state
	}
	slices.Sort(families)
	out := &api.ListTaskDefinitionFamiliesOutput{Families: api.StringList{}}
	for _, family := range families {
		state := states[family]
		if family <= after || status == "ACTIVE" && !state.active || status == "INACTIVE" && !state.inactive || status == "ALL" && !state.active && !state.inactive {
			continue
		}
		if len(out.Families) == limit {
			out.NextToken = nextPage(identity, string(out.Families[len(out.Families)-1]))
			break
		}
		out.Families = append(out.Families, api.String(family))
	}
	return out, nil
}

// reapTaskDefinitions is called inside the resource transaction, including after
// task transitions. Live service deployments retain their revisions independently
// of desired count. After ownership ends, the documented one-hour deletion and
// stopped-task history windows still apply before the next resource access reaps it.
func (s *Service) reapTaskDefinitions(tx Transaction, scope Scope) error {
	definitions, err := tx.TaskDefinitions(TaskDefinitionQuery{Scope: scope, Status: "DELETE_IN_PROGRESS"})
	if err != nil || len(definitions) == 0 {
		return err
	}
	now := s.clock.Now()
	candidates := make(map[string]bool, len(definitions))
	for _, definition := range definitions {
		if requested := definition.Data.DeleteRequestedAt; requested != nil && !now.Before(requested.Add(time.Hour)) {
			candidates[definition.Key.ARN()] = true
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	clusters, err := tx.Clusters(ClusterQuery{Scope: scope, IncludeInactive: true})
	if err != nil {
		return err
	}
	for _, cluster := range clusters {
		services, err := tx.Services(ServiceQuery{ClusterKey: cluster.Key, IncludeInactive: true})
		if err != nil {
			return err
		}
		for _, service := range services {
			if status := value(service.Data.Status); status != "ACTIVE" && status != "DRAINING" {
				continue
			}
			for _, deployment := range service.Deployments {
				delete(candidates, value(deployment.Definition.TaskDefinitionArn))
			}
		}
		if len(candidates) == 0 {
			return nil
		}
		tasks, err := tx.Tasks(TaskQuery{ClusterKey: cluster.Key})
		if err != nil {
			return err
		}
		for _, task := range tasks {
			arn := value(task.Data.TaskDefinitionArn)
			if _, candidate := candidates[arn]; !candidate {
				continue
			}
			if value(task.Data.LastStatus) != "STOPPED" || task.Data.StoppedAt != nil && now.Before(task.Data.StoppedAt.Add(time.Hour)) {
				delete(candidates, arn)
			}
		}
		if len(candidates) == 0 {
			return nil
		}
	}
	for _, definition := range definitions {
		if _, eligible := candidates[definition.Key.ARN()]; eligible {
			if err := tx.DeleteTaskDefinition(definition.Key); err != nil {
				return err
			}
		}
	}
	return nil
}
