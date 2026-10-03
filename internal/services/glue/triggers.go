package glue

import (
	"context"
	"errors"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awsschedule"
	"strings"
	"time"
)

func registerTriggers(s *Service) {
	registerControl(s, "CreateTrigger", s.createTrigger)
	registerControl(s, "UpdateTrigger", s.updateTrigger)
	registerControl(s, "DeleteTrigger", s.deleteTrigger)
	registerControl(s, "GetTrigger", s.getTrigger)
	registerControl(s, "GetTriggers", s.getTriggers)
	registerControl(s, "ListTriggers", s.listTriggers)
	registerControl(s, "BatchGetTriggers", s.batchGetTriggers)
	registerControl(s, "StartTrigger", s.startTrigger)
	registerControl(s, "StopTrigger", s.stopTrigger)
}
func triggerSchedule(expression string, now time.Time) (*time.Time, error) {
	if !strings.HasPrefix(expression, "cron(") {
		return nil, failure("InvalidInputException", "Glue schedules require a cron expression.")
	}
	schedule, err := awsschedule.ParseEventBridge(expression)
	if err != nil {
		return nil, failure("InvalidInputException", "Invalid schedule expression.")
	}
	next, ok := schedule.Next(now)
	if !ok {
		return nil, nil
	}
	// Calendar minute/hour fields repeat each eligible day. Check the first
	// complete daily pattern, not only its first pair (e.g. minutes 0,5,6).
	previous := next
	for range 289 {
		after, ok := schedule.Next(previous)
		if !ok {
			break
		}
		if after.Sub(previous) < 5*time.Minute {
			return nil, failure("InvalidInputException", "Schedule interval must be at least five minutes.")
		}
		if after.Sub(next) >= 24*time.Hour {
			break
		}
		previous = after
	}
	return &next, nil
}
func validateTrigger(v api.Trigger) error {
	// TODO: Comeback deliver Glue delayed job notifications through EventBridge
	// before admitting trigger actions that request NotificationProperty.
	// TODO: Comeback consume EventBridge deliveries and retain EVENT batching
	// windows before admitting EVENT triggers.
	for _, a := range v.Actions {
		if a.NotificationProperty != nil {
			return unsupported("Delayed Glue job notifications are not implemented.")
		}
	}
	if len(v.Actions) == 0 {
		return failure("InvalidInputException", "A trigger requires at least one action.")
	}
	crawlers := 0
	for _, a := range v.Actions {
		if (value(a.JobName) == "") == (value(a.CrawlerName) == "") {
			return failure("InvalidInputException", "An action must specify exactly one job or crawler.")
		}
		if value(a.CrawlerName) != "" {
			crawlers++
			if a.Arguments != nil || a.Timeout != nil || a.SecurityConfiguration != nil || a.NotificationProperty != nil {
				return failure("InvalidInputException", "Job parameters cannot be used with crawler actions.")
			}
		}
		if a.Timeout != nil && (*a.Timeout < 1 || *a.Timeout > 10080) {
			return failure("InvalidInputException", "Action timeout is out of range.")
		}
	}
	if crawlers > 2 {
		return failure("InvalidInputException", "A trigger can start at most two crawlers.")
	}
	switch value(v.Type) {
	case "ON_DEMAND":
		if v.Predicate != nil || v.Schedule != nil {
			return failure("InvalidInputException", "On-demand triggers cannot have a schedule or predicate.")
		}
	case "SCHEDULED":
		if v.Schedule == nil || v.Predicate != nil {
			return failure("InvalidInputException", "A scheduled trigger requires a schedule and no predicate.")
		}
	case "CONDITIONAL":
		if v.Predicate == nil || len(v.Predicate.Conditions) == 0 || v.Schedule != nil {
			return failure("InvalidInputException", "A conditional trigger requires a predicate and no schedule.")
		}
		if len(v.Predicate.Conditions) > 1 && value(v.Predicate.Logical) != "AND" && value(v.Predicate.Logical) != "ANY" {
			return failure("InvalidInputException", "A multi-condition predicate requires AND or ANY.")
		}
		for _, c := range v.Predicate.Conditions {
			if value(c.LogicalOperator) != "EQUALS" {
				return failure("InvalidInputException", "Only EQUALS conditions are supported by Glue.")
			}
			if (value(c.JobName) == "") == (value(c.CrawlerName) == "") {
				return failure("InvalidInputException", "A condition requires exactly one job or crawler.")
			}
			if value(c.JobName) != "" {
				switch value(c.State) {
				case "SUCCEEDED", "STOPPED", "FAILED", "TIMEOUT":
				default:
					return failure("InvalidInputException", "Invalid job condition state.")
				}
				if c.CrawlState != nil {
					return failure("InvalidInputException", "A job condition cannot contain CrawlState.")
				}
			} else {
				switch value(c.CrawlState) {
				case "SUCCEEDED", "FAILED", "CANCELLED":
				default:
					return failure("InvalidInputException", "Invalid crawler condition state.")
				}
				if c.State != nil {
					return failure("InvalidInputException", "A crawler condition cannot contain State.")
				}
			}
		}
	case "EVENT":
		return unsupported("EventBridge Glue trigger delivery is not implemented.")
	default:
		return failure("InvalidInputException", "Invalid trigger type.")
	}
	if v.EventBatchingCondition != nil {
		return failure("InvalidInputException", "Event batching requires an EVENT trigger.")
	}
	return nil
}
func (s *Service) triggerAccess(ctx context.Context, tx Reader, action string, key ResourceKey) (TriggerRecord, error) {
	v, err := tx.Trigger(key)
	if err != nil {
		return v, err
	}
	return v, s.authorize(ctx, tx, action, key.Scope, key.ARN("trigger"), v.Tags)
}
func (s *Service) createTrigger(ctx context.Context, tx Transaction, in *api.CreateTriggerInput) (*api.CreateTriggerOutput, error) {
	key := ResourceKey{scopeFor(ctx), value(in.Name)}
	if err := workflowName(key.Name); err != nil {
		return nil, err
	}
	v := TriggerRecord{Key: key, Trigger: api.Trigger{Name: in.Name, Type: in.Type, Description: in.Description, Actions: in.Actions, Predicate: in.Predicate, Schedule: in.Schedule, WorkflowName: in.WorkflowName, EventBatchingCondition: in.EventBatchingCondition, State: new(api.TriggerStateCREATED)}}
	if err := validateTrigger(v.Trigger); err != nil {
		return nil, err
	}
	tags, err := workflowInputTags(in.Tags)
	if err != nil {
		return nil, err
	}
	v.Tags = tags
	if err = s.authorizeCreate(ctx, tx, "CreateTrigger", key.Scope, key.ARN("trigger"), tags); err != nil {
		return nil, err
	}
	if _, err = tx.Trigger(key); err == nil {
		return nil, failure("AlreadyExistsException", "Trigger already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if value(in.WorkflowName) != "" {
		if _, err = tx.Workflow(ResourceKey{key.Scope, value(in.WorkflowName)}); err != nil {
			return nil, err
		}
	}
	var next *time.Time
	if in.Schedule != nil {
		next, err = triggerSchedule(value(in.Schedule), s.clock.Now())
		if err != nil {
			return nil, err
		}
	}
	if in.StartOnCreation != nil && bool(*in.StartOnCreation) {
		if value(in.Type) == "ON_DEMAND" {
			return nil, failure("InvalidInputException", "On-demand triggers cannot be activated on creation.")
		}
		v.Trigger.State = new(api.TriggerStateACTIVATED)
		if value(in.Type) == "SCHEDULED" {
			v.NextFire = next
		}
	}
	if err = tx.PutTrigger(v); err != nil {
		return nil, err
	}
	return &api.CreateTriggerOutput{Name: in.Name}, nil
}
func (s *Service) updateTrigger(ctx context.Context, tx Transaction, in *api.UpdateTriggerInput) (*api.UpdateTriggerOutput, error) {
	v, err := s.triggerAccess(ctx, tx, "UpdateTrigger", ResourceKey{scopeFor(ctx), value(in.Name)})
	if err != nil {
		return nil, err
	}
	u := in.TriggerUpdate
	if u == nil {
		return nil, failure("InvalidInputException", "TriggerUpdate is required.")
	}
	if u.Name != nil && value(u.Name) != v.Key.Name {
		return nil, failure("InvalidInputException", "A trigger cannot be renamed.")
	}
	v.Trigger.Actions = u.Actions
	v.Trigger.Description = u.Description
	v.Trigger.Predicate = u.Predicate
	v.Trigger.Schedule = u.Schedule
	v.Trigger.EventBatchingCondition = u.EventBatchingCondition
	if err = validateTrigger(v.Trigger); err != nil {
		return nil, err
	}
	if value(v.Trigger.Type) == "SCHEDULED" {
		next, err := triggerSchedule(value(v.Trigger.Schedule), s.clock.Now())
		if err != nil {
			return nil, err
		}
		if value(v.Trigger.State) == "ACTIVATED" {
			v.NextFire = next
		}
	}
	if err = tx.PutTrigger(v); err != nil {
		return nil, err
	}
	return &api.UpdateTriggerOutput{Trigger: &v.Trigger}, nil
}
func (s *Service) deleteTrigger(ctx context.Context, tx Transaction, in *api.DeleteTriggerInput) (*api.DeleteTriggerOutput, error) {
	key := ResourceKey{scopeFor(ctx), value(in.Name)}
	v, err := tx.Trigger(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err = s.authorize(ctx, tx, "DeleteTrigger", key.Scope, key.ARN("trigger"), v.Tags); err != nil {
		return nil, err
	}
	if err = tx.DeleteTrigger(key); err != nil {
		return nil, err
	}
	return &api.DeleteTriggerOutput{Name: in.Name}, nil
}
func (s *Service) getTrigger(ctx context.Context, tx Transaction, in *api.GetTriggerInput) (*api.GetTriggerOutput, error) {
	v, err := s.triggerAccess(ctx, tx, "GetTrigger", ResourceKey{scopeFor(ctx), value(in.Name)})
	if err != nil {
		return nil, err
	}
	return &api.GetTriggerOutput{Trigger: &v.Trigger}, nil
}
func (s *Service) startTrigger(ctx context.Context, tx Transaction, in *api.StartTriggerInput) (*api.StartTriggerOutput, error) {
	v, err := s.triggerAccess(ctx, tx, "StartTrigger", ResourceKey{scopeFor(ctx), value(in.Name)})
	if err != nil {
		return nil, err
	}
	if value(v.Trigger.Type) == "ON_DEMAND" {
		if _, err = s.admitTriggerRun(tx, v, nil); err != nil {
			return nil, err
		}
	} else {
		v.Trigger.State = new(api.TriggerStateACTIVATED)
		if value(v.Trigger.Type) == "SCHEDULED" && v.NextFire == nil {
			v.NextFire, err = triggerSchedule(value(v.Trigger.Schedule), s.clock.Now())
			if err != nil {
				return nil, err
			}
		}
		if err = tx.PutTrigger(v); err != nil {
			return nil, err
		}
	}
	return &api.StartTriggerOutput{Name: in.Name}, nil
}
func (s *Service) stopTrigger(ctx context.Context, tx Transaction, in *api.StopTriggerInput) (*api.StopTriggerOutput, error) {
	v, err := s.triggerAccess(ctx, tx, "StopTrigger", ResourceKey{scopeFor(ctx), value(in.Name)})
	if err != nil {
		return nil, err
	}
	if value(v.Trigger.Type) == "ON_DEMAND" {
		return nil, failure("InvalidInputException", "An on-demand trigger cannot be deactivated.")
	}
	v.Trigger.State = new(api.TriggerStateDEACTIVATED)
	v.NextFire = nil
	if err = tx.PutTrigger(v); err != nil {
		return nil, err
	}
	return &api.StopTriggerOutput{Name: in.Name}, nil
}
func triggerFilter(rows []TriggerRecord, job string, tags api.TagsMap) []TriggerRecord {
	out := make([]TriggerRecord, 0, len(rows))
	for _, v := range rows {
		match := job == ""
		for _, a := range v.Trigger.Actions {
			if value(a.JobName) == job && job != "" {
				match = true
			}
		}
		for k, want := range tags {
			if got, ok := v.Tags[string(k)]; !ok || got != string(want) {
				match = false
			}
		}
		if match {
			out = append(out, v)
		}
	}
	return out
}
func (s *Service) getTriggers(ctx context.Context, tx Transaction, in *api.GetTriggersInput) (*api.GetTriggersOutput, error) {
	scope := scopeFor(ctx)
	if err := s.authorize(ctx, tx, "GetTriggers", scope, "*", nil); err != nil {
		return nil, err
	}
	rows, err := tx.Triggers(scope)
	if err != nil {
		return nil, err
	}
	rows = triggerFilter(rows, value(in.DependentJobName), nil)
	rows, token, err := workflowPage(rows, func(v TriggerRecord) string { return v.Key.Name }, "triggers/"+workflowScope(scope)+"/"+value(in.DependentJobName), in.MaxResults, in.NextToken, 200)
	if err != nil {
		return nil, err
	}
	out := &api.GetTriggersOutput{NextToken: token, Triggers: api.TriggerList{}}
	for _, v := range rows {
		out.Triggers = append(out.Triggers, v.Trigger)
	}
	return out, nil
}
func (s *Service) listTriggers(ctx context.Context, tx Transaction, in *api.ListTriggersInput) (*api.ListTriggersOutput, error) {
	scope := scopeFor(ctx)
	if err := s.authorize(ctx, tx, "ListTriggers", scope, "*", nil); err != nil {
		return nil, err
	}
	rows, err := tx.Triggers(scope)
	if err != nil {
		return nil, err
	}
	rows = triggerFilter(rows, value(in.DependentJobName), in.Tags)
	filter, _ := jsonTriggerTags(in.Tags)
	rows, token, err := workflowPage(rows, func(v TriggerRecord) string { return v.Key.Name }, "trigger-names/"+workflowScope(scope)+"/"+value(in.DependentJobName)+filter, in.MaxResults, in.NextToken, 200)
	if err != nil {
		return nil, err
	}
	out := &api.ListTriggersOutput{NextToken: token, TriggerNames: api.TriggerNameList{}}
	for _, v := range rows {
		out.TriggerNames = append(out.TriggerNames, api.NameString(v.Key.Name))
	}
	return out, nil
}
func (s *Service) batchGetTriggers(ctx context.Context, tx Transaction, in *api.BatchGetTriggersInput) (*api.BatchGetTriggersOutput, error) {
	out := &api.BatchGetTriggersOutput{Triggers: api.TriggerList{}, TriggersNotFound: api.TriggerNameList{}}
	for _, name := range in.TriggerNames {
		v, err := s.triggerAccess(ctx, tx, "BatchGetTriggers", ResourceKey{scopeFor(ctx), string(name)})
		if errors.Is(err, ErrNotFound) {
			out.TriggersNotFound = append(out.TriggersNotFound, name)
			continue
		}
		if err != nil {
			return nil, err
		}
		out.Triggers = append(out.Triggers, v.Trigger)
	}
	return out, nil
}
