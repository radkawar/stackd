package eventbridge

import (
	"context"
	"errors"
	"strings"

	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awsschedule"
	"stackd/internal/awswire"
	"stackd/internal/services/eventbridge/eventpattern"
)

func (s *Service) registerRules() {
	register(s, "PutRule", s.putRule)
	register(s, "DescribeRule", s.describeRule)
	register(s, "DeleteRule", s.deleteRule)
	register(s, "EnableRule", s.enableRule)
	register(s, "DisableRule", s.disableRule)
	register(s, "ListRules", s.listRules)
}
func (s *Service) putRule(ctx context.Context, in *api.PutRuleInput) (out *api.PutRuleOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "PutRule", in, &out, &rejected, false)
	if value(in.EventPattern) == "" && value(in.ScheduleExpression) == "" {
		return nil, failure("ValidationException", "Parameter(s) EventPattern or ScheduleExpression must be specified.")
	}
	var schedule awsschedule.Schedule
	if expression := value(in.ScheduleExpression); expression != "" {
		var err error
		schedule, err = awsschedule.ParseEventBridge(expression)
		if err != nil {
			return nil, failure("ValidationException", "Parameter ScheduleExpression is not valid.")
		}
	}
	if pattern := value(in.EventPattern); pattern != "" {
		if _, err := eventpattern.Compile([]byte(pattern)); err != nil {
			return nil, failure("InvalidEventPatternException", err.Error())
		}
	}
	// PutRule uses the endpoint Region even when an ARN names another Region.
	bus, wire := resolveBus(scopeFor(ctx), value(in.EventBusName), true)
	if wire != nil {
		return nil, wire
	}
	if in.ScheduleExpression != nil && bus.Name != "default" {
		return nil, failure("ValidationException", "ScheduleExpression is supported only on the default event bus.")
	}
	k := RuleKey{bus, value(in.Name)}
	state := value(in.State)
	if state == "" {
		state = "ENABLED"
	}
	if state == "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS" && value(in.ScheduleExpression) != "" {
		return nil, failure("ValidationException", "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS rule state is not supported with scheduled rule expressions.")
	}
	tags, conditions, wire := tagInput(in.Tags)
	if wire != nil {
		return nil, wire
	}
	conditions["events:EventBusName"] = []string{bus.Name}
	err := s.configUpdate(ctx, bus, true, func(tx Transaction) error {
		old, foundErr := tx.Rule(k)
		if foundErr != nil && !errors.Is(foundErr, ErrNotFound) {
			return foundErr
		}
		old.Key = k
		if foundErr != nil {
			old.CreatedBy = scopeFor(ctx).Account
		}
		if err := s.authorizeRule(tx, "PutRule", old, conditions); err != nil {
			return err
		}
		if err := cloudFormationRuleCheck(tx.Context(), old, foundErr == nil); err != nil {
			return err
		}
		if old.ManagedBy != "" {
			return managedRuleError(old, false)
		}
		if _, err := s.bus(tx, bus); err != nil {
			return err
		}
		if roleARN := value(in.RoleArn); roleARN != "" {
			if denied := s.passRole(tx.Context(), roleARN, k.ARN()); denied != nil {
				return denied
			}
			if s.roles == nil {
				return unsupported("Rule execution-role authority is not configured.")
			}
			if rejected := s.roles.ValidateRuleRole(tx.Context(), roleARN, k); rejected != nil {
				return rejected
			}
		}
		if foundErr == nil {
			tags = old.Tags
		}
		rule := RuleRecord{Key: k, Pattern: value(in.EventPattern), Description: value(in.Description), State: state, CreatedBy: old.CreatedBy, RoleARN: value(in.RoleArn), Tags: tags,
			ScheduleExpression: value(in.ScheduleExpression), HasPattern: in.EventPattern != nil, HasDescription: in.Description != nil, HasScheduleExpression: in.ScheduleExpression != nil}
		rule.CFNOwner = old.CFNOwner
		if foundErr != nil {
			rule.CFNOwner = cloudFormationClaim(tx.Context(), "Rule")
		}
		if state != "DISABLED" && rule.ScheduleExpression != "" {
			if foundErr == nil && old.State != "DISABLED" && old.ScheduleExpression == rule.ScheduleExpression {
				rule.NextSchedule = old.NextSchedule
			} else if first, ok := schedule.First(s.clock.Now()); ok {
				rule.NextSchedule = &first
			}
		}
		if err := tx.PutRule(rule); err != nil {
			return err
		}
		out = &api.PutRuleOutput{RuleArn: str[api.RuleArn](k.ARN())}
		return s.recordCall(tx.Context(), "PutRule", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}
func (s *Service) describeRule(ctx context.Context, in *api.DescribeRuleInput) (out *api.DescribeRuleOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "DescribeRule", in, &out, &rejected, true)
	bus, wire := busKey(ctx, value(in.EventBusName))
	if wire != nil {
		return nil, wire
	}
	k := RuleKey{bus, value(in.Name)}
	var rule RuleRecord
	err := s.configUpdate(ctx, bus, true, func(tx Transaction) error {
		var err error
		rule, err = tx.Rule(k)
		if err != nil {
			return err
		}
		return s.authorizeRule(tx, "DescribeRule", rule, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	out = &api.DescribeRuleOutput{Arn: str[api.RuleArn](k.ARN()), Name: in.Name, EventBusName: str[api.EventBusName](bus.Name), State: str[api.RuleState](rule.State), CreatedBy: str[api.CreatedBy](rule.CreatedBy)}
	if rule.ManagedBy != "" {
		out.ManagedBy = str[api.ManagedBy](rule.ManagedBy)
	}
	if rule.HasPattern {
		out.EventPattern = str[api.EventPattern](rule.Pattern)
	}
	if rule.HasScheduleExpression {
		out.ScheduleExpression = str[api.ScheduleExpression](rule.ScheduleExpression)
	}
	if rule.HasDescription {
		out.Description = str[api.RuleDescription](rule.Description)
	}
	if rule.RoleARN != "" {
		out.RoleArn = str[api.RoleArn](rule.RoleARN)
	}
	return out, nil
}
func (s *Service) deleteRule(ctx context.Context, in *api.DeleteRuleInput) (out *api.DeleteRuleOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "DeleteRule", in, &out, &rejected, false)
	bus, wire := busKey(ctx, value(in.EventBusName))
	if wire != nil {
		return nil, wire
	}
	k := RuleKey{bus, value(in.Name)}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		rule, err := tx.Rule(k)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		found := err == nil
		rule.Key = k
		if err := s.authorizeRule(tx, "DeleteRule", rule, nil); err != nil {
			return err
		}
		if err := cloudFormationRuleCheck(tx.Context(), rule, found); err != nil {
			return err
		}
		if !found && cloudFormationClaim(tx.Context(), "Rule") != "" {
			return ErrNotFound // Controller deletion observes absence; it never acts on a successor.
		}
		if rule.ManagedBy != "" && (in.Force == nil || !bool(*in.Force)) {
			return managedRuleError(rule, true)
		}
		if _, err := s.bus(tx, bus); err != nil {
			return err
		}
		targets, err := tx.Targets(k)
		if err != nil {
			return err
		}
		if len(targets) > 0 {
			return failure("ValidationException", "Rule cannot be deleted since it has targets.")
		}
		if err := disableManagedArchive(tx, rule); err != nil {
			return err
		}
		if err := tx.DeleteRule(k); err != nil {
			return err
		}
		out = &api.DeleteRuleOutput{}
		return s.recordCall(tx.Context(), "DeleteRule", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}
func (s *Service) setRuleState(ctx context.Context, busName, name, state, action string, input, output any) *awswire.Error {
	bus, wire := busKey(ctx, busName)
	if wire != nil {
		return wire
	}
	k := RuleKey{bus, name}
	err := s.configUpdate(ctx, bus, true, func(tx Transaction) error {
		rule, err := tx.Rule(k)
		if err != nil {
			return err
		}
		if err := s.authorizeRule(tx, action, rule, nil); err != nil {
			return err
		}
		if rule.ManagedBy != "" {
			return managedRuleError(rule, false)
		}
		if state == "DISABLED" {
			rule.NextSchedule = nil
		} else if rule.State == "DISABLED" && rule.ScheduleExpression != "" {
			schedule, err := awsschedule.ParseEventBridge(rule.ScheduleExpression)
			if err != nil {
				return err
			}
			if first, ok := schedule.First(s.clock.Now()); ok {
				rule.NextSchedule = &first
			}
		}
		rule.State = state
		if err := tx.PutRule(rule); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), action, input, output, nil)
	})
	if err == nil {
		s.jobs.Wake()
	}
	return wireError(err)
}
func (s *Service) enableRule(ctx context.Context, in *api.EnableRuleInput) (out *api.EnableRuleOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "EnableRule", in, &out, &rejected, false)
	out = &api.EnableRuleOutput{}
	if err := s.setRuleState(ctx, value(in.EventBusName), value(in.Name), "ENABLED", "EnableRule", in, out); err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Service) disableRule(ctx context.Context, in *api.DisableRuleInput) (out *api.DisableRuleOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "DisableRule", in, &out, &rejected, false)
	out = &api.DisableRuleOutput{}
	if err := s.setRuleState(ctx, value(in.EventBusName), value(in.Name), "DISABLED", "DisableRule", in, out); err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Service) listRules(ctx context.Context, in *api.ListRulesInput) (out *api.ListRulesOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "ListRules", in, &out, &rejected, false)
	bus, wire := busKey(ctx, value(in.EventBusName))
	if wire != nil {
		return nil, wire
	}
	prefix := value(in.NamePrefix)
	var rows []RuleRecord
	err := s.configUpdate(ctx, bus, true, func(tx Transaction) error {
		record, err := s.bus(tx, bus)
		if err != nil {
			return err
		}
		if err := s.authorize(tx, "ListRules", bus.ARN(), record.Tags, nil, record.Policy); err != nil {
			return err
		}
		rows, err = tx.Rules(bus)
		if err != nil {
			return err
		}
		filtered := rows[:0]
		for _, v := range rows {
			if strings.HasPrefix(v.Key.Name, prefix) {
				filtered = append(filtered, v)
			}
		}
		rows, next, wire := page(filtered, func(v RuleRecord) string { return v.Key.Name }, bus.ARN()+"/ListRules/"+prefix, in.Limit, in.NextToken, "InvalidTokenException")
		if wire != nil {
			return wire
		}
		out = &api.ListRulesOutput{Rules: api.RuleResponseList{}, NextToken: next}
		for _, v := range rows {
			rule := api.Rule{Arn: str[api.RuleArn](v.Key.ARN()), Name: str[api.RuleName](v.Key.Name), EventBusName: str[api.EventBusName](bus.Name), State: str[api.RuleState](v.State)}
			if v.ManagedBy != "" {
				rule.ManagedBy = str[api.ManagedBy](v.ManagedBy)
			}
			if v.HasPattern {
				rule.EventPattern = str[api.EventPattern](v.Pattern)
			}
			if v.HasScheduleExpression {
				rule.ScheduleExpression = str[api.ScheduleExpression](v.ScheduleExpression)
			}
			if v.HasDescription {
				rule.Description = str[api.RuleDescription](v.Description)
			}
			if v.RoleARN != "" {
				rule.RoleArn = str[api.RoleArn](v.RoleARN)
			}
			out.Rules = append(out.Rules, rule)
		}
		return s.recordCall(tx.Context(), "ListRules", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
