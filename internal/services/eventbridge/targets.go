package eventbridge

import (
	"context"
	"strings"

	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/internal/services/eventbridge/inputtransform"
)

func (s *Service) registerTargets() {
	register(s, "PutTargets", s.putTargets)
	register(s, "ListTargetsByRule", s.listTargets)
	register(s, "ListRuleNamesByTarget", s.listRuleNamesByTarget)
	register(s, "RemoveTargets", s.removeTargets)
}
func targetRecord(rule RuleKey, in api.Target) (TargetRecord, *awswire.Error) {
	v := TargetRecord{Rule: rule, ID: value(in.Id), ARN: value(in.Arn), RoleARN: value(in.RoleArn), MaxRetries: 185, MaxAgeSeconds: 86400}
	p := strings.SplitN(v.ARN, ":", 6)
	if len(p) != 6 || p[0] != "arn" {
		return v, failure("ValidationException", "Target must identify a valid ARN.")
	}
	apiDestination := p[2] == "events" && strings.HasPrefix(p[5], "api-destination/")
	if apiDestination {
		resource := strings.Split(p[5], "/")
		if len(resource) != 3 || resource[1] == "" || resource[2] == "" || p[1] != rule.Bus.Partition || p[3] != rule.Bus.Region || p[4] != rule.Bus.Account {
			return v, failure("ValidationException", "API destination targets must identify a resource in the event bus account and Region.")
		}
		if v.RoleARN == "" {
			return v, failure("ValidationException", "RoleArn is required for target "+v.ARN+".")
		}
		if !validInvocationRole(rule, v.RoleARN) {
			return v, failure("ValidationException", "RoleArn must identify an IAM role in the event bus account for an API destination target.")
		}
		v.HttpParameters = cloneHTTPParameters(in.HttpParameters)
	} else if in.HttpParameters != nil {
		return v, unsupported("HTTP parameters require an API destination target.")
	}
	if p[2] == "ecs" {
		if rejected := validateECSTarget(rule, in); rejected != nil {
			return v, rejected
		}
		v.EcsParameters = cloneECSParameters(in.EcsParameters)
		if v.EcsParameters.TaskCount == nil {
			v.EcsParameters.TaskCount = ptr(api.LimitMin1(1))
		}
		if v.EcsParameters.EnableECSManagedTags == nil {
			v.EcsParameters.EnableECSManagedTags = ptr(api.Boolean(false))
		}
		if v.EcsParameters.EnableExecuteCommand == nil {
			v.EcsParameters.EnableExecuteCommand = ptr(api.Boolean(false))
		}
	} else if in.EcsParameters != nil {
		return v, failure("ValidationException", "EcsParameters require an ECS cluster target.")
	}
	if p[2] == "kinesis" {
		if rejected := validateKinesisTarget(rule, in); rejected != nil {
			return v, rejected
		}
		v.KinesisParameters = cloneKinesisParameters(in.KinesisParameters)
	} else if in.KinesisParameters != nil {
		return v, failure("ValidationException", "KinesisParameters require a Kinesis stream target.")
	}
	if p[2] == "firehose" {
		if rejected := validateFirehoseTarget(rule, in); rejected != nil {
			return v, rejected
		}
	}
	if p[2] == "codepipeline" {
		if strings.ContainsAny(p[5], ":/") || !validInvocationRole(rule, v.RoleARN) {
			return v, failure("ValidationException", "CodePipeline targets require a pipeline ARN and an IAM role in the event bus account.")
		}
		if p[4] != rule.Bus.Account {
			// TODO: Comeback — cross-account CodePipeline targets need their actual target-account invocation owner.
			return v, unsupported("Cross-account CodePipeline target delivery is not implemented.")
		}
	}
	if p[2] == "states" {
		// StartExecution owns machine existence and version/alias resolution.
		// Keep qualified ARNs intact rather than narrowing targets to latest.
		if !strings.HasPrefix(p[5], "stateMachine:") {
			return v, failure("ValidationException", "Step Functions targets must identify a state machine ARN.")
		}
		if v.RoleARN == "" {
			return v, failure("ValidationException", "RoleArn is required for target "+v.ARN+".")
		}
	}
	if p[2] == "logs" {
		if in.RoleArn != nil {
			return v, failure("ValidationException", "RoleArn is not supported for target "+v.ARN+".")
		}
		if in.Input != nil || in.InputPath != nil {
			return v, failure("ValidationException", "Input and InputPath are not valid forms of input for target "+v.ID+". The only valid form of input is InputTransformer.")
		}
		group, ok := strings.CutPrefix(p[5], "log-group:")
		if !ok || group == "" || strings.Contains(group, ":") {
			return v, failure("ValidationException", "Parameter "+v.ARN+" is not valid. Reason: Provided Arn is not in correct format.")
		}
	}
	if p[2] == "events" && !apiDestination {
		if awscatalog.RegionPartition(p[3]) != rule.Bus.Partition {
			return v, failure("ValidationException", "Event bus targets must identify a supported Region in the same partition.")
		}
		scope := rule.Bus.Scope
		scope.Region = p[3]
		targetBus, rejected := resolveBus(scope, v.ARN, false)
		if rejected != nil {
			return v, rejected
		}
		if targetBus == rule.Bus {
			return v, failure("ValidationException", "An event bus cannot target itself.")
		}
		if v.RoleARN == "" {
			return v, failure("ValidationException", "RoleArn is required for event bus targets.")
		}
		if in.Input != nil || in.InputPath != nil || in.InputTransformer != nil {
			return v, failure("ValidationException", "Input, InputPath and InputTransformer are not supported for event bus targets.")
		}
		if in.RetryPolicy != nil {
			return v, failure("ValidationException", "RetryPolicy is not supported for event bus targets.")
		}
	}
	if in.Input != nil {
		v.Input.Input = ptr(value(in.Input))
	}
	if in.InputPath != nil {
		v.Input.InputPath = ptr(value(in.InputPath))
	}
	if in.InputTransformer != nil {
		v.Input.Transformer = &inputtransform.Transformer{InputTemplate: value(in.InputTransformer.InputTemplate)}
		if in.InputTransformer.InputPathsMap != nil {
			v.Input.Transformer.InputPathsMap = make(map[string]string, len(in.InputTransformer.InputPathsMap))
			for key, path := range in.InputTransformer.InputPathsMap {
				v.Input.Transformer.InputPathsMap[string(key)] = string(path)
			}
		}
	}
	if _, err := inputtransform.Compile(v.Input); err != nil {
		return v, failure("ValidationException", err.Error())
	}
	if in.AppSyncParameters != nil || in.BatchParameters != nil || in.RedshiftDataParameters != nil || in.RunCommandParameters != nil || in.SageMakerPipelineParameters != nil {
		return v, unsupported("The supplied target parameters are not implemented.")
	}
	if p[2] != "sqs" && p[2] != "sns" && p[2] != "lambda" && p[2] != "logs" && p[2] != "events" && p[2] != "ecs" && p[2] != "kinesis" && p[2] != "firehose" && p[2] != "states" && p[2] != "codepipeline" {
		return v, unsupported("Only SQS, SNS, Lambda, CloudWatch Logs, ECS, Kinesis, Firehose, Step Functions, CodePipeline and event bus target delivery is implemented.")
	}
	if p[1] != rule.Bus.Partition || p[2] != "events" && p[2] != "firehose" && p[3] != rule.Bus.Region || len(p[4]) != 12 || strings.Trim(p[4], "0123456789") != "" || p[5] == "" {
		return v, failure("ValidationException", "Target must identify a resource in the event bus partition and, except for event bus and Firehose targets, Region.")
	}
	if p[2] == "lambda" && !strings.HasPrefix(p[5], "function:") {
		return v, failure("ValidationException", "Lambda targets must identify a function ARN.")
	}
	if in.SqsParameters != nil {
		v.MessageGroupID = value(in.SqsParameters.MessageGroupId)
	}
	if p[2] == "sqs" && strings.HasSuffix(p[5], ".fifo") && v.MessageGroupID == "" {
		return v, failure("ValidationException", "SqsParameters.MessageGroupId is required for a FIFO queue.")
	}
	if in.DeadLetterConfig != nil {
		v.DeadLetterARN = value(in.DeadLetterConfig.Arn)
		if v.DeadLetterARN != "" {
			if !validDeadLetterARN(rule.Bus, v.DeadLetterARN) {
				return v, failure("ValidationException", "The dead-letter queue must be a standard SQS queue in the same Region.")
			}
		}
	}
	if in.RetryPolicy != nil {
		v.HasRetryPolicy = true
		if in.RetryPolicy.MaximumRetryAttempts != nil {
			v.MaxRetries = int(*in.RetryPolicy.MaximumRetryAttempts)
			v.HasMaxRetries = true
		}
		if in.RetryPolicy.MaximumEventAgeInSeconds != nil {
			v.MaxAgeSeconds = int(*in.RetryPolicy.MaximumEventAgeInSeconds)
			v.HasMaxAge = true
		}
	}
	return v, nil
}
func targetOutput(v TargetRecord, managed bool) api.Target {
	out := api.Target{Id: str[api.TargetId](v.ID), Arn: str[api.TargetArn](v.ARN)}
	out.EcsParameters = cloneECSParameters(v.EcsParameters)
	out.KinesisParameters = cloneKinesisParameters(v.KinesisParameters)
	out.HttpParameters = cloneHTTPParameters(v.HttpParameters)
	if v.RoleARN != "" {
		out.RoleArn = str[api.RoleArn](v.RoleARN)
	}
	if v.Input.Input != nil {
		out.Input = str[api.TargetInput](*v.Input.Input)
	}
	if v.Input.InputPath != nil {
		out.InputPath = str[api.TargetInputPath](*v.Input.InputPath)
	}
	if v.Input.Transformer != nil {
		out.InputTransformer = &api.InputTransformer{InputTemplate: str[api.TransformerInput](v.Input.Transformer.InputTemplate)}
		if managed || v.Input.Transformer.InputPathsMap != nil {
			out.InputTransformer.InputPathsMap = api.TransformerPaths{}
			for key, path := range v.Input.Transformer.InputPathsMap {
				out.InputTransformer.InputPathsMap[api.InputTransformerPathKey(key)] = api.TargetInputPath(path)
			}
		}
	}
	if v.MessageGroupID != "" {
		out.SqsParameters = &api.SqsParameters{MessageGroupId: str[api.MessageGroupId](v.MessageGroupID)}
	}
	if v.DeadLetterARN != "" {
		out.DeadLetterConfig = &api.DeadLetterConfig{Arn: str[api.ResourceArn](v.DeadLetterARN)}
	}
	if v.HasRetryPolicy {
		out.RetryPolicy = &api.RetryPolicy{}
		if v.HasMaxRetries {
			out.RetryPolicy.MaximumRetryAttempts = ptr(api.MaximumRetryAttempts(v.MaxRetries))
		}
		if v.HasMaxAge {
			out.RetryPolicy.MaximumEventAgeInSeconds = ptr(api.MaximumEventAgeInSeconds(v.MaxAgeSeconds))
		}
	}
	return out
}
func (s *Service) putTargets(ctx context.Context, in *api.PutTargetsInput) (out *api.PutTargetsOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "PutTargets", in, &out, &rejected, false)
	bus, wire := busKey(ctx, value(in.EventBusName))
	if wire != nil {
		return nil, wire
	}
	k := RuleKey{bus, value(in.Rule)}
	out = &api.PutTargetsOutput{FailedEntries: api.PutTargetsResultEntryList{}, FailedEntryCount: ptr(api.Integer(0))}
	err := s.configUpdate(ctx, bus, true, func(tx Transaction) error {
		rule, err := tx.Rule(k)
		if err != nil {
			return err
		}
		conditions := map[string][]string{}
		for _, target := range in.Targets {
			conditions["events:TargetArn"] = append(conditions["events:TargetArn"], value(target.Arn))
		}
		if err := s.authorizeRule(tx, "PutTargets", rule, conditions); err != nil {
			return err
		}
		if bus.Account != scopeFor(ctx).Account {
			for _, target := range in.Targets {
				parts := strings.SplitN(value(target.Arn), ":", 6)
				if len(parts) != 6 || parts[2] != "events" || !strings.HasPrefix(parts[5], "event-bus/") {
					return failure("ValidationException", "Only EventBus targets are allowed on cross-account PutTargets calls.")
				}
			}
		}
		existing, err := tx.Targets(k)
		if err != nil {
			return err
		}
		ids := map[string]bool{}
		for _, t := range existing {
			ids[t.ID] = true
		}
		accepted := make([]TargetRecord, 0, len(in.Targets))
		for _, t := range in.Targets {
			v, e := targetRecord(k, t)
			if e != nil && (e.Code == "ValidationException" || e.Code == "AccessDeniedException") {
				return e
			}
			if rule.ManagedBy != "" {
				return managedRuleError(rule, false)
			}
			if e == nil && v.RoleARN != "" {
				if denied := s.passRole(tx.Context(), v.RoleARN, k.ARN()); denied != nil {
					return denied
				}
			}
			if e == nil && !ids[v.ID] && len(ids) == 5 {
				e = failure("LimitExceededException", "A rule can have at most five targets.")
			}
			if e != nil {
				out.FailedEntries = append(out.FailedEntries, api.PutTargetsResultEntry{TargetId: t.Id, ErrorCode: str[api.ErrorCode](e.Code), ErrorMessage: str[api.ErrorMessage](e.Message)})
				*out.FailedEntryCount++
				continue
			}
			accepted = append(accepted, v)
			ids[v.ID] = true
		}
		for _, target := range accepted {
			if err := tx.PutTarget(target); err != nil {
				return err
			}
		}
		return s.recordCall(tx.Context(), "PutTargets", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
func (s *Service) listTargets(ctx context.Context, in *api.ListTargetsByRuleInput) (out *api.ListTargetsByRuleOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "ListTargetsByRule", in, &out, &rejected, true)
	bus, wire := busKey(ctx, value(in.EventBusName))
	if wire != nil {
		return nil, wire
	}
	k := RuleKey{bus, value(in.Rule)}
	var rows []TargetRecord
	var managed bool
	err := s.configUpdate(ctx, bus, true, func(tx Transaction) error {
		rule, err := tx.Rule(k)
		if err != nil {
			return err
		}
		if err := s.authorizeRule(tx, "ListTargetsByRule", rule, nil); err != nil {
			return err
		}
		managed = rule.ManagedBy != ""
		rows, err = tx.Targets(k)
		return err
	})
	if err != nil {
		return nil, wireError(err)
	}
	rows, next, wire := page(rows, func(v TargetRecord) string { return v.ID }, k.ARN()+"/ListTargetsByRule", in.Limit, in.NextToken, "InvalidTokenException")
	if wire != nil {
		return nil, wire
	}
	out = &api.ListTargetsByRuleOutput{Targets: api.TargetList{}, NextToken: next}
	for _, v := range rows {
		out.Targets = append(out.Targets, targetOutput(v, managed))
	}
	return out, nil
}
func (s *Service) listRuleNamesByTarget(ctx context.Context, in *api.ListRuleNamesByTargetInput) (out *api.ListRuleNamesByTargetOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "ListRuleNamesByTarget", in, &out, &rejected, false)
	bus, wire := busKey(ctx, value(in.EventBusName))
	if wire != nil {
		return nil, wire
	}
	targetARN := value(in.TargetArn)
	parts := strings.SplitN(targetARN, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != bus.Partition || parts[5] == "" {
		return nil, failure("ValidationException", "Target must identify a valid ARN.")
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		record, err := s.bus(tx, bus)
		if err != nil {
			return err
		}
		// Discovery authorizes the rule namespace, not the bus or each rule.
		if err := s.authorize(tx, "ListRuleNamesByTarget", (RuleKey{Bus: bus, Name: "*"}).ARN(), nil, nil, record.Policy); err != nil {
			return err
		}
		names, err := tx.RuleNamesByTarget(bus, targetARN)
		if err != nil {
			return err
		}
		names, next, wire := page(names, func(name string) string { return name }, bus.ARN()+"/ListRuleNamesByTarget/"+targetARN, in.Limit, in.NextToken, "ValidationException")
		if wire != nil {
			return wire
		}
		out = &api.ListRuleNamesByTargetOutput{RuleNames: make(api.RuleNameList, len(names)), NextToken: next}
		for i, name := range names {
			out.RuleNames[i] = api.RuleName(name)
		}
		return s.recordCall(tx.Context(), "ListRuleNamesByTarget", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
func (s *Service) removeTargets(ctx context.Context, in *api.RemoveTargetsInput) (out *api.RemoveTargetsOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "RemoveTargets", in, &out, &rejected, false)
	bus, wire := busKey(ctx, value(in.EventBusName))
	if wire != nil {
		return nil, wire
	}
	k := RuleKey{bus, value(in.Rule)}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		rule, err := tx.Rule(k)
		if err != nil {
			return err
		}
		if err := s.authorizeRule(tx, "RemoveTargets", rule, nil); err != nil {
			return err
		}
		if rule.ManagedBy != "" {
			if in.Force == nil || !bool(*in.Force) {
				return managedRuleError(rule, true)
			}
			targets, err := tx.Targets(k)
			if err != nil {
				return err
			}
			for _, target := range targets {
				for _, id := range in.Ids {
					if target.ID == string(id) {
						if err := disableManagedArchive(tx, rule); err != nil {
							return err
						}
						break
					}
				}
			}
		}
		for _, id := range in.Ids {
			if err := tx.DeleteTarget(k, string(id)); err != nil {
				return err
			}
		}
		out = &api.RemoveTargetsOutput{FailedEntries: api.RemoveTargetsResultEntryList{}, FailedEntryCount: ptr(api.Integer(0))}
		return s.recordCall(tx.Context(), "RemoveTargets", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
