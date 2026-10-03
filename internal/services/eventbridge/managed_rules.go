package eventbridge

import (
	"context"
	"errors"

	"stackd/internal/awswire"
)

const stepFunctionsSyncRuleName = "StepFunctionsGetEventsForStepFunctionsExecutionRule"
const stepFunctionsManagedBy = "states.amazonaws.com"
const stepFunctionsSyncDescription = "This rule is used to notify Step Functions regarding integrated workflow executions"
const stepFunctionsSyncPattern = `{
  "source": [
    "aws.states"
  ],
  "detail-type": [
    "Step Functions Execution Status Change"
  ],
  "detail": {
    "status": [
      "FAILED",
      "SUCCEEDED",
      "TIMED_OUT",
      "ABORTED"
    ]
  }
}
`

const stepFunctionsECSSyncRuleName = "StepFunctionsGetEventsForECSTaskRule"
const stepFunctionsECSSyncDescription = "This rule is used to notify Step Functions regarding AWS ECS Tasks"
const stepFunctionsECSSyncPattern = `{
  "source": [
    "aws.ecs"
  ],
  "detail-type": [
    "ECS Task State Change"
  ],
  "detail": {
    "lastStatus": [
      "STOPPED"
    ],
    "desiredStatus": [
      "STOPPED"
    ],
    "startedBy": [
      "AWS Step Functions"
    ]
  }
}
`

func managedRuleError(rule RuleRecord, force bool) *awswire.Error {
	message := rule.Key.Name + " is a managed rule."
	if force {
		message += " Set 'force' parameter to true to override."
	}
	return failure("ManagedRuleException", message)
}

// ConfigureStepFunctionsSync admits the regional managed consumer using the
// workflow execution-role identity already carried by ctx. The owner writes
// actual rule and target state, not invented public PutRule/PutTargets calls.
// Neither a workflow's deletion nor subsequent role edits remove this consumer.
func (s *Service) ConfigureStepFunctionsSync(ctx context.Context) *awswire.Error {
	return s.configureStepFunctionsRule(ctx, stepFunctionsSyncRuleName, stepFunctionsSyncDescription, stepFunctionsSyncPattern, "aws.states", "Step Functions Execution Status Change")
}

// ConfigureStepFunctionsECSSync admits ECS completion under the execution role,
// using the same retained managed target as nested workflows.
func (s *Service) ConfigureStepFunctionsECSSync(ctx context.Context) *awswire.Error {
	return s.configureStepFunctionsRule(ctx, stepFunctionsECSSyncRuleName, stepFunctionsECSSyncDescription, stepFunctionsECSSyncPattern, "aws.ecs", "ECS Task State Change")
}

func (s *Service) configureStepFunctionsRule(ctx context.Context, name, description, pattern, source, detailType string) *awswire.Error {
	bus := BusKey{Scope: scopeFor(ctx), Name: "default"}
	key := RuleKey{Bus: bus, Name: name}
	target := TargetRecord{Rule: key, ID: key.Name + "-Id",
		ARN:        "arn:" + bus.Partition + ":states:" + bus.Region + ":::",
		MaxRetries: 185, MaxAgeSeconds: 86400,
	}
	err := s.configUpdate(ctx, bus, true, func(tx Transaction) error {
		rule, foundErr := tx.Rule(key)
		if foundErr != nil && !errors.Is(foundErr, ErrNotFound) {
			return foundErr
		}
		if foundErr != nil {
			rule = RuleRecord{Key: key, ManagedBy: stepFunctionsManagedBy,
				Pattern: pattern, HasPattern: true,
				Description: description, HasDescription: true,
				State: "ENABLED", CreatedBy: bus.Account,
			}
		}
		if err := s.authorizeRule(tx, "PutRule", rule, map[string][]string{
			"events:EventBusName": {bus.Name},
			"events:source":       {source},
			"events:detail-type":  {detailType},
		}); err != nil {
			return err
		}
		if err := s.authorizeRule(tx, "PutTargets", rule, map[string][]string{"events:TargetArn": {target.ARN}}); err != nil {
			return err
		}
		if err := s.authorizeRule(tx, "DescribeRule", rule, nil); err != nil {
			return err
		}
		if rule.ManagedBy != stepFunctionsManagedBy || rule.ArchiveID != "" {
			return failure("ResourceAlreadyExistsException", "Rule "+key.Name+" already exists.")
		}
		if _, err := s.bus(tx, bus); err != nil {
			return err
		}
		if foundErr != nil {
			if err := tx.PutRule(rule); err != nil {
				return err
			}
		}
		targets, err := tx.Targets(key)
		if err != nil {
			return err
		}
		for _, existing := range targets {
			if existing.ID == target.ID {
				return nil
			}
		}
		return tx.PutTarget(target)
	})
	return wireError(err)
}
