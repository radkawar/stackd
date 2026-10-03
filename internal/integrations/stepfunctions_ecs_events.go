package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"stackd/internal/awsctx"
)

// The scope subscription is installed before RunTask: even an immediately
// stopped task cannot outrun admission of its actual returned task ARN. Only
// delivered identities, not task state or results, live in this transient set.
type stepFunctionsECSCompletion struct {
	wake    chan struct{}
	task    string
	stopped map[string]struct{}
}

func ecsCompletionScope(partition, region, account string) string {
	return partition + ":" + region + ":" + account
}

func (t *StepFunctionsTasks) subscribeECS(ctx context.Context) (*stepFunctionsECSCompletion, func()) {
	metadata := awsctx.FromContext(ctx)
	scope := ecsCompletionScope(metadata.Partition, metadata.Region, metadata.AccountID)
	subscription := &stepFunctionsECSCompletion{wake: make(chan struct{}, 1), stopped: make(map[string]struct{})}
	t.completionsMu.Lock()
	if t.ecsCompletions == nil {
		t.ecsCompletions = make(map[string]map[*stepFunctionsECSCompletion]struct{})
	}
	if t.ecsCompletions[scope] == nil {
		t.ecsCompletions[scope] = make(map[*stepFunctionsECSCompletion]struct{})
	}
	t.ecsCompletions[scope][subscription] = struct{}{}
	t.completionsMu.Unlock()
	return subscription, func() {
		t.completionsMu.Lock()
		defer t.completionsMu.Unlock()
		delete(t.ecsCompletions[scope], subscription)
		if len(t.ecsCompletions[scope]) == 0 {
			delete(t.ecsCompletions, scope)
		}
	}
}

func (t *StepFunctionsTasks) selectECSTask(subscription *stepFunctionsECSCompletion, task string) {
	t.completionsMu.Lock()
	defer t.completionsMu.Unlock()
	subscription.task = task
	for arn := range subscription.stopped {
		if arn != task {
			delete(subscription.stopped, arn)
		}
	}
}

func (t *StepFunctionsTasks) ecsTaskDelivered(subscription *stepFunctionsECSCompletion) bool {
	t.completionsMu.Lock()
	defer t.completionsMu.Unlock()
	_, delivered := subscription.stopped[subscription.task]
	return delivered
}

func (t *StepFunctionsTasks) notifyECSCompletion(ctx context.Context, payload json.RawMessage) error {
	metadata := awsctx.FromContext(ctx)
	ruleARN := "arn:" + metadata.Partition + ":events:" + metadata.Region + ":" + metadata.AccountID + ":rule/StepFunctionsGetEventsForECSTaskRule"
	if metadata.ServicePrincipal.Name != "events.amazonaws.com" || metadata.ServicePrincipal.SourceARN != ruleARN {
		return errors.New("ECS completion requires the managed EventBridge rule")
	}
	var event struct {
		Source     string   `json:"source"`
		DetailType string   `json:"detail-type"`
		Account    string   `json:"account"`
		Region     string   `json:"region"`
		Resources  []string `json:"resources"`
		Detail     struct {
			TaskARN       string `json:"taskArn"`
			LastStatus    string `json:"lastStatus"`
			DesiredStatus string `json:"desiredStatus"`
			StartedBy     string `json:"startedBy"`
		} `json:"detail"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}
	if event.Source != "aws.ecs" || event.DetailType != "ECS Task State Change" || event.Detail.LastStatus != "STOPPED" || event.Detail.DesiredStatus != "STOPPED" || event.Detail.StartedBy != "AWS Step Functions" {
		return nil
	}
	parts := strings.SplitN(event.Detail.TaskARN, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != metadata.Partition || parts[2] != "ecs" || parts[3] != event.Region || parts[4] != event.Account || !strings.HasPrefix(parts[5], "task/") || event.Region != metadata.Region || event.Account != metadata.AccountID || !slices.Contains(event.Resources, event.Detail.TaskARN) {
		return errors.New("ECS completion envelope does not match its managed-rule scope")
	}
	t.completionsMu.Lock()
	defer t.completionsMu.Unlock()
	for subscription := range t.ecsCompletions[ecsCompletionScope(metadata.Partition, metadata.Region, metadata.AccountID)] {
		if subscription.task != "" && subscription.task != event.Detail.TaskARN {
			continue
		}
		subscription.stopped[event.Detail.TaskARN] = struct{}{}
		select {
		case subscription.wake <- struct{}{}:
		default:
		}
	}
	return nil
}
