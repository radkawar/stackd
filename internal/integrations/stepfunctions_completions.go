package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"stackd/internal/awsctx"
)

// NotifyCompletion is the reserved managed-rule target, not a task command. Only
// delivered terminal envelopes release subscribers; retained engine state alone
// cannot complete a same-account event wait.
func (t *StepFunctionsTasks) NotifyCompletion(ctx context.Context, payload json.RawMessage) error {
	metadata := awsctx.FromContext(ctx)
	if strings.HasSuffix(metadata.ServicePrincipal.SourceARN, ":rule/StepFunctionsGetEventsForECSTaskRule") {
		return t.notifyECSCompletion(ctx, payload)
	}
	ruleARN := "arn:" + metadata.Partition + ":events:" + metadata.Region + ":" + metadata.AccountID + ":rule/StepFunctionsGetEventsForStepFunctionsExecutionRule"
	if metadata.ServicePrincipal.Name != "events.amazonaws.com" || metadata.ServicePrincipal.SourceARN != ruleARN {
		return errors.New("step functions completion requires the managed EventBridge rule")
	}
	var event struct {
		Source     string   `json:"source"`
		DetailType string   `json:"detail-type"`
		Account    string   `json:"account"`
		Region     string   `json:"region"`
		Resources  []string `json:"resources"`
		Detail     struct {
			ExecutionARN string `json:"executionArn"`
			Status       string `json:"status"`
		} `json:"detail"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}
	if event.Source != "aws.states" || event.DetailType != "Step Functions Execution Status Change" {
		return nil
	}
	switch event.Detail.Status {
	case "SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED":
	default:
		return nil
	}
	parts := strings.SplitN(event.Detail.ExecutionARN, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != metadata.Partition || parts[2] != "states" || parts[3] != event.Region || parts[4] != event.Account || !strings.HasPrefix(parts[5], "execution:") || event.Region != metadata.Region || event.Account != metadata.AccountID || !slices.Contains(event.Resources, event.Detail.ExecutionARN) {
		return errors.New("step functions completion envelope does not match its managed-rule scope")
	}
	t.completionsMu.Lock()
	defer t.completionsMu.Unlock()
	for completion := range t.completions[event.Detail.ExecutionARN] {
		close(completion)
	}
	delete(t.completions, event.Detail.ExecutionARN)
	return nil
}

// Subscriptions last only as long as their task attempt. TaskRecord owns the
// accepted response across restarts; authorized observation reconciles missed
// prior events after the new subscription is installed.
func (t *StepFunctionsTasks) subscribeExecution(arn string) (<-chan struct{}, func()) {
	completion := make(chan struct{})
	t.completionsMu.Lock()
	if t.completions == nil {
		t.completions = make(map[string]map[chan struct{}]struct{})
	}
	if t.completions[arn] == nil {
		t.completions[arn] = make(map[chan struct{}]struct{})
	}
	t.completions[arn][completion] = struct{}{}
	t.completionsMu.Unlock()
	return completion, func() {
		t.completionsMu.Lock()
		defer t.completionsMu.Unlock()
		delete(t.completions[arn], completion)
		if len(t.completions[arn]) == 0 {
			delete(t.completions, arn)
		}
	}
}
