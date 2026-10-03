package integrations

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/services/cloudformation"
)

// Physical identity wins over desired properties during replacement cleanup.
func cfnLambdaQualifiedIdentity(r cloudformation.ResourceRequest) (string, string, error) {
	if r.PhysicalID == "" {
		return cfnComputeString(r.Properties, "FunctionName"), cfnComputeString(r.Properties, "Name"), nil
	}
	parsed, err := arn.Parse(r.PhysicalID)
	if err != nil || parsed.Service != "lambda" {
		return "", "", fmt.Errorf("identifier must be a qualified Lambda ARN")
	}
	resource, ok := strings.CutPrefix(parsed.Resource, "function:")
	function, qualifier, qualified := strings.Cut(resource, ":")
	if !ok || !qualified || function == "" || qualifier == "" || strings.Contains(qualifier, ":") {
		return "", "", fmt.Errorf("identifier must be a qualified Lambda ARN")
	}
	parsed.Resource = "function:" + function
	return parsed.String(), qualifier, nil
}

func cfnLambdaProvisioned(p cloudformation.Properties) (int32, bool, error) {
	raw, found := p["ProvisionedConcurrencyConfig"]
	if !found {
		return 0, false, nil
	}
	object, ok := cfnComputeObject(raw)
	if !ok {
		return 0, true, fmt.Errorf("ProvisionedConcurrencyConfig must be an object")
	}
	var config struct {
		ProvisionedConcurrentExecutions *cfnMessagingInt
	}
	if err := cfnMessagingDecode(object, &config); err != nil {
		return 0, true, err
	}
	if config.ProvisionedConcurrentExecutions == nil || *config.ProvisionedConcurrentExecutions < 1 || *config.ProvisionedConcurrentExecutions > math.MaxInt32 {
		return 0, true, fmt.Errorf("ProvisionedConcurrentExecutions must be a positive 32-bit integer")
	}
	return int32(*config.ProvisionedConcurrentExecutions), true, nil
}

func cfnLambdaStabilizeProvisioned(ctx context.Context, commands StepFunctionsCommands, function, qualifier string, requested int32, present, previous bool) (bool, error) {
	if !present && !previous {
		return true, nil
	}
	input := map[string]any{"FunctionName": function, "Qualifier": qualifier}
	if !present {
		err := cfnComputeRun(ctx, commands, "lambda", "DeleteProvisionedConcurrencyConfig", input)
		if cfnMessagingMissing(err, "ProvisionedConcurrencyConfigNotFoundException") {
			err = nil
		}
		return err == nil, err
	}
	current, err := cfnComputeCall[api.GetProvisionedConcurrencyConfigOutput](ctx, commands, "lambda", "GetProvisionedConcurrencyConfig", input)
	if err != nil && !cfnMessagingMissing(err, "ProvisionedConcurrencyConfigNotFoundException") {
		return false, err
	}
	if err != nil || current.RequestedProvisionedConcurrentExecutions == nil || int32(*current.RequestedProvisionedConcurrentExecutions) != requested {
		input["ProvisionedConcurrentExecutions"] = requested
		return false, cfnComputeRun(ctx, commands, "lambda", "PutProvisionedConcurrencyConfig", input)
	}
	switch cfnComputeValue(current.Status) {
	case "READY":
		return true, nil
	case "FAILED":
		return false, fmt.Errorf("lambda provisioned concurrency failed: %s", cfnComputeValue(current.StatusReason))
	default:
		return false, nil
	}
}
