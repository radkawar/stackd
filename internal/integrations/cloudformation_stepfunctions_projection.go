package integrations

import (
	"context"
	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/services/cloudformation"
	sfn "stackd/internal/services/stepfunctions"
	"strings"
)

// Step Functions wire members are lower-camel while its CFN configuration
// members are upper-camel. ASL documents and customer substitution maps are
// projected separately and never passed through this configuration conversion.
func cfnSFNProjection(v any, keys ...string) (cloudformation.Properties, error) {
	p, err := cfnWorkflowProjection(v, keys...)
	if err != nil {
		return nil, err
	}
	for key, value := range p {
		p[key] = cfnSFNConfiguration(value)
	}
	return p, nil
}
func cfnSFNConfiguration(value any) any {
	switch value := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(value))
		for key, item := range value {
			if key != "" {
				key = strings.ToUpper(key[:1]) + key[1:]
			}
			out[key] = cfnSFNConfiguration(item)
		}
		return out
	case []any:
		for i, item := range value {
			value[i] = cfnSFNConfiguration(item)
		}
		return value
	default:
		return value
	}
}

func cfnSFNName(r cloudformation.ResourceRequest, property string) string {
	if strings.HasPrefix(r.PhysicalID, "arn:") {
		if at := strings.LastIndex(r.PhysicalID, ":"); at >= 0 {
			return r.PhysicalID[at+1:]
		}
	}
	return cfnComputeName(r, property, 80)
}
func cfnSFNMachineIDs(ctx context.Context, c StepFunctionsCommands) ([]string, error) {
	var result []string
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListStateMachinesOutput](ctx, c, "stepfunctions", "ListStateMachines", in)
		if err != nil {
			return nil, err
		}
		for _, row := range out.StateMachines {
			result = append(result, cfnComputeValue(row.StateMachineArn))
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		in["NextToken"] = cfnComputeValue(out.NextToken)
	}
}

func cfnSFNCreateContext(ctx context.Context, r cloudformation.ResourceRequest, kind string) context.Context {
	return sfn.WithCloudFormationCreate(ctx, kind, cfnMessagingMarker(r))
}
