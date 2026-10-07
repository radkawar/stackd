package integrations

import (
	"context"
	"encoding/json"
	"fmt"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

// ResourcePolicy is already registered by the compute registry. Its native
// schema supports reads, but no list handler. Keep the calibrated function
// policy ownership/deletion semantics unchanged.
func (h cfnLambdaResourcePolicy) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	resource := cfnLambdaResourcePolicyARN(r)
	out, err := cfnMessagingCall[api.GetResourcePolicyResponse](ctx, h.commands, "lambda", "GetResourcePolicy", &api.GetResourcePolicyRequest{ResourceArn: new(api.PolicyResourceArn(resource))})
	if err != nil {
		return nil, err
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(cfnComputeValue(out.Policy)), &document); err != nil {
		return nil, fmt.Errorf("lambda returned invalid resource policy: %w", err)
	}
	return cloudformation.Properties{"ResourceArn": resource, "PolicyDocument": document}, nil
}

func (h cfnLambdaResourcePolicy) List(context.Context, cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	return nil, &awswire.Error{Code: "UnsupportedActionException", Message: "The native AWS::Lambda::ResourcePolicy schema does not provide a list handler.", StatusCode: 400}
}
