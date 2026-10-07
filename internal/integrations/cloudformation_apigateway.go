package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"stackd/internal/awsapi"
	"stackd/internal/services/apigatewayv2"
	"stackd/internal/services/cloudformation"
)

// CloudFormationAPIGatewayHandlers delegates every API Gateway resource type to
// the REST or V2 configuration owner. Deployments remain owner snapshots.
func CloudFormationAPIGatewayHandlers(commands StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	handlers := CloudFormationAPIGatewayRESTHandlers(commands)
	for name, handler := range CloudFormationAPIGatewayV2Handlers(commands) {
		handlers[name] = handler
	}
	for name, handler := range CloudFormationAPIGatewayV2DomainHandlers(commands) {
		handlers[name] = handler
	}
	return handlers
}

// cfnGatewayV2Context binds stack mutations to the owner row's persisted
// resource incarnation. Cloud Control operates on resources directly.
func cfnGatewayV2Context(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return apigatewayv2.WithResourceOwner(ctx, apigatewayv2.ResourceOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token})
}

// cfnGatewayV2Call projects owner output through generated Smithy member names,
// which are the CloudFormation property names, never the service wire names.
func cfnGatewayV2Call(ctx context.Context, commands StepFunctionsCommands, operation string, input map[string]any) (map[string]any, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	out, rejected := commands.callCloudFormation(ctx, "apigatewayv2", operation, body)
	if rejected != nil {
		return nil, rejected
	}
	data, err := awsapi.EncodeSDKOutput(out.Service, out.Operation, out.Output)
	if err != nil {
		return nil, err
	}
	p := map[string]any{}
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return p, nil
}

// cfnGatewayV2Identifier parses the native Cloud Control compound identifier:
// primaryIdentifier values joined by "|" in resource schema order.
func cfnGatewayV2Identifier(r cloudformation.ResourceRequest, keys ...string) (map[string]any, error) {
	ids := make(map[string]any, len(keys))
	if r.PhysicalID == "" {
		for _, key := range keys {
			ids[key] = r.Properties[key]
		}
	} else {
		parts := strings.Split(r.PhysicalID, "|")
		if len(parts) != len(keys) {
			return nil, fmt.Errorf("identifier must be %s", strings.Join(keys, "|"))
		}
		for i, key := range keys {
			ids[key] = parts[i]
		}
	}
	for _, key := range keys {
		if text, ok := ids[key].(string); !ok || text == "" || strings.Contains(text, "|") {
			return nil, fmt.Errorf("identifier requires %s", key)
		}
	}
	return ids, nil
}

func cfnGatewayV2PhysicalID(keys []string, ids map[string]any) string {
	parts := make([]string, len(keys))
	for i, key := range keys {
		parts[i], _ = ids[key].(string)
	}
	return strings.Join(parts, "|")
}

func cfnGatewayV2Result(keys []string, ids map[string]any, ref string, attrs map[string]any) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: cfnGatewayV2PhysicalID(keys, ids), Ref: ref, Attributes: attrs}
}

func cfnGatewayV2Absent(err error) error {
	if cfnMessagingMissing(err, "NotFoundException") {
		return nil
	}
	return err
}

func cfnGatewayV2Projection(output map[string]any, ids map[string]any, fields ...string) cloudformation.Properties {
	p := cloudformation.Properties(cfnComputeCopy(output, fields...))
	for key, value := range ids {
		p[key] = value
	}
	return p
}

// cfnGatewayV2Tags reads the V2 map-shaped Tags property.
func cfnGatewayV2Tags(p map[string]any) (map[string]string, error) {
	tags := map[string]string{}
	if p["Tags"] == nil {
		return tags, nil
	}
	values, ok := p["Tags"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("tags must be an object of strings")
	}
	for key, value := range values {
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("tags values must be strings")
		}
		if key == "" || strings.HasPrefix(strings.ToLower(key), "aws:") {
			return nil, fmt.Errorf("invalid or reserved tag key %s", key)
		}
		tags[key] = text
	}
	return tags, nil
}

// cfnGatewayV2DesiredTags applies stack-level tags under resource tags, as
// CloudFormation propagates stack tags to taggable resources.
func cfnGatewayV2DesiredTags(r cloudformation.ResourceRequest) (map[string]string, error) {
	resource, err := cfnGatewayV2Tags(r.Properties)
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string, len(r.Tags)+len(resource))
	if !r.CloudControl {
		for key, value := range r.Tags {
			tags[key] = value
		}
	}
	for key, value := range resource {
		tags[key] = value
	}
	return tags, nil
}

func cfnGatewayV2ARN(r cloudformation.ResourceRequest, path string) string {
	return "arn:" + r.Scope.Partition + ":apigateway:" + r.Scope.Region + "::" + path
}

func cfnGatewayV2SyncTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, path string) error {
	desired, err := cfnGatewayV2DesiredTags(r)
	if err != nil {
		return err
	}
	arn := cfnGatewayV2ARN(r, path)
	out, err := cfnGatewayV2Call(ctx, c, "GetTags", map[string]any{"ResourceArn": arn})
	if err != nil {
		return err
	}
	current := map[string]string{}
	if values, ok := out["Tags"].(map[string]any); ok {
		for key, value := range values {
			current[key], _ = value.(string)
		}
	}
	removed := cfnComputeRemovedTags(current, desired)
	if len(removed) > 0 {
		if err := cfnComputeRun(ctx, c, "apigatewayv2", "UntagResource", map[string]any{"ResourceArn": arn, "TagKeys": removed}); err != nil {
			return err
		}
	}
	changed := map[string]string{}
	for key, value := range desired {
		if current[key] != value {
			changed[key] = value
		}
	}
	if len(changed) == 0 {
		return nil
	}
	return cfnComputeRun(ctx, c, "apigatewayv2", "TagResource", map[string]any{"ResourceArn": arn, "Tags": changed})
}

func cfnGatewayV2Pages(ctx context.Context, c StepFunctionsCommands, operation string, input map[string]any) ([]map[string]any, error) {
	rows := []map[string]any{}
	for {
		out, err := cfnGatewayV2Call(ctx, c, operation, input)
		if err != nil {
			return nil, err
		}
		items, _ := out["Items"].([]any)
		for _, item := range items {
			row, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s returned an invalid item", operation)
			}
			rows = append(rows, row)
		}
		token := cfnComputeString(out, "NextToken")
		if token == "" {
			return rows, nil
		}
		input["NextToken"] = token
	}
}

// cfnGatewayV2Scalar accepts CloudFormation's string-encoded booleans and
// integers for the named members, as the native resource providers do.
func cfnGatewayV2Scalar(p map[string]any, ints, bools []string) error {
	for _, key := range ints {
		switch v := p[key].(type) {
		case nil:
		case float64:
			if v != float64(int64(v)) {
				return fmt.Errorf("%s must be an integer", key)
			}
			p[key] = int64(v)
		case int, int32, int64:
		case string:
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return fmt.Errorf("%s must be an integer", key)
			}
			p[key] = n
		default:
			return fmt.Errorf("%s must be an integer", key)
		}
	}
	for _, key := range bools {
		switch v := p[key].(type) {
		case nil, bool:
		case string:
			b, err := strconv.ParseBool(v)
			if err != nil {
				return fmt.Errorf("%s must be a boolean", key)
			}
			p[key] = b
		default:
			return fmt.Errorf("%s must be a boolean", key)
		}
	}
	return nil
}
