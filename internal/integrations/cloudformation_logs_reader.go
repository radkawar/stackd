package integrations

import (
	"context"
	"fmt"
	"strings"

	api "stackd/internal/awsapi/logs"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

func cfnLogGroupIdentifier(r cloudformation.ResourceRequest) (string, error) {
	name := r.PhysicalID
	if strings.HasPrefix(name, "arn:") {
		if err := cfnMessagingScopeARN(r, name, "logs"); err != nil {
			return "", err
		}
		resource := strings.SplitN(name, ":", 6)[5]
		if !strings.HasPrefix(resource, "log-group:") {
			return "", fmt.Errorf("identifier must name a log group")
		}
		name = strings.TrimSuffix(strings.TrimPrefix(resource, "log-group:"), ":*")
	}
	if name == "" {
		return "", fmt.Errorf("log group identifier is required")
	}
	return name, nil
}
func (h cfnLogGroup) readGroup(ctx context.Context, r cloudformation.ResourceRequest, group api.LogGroup) (cloudformation.Properties, error) {
	name := cfnComputeValue(group.LogGroupName)
	tags, err := cfnComputeCall[api.ListTagsForResourceOutput](ctx, h.commands, "logs", "ListTagsForResource", map[string]any{"ResourceArn": cfnLogGroupARN(r, name)})
	if err != nil {
		return nil, err
	}
	publicTags := make(map[string]string, len(tags.Tags))
	for key, value := range tags.Tags {
		publicTags[string(key)] = string(value)
	}
	p := cloudformation.Properties{"LogGroupName": name, "Arn": cfnComputeValue(group.Arn), "Tags": cfnResourcePublicTags(publicTags)}
	if group.RetentionInDays != nil {
		p["RetentionInDays"] = int32(*group.RetentionInDays)
	}
	if group.LogGroupClass != nil {
		p["LogGroupClass"] = string(*group.LogGroupClass)
	}
	return p, nil
}
func (h cfnLogGroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	name, err := cfnLogGroupIdentifier(r)
	if err != nil {
		return nil, err
	}
	input := map[string]any{"LogGroupNamePrefix": name}
	for {
		out, err := cfnComputeCall[api.DescribeLogGroupsOutput](ctx, h.commands, "logs", "DescribeLogGroups", input)
		if err != nil {
			return nil, err
		}
		for _, group := range out.LogGroups {
			if cfnComputeValue(group.LogGroupName) == name {
				return h.readGroup(ctx, r, group)
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "The specified log group does not exist.", StatusCode: 400}
		}
		input["NextToken"] = string(*out.NextToken)
	}
}
func (h cfnLogGroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var resources []cloudformation.ResourceDescription
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeLogGroupsOutput](ctx, h.commands, "logs", "DescribeLogGroups", input)
		if err != nil {
			return nil, err
		}
		for _, group := range out.LogGroups {
			p, err := h.readGroup(ctx, r, group)
			if err != nil {
				return nil, err
			}
			resources = append(resources, cloudformation.ResourceDescription{Identifier: cfnComputeValue(group.LogGroupName), Properties: p})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return resources, nil
		}
		input["NextToken"] = string(*out.NextToken)
	}
}
