package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/services/cloudformation"
	events "stackd/internal/services/eventbridge"
)

func cfnEventsContext(ctx context.Context, r cloudformation.ResourceRequest, kind, sid string) context.Context {
	owner := ""
	if !r.CloudControl {
		owner = cfnMessagingMarker(r)
	}
	return events.WithCloudFormationOwner(ctx, kind, owner, sid)
}
func cfnEventsOwned(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, kind, name string) error {
	if r.CloudControl {
		return nil
	}
	provider, ok := c.providers["eventbridge"]
	if !ok {
		return fmt.Errorf("EventBridge owner unavailable")
	}
	owner, ok := provider.executor.(interface {
		CloudFormationResourceOwned(context.Context, string, string, string) error
	})
	if !ok {
		return fmt.Errorf("EventBridge incarnation authority unavailable")
	}
	return owner.CloudFormationResourceOwned(ctx, kind, name, cfnMessagingMarker(r))
}

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-events-archive.html
type cfnEventArchive struct{ commands StepFunctionsCommands }

func (h cfnEventArchive) Validate(p cloudformation.Properties) error {
	if err := cfnWorkflowValidate(p, []string{"SourceArn"}, "ArchiveName", "SourceArn", "Description", "EventPattern", "RetentionDays", "KmsKeyIdentifier"); err != nil {
		return err
	}
	if p["EventPattern"] != nil {
		_, err := cfnComputeDocument(p["EventPattern"])
		return err
	}
	return nil
}
func (h cfnEventArchive) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ArchiveName", "SourceArn"), h.Validate(b)
}
func cfnEventArchiveResult(r cloudformation.ResourceRequest, name string) cloudformation.ResourceResult {
	return cfnWorkflowResult(name, name, "arn:"+r.Scope.Partition+":events:"+r.Scope.Region+":"+r.Scope.Account+":archive/"+name)
}
func (h cfnEventArchive) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "ArchiveName", 48)
	result := cfnEventArchiveResult(r, name)
	err := cfnEventsOwned(ctx, h.commands, r, "Archive", name)
	if err == nil {
		if !r.CloudControl {
			return result, nil
		}
		if _, err = h.Read(ctx, cloudformation.ResourceRequest{PhysicalID: name}); err == nil {
			return result, fmt.Errorf("archive already exists")
		}
	}
	if err != nil && !cfnComputeMissing(err) {
		return result, err
	}
	in := cfnComputeCopy(r.Properties, "Description", "RetentionDays", "KmsKeyIdentifier")
	in["ArchiveName"] = name
	in["EventSourceArn"] = r.Properties["SourceArn"]
	if r.Properties["EventPattern"] != nil {
		in["EventPattern"], _ = cfnComputeDocument(r.Properties["EventPattern"])
	}
	return result, cfnComputeRun(cfnEventsContext(ctx, r, "Archive", ""), h.commands, "eventbridge", "CreateArchive", in)
}
func (h cfnEventArchive) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnEventArchiveResult(r, r.PhysicalID)
	in := map[string]any{"ArchiveName": r.PhysicalID, "Description": cfnComputeDefault(r.Properties, "Description", ""), "RetentionDays": cfnComputeDefault(r.Properties, "RetentionDays", 0)}
	if pattern := r.Properties["EventPattern"]; pattern != nil {
		in["EventPattern"], _ = cfnComputeDocument(pattern)
	} else {
		in["EventPattern"] = ""
	}
	if key := r.Properties["KmsKeyIdentifier"]; key != nil {
		in["KmsKeyIdentifier"] = key
	} else if r.Previous["KmsKeyIdentifier"] != nil {
		in["KmsKeyIdentifier"] = ""
	}
	return result, cfnComputeRun(cfnEventsContext(ctx, r, "Archive", ""), h.commands, "eventbridge", "UpdateArchive", in)
}
func (h cfnEventArchive) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	return cfnComputeAbsent(cfnComputeRun(cfnEventsContext(ctx, r, "Archive", ""), h.commands, "eventbridge", "DeleteArchive", map[string]any{"ArchiveName": cfnComputeName(r, "ArchiveName", 48)}))
}
func (h cfnEventArchive) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, err := cfnComputeCall[api.DescribeArchiveOutput](ctx, h.commands, "eventbridge", "DescribeArchive", map[string]any{"ArchiveName": r.PhysicalID})
	if err != nil {
		return nil, err
	}
	p, err := cfnWorkflowProjection(out, "ArchiveName", "Description", "RetentionDays", "KmsKeyIdentifier")
	if err != nil {
		return nil, err
	}
	p["Arn"] = cfnComputeValue(out.ArchiveArn)
	p["SourceArn"] = cfnComputeValue(out.EventSourceArn)
	if pattern := cfnComputeValue(out.EventPattern); pattern != "" {
		var value any
		if err = json.Unmarshal([]byte(pattern), &value); err != nil {
			return nil, err
		}
		p["EventPattern"] = value
	}
	return p, nil
}
func (h cfnEventArchive) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListArchivesOutput](ctx, h.commands, "eventbridge", "ListArchives", in)
		if err != nil {
			return nil, err
		}
		for _, row := range out.Archives {
			rr := r
			rr.PhysicalID = cfnComputeValue(row.ArchiveName)
			p, err := h.Read(ctx, rr)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: rr.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		in["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func (h cfnEventArchive) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	out, err := cfnComputeCall[api.DescribeArchiveOutput](ctx, h.commands, "eventbridge", "DescribeArchive", map[string]any{"ArchiveName": r.PhysicalID})
	if err != nil {
		return false, err
	}
	state := cfnComputeValue(out.State)
	if state == "CREATE_FAILED" || state == "UPDATE_FAILED" {
		return false, fmt.Errorf("archive %s: %s", state, cfnComputeValue(out.StateReason))
	}
	return state == "ENABLED" || state == "DISABLED", nil
}

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-events-connection.html
type cfnEventConnection struct{ commands StepFunctionsCommands }

func (h cfnEventConnection) Validate(p cloudformation.Properties) error {
	return cfnWorkflowValidate(p, []string{"AuthorizationType", "AuthParameters"}, "Name", "Description", "AuthorizationType", "AuthParameters", "InvocationConnectivityParameters", "KmsKeyIdentifier")
}
func (h cfnEventConnection) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name"), h.Validate(b)
}
func cfnEventConnectionResult(name, arn, secret string) cloudformation.ResourceResult {
	result := cfnWorkflowResult(name, name, arn)
	result.Attributes["ArnForPolicy"] = arn[:strings.LastIndex(arn, "/")] + "/*"
	result.Attributes["SecretArn"] = secret
	return result
}
func (h cfnEventConnection) describe(ctx context.Context, name string) (*api.DescribeConnectionOutput, error) {
	return cfnComputeCall[api.DescribeConnectionOutput](ctx, h.commands, "eventbridge", "DescribeConnection", map[string]any{"Name": name})
}
func (h cfnEventConnection) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "Name", 64)
	old, err := h.describe(ctx, name)
	if err == nil {
		if r.CloudControl {
			return cloudformation.ResourceResult{}, fmt.Errorf("connection already exists")
		}
		if err = cfnEventsOwned(ctx, h.commands, r, "Connection", name); err != nil {
			return cloudformation.ResourceResult{}, err
		}
		return cfnEventConnectionResult(name, cfnComputeValue(old.ConnectionArn), cfnComputeValue(old.SecretArn)), nil
	}
	if !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	in := cfnComputeCopy(r.Properties, "Description", "AuthorizationType", "AuthParameters", "InvocationConnectivityParameters", "KmsKeyIdentifier")
	in["Name"] = name
	if err = cfnComputeRun(cfnEventsContext(ctx, r, "Connection", ""), h.commands, "eventbridge", "CreateConnection", in); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	old, err = h.describe(ctx, name)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEventConnectionResult(name, cfnComputeValue(old.ConnectionArn), cfnComputeValue(old.SecretArn)), nil
}
func (h cfnEventConnection) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	in := cfnComputeCopy(r.Properties, "AuthorizationType", "AuthParameters", "InvocationConnectivityParameters")
	in["Name"] = r.PhysicalID
	in["Description"] = cfnComputeDefault(r.Properties, "Description", "")
	if key := r.Properties["KmsKeyIdentifier"]; key != nil {
		in["KmsKeyIdentifier"] = key
	} else if r.Previous["KmsKeyIdentifier"] != nil {
		in["KmsKeyIdentifier"] = ""
	}
	if err := cfnComputeRun(cfnEventsContext(ctx, r, "Connection", ""), h.commands, "eventbridge", "UpdateConnection", in); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.Result(ctx, r)
}
func (h cfnEventConnection) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	return cfnComputeAbsent(cfnComputeRun(cfnEventsContext(ctx, r, "Connection", ""), h.commands, "eventbridge", "DeleteConnection", map[string]any{"Name": cfnComputeName(r, "Name", 64)}))
}
func (h cfnEventConnection) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	out, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEventConnectionResult(r.PhysicalID, cfnComputeValue(out.ConnectionArn), cfnComputeValue(out.SecretArn)), nil
}
func (h cfnEventConnection) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p, err := cfnWorkflowProjection(out, "Name", "Description", "AuthorizationType", "AuthParameters", "InvocationConnectivityParameters", "KmsKeyIdentifier")
	if err != nil {
		return nil, err
	}
	result := cfnEventConnectionResult(r.PhysicalID, cfnComputeValue(out.ConnectionArn), cfnComputeValue(out.SecretArn))
	for k, v := range result.Attributes {
		p[k] = v
	}
	return p, nil
}
func (h cfnEventConnection) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListConnectionsOutput](ctx, h.commands, "eventbridge", "ListConnections", in)
		if err != nil {
			return nil, err
		}
		for _, row := range out.Connections {
			rr := r
			rr.PhysicalID = cfnComputeValue(row.Name)
			p, err := h.Read(ctx, rr)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: rr.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		in["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func (h cfnEventConnection) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	out, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	state := cfnComputeValue(out.ConnectionState)
	if state == "DEAUTHORIZED" {
		return false, fmt.Errorf("connection authorization failed: %s", cfnComputeValue(out.StateReason))
	}
	return state == "AUTHORIZED", nil
}
func (h cfnEventConnection) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.describe(ctx, r.PhysicalID)
	if cfnComputeMissing(err) {
		return true, nil
	}
	return false, err
}

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-events-apidestination.html
type cfnEventAPIDestination struct{ commands StepFunctionsCommands }

func (h cfnEventAPIDestination) Validate(p cloudformation.Properties) error {
	return cfnWorkflowValidate(p, []string{"ConnectionArn", "InvocationEndpoint", "HttpMethod"}, "Name", "Description", "ConnectionArn", "InvocationEndpoint", "HttpMethod", "InvocationRateLimitPerSecond")
}
func (h cfnEventAPIDestination) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name"), h.Validate(b)
}
func cfnEventAPIDestinationResult(name, arn string) cloudformation.ResourceResult {
	result := cfnWorkflowResult(name, name, arn)
	if at := strings.LastIndex(arn, "/"); at >= 0 {
		result.Attributes["ArnForPolicy"] = arn[:at] + "/*"
	}
	return result
}
func (h cfnEventAPIDestination) describe(ctx context.Context, name string) (*api.DescribeApiDestinationOutput, error) {
	return cfnComputeCall[api.DescribeApiDestinationOutput](ctx, h.commands, "eventbridge", "DescribeApiDestination", map[string]any{"Name": name})
}
func (h cfnEventAPIDestination) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "Name", 64)
	old, err := h.describe(ctx, name)
	if err == nil {
		if r.CloudControl {
			return cloudformation.ResourceResult{}, fmt.Errorf("api destination already exists")
		}
		return cfnEventAPIDestinationResult(name, cfnComputeValue(old.ApiDestinationArn)), cfnEventsOwned(ctx, h.commands, r, "ApiDestination", name)
	}
	if !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	in := cfnComputeCopy(r.Properties, "Description", "ConnectionArn", "InvocationEndpoint", "HttpMethod", "InvocationRateLimitPerSecond")
	in["Name"] = name
	out, err := cfnComputeCall[api.CreateApiDestinationOutput](cfnEventsContext(ctx, r, "ApiDestination", ""), h.commands, "eventbridge", "CreateApiDestination", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEventAPIDestinationResult(name, cfnComputeValue(out.ApiDestinationArn)), nil
}
func (h cfnEventAPIDestination) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	in := cfnComputeCopy(r.Properties, "ConnectionArn", "InvocationEndpoint", "HttpMethod")
	in["Name"] = r.PhysicalID
	in["Description"] = cfnComputeDefault(r.Properties, "Description", "")
	in["InvocationRateLimitPerSecond"] = cfnComputeDefault(r.Properties, "InvocationRateLimitPerSecond", 300)
	out, err := cfnComputeCall[api.UpdateApiDestinationOutput](cfnEventsContext(ctx, r, "ApiDestination", ""), h.commands, "eventbridge", "UpdateApiDestination", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEventAPIDestinationResult(r.PhysicalID, cfnComputeValue(out.ApiDestinationArn)), nil
}
func (h cfnEventAPIDestination) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	return cfnComputeAbsent(cfnComputeRun(cfnEventsContext(ctx, r, "ApiDestination", ""), h.commands, "eventbridge", "DeleteApiDestination", map[string]any{"Name": cfnComputeName(r, "Name", 64)}))
}
func (h cfnEventAPIDestination) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p, err := cfnWorkflowProjection(out, "Name", "Description", "ConnectionArn", "InvocationEndpoint", "HttpMethod", "InvocationRateLimitPerSecond")
	if err != nil {
		return nil, err
	}
	for k, v := range cfnEventAPIDestinationResult(r.PhysicalID, cfnComputeValue(out.ApiDestinationArn)).Attributes {
		p[k] = v
	}
	return p, nil
}
func (h cfnEventAPIDestination) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListApiDestinationsOutput](ctx, h.commands, "eventbridge", "ListApiDestinations", in)
		if err != nil {
			return nil, err
		}
		for _, row := range out.ApiDestinations {
			rr := r
			rr.PhysicalID = cfnComputeValue(row.Name)
			p, err := h.Read(ctx, rr)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: rr.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		in["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
