package integrations

import (
	"context"
	"errors"
	"fmt"
	api "stackd/internal/awsapi/cloudtrail"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/cloudtrail"
)

// Trail configuration and logging are applied through the real destination,
// digest, organization and audit boundaries, never projected into a CFN store.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudtrail-trail.html
type cfnTrail struct{ commands StepFunctionsCommands }

func (h cfnTrail) fields() []string {
	return []string{"TrailName", "S3BucketName", "S3KeyPrefix", "SnsTopicName", "KMSKeyId", "IncludeGlobalServiceEvents", "IsMultiRegionTrail", "IsOrganizationTrail", "EnableLogFileValidation", "CloudWatchLogsLogGroupArn", "CloudWatchLogsRoleArn", "IsLogging", "EventSelectors", "AdvancedEventSelectors", "Tags"}
}
func (h cfnTrail) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, h.fields()...); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "S3BucketName"); err != nil {
		return err
	}
	if _, ok := p["IsLogging"].(bool); !ok {
		return fmt.Errorf("IsLogging must be a boolean")
	}
	if p["EventSelectors"] != nil && p["AdvancedEventSelectors"] != nil {
		return fmt.Errorf("EventSelectors and AdvancedEventSelectors are mutually exclusive")
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnTrail) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "TrailName"), h.Validate(b)
}
func cfnTrailContext(ctx context.Context, r cloudformation.ResourceRequest, create bool) context.Context {
	if r.CloudControl && !create {
		return ctx
	}
	return cloudtrail.WithCloudFormationOwner(ctx, cfnLogsMarker(r), create)
}
func cfnTrailMissing(err error) bool {
	var wire *awswire.Error
	return cfnComputeMissing(err) || errors.As(err, &wire) && wire.Code == "TrailNotFoundException"
}
func cfnTrailPublicTags(r cloudformation.ResourceRequest) map[string]string {
	return cfnResourceTags(r)
}
func (h cfnTrail) tags(ctx context.Context, arn string) (map[string]string, error) {
	out, err := cfnComputeCall[api.ListTagsOutput](ctx, h.commands, "cloudtrail", "ListTags", map[string]any{"ResourceIdList": []string{arn}})
	if err != nil {
		return nil, err
	}
	tags := map[string]string{}
	for _, resource := range out.ResourceTagList {
		for _, tag := range resource.TagsList {
			tags[cfnComputeValue(tag.Key)] = cfnComputeValue(tag.Value)
		}
	}
	return tags, nil
}
func (h cfnTrail) syncTags(ctx context.Context, r cloudformation.ResourceRequest, arn string) error {
	current, err := h.tags(ctx, arn)
	if err != nil {
		return err
	}
	desired := cfnTrailPublicTags(r)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		keys := make([]map[string]string, 0, len(removed))
		for _, key := range removed {
			keys = append(keys, map[string]string{"Key": key})
		}
		if err := cfnComputeRun(ctx, h.commands, "cloudtrail", "RemoveTags", map[string]any{"ResourceId": arn, "TagsList": keys}); err != nil {
			return err
		}
	}
	if len(desired) > 0 {
		return cfnComputeRun(ctx, h.commands, "cloudtrail", "AddTags", map[string]any{"ResourceId": arn, "TagsList": cfnComputeTagList(desired)})
	}
	return nil
}
func (h cfnTrail) configure(ctx context.Context, r cloudformation.ResourceRequest, name string) error {
	selector := map[string]any{"TrailName": name}
	if advanced, ok := r.Properties["AdvancedEventSelectors"]; ok {
		selector["AdvancedEventSelectors"] = advanced
	} else if basic, ok := r.Properties["EventSelectors"]; ok {
		selector["EventSelectors"] = basic
	} else {
		selector["EventSelectors"] = []any{map[string]any{"ReadWriteType": "All", "IncludeManagementEvents": true}}
	}
	if err := cfnComputeRun(ctx, h.commands, "cloudtrail", "PutEventSelectors", selector); err != nil {
		return err
	}
	operation := "StopLogging"
	if logging, _ := r.Properties["IsLogging"].(bool); logging {
		operation = "StartLogging"
	}
	return cfnComputeRun(ctx, h.commands, "cloudtrail", operation, map[string]any{"Name": name})
}
func (h cfnTrail) result(ctx context.Context, r cloudformation.ResourceRequest, name string) (cloudformation.ResourceResult, error) {
	out, err := cfnComputeCall[api.GetTrailOutput](ctx, h.commands, "cloudtrail", "GetTrail", map[string]any{"Name": name})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if out.Trail == nil {
		return cloudformation.ResourceResult{}, cfnObservabilityNotFound()
	}
	return cloudformation.ResourceResult{PhysicalID: cfnComputeValue(out.Trail.Name), Ref: cfnComputeValue(out.Trail.Name), Attributes: map[string]any{"Arn": cfnComputeValue(out.Trail.TrailARN), "SnsTopicArn": cfnComputeValue(out.Trail.SnsTopicARN)}}, nil
}
func (h cfnTrail) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "TrailName", 128)
	ctx = cfnTrailContext(ctx, r, true)
	result, err := h.result(ctx, r, name)
	if err == nil {
		r.PhysicalID = result.PhysicalID
		updated, err := h.Update(ctx, r)
		if updated.PhysicalID == "" {
			updated = result
		}
		return updated, err
	}
	if !cfnTrailMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnComputeCopy(r.Properties, "S3BucketName", "S3KeyPrefix", "SnsTopicName", "IncludeGlobalServiceEvents", "IsMultiRegionTrail", "IsOrganizationTrail", "EnableLogFileValidation", "CloudWatchLogsLogGroupArn", "CloudWatchLogsRoleArn")
	input["Name"] = name
	input["KmsKeyId"] = cfnComputeString(r.Properties, "KMSKeyId")
	input["TagsList"] = cfnComputeTagList(cfnTrailPublicTags(r))
	out, err := cfnComputeCall[api.CreateTrailOutput](ctx, h.commands, "cloudtrail", "CreateTrail", input)
	if err != nil {
		recovered, observationErr := h.result(ctx, r, name)
		if observationErr == nil {
			return recovered, err
		}
		if !cfnTrailMissing(observationErr) {
			return cloudformation.ResourceResult{}, errors.Join(err, observationErr)
		}
		return cloudformation.ResourceResult{}, err
	}
	result = cloudformation.ResourceResult{PhysicalID: cfnComputeValue(out.Name), Ref: cfnComputeValue(out.Name), Attributes: map[string]any{"Arn": cfnComputeValue(out.TrailARN), "SnsTopicArn": cfnComputeValue(out.SnsTopicARN)}}
	return result, h.configure(ctx, r, result.PhysicalID)
}
func (h cfnTrail) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnComputeName(r, "TrailName", 128)
	if r.PhysicalID != "" {
		var err error
		name, err = cfnObservabilityARNName(r, "cloudtrail", "trail/")
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	return h.result(cfnTrailContext(ctx, r, true), r, name)
}
func (h cfnTrail) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name, err := cfnObservabilityARNName(r, "cloudtrail", "trail/")
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnTrailContext(ctx, r, false)
	input := map[string]any{"Name": name, "S3BucketName": r.Properties["S3BucketName"], "S3KeyPrefix": cfnComputeString(r.Properties, "S3KeyPrefix"), "SnsTopicName": cfnComputeString(r.Properties, "SnsTopicName"), "KmsKeyId": cfnComputeString(r.Properties, "KMSKeyId"), "CloudWatchLogsLogGroupArn": cfnComputeString(r.Properties, "CloudWatchLogsLogGroupArn"), "CloudWatchLogsRoleArn": cfnComputeString(r.Properties, "CloudWatchLogsRoleArn"), "IncludeGlobalServiceEvents": cfnComputeDefault(r.Properties, "IncludeGlobalServiceEvents", true), "IsMultiRegionTrail": cfnComputeDefault(r.Properties, "IsMultiRegionTrail", false), "IsOrganizationTrail": cfnComputeDefault(r.Properties, "IsOrganizationTrail", false), "EnableLogFileValidation": cfnComputeDefault(r.Properties, "EnableLogFileValidation", false)}
	if err := cfnComputeRun(ctx, h.commands, "cloudtrail", "UpdateTrail", input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result, err := h.result(ctx, r, name)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.configure(ctx, r, name); err != nil {
		return result, err
	}
	return result, h.syncTags(ctx, r, result.Attributes["Arn"].(string))
}
func (h cfnTrail) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnObservabilityName(r, "TrailName", 128)
	if r.CloudControl {
		var err error
		name, err = cfnObservabilityARNName(r, "cloudtrail", "trail/")
		if err != nil {
			return err
		}
	}
	err := cfnComputeRun(cfnTrailContext(ctx, r, false), h.commands, "cloudtrail", "DeleteTrail", map[string]any{"Name": name})
	if cfnTrailMissing(err) {
		return nil
	}
	return err
}
func (h cfnTrail) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	name, err := cfnObservabilityARNName(r, "cloudtrail", "trail/")
	if err != nil {
		return nil, err
	}
	out, err := cfnComputeCall[api.GetTrailOutput](ctx, h.commands, "cloudtrail", "GetTrail", map[string]any{"Name": name})
	if err != nil {
		if cfnTrailMissing(err) {
			return nil, cfnObservabilityNotFound()
		}
		return nil, err
	}
	if out.Trail == nil {
		return nil, cfnObservabilityNotFound()
	}
	model := cfnObservabilityModel(out.Trail)
	p := cloudformation.Properties(cfnComputeCopy(model, "S3BucketName", "S3KeyPrefix", "SnsTopicName", "IncludeGlobalServiceEvents", "IsMultiRegionTrail", "IsOrganizationTrail", "CloudWatchLogsLogGroupArn", "CloudWatchLogsRoleArn"))
	p["TrailName"] = cfnComputeValue(out.Trail.Name)
	p["Arn"] = cfnComputeValue(out.Trail.TrailARN)
	p["SnsTopicArn"] = cfnComputeValue(out.Trail.SnsTopicARN)
	if value, ok := model["KmsKeyId"]; ok {
		p["KMSKeyId"] = value
	}
	p["EnableLogFileValidation"] = model["LogFileValidationEnabled"]
	status, err := cfnComputeCall[api.GetTrailStatusOutput](ctx, h.commands, "cloudtrail", "GetTrailStatus", map[string]any{"Name": name})
	if err != nil {
		return nil, err
	}
	if status.IsLogging != nil {
		p["IsLogging"] = bool(*status.IsLogging)
	}
	selectors, err := cfnComputeCall[api.GetEventSelectorsOutput](ctx, h.commands, "cloudtrail", "GetEventSelectors", map[string]any{"TrailName": name})
	if err != nil {
		return nil, err
	}
	selection := cfnObservabilityModel(selectors)
	if len(selectors.AdvancedEventSelectors) > 0 {
		p["AdvancedEventSelectors"] = selection["AdvancedEventSelectors"]
	} else {
		p["EventSelectors"] = selection["EventSelectors"]
	}
	tags, err := h.tags(ctx, cfnComputeValue(out.Trail.TrailARN))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnTrail) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListTrailsOutput](ctx, h.commands, "cloudtrail", "ListTrails", input)
		if err != nil {
			return nil, err
		}
		for _, trail := range out.Trails {
			if cfnComputeValue(trail.HomeRegion) != r.Scope.Region {
				continue
			}
			r.PhysicalID = cfnComputeValue(trail.TrailARN)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: cfnComputeValue(trail.Name), Properties: p})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return result, nil
		}
		input["NextToken"] = string(*out.NextToken)
	}
}
