package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/cloudwatch"
)

// CloudFormationObservabilityHandlers uses only the existing authoritative
// observability command owners. Contributor Insights has no implemented owner.
func CloudFormationObservabilityHandlers(c StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{
		"AWS::CloudWatch::Alarm":          cfnMetricAlarm{cfnCWAlarm{c, false}},
		"AWS::CloudWatch::CompositeAlarm": cfnCompositeAlarm{cfnCWAlarm{c, true}},
		"AWS::CloudWatch::Dashboard":      cfnCWDashboard{c},
		"AWS::Logs::LogStream":            cfnLogStream{c},
		"AWS::Logs::MetricFilter":         cfnLogMetricFilter{c},
		"AWS::Logs::SubscriptionFilter":   cfnLogSubscriptionFilter{c},
		"AWS::Logs::Destination":          cfnLogDestination{c},
		"AWS::Logs::ResourcePolicy":       cfnLogResourcePolicy{c},
		"AWS::CloudTrail::Trail":          cfnTrail{c},
		"AWS::XRay::Group":                cfnXRayGroup{c},
		"AWS::XRay::SamplingRule":         cfnXRaySamplingRule{c},
		"AWS::XRay::ResourcePolicy":       cfnXRayResourcePolicy{c},
	}
}

func cfnObservabilityModel(v any) cloudformation.Properties {
	b, _ := json.Marshal(v)
	var p cloudformation.Properties
	_ = json.Unmarshal(b, &p)
	return p
}
func cfnObservabilityNotFound() error {
	return &awswire.Error{Code: "ResourceNotFoundException", Message: "The observability resource does not exist.", StatusCode: 404}
}
func cfnObservabilityName(r cloudformation.ResourceRequest, property string, limit int) string {
	if r.PhysicalID != "" {
		return r.PhysicalID
	}
	return cfnComputeName(r, property, limit)
}
func cfnObservabilityARNName(r cloudformation.ResourceRequest, service, prefix string) (string, error) {
	id := r.PhysicalID
	if strings.HasPrefix(id, "arn:") {
		if err := cfnMessagingScopeARN(r, id, service); err != nil {
			return "", err
		}
		resource := strings.SplitN(id, ":", 6)[5]
		if !strings.HasPrefix(resource, prefix) {
			return "", fmt.Errorf("invalid %s identifier", service)
		}
		id = strings.TrimPrefix(resource, prefix)
	}
	if id == "" {
		return "", fmt.Errorf("resource identifier is required")
	}
	return id, nil
}
func cfnCWContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return cloudwatch.WithCloudFormationOwner(ctx, cfnLogsMarker(r), false)
}
func cfnCWCreateContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	return cloudwatch.WithCloudFormationOwner(ctx, cfnLogsMarker(r), true)
}
func cfnObservabilityCreateTags(r cloudformation.ResourceRequest) map[string]string {
	tags := make(map[string]string, len(r.Tags))
	for key, value := range r.Tags {
		tags[key] = value
	}
	resource, _ := cfnComputeTags(r.Properties)
	for key, value := range resource {
		tags[key] = value
	}
	return tags
}
func cfnCWTags(ctx context.Context, c StepFunctionsCommands, arn string) (map[string]string, error) {
	out, err := cfnComputeCall[api.ListTagsForResourceOutput](ctx, c, "cloudwatch", "ListTagsForResource", map[string]any{"ResourceARN": arn})
	if err != nil {
		return nil, err
	}
	tags := map[string]string{}
	for _, t := range out.Tags {
		tags[cfnComputeValue(t.Key)] = cfnComputeValue(t.Value)
	}
	return tags, nil
}
func cfnCWSyncTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string) error {
	current, err := cfnCWTags(ctx, c, arn)
	if err != nil {
		return err
	}
	desired := cfnObservabilityCreateTags(r)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if err := cfnComputeRun(ctx, c, "cloudwatch", "UntagResource", map[string]any{"ResourceARN": arn, "TagKeys": removed}); err != nil {
			return err
		}
	}
	if len(desired) > 0 {
		return cfnComputeRun(ctx, c, "cloudwatch", "TagResource", map[string]any{"ResourceARN": arn, "Tags": cfnComputeTagList(desired)})
	}
	return nil
}

type cfnCWAlarm struct {
	commands  StepFunctionsCommands
	composite bool
}
type cfnMetricAlarm struct{ cfnCWAlarm }
type cfnCompositeAlarm struct{ cfnCWAlarm }

func (h cfnCWAlarm) fields() []string {
	fields := []string{"AlarmName", "AlarmDescription", "ActionsEnabled", "AlarmActions", "OKActions", "InsufficientDataActions", "Tags"}
	if h.composite {
		return append(fields, "AlarmRule", "ActionsSuppressor", "ActionsSuppressorWaitPeriod", "ActionsSuppressorExtensionPeriod")
	}
	return append(fields, "ComparisonOperator", "DatapointsToAlarm", "Dimensions", "EvaluateLowSampleCountPercentile", "EvaluationPeriods", "ExtendedStatistic", "MetricName", "Metrics", "Namespace", "Period", "Statistic", "Threshold", "ThresholdMetricId", "TreatMissingData", "Unit")
}
func (h cfnCWAlarm) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, h.fields()...); err != nil {
		return err
	}
	if h.composite {
		if err := cfnComputeRequired(p, "AlarmRule"); err != nil {
			return err
		}
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnCWAlarm) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "AlarmName"), h.Validate(b)
}
func (h cfnCWAlarm) result(r cloudformation.ResourceRequest, name string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{"Arn": "arn:" + r.Scope.Partition + ":cloudwatch:" + r.Scope.Region + ":" + r.Scope.Account + ":alarm:" + name}}
}
func (h cfnCWAlarm) write(ctx context.Context, r cloudformation.ResourceRequest, create bool) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnObservabilityName(r, "AlarmName", 255)
	result := h.result(r, name)
	input := cfnComputeCopy(r.Properties, h.fields()...)
	input["AlarmName"] = name
	if create {
		input["Tags"] = cfnComputeTagList(cfnObservabilityCreateTags(r))
		ctx = cfnCWCreateContext(ctx, r)
	} else {
		delete(input, "Tags")
		ctx = cfnCWContext(ctx, r)
	}
	operation := "PutMetricAlarm"
	if h.composite {
		operation = "PutCompositeAlarm"
	}
	var admissions map[string]string
	if create {
		admissions = map[string]string{}
		kind := "MetricAlarm"
		if h.composite {
			kind = "CompositeAlarm"
		}
		ctx = cloudwatch.WithCloudFormationObservation(ctx, kind, name, admissions)
	}
	if err := cfnComputeRun(ctx, h.commands, "cloudwatch", operation, input); err != nil {
		if !create || admissions[name] == cfnLogsMarker(r) {
			return result, err
		}
		admitted, recoveryErr := h.RecoverCreation(ctx, r)
		if recoveryErr == nil {
			return admitted, err
		}
		return cloudformation.ResourceResult{}, err
	}
	return result, cfnCWSyncTags(ctx, h.commands, r, result.Attributes["Arn"].(string))
}
func (h cfnCWAlarm) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.write(ctx, r, true)
}
func (h cfnCWAlarm) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name, err := cfnObservabilityARNName(r, "cloudwatch", "alarm:")
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	r.PhysicalID = name
	return h.write(ctx, r, false)
}
func (h cfnCWAlarm) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnObservabilityName(r, "AlarmName", 255)
	if r.CloudControl {
		var err error
		name, err = cfnObservabilityARNName(r, "cloudwatch", "alarm:")
		if err != nil {
			return err
		}
	}
	return cfnComputeAbsent(cfnComputeRun(cfnCWContext(ctx, r), h.commands, "cloudwatch", "DeleteAlarms", map[string]any{"AlarmNames": []string{name}}))
}
func (h cfnCWAlarm) describe(ctx context.Context, r cloudformation.ResourceRequest, input map[string]any) ([]cloudformation.ResourceDescription, error) {
	kind := "MetricAlarm"
	if h.composite {
		kind = "CompositeAlarm"
	}
	input["AlarmTypes"] = []string{kind}
	var result []cloudformation.ResourceDescription
	for {
		out, err := cfnComputeCall[api.DescribeAlarmsOutput](ctx, h.commands, "cloudwatch", "DescribeAlarms", input)
		if err != nil {
			return nil, err
		}
		models := []cloudformation.Properties{}
		if h.composite {
			for _, alarm := range out.CompositeAlarms {
				models = append(models, cfnObservabilityModel(alarm))
			}
		} else {
			for _, alarm := range out.MetricAlarms {
				models = append(models, cfnObservabilityModel(alarm))
			}
		}
		for _, model := range models {
			name := cfnComputeString(model, "AlarmName")
			p := cloudformation.Properties(cfnComputeCopy(model, h.fields()...))
			p["Arn"] = model["AlarmArn"]
			tags, err := cfnCWTags(ctx, h.commands, cfnComputeString(model, "AlarmArn"))
			if err != nil {
				return nil, err
			}
			p["Tags"] = cfnResourcePublicTags(tags)
			result = append(result, cloudformation.ResourceDescription{Identifier: name, Properties: p})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return result, nil
		}
		input["NextToken"] = string(*out.NextToken)
	}
}
func (h cfnCWAlarm) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	name, err := cfnObservabilityARNName(r, "cloudwatch", "alarm:")
	if err != nil {
		return nil, err
	}
	out, err := h.describe(ctx, r, map[string]any{"AlarmNames": []string{name}})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, cfnObservabilityNotFound()
	}
	return out[0].Properties, nil
}
func (h cfnCWAlarm) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	return h.describe(ctx, r, map[string]any{})
}

// Dashboard lifecycle follows the native global dashboard owner:
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudwatch-dashboard.html
type cfnCWDashboard struct{ commands StepFunctionsCommands }

func (h cfnCWDashboard) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "DashboardName", "DashboardBody", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "DashboardBody"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnCWDashboard) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "DashboardName"), h.Validate(b)
}
func (h cfnCWDashboard) result(r cloudformation.ResourceRequest, name string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name}
}
func (h cfnCWDashboard) write(ctx context.Context, r cloudformation.ResourceRequest, create bool) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnObservabilityName(r, "DashboardName", 255)
	result := h.result(r, name)
	if create {
		ctx = cfnCWCreateContext(ctx, r)
	} else {
		ctx = cfnCWContext(ctx, r)
	}
	var admissions map[string]string
	if create {
		admissions = map[string]string{}
		ctx = cloudwatch.WithCloudFormationObservation(ctx, "Dashboard", name, admissions)
	}
	if err := cfnComputeRun(ctx, h.commands, "cloudwatch", "PutDashboard", map[string]any{"DashboardName": name, "DashboardBody": r.Properties["DashboardBody"], "Tags": cfnComputeTagList(cfnObservabilityCreateTags(r))}); err != nil {
		if !create || admissions[name] == cfnLogsMarker(r) {
			return result, err
		}
		admitted, recoveryErr := h.RecoverCreation(ctx, r)
		if recoveryErr == nil {
			return admitted, err
		}
		return cloudformation.ResourceResult{}, err
	}
	return result, cfnCWSyncTags(ctx, h.commands, r, "arn:"+r.Scope.Partition+":cloudwatch::"+r.Scope.Account+":dashboard/"+name)
}
func (h cfnCWDashboard) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.write(ctx, r, true)
}
func (h cfnCWDashboard) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.write(ctx, r, false)
}
func (h cfnCWDashboard) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	return cfnComputeAbsent(cfnComputeRun(cfnCWContext(ctx, r), h.commands, "cloudwatch", "DeleteDashboards", map[string]any{"DashboardNames": []string{cfnObservabilityName(r, "DashboardName", 255)}}))
}
func (h cfnCWDashboard) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, err := cfnComputeCall[api.GetDashboardOutput](ctx, h.commands, "cloudwatch", "GetDashboard", map[string]any{"DashboardName": r.PhysicalID})
	if err != nil {
		return nil, err
	}
	tags, err := cfnCWTags(ctx, h.commands, cfnComputeValue(out.DashboardArn))
	if err != nil {
		return nil, err
	}
	return cloudformation.Properties{"DashboardName": cfnComputeValue(out.DashboardName), "DashboardBody": cfnComputeValue(out.DashboardBody), "Tags": cfnResourcePublicTags(tags)}, nil
}
func (h cfnCWDashboard) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListDashboardsOutput](ctx, h.commands, "cloudwatch", "ListDashboards", input)
		if err != nil {
			return nil, err
		}
		for _, entry := range out.DashboardEntries {
			r.PhysicalID = cfnComputeValue(entry.DashboardName)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return result, nil
		}
		input["NextToken"] = string(*out.NextToken)
	}
}

func (h cfnCWAlarm) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnObservabilityName(r, "AlarmName", 255)
	kind := "MetricAlarm"
	if h.composite {
		kind = "CompositeAlarm"
	}
	rows := map[string]string{}
	ctx = cloudwatch.WithCloudFormationObservation(ctx, kind, name, rows)
	out, err := h.describe(ctx, r, map[string]any{"AlarmNames": []string{name}})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if len(out) == 0 {
		return cloudformation.ResourceResult{}, cfnObservabilityNotFound()
	}
	if rows[name] != cfnLogsMarker(r) {
		return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, fmt.Errorf("alarm is not owned by this creation"))
	}
	return h.result(r, name), nil
}
func (h cfnCWDashboard) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnObservabilityName(r, "DashboardName", 255)
	rows := map[string]string{}
	ctx = cloudwatch.WithCloudFormationObservation(ctx, "Dashboard", name, rows)
	_, err := cfnComputeCall[api.GetDashboardOutput](ctx, h.commands, "cloudwatch", "GetDashboard", map[string]any{"DashboardName": name})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if rows[name] != cfnLogsMarker(r) {
		return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, fmt.Errorf("dashboard is not owned by this creation"))
	}
	return h.result(r, name), nil
}
