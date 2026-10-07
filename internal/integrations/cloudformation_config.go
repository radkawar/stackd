package integrations

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	api "stackd/internal/awsapi/configservice"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	config "stackd/internal/services/configservice"
)

// CloudFormationConfigSecurityHandlers contains only implemented Config and
// GuardDuty control owners. Findings continue to come from real source evidence.
// Resource contracts: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/AWS_Config.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/AWS_GuardDuty.html
// Recorder auto-start and stop/delete behavior follows:
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-config-configurationrecorder.html
// Authorization Ref is its ARN, rather than its compound registry identifier:
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-config-aggregationauthorization.html
// Publishing status/epoch-millisecond attributes are service-owned observations:
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-guardduty-publishingdestination.html
func CloudFormationConfigSecurityHandlers(c StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{
		"AWS::Config::ConfigurationRecorder":    cfnConfigRecorder{c},
		"AWS::Config::DeliveryChannel":          cfnConfigChannel{c},
		"AWS::Config::ConfigRule":               cfnConfigRule{c},
		"AWS::Config::ConfigurationAggregator":  cfnConfigAggregator{c},
		"AWS::Config::AggregationAuthorization": cfnConfigAuthorization{c},
		"AWS::GuardDuty::Detector":              cfnGuardDutyDetector{c},
		"AWS::GuardDuty::Filter":                cfnGuardDutyFilter{c},
		"AWS::GuardDuty::IPSet":                 cfnGuardDutyIPSet{c},
		"AWS::GuardDuty::ThreatIntelSet":        cfnGuardDutyThreatIntelSet{c},
		"AWS::GuardDuty::PublishingDestination": cfnGuardDutyDestination{c},
	}
}
func cfnConfigContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return config.WithCloudFormationOwnership(ctx, config.CloudFormationOwnership{Owner: cfnMessagingOwner(r), Token: cfnMessagingHash(r.Token)})
}
func cfnConfigCreateContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	r.CloudControl = false
	return cfnConfigContext(ctx, r)
}
func cfnSecurityTags(r cloudformation.ResourceRequest) (map[string]string, error) {
	tags, err := cfnComputeTags(r.Properties)
	if err != nil {
		return nil, err
	}
	for key, value := range r.Tags {
		if _, explicit := tags[key]; !explicit {
			tags[key] = value
		}
	}
	for key, value := range tags {
		if key == "" || len(key) > 128 || len(value) > 256 || strings.HasPrefix(strings.ToLower(key), "aws:") {
			return nil, fmt.Errorf("invalid or reserved tag %q", key)
		}
	}
	if len(tags) == 0 {
		return nil, nil
	}
	return tags, nil
}
func cfnConfigTagInput(tags map[string]string) []any {
	if len(tags) == 0 {
		return nil
	}
	out := make([]any, 0, len(tags))
	for _, k := range cfnMessagingKeys(tags) {
		out = append(out, map[string]any{"Key": k, "Value": tags[k]})
	}
	return out
}
func cfnConfigTags(ctx context.Context, c StepFunctionsCommands, arn string) (map[string]string, error) {
	o, e := cfnComputeCall[api.ListTagsForResourceOutput](ctx, c, "configservice", "ListTagsForResource", map[string]any{"ResourceArn": arn})
	if e != nil {
		return nil, e
	}
	out := map[string]string{}
	for _, t := range o.Tags {
		out[cfnComputeValue(t.Key)] = cfnComputeValue(t.Value)
	}
	return out, nil
}
func cfnConfigOwned(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string) error {
	if r.CloudControl {
		return nil
	}
	_, e := cfnConfigTags(cfnConfigContext(ctx, r), c, arn)
	return e
}
func cfnConfigUpdateTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string) error {
	ctx = cfnConfigContext(ctx, r)
	old, e := cfnConfigTags(ctx, c, arn)
	if e != nil {
		return e
	}
	next, e := cfnSecurityTags(r)
	if e != nil {
		return e
	}
	remove := []string{}
	for k := range old {
		if _, ok := next[k]; !ok {
			remove = append(remove, k)
		}
	}
	if len(remove) > 0 {
		if e := cfnComputeRun(ctx, c, "configservice", "UntagResource", map[string]any{"ResourceArn": arn, "TagKeys": remove}); e != nil {
			return e
		}
	}
	if len(next) > 0 {
		return cfnComputeRun(ctx, c, "configservice", "TagResource", map[string]any{"ResourceArn": arn, "Tags": cfnConfigTagInput(next)})
	}
	return nil
}
func cfnSecurityMissing(err error) bool {
	return cfnMessagingMissing(err, "ResourceNotFoundException", "NoSuchConfigurationRecorderException", "NoSuchDeliveryChannelException", "NoSuchConfigRuleException", "NoSuchConfigurationAggregatorException")
}
func cfnSecurityAbsent(err error) error {
	if cfnSecurityMissing(err) {
		return nil
	}
	return err
}
func cfnSecurityNotFound() error {
	return &awswire.Error{Code: "ResourceNotFoundException", Message: "The resource does not exist.", StatusCode: 404}
}

// Project generated DTOs by Smithy field name, preserving map keys such as
// finding criteria and recursively excluding absent optional fields.
func cfnSecurityValue(v reflect.Value) any {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		return cfnSecurityValue(v.Elem())
	}
	switch v.Kind() {
	case reflect.Struct:
		o := map[string]any{}
		t := v.Type()
		for i := range v.NumField() {
			f := v.Field(i)
			if !f.CanInterface() {
				continue
			}
			if (f.Kind() == reflect.Pointer || f.Kind() == reflect.Slice || f.Kind() == reflect.Map) && f.IsNil() {
				continue
			}
			o[t.Field(i).Name] = cfnSecurityValue(f)
		}
		return o
	case reflect.Slice:
		o := []any{}
		for i := range v.Len() {
			o = append(o, cfnSecurityValue(v.Index(i)))
		}
		return o
	case reflect.Map:
		o := map[string]any{}
		it := v.MapRange()
		for it.Next() {
			o[fmt.Sprint(it.Key().Interface())] = cfnSecurityValue(it.Value())
		}
		return o
	default:
		return v.Interface()
	}
}
func cfnSecurityModel(v any) cloudformation.Properties {
	return cloudformation.Properties(cfnSecurityValue(reflect.ValueOf(v)).(map[string]any))
}
func cfnSecuritySelect(v any, keys ...string) cloudformation.Properties {
	return cloudformation.Properties(cfnComputeCopy(cfnSecurityModel(v), keys...))
}
func cfnSecurityResult(id, ref string, attrs map[string]any) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: id, Ref: ref, Attributes: attrs}
}
func cfnSecurityName(r cloudformation.ResourceRequest, key string) string {
	if r.PhysicalID != "" {
		return r.PhysicalID
	}
	return cfnComputeName(r, key, 64)
}
func cfnSecurityUserTags[K ~string, V ~string](tags map[K]V) []any {
	out := make([]any, 0, len(tags))
	for _, k := range cfnMessagingKeys(tags) {
		out = append(out, map[string]any{"Key": string(k), "Value": string(tags[k])})
	}
	return out
}
