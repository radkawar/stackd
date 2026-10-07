package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/configservice"
	"stackd/internal/services/cloudformation"
)

type cfnConfigRecorder struct{ c StepFunctionsCommands }

func (h cfnConfigRecorder) Validate(p cloudformation.Properties) error {
	if e := cfnComputeProperties(p, "Name", "RoleARN", "RecordingGroup", "RecordingMode", "StartedOnCreate"); e != nil {
		return e
	}
	return cfnComputeRequired(p, "RoleARN")
}
func (h cfnConfigRecorder) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name", "StartedOnCreate"), nil
}
func (h cfnConfigRecorder) load(ctx context.Context, r cloudformation.ResourceRequest) (api.ConfigurationRecorder, error) {
	name := r.PhysicalID
	if name == "" {
		name = cfnComputeString(r.Properties, "Name")
		if name == "" {
			name = "default"
		}
	}
	o, e := cfnComputeCall[api.DescribeConfigurationRecordersOutput](ctx, h.c, "configservice", "DescribeConfigurationRecorders", map[string]any{"ConfigurationRecorderNames": []string{name}})
	if e != nil {
		return api.ConfigurationRecorder{}, e
	}
	if len(o.ConfigurationRecorders) == 0 {
		return api.ConfigurationRecorder{}, cfnSecurityNotFound()
	}
	v := o.ConfigurationRecorders[0]
	if e := cfnConfigOwned(ctx, h.c, r, cfnComputeValue(v.Arn)); e != nil {
		return api.ConfigurationRecorder{}, e
	}
	return v, nil
}
func (h cfnConfigRecorder) result(v api.ConfigurationRecorder) cloudformation.ResourceResult {
	return cfnSecurityResult(cfnComputeValue(v.Name), cfnComputeValue(v.Name), map[string]any{"ResourceARN": cfnComputeValue(v.Arn)})
}
func (h cfnConfigRecorder) create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p := cfnComputeCopy(r.Properties, "Name", "RoleARN", "RecordingGroup", "RecordingMode")
	if p["Name"] == nil {
		p["Name"] = "default"
	}
	name := cfnComputeString(cloudformation.Properties(p), "Name")
	if name == "" {
		name = "default"
		p["Name"] = name
	}
	t, e := cfnSecurityTags(r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	e = cfnComputeRun(cfnConfigContext(ctx, r), h.c, "configservice", "PutConfigurationRecorder", map[string]any{"ConfigurationRecorder": p, "Tags": cfnConfigTagInput(t)})
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	// Put admitted this name even if the subsequent authorized read fails.
	res := cfnSecurityResult(name, name, nil)
	lookup := r
	lookup.PhysicalID = name
	v, e := h.load(ctx, lookup)
	if e != nil {
		return res, e
	}
	res = h.result(v)
	return res, nil
}
func (h cfnConfigRecorder) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	v, e := h.load(ctx, r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	if e = cfnConfigOwned(ctx, h.c, r, cfnComputeValue(v.Arn)); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	p := cfnComputeCopy(r.Properties, "RoleARN", "RecordingGroup", "RecordingMode")
	p["Name"] = r.PhysicalID
	e = cfnComputeRun(cfnConfigContext(ctx, r), h.c, "configservice", "PutConfigurationRecorder", map[string]any{"ConfigurationRecorder": p})
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	v, e = h.load(ctx, r)
	return h.result(v), e
}
func (h cfnConfigRecorder) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	v, e := h.load(ctx, r)
	if e != nil {
		return cfnSecurityAbsent(e)
	}
	if e = cfnConfigOwned(ctx, h.c, r, cfnComputeValue(v.Arn)); e != nil {
		return e
	}
	if e = cfnComputeRun(cfnConfigContext(ctx, r), h.c, "configservice", "StopConfigurationRecorder", map[string]any{"ConfigurationRecorderName": cfnComputeValue(v.Name)}); e != nil {
		return e
	}
	return cfnSecurityAbsent(cfnComputeRun(cfnConfigContext(ctx, r), h.c, "configservice", "DeleteConfigurationRecorder", map[string]any{"ConfigurationRecorderName": cfnComputeValue(v.Name)}))
}
func (h cfnConfigRecorder) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, e := h.load(ctx, r)
	if e != nil {
		return nil, e
	}
	p := cfnSecuritySelect(v, "Name", "RoleARN", "RecordingGroup", "RecordingMode")
	p["ResourceARN"] = cfnComputeValue(v.Arn)
	source, ok := h.c.providers["configservice"].executor.(interface {
		CloudFormationRecorderStartedOnCreate(context.Context, string) (bool, bool, error)
	})
	if !ok {
		return nil, fmt.Errorf("config native recorder creation metadata unavailable")
	}
	started, known, e := source.CloudFormationRecorderStartedOnCreate(cfnConfigContext(ctx, r), cfnComputeValue(v.Name))
	if e != nil {
		return nil, e
	}
	if known {
		p["StartedOnCreate"] = started
	}
	return p, nil
}
func (h cfnConfigRecorder) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	o, e := cfnComputeCall[api.DescribeConfigurationRecordersOutput](ctx, h.c, "configservice", "DescribeConfigurationRecorders", map[string]any{})
	if e != nil {
		return nil, e
	}
	out := []cloudformation.ResourceDescription{}
	for _, v := range o.ConfigurationRecorders {
		r.PhysicalID = cfnComputeValue(v.Name)
		p, e := h.Read(ctx, r)
		if e != nil {
			return nil, e
		}
		out = append(out, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
	}
	return out, nil
}

type cfnConfigChannel struct{ c StepFunctionsCommands }

func (h cfnConfigChannel) Validate(p cloudformation.Properties) error {
	if e := cfnComputeProperties(p, "Name", "S3BucketName", "S3KeyPrefix", "S3KmsKeyArn", "SnsTopicARN", "ConfigSnapshotDeliveryProperties"); e != nil {
		return e
	}
	return cfnComputeRequired(p, "S3BucketName")
}
func (h cfnConfigChannel) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name"), nil
}
func (h cfnConfigChannel) load(ctx context.Context, r cloudformation.ResourceRequest) (api.DeliveryChannel, error) {
	name := cfnSecurityName(r, "Name")
	o, e := cfnComputeCall[api.DescribeDeliveryChannelsOutput](cfnConfigContext(ctx, r), h.c, "configservice", "DescribeDeliveryChannels", map[string]any{"DeliveryChannelNames": []string{name}})
	if e != nil {
		return api.DeliveryChannel{}, e
	}
	if len(o.DeliveryChannels) == 0 {
		return api.DeliveryChannel{}, cfnSecurityNotFound()
	}
	return o.DeliveryChannels[0], nil
}
func (h cfnConfigChannel) create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnSecurityName(r, "Name")
	p := cfnComputeCopy(r.Properties, "S3BucketName", "S3KeyPrefix", "S3KmsKeyArn", "SnsTopicARN", "ConfigSnapshotDeliveryProperties")
	p["Name"] = name
	res := cfnSecurityResult(name, name, nil)
	if e := cfnComputeRun(cfnConfigContext(ctx, r), h.c, "configservice", "PutDeliveryChannel", map[string]any{"DeliveryChannel": p}); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	return res, nil
}
func (h cfnConfigChannel) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if _, e := h.load(ctx, r); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	return h.create(ctx, r)
}
func (h cfnConfigChannel) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if _, e := h.load(ctx, r); e != nil {
		return cfnSecurityAbsent(e)
	}
	// Only the recorder resource owner may stop its recorder. Native admission
	// rejects deletion while recording, without changing another resource.
	return cfnSecurityAbsent(cfnComputeRun(cfnConfigContext(ctx, r), h.c, "configservice", "DeleteDeliveryChannel", map[string]any{"DeliveryChannelName": cfnSecurityName(r, "Name")}))
}
func (h cfnConfigChannel) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, e := h.load(ctx, r)
	if e != nil {
		return nil, e
	}
	return cfnSecuritySelect(v, "Name", "S3BucketName", "S3KeyPrefix", "S3KmsKeyArn", "SnsTopicARN", "ConfigSnapshotDeliveryProperties"), nil
}
func (h cfnConfigChannel) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	o, e := cfnComputeCall[api.DescribeDeliveryChannelsOutput](ctx, h.c, "configservice", "DescribeDeliveryChannels", map[string]any{})
	if e != nil {
		return nil, e
	}
	out := []cloudformation.ResourceDescription{}
	for _, v := range o.DeliveryChannels {
		out = append(out, cloudformation.ResourceDescription{Identifier: cfnComputeValue(v.Name), Properties: cfnSecuritySelect(v, "Name", "S3BucketName", "S3KeyPrefix", "S3KmsKeyArn", "SnsTopicARN", "ConfigSnapshotDeliveryProperties")})
	}
	return out, nil
}
