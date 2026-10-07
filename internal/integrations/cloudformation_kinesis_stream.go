package integrations

import (
	"context"
	"fmt"
	"slices"
	"strings"

	kinesisapi "stackd/internal/awsapi/kinesis"
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/services/cloudformation"
)

// cfnKinesisStream drives the Kinesis owner's CreateStream and its explicit
// stream transitions. Each asynchronous transition waits for ACTIVE.
type cfnKinesisStream struct{ commands StepFunctionsCommands }

type cfnKinesisStreamMode struct{ StreamMode string }
type cfnKinesisEncryption struct{ EncryptionType, KeyId string }

type cfnKinesisStreamProperties struct {
	Name                       string
	ShardCount                 *cfnMessagingInt
	StreamModeDetails          *cfnKinesisStreamMode
	RetentionPeriodHours       *cfnMessagingInt
	StreamEncryption           *cfnKinesisEncryption
	DesiredShardLevelMetrics   []string
	MaxRecordSizeInKiB         *cfnMessagingInt
	WarmThroughputMiBps        *cfnMessagingInt
	RecordDistributionStrategy string
	Tags                       []cfnMessagingTag
}

// Kinesis exposes these as the enhanced shard-level metrics; ALL selects them.
var cfnKinesisMetrics = []string{"IncomingBytes", "IncomingRecords", "OutgoingBytes", "OutgoingRecords", "WriteProvisionedThroughputExceeded", "ReadProvisionedThroughputExceeded", "IteratorAgeMilliseconds"}

func (p cfnKinesisStreamProperties) mode() string {
	if p.StreamModeDetails == nil {
		// Pinned schema default for /properties/StreamModeDetails.
		return "PROVISIONED"
	}
	return p.StreamModeDetails.StreamMode
}

func (p cfnKinesisStreamProperties) retention() int64 {
	if p.RetentionPeriodHours == nil {
		return 24
	}
	return int64(*p.RetentionPeriodHours)
}

func (p cfnKinesisStreamProperties) recordSize() int64 {
	if p.MaxRecordSizeInKiB == nil {
		return 1024
	}
	return int64(*p.MaxRecordSizeInKiB)
}

func (p cfnKinesisStreamProperties) metrics() []string {
	if slices.Contains(p.DesiredShardLevelMetrics, "ALL") {
		return slices.Clone(cfnKinesisMetrics)
	}
	out := slices.Clone(p.DesiredShardLevelMetrics)
	slices.Sort(out)
	return slices.Compact(out)
}

func cfnKinesisStreamDecode(raw cloudformation.Properties) (cfnKinesisStreamProperties, error) {
	var p cfnKinesisStreamProperties
	if raw == nil {
		raw = cloudformation.Properties{}
	}
	if err := cfnMessagingDecode(raw, &p); err != nil {
		return p, err
	}
	mode := p.mode()
	switch mode {
	case "PROVISIONED":
		if p.ShardCount == nil {
			return p, fmt.Errorf("ShardCount is required when StreamModeDetails.StreamMode is PROVISIONED")
		}
		if p.WarmThroughputMiBps != nil {
			return p, fmt.Errorf("WarmThroughputMiBps can only be set when StreamMode is ON_DEMAND")
		}
	case "ON_DEMAND":
		if p.ShardCount != nil {
			return p, fmt.Errorf("ShardCount must not be specified when StreamMode is ON_DEMAND")
		}
	default:
		return p, fmt.Errorf("StreamModeDetails.StreamMode must be ON_DEMAND or PROVISIONED")
	}
	switch p.RecordDistributionStrategy {
	case "":
	case "USER_PARTITION_KEY":
		if mode != "ON_DEMAND" {
			return p, fmt.Errorf("RecordDistributionStrategy is only supported for ON_DEMAND streams")
		}
	case "AUTO":
		// The pinned Kinesis model and owner have no API selecting AUTO distribution.
		return p, cfnDataUnsupported("The stackd Kinesis owner", map[string]bool{"RecordDistributionStrategy=AUTO": true})
	default:
		return p, fmt.Errorf("RecordDistributionStrategy must be AUTO or USER_PARTITION_KEY")
	}
	if e := p.StreamEncryption; e != nil && (e.EncryptionType != "KMS" || e.KeyId == "") {
		return p, fmt.Errorf("StreamEncryption requires EncryptionType KMS and a KeyId")
	}
	for _, metric := range p.DesiredShardLevelMetrics {
		if metric != "ALL" && !slices.Contains(cfnKinesisMetrics, metric) {
			return p, fmt.Errorf("invalid DesiredShardLevelMetrics value %q", metric)
		}
	}
	_, err := cfnComputeTags(raw)
	return p, err
}

func (h cfnKinesisStream) Validate(p cloudformation.Properties) error {
	_, err := cfnKinesisStreamDecode(p)
	return err
}

func (h cfnKinesisStream) Replacement(a, b cloudformation.Properties) (bool, error) {
	before, err := cfnKinesisStreamDecode(a)
	if err != nil {
		return false, err
	}
	after, err := cfnKinesisStreamDecode(b)
	if err != nil {
		return false, err
	}
	return cfnMessagingReplacement(after.Name != "" && before.Name == after.Name, before.Name != after.Name)
}

func (h cfnKinesisStream) describe(ctx context.Context, name string) (*kinesisapi.StreamDescriptionSummary, error) {
	out, err := cfnComputeCall[kinesisapi.DescribeStreamSummaryOutput](ctx, h.commands, "kinesis", "DescribeStreamSummary", map[string]any{"StreamName": name})
	if err != nil {
		return nil, err
	}
	if out.StreamDescriptionSummary == nil {
		return nil, fmt.Errorf("Kinesis returned no stream summary for %s", name)
	}
	return out.StreamDescriptionSummary, nil
}

func cfnKinesisTags(ctx context.Context, commands StepFunctionsCommands, arn string) (map[string]string, error) {
	out, err := cfnComputeCall[kinesisapi.ListTagsForResourceOutput](ctx, commands, "kinesis", "ListTagsForResource", map[string]any{"ResourceARN": arn})
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string, len(out.Tags))
	for _, tag := range out.Tags {
		tags[cfnComputeValue(tag.Key)] = cfnComputeValue(tag.Value)
	}
	return tags, nil
}

func cfnKinesisStreamResult(stream *kinesisapi.StreamDescriptionSummary) cloudformation.ResourceResult {
	name := cfnComputeValue(stream.StreamName)
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{"Arn": cfnComputeValue(stream.StreamARN)}}
}

func (h cfnKinesisStream) owned(ctx context.Context, r cloudformation.ResourceRequest, name string) (*kinesisapi.StreamDescriptionSummary, error) {
	return h.describe(cfnKinesisOwnerContext(ctx, r, "stream", false), name)
}

func (h cfnKinesisStream) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnKinesisOwnerContext(ctx, r, "stream", true)
	p, err := cfnKinesisStreamDecode(r.Properties)
	if err != nil {
		result, _ := h.RecoverCreation(ctx, r)
		return result, err
	}
	name := cfnComputeName(r, "Name", 128)
	if stream, err := h.describe(ctx, name); err == nil {
		return cfnKinesisStreamResult(stream), nil
	} else if !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	in := map[string]any{"StreamName": name, "StreamModeDetails": map[string]any{"StreamMode": p.mode()}}
	if tags := cfnDataCreateTags(r); len(tags) > 0 {
		in["Tags"] = tags
	}
	if p.ShardCount != nil {
		in["ShardCount"] = int64(*p.ShardCount)
	}
	if p.MaxRecordSizeInKiB != nil {
		in["MaxRecordSizeInKiB"] = int64(*p.MaxRecordSizeInKiB)
	}
	if p.WarmThroughputMiBps != nil {
		in["WarmThroughputMiBps"] = int64(*p.WarmThroughputMiBps)
	}
	if err := cfnComputeRun(ctx, h.commands, "kinesis", "CreateStream", in); err != nil {
		result, _ := h.RecoverCreation(ctx, r)
		return result, err
	}
	stream, err := h.describe(ctx, name)
	if err != nil {
		return cloudformation.ResourceResult{PhysicalID: name, Ref: name}, err
	}
	return cfnKinesisStreamResult(stream), nil
}

func (h cfnKinesisStream) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnKinesisOwnerContext(ctx, r, "stream", false)
	p, err := cfnKinesisStreamDecode(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	stream, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnKinesisStreamResult(stream)
	_, err = h.converge(ctx, r, p, stream)
	return result, err
}

func (h cfnKinesisStream) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnKinesisOwnerContext(ctx, r, "stream", false)
	p, err := cfnKinesisStreamDecode(r.Properties)
	if err != nil {
		return false, err
	}
	stream, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	return h.converge(ctx, r, p, stream)
}

func (h cfnKinesisStream) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnKinesisOwnerContext(ctx, r, "stream", false)
	stream, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnKinesisStreamResult(stream), nil
}

func cfnKinesisCurrentMetrics(stream *kinesisapi.StreamDescriptionSummary) []string {
	var out []string
	for _, monitoring := range stream.EnhancedMonitoring {
		for _, metric := range monitoring.ShardLevelMetrics {
			out = append(out, string(metric))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// converge issues at most one asynchronous stream transition per pass. Tags
// are synchronous and are reconciled after the stream reaches the requested state.
func (h cfnKinesisStream) converge(ctx context.Context, r cloudformation.ResourceRequest, p cfnKinesisStreamProperties, stream *kinesisapi.StreamDescriptionSummary) (bool, error) {
	switch status := cfnComputeValue(stream.StreamStatus); status {
	case "ACTIVE":
	case "CREATING", "UPDATING":
		return false, nil
	default:
		return false, fmt.Errorf("Kinesis stream %s is %s", cfnComputeValue(stream.StreamName), status)
	}
	arn := cfnComputeValue(stream.StreamARN)
	mode := "PROVISIONED"
	if stream.StreamModeDetails != nil && stream.StreamModeDetails.StreamMode != nil {
		mode = string(*stream.StreamModeDetails.StreamMode)
	}
	run := func(operation string, in map[string]any) (bool, error) {
		in["StreamARN"] = arn
		return false, cfnComputeRun(ctx, h.commands, "kinesis", operation, in)
	}
	if mode != p.mode() {
		in := map[string]any{"StreamModeDetails": map[string]any{"StreamMode": p.mode()}}
		if p.WarmThroughputMiBps != nil {
			in["WarmThroughputMiBps"] = int64(*p.WarmThroughputMiBps)
		}
		return run("UpdateStreamMode", in)
	}
	if mode == "PROVISIONED" && int64(*p.ShardCount) != cfnDataInt(stream.OpenShardCount) {
		return run("UpdateShardCount", map[string]any{"TargetShardCount": int64(*p.ShardCount), "ScalingType": "UNIFORM_SCALING"})
	}
	if current := cfnDataInt(stream.RetentionPeriodHours); p.retention() > current {
		return run("IncreaseStreamRetentionPeriod", map[string]any{"RetentionPeriodHours": p.retention()})
	} else if p.retention() < current {
		return run("DecreaseStreamRetentionPeriod", map[string]any{"RetentionPeriodHours": p.retention()})
	}
	if p.recordSize() != cfnDataInt(stream.MaxRecordSizeInKiB) {
		return run("UpdateMaxRecordSize", map[string]any{"MaxRecordSizeInKiB": p.recordSize()})
	}
	if mode == "ON_DEMAND" && p.WarmThroughputMiBps != nil {
		target := int64(-1)
		if stream.WarmThroughput != nil {
			target = cfnDataInt(stream.WarmThroughput.TargetMiBps)
		}
		if target != int64(*p.WarmThroughputMiBps) {
			return run("UpdateStreamWarmThroughput", map[string]any{"WarmThroughputMiBps": int64(*p.WarmThroughputMiBps)})
		}
	}
	encrypted := cfnComputeValue(stream.EncryptionType) == "KMS"
	if p.StreamEncryption == nil && encrypted {
		return run("StopStreamEncryption", map[string]any{"EncryptionType": "KMS", "KeyId": cfnComputeValue(stream.KeyId)})
	}
	if p.StreamEncryption != nil {
		same := false
		if encrypted {
			var err error
			if same, err = cfnKinesisSameKey(ctx, h.commands, p.StreamEncryption.KeyId, cfnComputeValue(stream.KeyId)); err != nil {
				return false, err
			}
		}
		if !same {
			return run("StartStreamEncryption", map[string]any{"EncryptionType": "KMS", "KeyId": p.StreamEncryption.KeyId})
		}
	}
	current, desired := cfnKinesisCurrentMetrics(stream), p.metrics()
	var enable, disable []string
	for _, metric := range desired {
		if !slices.Contains(current, metric) {
			enable = append(enable, metric)
		}
	}
	for _, metric := range current {
		if !slices.Contains(desired, metric) {
			disable = append(disable, metric)
		}
	}
	if len(enable) > 0 {
		return run("EnableEnhancedMonitoring", map[string]any{"ShardLevelMetrics": enable})
	}
	if len(disable) > 0 {
		return run("DisableEnhancedMonitoring", map[string]any{"ShardLevelMetrics": disable})
	}
	return true, cfnKinesisReconcileTags(ctx, h.commands, r, arn)
}

// cfnKinesisSameKey compares the requested key with the owner's resolved key.
// Aliases and key IDs are resolved by the KMS owner, not by string guessing.
func cfnKinesisSameKey(ctx context.Context, commands StepFunctionsCommands, requested, current string) (bool, error) {
	if requested == current || strings.HasSuffix(current, ":key/"+requested) {
		return true, nil
	}
	if requested == "alias/aws/kinesis" || current == "alias/aws/kinesis" {
		return false, nil
	}
	out, err := cfnComputeCall[kmsapi.DescribeKeyResponse](ctx, commands, "kms", "DescribeKey", map[string]any{"KeyId": requested})
	if err != nil {
		return false, err
	}
	return out.KeyMetadata != nil && cfnComputeValue(out.KeyMetadata.Arn) == current, nil
}

func cfnKinesisReconcileTags(ctx context.Context, commands StepFunctionsCommands, r cloudformation.ResourceRequest, arn string) error {
	current, err := cfnKinesisTags(ctx, commands, arn)
	if err != nil {
		return err
	}
	desired := cfnDataCreateTags(r)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if err := cfnComputeRun(ctx, commands, "kinesis", "UntagResource", map[string]any{"ResourceARN": arn, "TagKeys": removed}); err != nil {
			return err
		}
	}
	if changed := cfnDataChangedTags(current, desired); len(changed) > 0 {
		return cfnComputeRun(ctx, commands, "kinesis", "TagResource", map[string]any{"ResourceARN": arn, "Tags": changed})
	}
	return nil
}

// Delete admits deletion only from ACTIVE, as the owner requires; transitional
// streams are deleted by StabilizeDeletion once their transition completes.
func (h cfnKinesisStream) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnKinesisOwnerContext(ctx, r, "stream", false)
	_, err := h.deleteOnce(ctx, r)
	return err
}

func (h cfnKinesisStream) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnKinesisOwnerContext(ctx, r, "stream", false)
	return h.deleteOnce(ctx, r)
}

func (h cfnKinesisStream) deleteOnce(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	name := r.PhysicalID
	if name == "" {
		name = cfnComputeName(r, "Name", 128)
	}
	stream, err := h.owned(ctx, r, name)
	if cfnComputeMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if cfnComputeValue(stream.StreamStatus) != "ACTIVE" {
		return false, nil
	}
	err = cfnComputeRun(ctx, h.commands, "kinesis", "DeleteStream", map[string]any{"StreamARN": cfnComputeValue(stream.StreamARN), "EnforceConsumerDeletion": false})
	if cfnComputeMissing(err) {
		return true, nil
	}
	return false, err
}

func (h cfnKinesisStream) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	stream, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	mode := "PROVISIONED"
	if stream.StreamModeDetails != nil && stream.StreamModeDetails.StreamMode != nil {
		mode = string(*stream.StreamModeDetails.StreamMode)
	}
	p := cloudformation.Properties{
		"Name":                     cfnComputeValue(stream.StreamName),
		"Arn":                      cfnComputeValue(stream.StreamARN),
		"StreamModeDetails":        map[string]any{"StreamMode": mode},
		"RetentionPeriodHours":     cfnDataInt(stream.RetentionPeriodHours),
		"MaxRecordSizeInKiB":       cfnDataInt(stream.MaxRecordSizeInKiB),
		"DesiredShardLevelMetrics": cfnKinesisCurrentMetrics(stream),
	}
	if mode == "PROVISIONED" {
		p["ShardCount"] = cfnDataInt(stream.OpenShardCount)
	}
	if cfnComputeValue(stream.EncryptionType) == "KMS" {
		p["StreamEncryption"] = map[string]any{"EncryptionType": "KMS", "KeyId": cfnComputeValue(stream.KeyId)}
	}
	if w := stream.WarmThroughput; w != nil {
		p["WarmThroughputObject"] = map[string]any{"TargetMiBps": cfnDataInt(w.TargetMiBps), "CurrentMiBps": cfnDataInt(w.CurrentMiBps)}
	}
	tags, err := cfnKinesisTags(ctx, h.commands, cfnComputeValue(stream.StreamARN))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnDataUserTags(tags)
	return p, nil
}

func (h cfnKinesisStream) List(ctx context.Context, _ cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	result := []cloudformation.ResourceDescription{}
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[kinesisapi.ListStreamsOutput](ctx, h.commands, "kinesis", "ListStreams", in)
		if err != nil {
			return nil, err
		}
		for _, summary := range out.StreamSummaries {
			name := cfnComputeValue(summary.StreamName)
			result = append(result, cloudformation.ResourceDescription{Identifier: name, Properties: cloudformation.Properties{"Name": name, "Arn": cfnComputeValue(summary.StreamARN)}})
		}
		if len(out.StreamSummaries) == 0 {
			for _, name := range out.StreamNames {
				result = append(result, cloudformation.ResourceDescription{Identifier: string(name), Properties: cloudformation.Properties{"Name": string(name)}})
			}
		}
		if !cfnDataBool(out.HasMoreStreams) || cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		in = map[string]any{"NextToken": cfnComputeValue(out.NextToken)}
	}
}
