package integrations

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/firehose"
	"stackd/internal/services/cloudformation"
	firehose "stackd/internal/services/firehose"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kinesisfirehose-deliverystream.html
type cfnDeliveryStream struct{ commands StepFunctionsCommands }

func cfnFirehoseContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return firehose.WithCloudFormationOwner(ctx, cfnMessagingMarker(r))
}
func (h cfnDeliveryStream) Validate(p cloudformation.Properties) error {
	if err := cfnWorkflowValidate(p, nil, "DeliveryStreamEncryptionConfigurationInput", "HttpEndpointDestinationConfiguration", "KinesisStreamSourceConfiguration", "DeliveryStreamType", "IcebergDestinationConfiguration", "RedshiftDestinationConfiguration", "AmazonopensearchserviceDestinationConfiguration", "MSKSourceConfiguration", "DirectPutSourceConfiguration", "SplunkDestinationConfiguration", "ExtendedS3DestinationConfiguration", "AmazonOpenSearchServerlessDestinationConfiguration", "ElasticsearchDestinationConfiguration", "SnowflakeDestinationConfiguration", "DatabaseSourceConfiguration", "S3DestinationConfiguration", "DeliveryStreamName", "Tags"); err != nil {
		return err
	}
	if p["DeliveryStreamEncryptionConfigurationInput"] != nil {
		return fmt.Errorf("the Firehose owner does not support delivery stream encryption")
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnDeliveryStream) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "DeliveryStreamName", "DeliveryStreamType", "KinesisStreamSourceConfiguration", "MSKSourceConfiguration", "DirectPutSourceConfiguration", "DatabaseSourceConfiguration"), h.Validate(b)
}
func cfnDeliveryStreamResult(r cloudformation.ResourceRequest, name string) cloudformation.ResourceResult {
	return cfnWorkflowResult(name, name, "arn:"+r.Scope.Partition+":firehose:"+r.Scope.Region+":"+r.Scope.Account+":deliverystream/"+name)
}
func (h cfnDeliveryStream) describe(ctx context.Context, name string) (*api.DeliveryStreamDescription, error) {
	out, err := cfnComputeCall[api.DescribeDeliveryStreamOutput](ctx, h.commands, "firehose", "DescribeDeliveryStream", map[string]any{"DeliveryStreamName": name})
	if err != nil {
		return nil, err
	}
	if out.DeliveryStreamDescription == nil {
		return nil, fmt.Errorf("firehose owner returned no stream description")
	}
	return out.DeliveryStreamDescription, nil
}
func (h cfnDeliveryStream) tags(ctx context.Context, name string) (map[string]string, error) {
	tags := map[string]string{}
	in := map[string]any{"DeliveryStreamName": name}
	for {
		out, err := cfnComputeCall[api.ListTagsForDeliveryStreamOutput](ctx, h.commands, "firehose", "ListTagsForDeliveryStream", in)
		if err != nil {
			return nil, err
		}
		for _, tag := range out.Tags {
			tags[cfnComputeValue(tag.Key)] = cfnComputeValue(tag.Value)
		}
		if out.HasMoreTags == nil || !bool(*out.HasMoreTags) {
			return tags, nil
		}
		if len(out.Tags) == 0 {
			return nil, fmt.Errorf("firehose tag pagination made no progress")
		}
		in["ExclusiveStartTagKey"] = cfnComputeValue(out.Tags[len(out.Tags)-1].Key)
	}
}
func (h cfnDeliveryStream) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "DeliveryStreamName", 64)
	result := cfnDeliveryStreamResult(r, name)
	ctx = firehose.WithCloudFormationOwner(ctx, cfnMessagingMarker(r))
	_, err := h.describe(ctx, name)
	if err == nil {
		return result, nil
	}
	if !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	in := map[string]any{}
	for k, v := range r.Properties {
		if k != "Tags" {
			in[k] = v
		}
	}
	in["DeliveryStreamName"] = name
	tags, err := cfnWorkflowTags(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	in["Tags"] = cfnComputeTagList(tags)
	if err = cfnComputeRun(ctx, h.commands, "firehose", "CreateDeliveryStream", in); err != nil {
		// A modeled command error may be a lost reply after admission. Only the
		// exact incarnation's authorized read can establish rollback ownership.
		if _, readErr := h.describe(ctx, name); readErr == nil {
			return result, err
		}
		return cloudformation.ResourceResult{}, err
	}
	return result, nil
}
func (h cfnDeliveryStream) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnComputeName(r, "DeliveryStreamName", 64)
	out, err := h.describe(firehose.WithCloudFormationOwner(ctx, cfnMessagingMarker(r)), name)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnDeliveryStreamResult(r, cfnComputeValue(out.DeliveryStreamName)), nil
}
func cfnFirehoseS3Update(configuration map[string]any, extended bool) map[string]any {
	out := map[string]any{}
	for k, v := range configuration {
		if k == "S3BackupConfiguration" {
			if backup, ok := cfnComputeObject(v); ok {
				out["S3BackupUpdate"] = cfnFirehoseS3Update(backup, false)
			}
		} else {
			out[k] = v
		}
	}
	for k, v := range map[string]any{"Prefix": "", "ErrorOutputPrefix": "", "BufferingHints": map[string]any{"SizeInMBs": 5, "IntervalInSeconds": 300}, "CompressionFormat": "UNCOMPRESSED", "EncryptionConfiguration": map[string]any{"NoEncryptionConfig": "NoEncryption"}, "CloudWatchLoggingOptions": map[string]any{"Enabled": false, "LogGroupName": "", "LogStreamName": ""}} {
		if _, ok := out[k]; !ok {
			out[k] = v
		}
	}
	if extended {
		for k, v := range map[string]any{"ProcessingConfiguration": map[string]any{"Enabled": false}, "S3BackupMode": "Disabled", "CustomTimeZone": "UTC", "FileExtension": ""} {
			if _, ok := out[k]; !ok {
				out[k] = v
			}
		}
	}
	return out
}
func (h cfnDeliveryStream) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if cfnComputeChanged(r.Previous, r.Properties, "DeliveryStreamEncryptionConfigurationInput") && r.Previous["DeliveryStreamEncryptionConfigurationInput"] != nil {
		return cloudformation.ResourceResult{}, fmt.Errorf("the Firehose owner does not support delivery stream encryption updates")
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnDeliveryStreamResult(r, r.PhysicalID)
	ctx = cfnFirehoseContext(ctx, r)
	old, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	if len(old.Destinations) != 1 {
		return result, fmt.Errorf("firehose owner returned an unexpected destination count")
	}
	in := map[string]any{"DeliveryStreamName": r.PhysicalID, "CurrentDeliveryStreamVersionId": cfnComputeValue(old.VersionId), "DestinationId": cfnComputeValue(old.Destinations[0].DestinationId)}
	if configuration, ok := cfnComputeObject(r.Properties["ExtendedS3DestinationConfiguration"]); ok {
		in["ExtendedS3DestinationUpdate"] = cfnFirehoseS3Update(configuration, true)
	} else if configuration, ok := cfnComputeObject(r.Properties["S3DestinationConfiguration"]); ok {
		in["S3DestinationUpdate"] = cfnFirehoseS3Update(configuration, false)
	} else {
		return result, fmt.Errorf("the Firehose owner supports only S3 destinations")
	}
	if err = cfnComputeRun(ctx, h.commands, "firehose", "UpdateDestination", in); err != nil {
		return result, err
	}
	current, err := h.tags(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	desired, err := cfnWorkflowTags(r)
	if err != nil {
		return result, err
	}
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if err = cfnComputeRun(ctx, h.commands, "firehose", "UntagDeliveryStream", map[string]any{"DeliveryStreamName": r.PhysicalID, "TagKeys": removed}); err != nil {
			return result, err
		}
	}
	return result, cfnComputeRun(ctx, h.commands, "firehose", "TagDeliveryStream", map[string]any{"DeliveryStreamName": r.PhysicalID, "Tags": cfnComputeTagList(desired)})
}
func (h cfnDeliveryStream) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.CloudControl && r.Token != "" {
		// Failed CC creates retain their original token. Establish the exact private
		// incarnation before allowing rollback of a still-CREATING delivery stream.
		if _, err := h.RecoverCreation(ctx, r); err == nil {
			ctx = firehose.WithCloudFormationOwner(ctx, cfnMessagingMarker(r))
		}
	}
	return cfnComputeAbsent(cfnComputeRun(cfnFirehoseContext(ctx, r), h.commands, "firehose", "DeleteDeliveryStream", map[string]any{"DeliveryStreamName": cfnComputeName(r, "DeliveryStreamName", 64)}))
}
func (h cfnDeliveryStream) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"DeliveryStreamName": cfnComputeValue(out.DeliveryStreamName), "Arn": cfnComputeValue(out.DeliveryStreamARN), "DeliveryStreamType": cfnComputeValue(out.DeliveryStreamType)}
	if out.Source != nil && out.Source.KinesisStreamSourceDescription != nil {
		source, err := cfnWorkflowProjection(out.Source.KinesisStreamSourceDescription, "KinesisStreamARN", "RoleARN")
		if err != nil {
			return nil, err
		}
		p["KinesisStreamSourceConfiguration"] = source
	}
	if len(out.Destinations) == 1 {
		destination := out.Destinations[0].ExtendedS3DestinationDescription
		if destination != nil {
			configuration, err := cfnWorkflowProjection(destination, "BucketARN", "RoleARN", "Prefix", "ErrorOutputPrefix", "BufferingHints", "CompressionFormat", "EncryptionConfiguration", "CloudWatchLoggingOptions", "ProcessingConfiguration", "S3BackupMode", "CustomTimeZone", "FileExtension", "DataFormatConversionConfiguration", "DynamicPartitioningConfiguration")
			if err != nil {
				return nil, err
			}
			if destination.S3BackupDescription != nil {
				backup, err := cfnWorkflowProjection(destination.S3BackupDescription, "BucketARN", "RoleARN", "Prefix", "ErrorOutputPrefix", "BufferingHints", "CompressionFormat", "EncryptionConfiguration", "CloudWatchLoggingOptions")
				if err != nil {
					return nil, err
				}
				configuration["S3BackupConfiguration"] = backup
			}
			p["ExtendedS3DestinationConfiguration"] = configuration
		}
	}
	tags, err := h.tags(ctx, r.PhysicalID)
	p["Tags"] = cfnWorkflowUserTags(tags)
	return p, err
}
func (h cfnDeliveryStream) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListDeliveryStreamsOutput](ctx, h.commands, "firehose", "ListDeliveryStreams", in)
		if err != nil {
			return nil, err
		}
		for _, name := range out.DeliveryStreamNames {
			rr := r
			rr.PhysicalID = string(name)
			p, err := h.Read(ctx, rr)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: rr.PhysicalID, Properties: p})
		}
		if out.HasMoreDeliveryStreams == nil || !bool(*out.HasMoreDeliveryStreams) {
			return result, nil
		}
		if len(out.DeliveryStreamNames) == 0 {
			return nil, fmt.Errorf("firehose list pagination made no progress")
		}
		in["ExclusiveStartDeliveryStreamName"] = string(out.DeliveryStreamNames[len(out.DeliveryStreamNames)-1])
	}
}
func (h cfnDeliveryStream) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	out, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	status := cfnComputeValue(out.DeliveryStreamStatus)
	if status == "CREATING_FAILED" || status == "DELETING_FAILED" {
		return false, fmt.Errorf("firehose stream entered %s", status)
	}
	return status == "ACTIVE", nil
}
func (h cfnDeliveryStream) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.describe(ctx, r.PhysicalID)
	if cfnComputeMissing(err) {
		return true, nil
	}
	return false, err
}
