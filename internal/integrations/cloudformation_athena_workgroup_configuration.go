package integrations

import (
	"context"
	api "stackd/internal/awsapi/athena"
	"stackd/internal/services/cloudformation"
	"strconv"
)

func cfnAthenaConfigurationUpdates(r cloudformation.ResourceRequest) map[string]any {
	if p, ok := cfnComputeObject(r.Properties["WorkGroupConfigurationUpdates"]); ok {
		out := cfnComputeCopy(p, "BytesScannedCutoffPerQuery", "EnforceWorkGroupConfiguration", "PublishCloudWatchMetricsEnabled", "RequesterPaysEnabled", "ResultConfigurationUpdates", "RemoveBytesScannedCutoffPerQuery", "EngineVersion", "AdditionalConfiguration", "ExecutionRole", "CustomerContentEncryptionConfiguration", "RemoveCustomerContentEncryptionConfiguration", "EngineConfiguration", "MonitoringConfiguration")
		if v, ok := p["ManagedQueryResultsConfiguration"]; ok {
			out["ManagedQueryResultsConfigurationUpdates"] = v
		}
		return out
	}
	p, _ := cfnComputeObject(r.Properties["WorkGroupConfiguration"])
	previous, _ := cfnComputeObject(r.Previous["WorkGroupConfiguration"])
	out := cfnComputeCopy(p, "BytesScannedCutoffPerQuery", "EngineVersion", "AdditionalConfiguration", "ExecutionRole", "CustomerContentEncryptionConfiguration", "EngineConfiguration", "MonitoringConfiguration")
	for key, def := range map[string]any{"EnforceWorkGroupConfiguration": true, "PublishCloudWatchMetricsEnabled": true, "RequesterPaysEnabled": false} {
		out[key] = cfnComputeDefault(p, key, def)
	}
	if p["BytesScannedCutoffPerQuery"] == nil && previous["BytesScannedCutoffPerQuery"] != nil {
		out["RemoveBytesScannedCutoffPerQuery"] = true
	}
	if p["CustomerContentEncryptionConfiguration"] == nil && previous["CustomerContentEncryptionConfiguration"] != nil {
		out["RemoveCustomerContentEncryptionConfiguration"] = true
	}
	if v, ok := p["ManagedQueryResultsConfiguration"]; ok {
		out["ManagedQueryResultsConfigurationUpdates"] = v
	}
	results, _ := cfnComputeObject(p["ResultConfiguration"])
	oldResults, _ := cfnComputeObject(previous["ResultConfiguration"])
	changes := cfnComputeCopy(results, "OutputLocation", "EncryptionConfiguration", "ExpectedBucketOwner", "AclConfiguration")
	for _, key := range []string{"OutputLocation", "EncryptionConfiguration", "ExpectedBucketOwner", "AclConfiguration"} {
		if results[key] == nil && oldResults[key] != nil {
			changes["Remove"+key] = true
		}
	}
	if len(changes) > 0 {
		out["ResultConfigurationUpdates"] = changes
	}
	return out
}
func (h cfnAthenaWorkGroup) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	out, err := cfnComputeCall[api.GetWorkGroupOutput](ctx, h.commands, "athena", "GetWorkGroup", map[string]any{"WorkGroup": r.PhysicalID})
	if err != nil {
		return cfnAnalyticsResult(r.PhysicalID, r.PhysicalID, nil), err
	}
	attrs := map[string]any{}
	if out.WorkGroup != nil {
		if out.WorkGroup.CreationTime != nil {
			attrs["CreationTime"] = strconv.FormatInt(out.WorkGroup.CreationTime.Unix(), 10)
		}
		if c := out.WorkGroup.Configuration; c != nil && c.EngineVersion != nil {
			engine := cfnComputeValue(c.EngineVersion.EffectiveEngineVersion)
			attrs["WorkGroupConfiguration.EngineVersion.EffectiveEngineVersion"] = engine
			attrs["WorkGroupConfigurationUpdates.EngineVersion.EffectiveEngineVersion"] = engine
		}
	}
	return cfnAnalyticsResult(r.PhysicalID, r.PhysicalID, attrs), nil
}
func cfnAthenaEpoch(t *api.Date) string { return strconv.FormatInt(t.Unix(), 10) }
