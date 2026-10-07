package integrations

import (
	"context"
	"stackd/internal/services/cloudformation"
)

func (h cfnGlueCatalog) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(r.PhysicalID, r.PhysicalID, cfnComputeCopy(p, "CatalogId", "ResourceArn", "CreateTime", "UpdateTime")), nil
}
func (h cfnGlueClassifier) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(r.PhysicalID, r.PhysicalID, map[string]any{"Name": p["Name"]}), nil
}
func (h cfnGlueConnection) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeString(p, "Name")
	return cfnAnalyticsResult(r.PhysicalID, name, map[string]any{"Name": name}), nil
}
func (h cfnGlueTable) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(r.PhysicalID, cfnComputeString(p, "Name"), map[string]any{"Id": p["Id"]}), nil
}
func (h cfnGluePartition) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(r.PhysicalID, r.PhysicalID, map[string]any{"IdentifierPartitionInputValues": p["IdentifierPartitionInputValues"]}), nil
}
