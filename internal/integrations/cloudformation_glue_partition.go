package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-partition.html
type cfnGluePartition struct{ commands StepFunctionsCommands }

func (h cfnGluePartition) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "CatalogId", "DatabaseName", "TableName", "PartitionInput"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "DatabaseName", "TableName", "PartitionInput"); err != nil {
		return err
	}
	return cloudformation.ValidateResourceProperties("AWS::Glue::Partition", p)
}
func (h cfnGluePartition) Replacement(a, b cloudformation.Properties) (bool, error) {
	av, _ := cfnComputeObject(a["PartitionInput"])
	bv, _ := cfnComputeObject(b["PartitionInput"])
	return cfnComputeChanged(a, b, "CatalogId", "DatabaseName", "TableName") || cfnComputeChanged(av, bv, "Values"), h.Validate(b)
}
func (h cfnGluePartition) identity(ctx context.Context, r cloudformation.ResourceRequest) (map[string]any, string, error) {
	catalog := cfnGlueCatalogID(r)
	db, table := cfnComputeString(r.Properties, "DatabaseName"), cfnComputeString(r.Properties, "TableName")
	body, _ := cfnComputeObject(r.Properties["PartitionInput"])
	values := body["Values"]
	hash := ""
	if r.PhysicalID != "" {
		parts, err := cfnGlueCompound(r.PhysicalID, 4)
		if err != nil {
			return nil, "", err
		}
		catalog, db, table, hash = parts[0], parts[1], parts[2], parts[3]
	}
	if values == nil && hash != "" {
		input := map[string]any{"CatalogId": catalog, "DatabaseName": db, "TableName": table}
		for {
			out, err := cfnComputeCall[api.GetPartitionsOutput](ctx, h.commands, "glue", "GetPartitions", input)
			if err != nil {
				return nil, "", err
			}
			for _, v := range out.Partitions {
				encoded, err := cfnGluePartitionValues(v.Values)
				if err != nil {
					return nil, "", err
				}
				if cfnComputeHash(encoded) == hash {
					values = v.Values
					break
				}
			}
			if values != nil || cfnComputeValue(out.NextToken) == "" {
				break
			}
			input["NextToken"] = out.NextToken
		}
	}
	if values == nil {
		return nil, "", &awswire.Error{Code: "EntityNotFoundException", Message: "Partition values do not identify an existing partition.", StatusCode: 400}
	}
	encoded, err := cfnGluePartitionValues(values)
	if err != nil {
		return nil, "", err
	}
	if hash != "" && hash != cfnComputeHash(encoded) {
		return nil, "", fmt.Errorf("partition values cannot change physical identity")
	}
	hash = cfnComputeHash(encoded)
	return map[string]any{"CatalogId": catalog, "DatabaseName": db, "TableName": table, "PartitionValues": values}, catalog + "|" + db + "|" + table + "|" + hash, nil
}
func (h cfnGluePartition) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input, id, err := h.identity(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnAnalyticsContext(ctx, r, "glue", "Partition")
	r.PhysicalID = id
	_, err = h.Read(ctx, r)
	if err == nil {
		return cfnAnalyticsResult(id, id, nil), nil
	}
	if !cfnAnalyticsMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	delete(input, "PartitionValues")
	input["PartitionInput"] = r.Properties["PartitionInput"]
	if err = cfnComputeRun(ctx, h.commands, "glue", "CreatePartition", input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(id, id, nil), nil
}
func (h cfnGluePartition) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnAnalyticsRequireIdentity(h, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input, id, err := h.identity(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnAnalyticsContext(ctx, r, "glue", "Partition")
	if _, err = h.Read(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input["PartitionValueList"] = input["PartitionValues"]
	delete(input, "PartitionValues")
	input["PartitionInput"] = r.Properties["PartitionInput"]
	return cfnAnalyticsResult(id, id, nil), cfnComputeRun(ctx, h.commands, "glue", "UpdatePartition", input)
}
func (h cfnGluePartition) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnAnalyticsContext(ctx, r, "glue", "Partition")
	if _, err := h.Read(ctx, r); err != nil {
		return cfnAnalyticsAbsent(err)
	}
	input, _, err := h.identity(ctx, r)
	if err != nil {
		return err
	}
	return cfnAnalyticsAbsent(cfnComputeRun(ctx, h.commands, "glue", "DeletePartition", input))
}
func (h cfnGluePartition) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	input, id, err := h.identity(ctx, r)
	if err != nil {
		return nil, err
	}
	ctx = cfnAnalyticsContext(ctx, r, "glue", "Partition")
	out, err := cfnComputeCall[api.GetPartitionOutput](ctx, h.commands, "glue", "GetPartition", input)
	if err != nil {
		return nil, err
	}
	body, err := cfnAnalyticsProject(out.Partition, "Values", "Parameters", "StorageDescriptor")
	if err != nil {
		return nil, err
	}
	parts, _ := cfnGlueCompound(id, 4)
	return cloudformation.Properties{"CatalogId": parts[0], "DatabaseName": parts[1], "TableName": parts[2], "IdentifierPartitionInputValues": parts[3], "PartitionInput": body}, nil
}
func (h cfnGluePartition) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	tables, err := cfnGlueTables(ctx, h.commands, r)
	if err != nil {
		return nil, err
	}
	rows := []cloudformation.ResourceDescription{}
	for _, table := range tables {
		input := map[string]any{"CatalogId": table["CatalogId"], "DatabaseName": table["DatabaseName"], "TableName": table["Name"]}
		for {
			out, err := cfnComputeCall[api.GetPartitionsOutput](ctx, h.commands, "glue", "GetPartitions", input)
			if err != nil {
				return nil, err
			}
			for _, v := range out.Partitions {
				encoded, err := cfnGluePartitionValues(v.Values)
				if err != nil {
					return nil, err
				}
				r.PhysicalID = cfnComputeString(table, "CatalogId") + "|" + cfnComputeString(table, "DatabaseName") + "|" + cfnComputeString(table, "Name") + "|" + cfnComputeHash(encoded)
				r.Properties = cloudformation.Properties{"PartitionInput": map[string]any{"Values": v.Values}}
				p, err := h.Read(ctx, r)
				if err != nil {
					return nil, err
				}
				rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
			}
			if cfnComputeValue(out.NextToken) == "" {
				break
			}
			input["NextToken"] = out.NextToken
		}
	}
	return cfnAnalyticsSort(rows), nil
}
