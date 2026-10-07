package integrations

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/rds"
	"stackd/internal/services/cloudformation"
)

// Subnet membership is resolved and authorized by RDS against the existing EC2
// networking owner, not inferred from subnet-shaped strings.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbsubnetgroup.html
type cfnRDSSubnetGroup struct{ commands StepFunctionsCommands }

func (h cfnRDSSubnetGroup) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "DBSubnetGroupName", "DBSubnetGroupDescription", "SubnetIds", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "DBSubnetGroupDescription", "SubnetIds"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "DBSubnetGroupName", "DBSubnetGroupDescription"); err != nil {
		return err
	}
	ids, err := cfnComputeStringList(p, "SubnetIds")
	if err != nil {
		return err
	}
	if len(ids) < 2 {
		return fmt.Errorf("SubnetIds must cover at least two Availability Zones")
	}
	_, err = cfnComputeTags(p)
	return err
}
func (h cfnRDSSubnetGroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "DBSubnetGroupName"), h.Validate(b)
}
func (h cfnRDSSubnetGroup) get(ctx context.Context, name string) (*api.DBSubnetGroup, error) {
	out, err := cfnComputeCall[api.DBSubnetGroupMessage](ctx, h.commands, "rds", "DescribeDBSubnetGroups", map[string]any{"DBSubnetGroupName": name})
	if err != nil {
		return nil, err
	}
	if len(out.DBSubnetGroups) != 1 {
		return nil, fmt.Errorf("RDS returned no subnet group")
	}
	return &out.DBSubnetGroups[0], nil
}
func cfnRDSSubnetGroupResult(v *api.DBSubnetGroup) cloudformation.ResourceResult {
	name := cfnComputeValue(v.DBSubnetGroupName)
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{"DBSubnetGroupArn": cfnComputeValue(v.DBSubnetGroupArn)}}
}
func (h cfnRDSSubnetGroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (result cloudformation.ResourceResult, err error) {
	ctx = cfnRelationalContext(ctx, r, "rds", "subgrp", "DBSubnetGroupName", 255, true)
	defer func() {
		if err != nil && result.PhysicalID == "" {
			result, err = cfnRDSCreateFailure(ctx, r, h, err)
		}
	}()
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnRDSName(r, "DBSubnetGroupName", 255)
	v, err := h.get(ctx, name)
	if err == nil {
		return cfnRDSSubnetGroupResult(v), nil
	}
	if !cfnRDSMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnComputeCopy(r.Properties, "DBSubnetGroupDescription", "SubnetIds")
	input["DBSubnetGroupName"], input["Tags"] = name, cfnComputeTagList(cfnRDSPublicTags(r))
	out, err := cfnComputeCall[api.CreateDBSubnetGroupResult](ctx, h.commands, "rds", "CreateDBSubnetGroup", input)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if out.DBSubnetGroup == nil {
		return cloudformation.ResourceResult{}, fmt.Errorf("RDS create returned no subnet group")
	}
	return cfnRDSSubnetGroupResult(out.DBSubnetGroup), nil
}
func (h cfnRDSSubnetGroup) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnRelationalContext(ctx, r, "rds", "subgrp", "DBSubnetGroupName", 255, true)
	v, err := h.get(ctx, cfnRDSName(r, "DBSubnetGroupName", 255))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnRDSSubnetGroupResult(v), nil
}
func (h cfnRDSSubnetGroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnRelationalContext(ctx, r, "rds", "subgrp", "DBSubnetGroupName", 255, false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnRDSSubnetGroupResult(v)
	tags, err := cfnRDSTags(ctx, h.commands, cfnComputeValue(v.DBSubnetGroupArn))
	if err != nil {
		return result, err
	}

	input := cfnComputeCopy(r.Properties, "DBSubnetGroupDescription", "SubnetIds")
	input["DBSubnetGroupName"] = r.PhysicalID
	out, err := cfnComputeCall[api.ModifyDBSubnetGroupResult](ctx, h.commands, "rds", "ModifyDBSubnetGroup", input)
	if err != nil {
		return result, err
	}
	if out.DBSubnetGroup == nil {
		return result, fmt.Errorf("RDS modify returned no subnet group")
	}
	return cfnRDSSubnetGroupResult(out.DBSubnetGroup), cfnRDSUpdateTags(ctx, h.commands, r, cfnComputeValue(v.DBSubnetGroupArn), tags)
}
func (h cfnRDSSubnetGroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnRelationalContext(ctx, r, "rds", "subgrp", "DBSubnetGroupName", 255, false)
	name := cfnRDSName(r, "DBSubnetGroupName", 255)
	_, err := h.get(ctx, name)
	if cfnRDSMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return cfnRDSAbsent(cfnComputeRun(ctx, h.commands, "rds", "DeleteDBSubnetGroup", map[string]any{"DBSubnetGroupName": name}))
}
func (h cfnRDSSubnetGroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	ids := make([]any, 0, len(v.Subnets))
	for _, subnet := range v.Subnets {
		ids = append(ids, cfnComputeValue(subnet.SubnetIdentifier))
	}
	p := cloudformation.Properties{"DBSubnetGroupName": cfnComputeValue(v.DBSubnetGroupName), "DBSubnetGroupArn": cfnComputeValue(v.DBSubnetGroupArn), "DBSubnetGroupDescription": cfnComputeValue(v.DBSubnetGroupDescription), "SubnetIds": ids}
	tags, err := cfnRDSTags(ctx, h.commands, cfnComputeValue(v.DBSubnetGroupArn))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnRDSSubnetGroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DBSubnetGroupMessage](ctx, h.commands, "rds", "DescribeDBSubnetGroups", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.DBSubnetGroups {
			r.PhysicalID = cfnComputeValue(v.DBSubnetGroupName)
			p, err := h.Read(ctx, r)
			if err != nil {
				if cfnRDSMissing(err) {
					continue
				}
				return nil, err
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if marker := cfnComputeValue(out.Marker); marker != "" {
			input["Marker"] = marker
		} else {
			return rows, nil
		}
	}
}
