package integrations

import (
	"context"
	"errors"
	"fmt"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ec2"
)

type cfnEC2RouteAssociation struct{ commands StepFunctionsCommands }

func (h cfnEC2RouteAssociation) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "SubnetId", "RouteTableId"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "SubnetId", "RouteTableId"); err != nil {
		return err
	}
	return cfnComputeStrings(p, "SubnetId", "RouteTableId")
}
func (h cfnEC2RouteAssociation) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "SubnetId", "RouteTableId"), h.Validate(b)
}
func (h cfnEC2RouteAssociation) find(ctx context.Context, subnet, id string) (api.RouteTableAssociation, error) {
	if subnet == "" && id == "" {
		return api.RouteTableAssociation{}, fmt.Errorf("subnet route association lookup requires an exact subnet or association ID")
	}
	input := map[string]any{}
	if subnet != "" {
		input["Filters"] = []map[string]any{{"Name": "association.subnet-id", "Values": []string{subnet}}}
	}
	for {
		out, err := cfnComputeCall[api.DescribeRouteTablesResult](ctx, h.commands, "ec2", "DescribeRouteTables", input)
		if err != nil {
			return api.RouteTableAssociation{}, err
		}
		for _, table := range out.RouteTables {
			for _, a := range table.Associations {
				if cfnComputeValue(a.SubnetId) != "" && (subnet == "" || cfnComputeValue(a.SubnetId) == subnet) && (id == "" || cfnComputeValue(a.RouteTableAssociationId) == id) {
					return a, nil
				}
			}
		}
		if cfnComputeValue(out.NextToken) == "" {
			return api.RouteTableAssociation{}, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func (h cfnEC2RouteAssociation) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, _, receiptErr := cfnEC2RelationReceipt(ctx, h.commands, r, "")
	if receiptErr != nil && !errors.Is(receiptErr, ec2.ErrNotFound) {
		return cfnEC2IDResult(id), receiptErr
	}
	if err := h.Validate(r.Properties); err != nil {
		return cfnEC2IDResult(id), err
	}
	subnet, table := cfnComputeString(r.Properties, "SubnetId"), cfnComputeString(r.Properties, "RouteTableId")
	_, err := cfnEC2Subnet(h).describe(ctx, subnet)
	if err != nil {
		return cfnEC2IDResult(id), err
	}
	a, err := h.find(ctx, subnet, "")
	if err != nil {
		return cfnEC2IDResult(id), err
	}
	if receiptErr == nil {
		result, err := h.RecoverCreation(ctx, r)
		if err != nil {
			return result, err
		}
		if cfnComputeValue(a.RouteTableId) != table {
			return result, fmt.Errorf("the admitted subnet route association has different properties")
		}
		return result, nil
	}
	if cfnComputeValue(a.RouteTableAssociationId) != "" {
		return cloudformation.ResourceResult{}, fmt.Errorf("cannot adopt or overwrite an existing subnet route association")
	}
	out, err := cfnComputeCall[api.AssociateRouteTableResult](cfnEC2RelationContext(ctx, r, subnet), h.commands, "ec2", "AssociateRouteTable", map[string]any{"SubnetId": subnet, "RouteTableId": table})
	if err != nil {
		return cfnEC2RelationFailedCreate(ctx, h.commands, r, h.RecoverCreation, err)
	}
	result := cfnEC2IDResult(cfnComputeValue(out.AssociationId))
	result.Attributes = map[string]any{"Id": result.PhysicalID}
	return result, nil
}
func (h cfnEC2RouteAssociation) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if replacement, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	} else if replacement {
		return cloudformation.ResourceResult{}, fmt.Errorf("subnet route association requires replacement")
	}
	_, err := h.Read(ctx, r)
	result := cfnEC2IDResult(r.PhysicalID)
	result.Attributes = map[string]any{"Id": r.PhysicalID}
	return result, err
}
func (h cfnEC2RouteAssociation) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		return fmt.Errorf("subnet route association deletion requires an admitted association ID")
	}
	a, err := h.find(ctx, "", r.PhysicalID)
	if err != nil {
		return err
	}
	subnet := cfnComputeValue(a.SubnetId)
	if subnet == "" {
		subnet = cfnComputeString(r.Properties, "SubnetId")
	}
	if subnet == "" {
		return fmt.Errorf("cannot identify the exact subnet route association parent")
	}
	_, err = cfnEC2Subnet(h).describe(ctx, subnet)
	if err != nil {
		return cfnEC2Absent(err)
	}
	if cfnComputeValue(a.RouteTableAssociationId) != "" {
		if err = cfnEC2RelationOwned(ctx, h.commands, r, subnet, r.PhysicalID); err != nil {
			return err
		}
		if err = cfnComputeRun(cfnEC2RelationDeletionContext(ctx, r, subnet), h.commands, "ec2", "DisassociateRouteTable", map[string]any{"AssociationId": r.PhysicalID}); err != nil && !cfnEC2Missing(err) {
			return err
		}
	} else if !r.CloudControl {
		id, _, e := cfnEC2RelationReceipt(ctx, h.commands, r, subnet)
		if errors.Is(e, ec2.ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if id != r.PhysicalID {
			return fmt.Errorf("route association deletion ID differs from its native creation receipt")
		}
	}
	return nil
}
func (h cfnEC2RouteAssociation) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	a, err := h.find(ctx, "", r.PhysicalID)
	if err != nil {
		return nil, err
	}
	subnet := cfnComputeValue(a.SubnetId)
	if subnet == "" {
		return nil, cfnEC2NotFound("subnet route association")
	}
	if _, err = cfnEC2Subnet(h).describe(ctx, subnet); err != nil {
		return nil, err
	}
	if err = cfnEC2RelationOwned(ctx, h.commands, r, subnet, r.PhysicalID); err != nil {
		return nil, err
	}
	return cloudformation.Properties{"Id": cfnComputeValue(a.RouteTableAssociationId), "SubnetId": subnet, "RouteTableId": cfnComputeValue(a.RouteTableId)}, nil
}

func (h cfnEC2RouteAssociation) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, _, receiptErr := cfnEC2RelationReceipt(ctx, h.commands, r, "")
	result := cfnEC2IDResult(id)
	if receiptErr != nil && !errors.Is(receiptErr, ec2.ErrNotFound) {
		return result, receiptErr
	}
	subnet := cfnComputeString(r.Properties, "SubnetId")
	if subnet == "" {
		return result, fmt.Errorf("subnet route recovery requires the exact subnet")
	}
	_, err := cfnEC2Subnet(h).describe(ctx, subnet)
	if err != nil {
		return result, fmt.Errorf("cannot observe the exact subnet during creation recovery: %v", err)
	}
	a, err := h.find(ctx, subnet, "")
	if err != nil {
		return result, fmt.Errorf("cannot observe the current subnet route association: %v", err)
	}
	result, err = cfnEC2RelationRecover(ctx, h.commands, r, subnet, cfnComputeValue(a.RouteTableAssociationId))
	if result.PhysicalID != "" {
		result.Attributes = map[string]any{"Id": result.PhysicalID}
	}
	return result, err
}
func (h cfnEC2RouteAssociation) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	for input := map[string]any{}; ; {
		out, err := cfnComputeCall[api.DescribeRouteTablesResult](ctx, h.commands, "ec2", "DescribeRouteTables", input)
		if err != nil {
			return nil, err
		}
		for _, table := range out.RouteTables {
			for _, a := range table.Associations {
				subnet, id := cfnComputeValue(a.SubnetId), cfnComputeValue(a.RouteTableAssociationId)
				if subnet == "" {
					continue
				}
				if !r.CloudControl && cfnEC2RelationOwned(ctx, h.commands, r, subnet, id) != nil {
					continue
				}
				result = append(result, cloudformation.ResourceDescription{Identifier: id, Properties: cloudformation.Properties{"Id": id, "SubnetId": subnet, "RouteTableId": cfnComputeValue(a.RouteTableId)}})
			}
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
