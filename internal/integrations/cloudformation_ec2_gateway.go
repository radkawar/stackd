package integrations

import (
	"context"
	"errors"
	"fmt"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ec2"
)

type cfnEC2InternetGateway struct{ commands StepFunctionsCommands }

func (h cfnEC2InternetGateway) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Tags"); err != nil {
		return err
	}
	_, err := cfnEC2NetworkTags(p)
	return err
}
func (h cfnEC2InternetGateway) Replacement(a, b cloudformation.Properties) (bool, error) {
	return false, h.Validate(b)
}
func (h cfnEC2InternetGateway) describe(ctx context.Context, id string) (api.InternetGateway, error) {
	out, err := cfnComputeCall[api.DescribeInternetGatewaysResult](ctx, h.commands, "ec2", "DescribeInternetGateways", map[string]any{"InternetGatewayIds": []string{id}})
	if err != nil {
		return api.InternetGateway{}, err
	}
	if len(out.InternetGateways) != 1 {
		return api.InternetGateway{}, fmt.Errorf("internet gateway %s not found", id)
	}
	return out.InternetGateways[0], nil
}
func (h cfnEC2InternetGateway) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	if err != nil {
		return cfnEC2IDResult(id), err
	}
	if id == "" {
		out, err := cfnComputeCall[api.CreateInternetGatewayResult](cfnEC2NativeContext(ctx, r, "create"), h.commands, "ec2", "CreateInternetGateway", map[string]any{"TagSpecifications": cfnEC2NetworkTagSpecifications(r, "internet-gateway")})
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		id = cfnComputeValue(out.InternetGateway.InternetGatewayId)
	}
	v, err := h.describe(ctx, id)
	result := cfnEC2IDResult(id)
	result.Attributes = map[string]any{"InternetGatewayId": id}
	if err != nil {
		return result, err
	}
	return result, cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.InternetGatewayId))
}
func (h cfnEC2InternetGateway) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	v, err := h.describe(ctx, r.PhysicalID)
	result := cfnEC2IDResult(r.PhysicalID)
	result.Attributes = map[string]any{"InternetGatewayId": r.PhysicalID}
	if err != nil {
		return result, err
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.InternetGatewayId)); err != nil {
		return result, err
	}
	return result, cfnEC2NetworkUpdateTags(ctx, h.commands, r, r.PhysicalID, cfnEC2Tags(v.Tags))
}
func (h cfnEC2InternetGateway) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	v, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return cfnEC2Absent(err)
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.InternetGatewayId)); err != nil {
		return err
	}
	return cfnEC2Absent(cfnComputeRun(cfnEC2NativeContext(ctx, r, "mutate"), h.commands, "ec2", "DeleteInternetGateway", map[string]any{"InternetGatewayId": r.PhysicalID}))
}
func (h cfnEC2InternetGateway) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.InternetGatewayId)); err != nil {
		return nil, err
	}
	return cloudformation.Properties{"InternetGatewayId": cfnComputeValue(v.InternetGatewayId), "Tags": cfnEC2NetworkUserTags(v.Tags)}, nil
}
func (h cfnEC2InternetGateway) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	for input := map[string]any{}; ; {
		out, err := cfnComputeCall[api.DescribeInternetGatewaysResult](ctx, h.commands, "ec2", "DescribeInternetGateways", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.InternetGateways {
			if !r.CloudControl && cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.InternetGatewayId)) != nil {
				continue
			}
			id := cfnComputeValue(v.InternetGatewayId)
			result = append(result, cloudformation.ResourceDescription{Identifier: id, Properties: cloudformation.Properties{"InternetGatewayId": id, "Tags": cfnEC2NetworkUserTags(v.Tags)}})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func (h cfnEC2InternetGateway) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	result := cfnEC2IDResult(id)
	if err != nil || id == "" {
		if err == nil {
			err = cfnEC2NotFound(r.Type)
		}
		return result, err
	}
	r.PhysicalID = id
	if _, err = h.Read(ctx, r); err != nil {
		return result, err
	}
	result.Attributes = map[string]any{"InternetGatewayId": id}
	return result, nil
}

type cfnEC2GatewayAttachment struct{ commands StepFunctionsCommands }

func (h cfnEC2GatewayAttachment) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "VpcId", "InternetGatewayId"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "VpcId", "InternetGatewayId"); err != nil {
		return err
	}
	return cfnComputeStrings(p, "VpcId", "InternetGatewayId")
}
func (h cfnEC2GatewayAttachment) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "VpcId"), h.Validate(b)
}
func (h cfnEC2GatewayAttachment) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.admit(ctx, r, false)
}
func cfnEC2GatewayAttachmentResult(r cloudformation.ResourceRequest, result cloudformation.ResourceResult) cloudformation.ResourceResult {
	if result.PhysicalID == "" {
		return result
	}
	kind, vpc, err := cfnEC2Pair(result.PhysicalID, "AttachmentType", "VpcId")
	if err != nil {
		return result
	}
	result.PhysicalID = cfnEC2PairID(r, kind, vpc, "AttachmentType", "VpcId")
	result.Ref = result.PhysicalID
	result.Attributes = map[string]any{"AttachmentType": kind}
	return result
}
func (h cfnEC2GatewayAttachment) admit(ctx context.Context, r cloudformation.ResourceRequest, migration bool) (cloudformation.ResourceResult, error) {
	admitted, _, receiptErr := cfnEC2RelationReceipt(ctx, h.commands, r, "")
	result := cfnEC2GatewayAttachmentResult(r, cfnEC2IDResult(admitted))
	if receiptErr != nil && !errors.Is(receiptErr, ec2.ErrNotFound) {
		return result, receiptErr
	}
	if err := h.Validate(r.Properties); err != nil {
		return result, err
	}
	id, vpc := cfnComputeString(r.Properties, "InternetGatewayId"), cfnComputeString(r.Properties, "VpcId")
	v, err := cfnEC2InternetGateway(h).describe(ctx, id)
	if err != nil {
		return result, err
	}
	canonical := "INTERNET_GATEWAY|" + vpc
	if receiptErr == nil && admitted != canonical {
		return result, fmt.Errorf("gateway attachment native receipt belongs to another VPC")
	}
	if len(v.Attachments) > 0 {
		if len(v.Attachments) != 1 || cfnComputeValue(v.Attachments[0].VpcId) != vpc {
			return result, fmt.Errorf("internet gateway is attached to another VPC")
		}
		owned := r
		owned.PhysicalID = canonical
		owned.CloudControl = false
		if err := cfnEC2RelationOwned(ctx, h.commands, owned, id, canonical); err != nil || receiptErr != nil {
			if err == nil {
				err = fmt.Errorf("cannot adopt an existing internet gateway attachment")
			}
			return result, err
		}
		return result, nil
	}
	if receiptErr == nil && !migration {
		return h.RecoverCreation(ctx, r)
	}
	if err = cfnComputeRun(cfnEC2RelationContext(ctx, r, id), h.commands, "ec2", "AttachInternetGateway", map[string]any{"InternetGatewayId": id, "VpcId": vpc}); err != nil {
		return cfnEC2RelationFailedCreate(ctx, h.commands, r, h.RecoverCreation, err)
	}
	return cfnEC2GatewayAttachmentResult(r, cfnEC2IDResult(canonical)), nil
}
func (h cfnEC2GatewayAttachment) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID, Attributes: map[string]any{"AttachmentType": "INTERNET_GATEWAY"}}
	if replacement, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return result, err
	} else if replacement {
		return result, fmt.Errorf("gateway attachment requires replacement")
	}
	if !cfnComputeChanged(r.Previous, r.Properties, "InternetGatewayId") {
		_, err := h.Read(ctx, r)
		return result, err
	}
	kind, vpc, err := cfnEC2Pair(r.PhysicalID, "AttachmentType", "VpcId")
	if err != nil || kind != "INTERNET_GATEWAY" {
		return result, fmt.Errorf("gateway migration requires an admitted internet gateway attachment")
	}
	next := cfnComputeString(r.Properties, "InternetGatewayId")
	v, err := cfnEC2InternetGateway(h).describe(ctx, next)
	if err != nil {
		return result, err
	}
	if len(v.Attachments) > 0 {
		if len(v.Attachments) != 1 || cfnComputeValue(v.Attachments[0].VpcId) != vpc {
			return result, fmt.Errorf("destination gateway has another native attachment")
		}
		canonical := "INTERNET_GATEWAY|" + vpc
		if err := cfnEC2RelationOwned(ctx, h.commands, r, next, canonical); err != nil {
			return result, err
		}
		return result, nil
	}
	old := r
	old.Properties = r.Previous
	if err = h.Delete(ctx, old); err != nil {
		return result, err
	}
	updated, err := h.admit(ctx, r, true)
	if updated.PhysicalID != "" {
		result = updated
	}
	return result, err
}
func (h cfnEC2GatewayAttachment) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		return fmt.Errorf("gateway attachment deletion requires an admitted physical ID")
	}
	kind, vpc, err := cfnEC2Pair(r.PhysicalID, "AttachmentType", "VpcId")
	if err != nil {
		return err
	}
	if kind != "INTERNET_GATEWAY" {
		return fmt.Errorf("unsupported gateway attachment type")
	}
	id := cfnComputeString(r.Properties, "InternetGatewayId")
	if id == "" {
		return fmt.Errorf("gateway attachment deletion requires its exact gateway")
	}
	v, err := cfnEC2InternetGateway(h).describe(ctx, id)
	if err != nil {
		return cfnEC2Absent(err)
	}
	canonical := "INTERNET_GATEWAY|" + vpc
	owned := r
	owned.PhysicalID = canonical
	if len(v.Attachments) > 0 {
		if len(v.Attachments) != 1 || cfnComputeValue(v.Attachments[0].VpcId) != vpc {
			return fmt.Errorf("gateway attachment changed outside this resource")
		}
		if err = cfnEC2RelationOwned(ctx, h.commands, owned, id, canonical); err != nil {
			return err
		}
		if err = cfnComputeRun(cfnEC2RelationDeletionContext(ctx, owned, id), h.commands, "ec2", "DetachInternetGateway", map[string]any{"InternetGatewayId": id, "VpcId": vpc}); err != nil {
			return err
		}
	} else if !r.CloudControl {
		admitted, _, err := cfnEC2RelationReceipt(ctx, h.commands, r, id)
		if errors.Is(err, ec2.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if admitted != canonical {
			return fmt.Errorf("gateway deletion ID differs from its native admission receipt")
		}
	}
	return nil
}

func (h cfnEC2GatewayAttachment) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	admitted, _, receiptErr := cfnEC2RelationReceipt(ctx, h.commands, r, "")
	result := cfnEC2GatewayAttachmentResult(r, cfnEC2IDResult(admitted))
	if receiptErr != nil && !errors.Is(receiptErr, ec2.ErrNotFound) {
		return result, receiptErr
	}
	id := cfnComputeString(r.Properties, "InternetGatewayId")
	if id == "" {
		return result, fmt.Errorf("gateway attachment recovery requires its exact gateway")
	}
	v, err := cfnEC2InternetGateway(h).describe(ctx, id)
	if err != nil {
		return result, fmt.Errorf("cannot observe exact internet gateway during recovery: %v", err)
	}
	liveID := ""
	if len(v.Attachments) > 1 {
		return result, fmt.Errorf("internet gateway has multiple native attachments")
	}
	if len(v.Attachments) == 1 {
		liveID = "INTERNET_GATEWAY|" + cfnComputeValue(v.Attachments[0].VpcId)
	}
	recovered, err := cfnEC2RelationRecover(ctx, h.commands, r, id, liveID)
	return cfnEC2GatewayAttachmentResult(r, recovered), err
}
func (h cfnEC2GatewayAttachment) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	kind, vpc, err := cfnEC2Pair(r.PhysicalID, "AttachmentType", "VpcId")
	if err != nil {
		return nil, err
	}
	if kind != "INTERNET_GATEWAY" {
		return nil, cfnEC2NotFound("gateway attachment")
	}
	input := map[string]any{"Filters": []map[string]any{{"Name": "attachment.vpc-id", "Values": []string{vpc}}}}
	for {
		out, err := cfnComputeCall[api.DescribeInternetGatewaysResult](ctx, h.commands, "ec2", "DescribeInternetGateways", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.InternetGateways {
			id := cfnComputeValue(v.InternetGatewayId)
			if err = cfnEC2RelationOwned(ctx, h.commands, r, id, "INTERNET_GATEWAY|"+vpc); err != nil {
				return nil, err
			}
			for _, a := range v.Attachments {
				if cfnComputeValue(a.VpcId) == vpc {
					return cloudformation.Properties{"InternetGatewayId": id, "VpcId": vpc, "AttachmentType": "INTERNET_GATEWAY"}, nil
				}
			}
		}
		if cfnComputeValue(out.NextToken) == "" {
			return nil, cfnEC2NotFound("gateway attachment")
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func (h cfnEC2GatewayAttachment) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	for input := map[string]any{}; ; {
		out, err := cfnComputeCall[api.DescribeInternetGatewaysResult](ctx, h.commands, "ec2", "DescribeInternetGateways", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.InternetGateways {
			id := cfnComputeValue(v.InternetGatewayId)
			for _, a := range v.Attachments {
				vpc := cfnComputeValue(a.VpcId)
				if !r.CloudControl && cfnEC2RelationOwned(ctx, h.commands, r, id, "INTERNET_GATEWAY|"+vpc) != nil {
					continue
				}
				result = append(result, cloudformation.ResourceDescription{Identifier: cfnEC2PairID(r, "INTERNET_GATEWAY", vpc, "AttachmentType", "VpcId"), Properties: cloudformation.Properties{"InternetGatewayId": id, "VpcId": vpc, "AttachmentType": "INTERNET_GATEWAY"}})
			}
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
