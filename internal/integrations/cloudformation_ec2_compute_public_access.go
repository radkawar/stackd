package integrations

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ebs"
)

// SnapshotBlockPublicAccess is an account/Region singleton, not a snapshot.
// The private incarnation binding lives alongside the actual EBS setting and
// is committed atomically by the ordinary authorized EC2 setting commands.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-snapshotblockpublicaccess.html
// https://schema.cloudformation.us-east-2.amazonaws.com/CloudformationSchema.zip
// member aws-ec2-snapshotblockpublicaccess.json

type cfnEC2SnapshotBlockPublicAccess struct{ commands StepFunctionsCommands }

func (h cfnEC2SnapshotBlockPublicAccess) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "State"); err != nil {
		return err
	}
	switch cfnComputeString(p, "State") {
	case "block-all-sharing", "block-new-sharing":
		return nil
	default:
		return fmt.Errorf("State must be block-all-sharing or block-new-sharing")
	}
}
func (h cfnEC2SnapshotBlockPublicAccess) Replacement(a, b cloudformation.Properties) (bool, error) {
	return false, nil
}
func cfnEC2SnapshotBlockResult(account string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: account, Ref: account, Attributes: map[string]any{"AccountId": account}}
}
func cfnEC2SnapshotBlockContext(ctx context.Context, r cloudformation.ResourceRequest, intent string) context.Context {
	if r.CloudControl && intent != "create" && intent != "recover-create" {
		return ctx
	}
	return ebs.WithSnapshotPublicAccessOwner(ctx, ebs.SnapshotPublicAccessOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token, Intent: intent})
}
func (h cfnEC2SnapshotBlockPublicAccess) state(ctx context.Context, r cloudformation.ResourceRequest, intent string) (string, error) {
	out, err := cfnComputeCall[api.GetSnapshotBlockPublicAccessStateResult](cfnEC2SnapshotBlockContext(ctx, r, intent), h.commands, "ec2", "GetSnapshotBlockPublicAccessState", map[string]any{})
	if err != nil {
		return "", err
	}
	account := awsctx.FromContext(ctx).AccountID
	if r.PhysicalID != "" && r.PhysicalID != account {
		return "", cfnEC2ComputeMissing("snapshot public access setting", r.PhysicalID)
	}
	return cfnComputeValue(out.State), nil
}
func (h cfnEC2SnapshotBlockPublicAccess) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	state, err := h.state(ctx, r, "recover-create")
	if err == nil {
		if state != cfnComputeString(r.Properties, "State") {
			return cloudformation.ResourceResult{}, fmt.Errorf("resource incarnation already owns a different snapshot public access state")
		}
		return cfnEC2SnapshotBlockResult(awsctx.FromContext(ctx).AccountID), nil
	}
	if !cfnEC2Missing(err) {
		return cloudformation.ResourceResult{}, err
	}
	_, err = cfnComputeCall[api.EnableSnapshotBlockPublicAccessResult](cfnEC2SnapshotBlockContext(ctx, r, "create"), h.commands, "ec2", "EnableSnapshotBlockPublicAccess", map[string]any{"State": r.Properties["State"]})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEC2SnapshotBlockResult(awsctx.FromContext(ctx).AccountID), nil
}
func (h cfnEC2SnapshotBlockPublicAccess) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	state, err := h.state(ctx, r, "observe")
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnEC2SnapshotBlockResult(awsctx.FromContext(ctx).AccountID)
	if state == cfnComputeString(r.Properties, "State") {
		return result, nil
	}
	_, err = cfnComputeCall[api.EnableSnapshotBlockPublicAccessResult](cfnEC2SnapshotBlockContext(ctx, r, "update"), h.commands, "ec2", "EnableSnapshotBlockPublicAccess", map[string]any{"State": r.Properties["State"]})
	return result, err
}
func (h cfnEC2SnapshotBlockPublicAccess) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	state, err := h.state(ctx, r, "observe")
	if cfnEC2Missing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if r.CloudControl && state == "unblocked" {
		return nil
	}
	_, err = cfnComputeCall[api.DisableSnapshotBlockPublicAccessResult](cfnEC2SnapshotBlockContext(ctx, r, "delete"), h.commands, "ec2", "DisableSnapshotBlockPublicAccess", map[string]any{})
	if cfnEC2Missing(err) {
		return nil
	}
	return err
}
func (h cfnEC2SnapshotBlockPublicAccess) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	// Discovery is always authorized by the actual EC2 owner. Stack reads also
	// require the exact durable incarnation; direct Cloud Control reads do not.
	state, err := h.state(ctx, r, "observe")
	if err != nil {
		return nil, err
	}
	if state == "unblocked" {
		return nil, cfnEC2ComputeMissing("snapshot public access setting", awsctx.FromContext(ctx).AccountID)
	}
	return cloudformation.Properties{"AccountId": awsctx.FromContext(ctx).AccountID, "State": state}, nil
}
func (h cfnEC2SnapshotBlockPublicAccess) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	r.PhysicalID = ""
	p, err := h.Read(ctx, r)
	if cfnEC2Missing(err) {
		return []cloudformation.ResourceDescription{}, nil
	}
	if err != nil {
		return nil, err
	}
	return []cloudformation.ResourceDescription{{Identifier: awsctx.FromContext(ctx).AccountID, Properties: p}}, nil
}
func (h cfnEC2SnapshotBlockPublicAccess) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	state, err := h.state(ctx, r, "observe")
	return err == nil && state == cfnComputeString(r.Properties, "State"), err
}
func (h cfnEC2SnapshotBlockPublicAccess) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	state, err := h.state(ctx, r, "observe-deletion")
	if cfnEC2Missing(err) {
		return true, nil
	}
	return r.CloudControl && err == nil && state == "unblocked", err
}
