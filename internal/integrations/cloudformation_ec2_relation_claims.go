package integrations

import (
	"context"
	"errors"
	"fmt"

	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ec2"
)

type cfnEC2RelationOwner interface {
	RelationCreation(context.Context, string, string, string) (string, bool, error)
}

func cfnEC2RelationContext(ctx context.Context, r cloudformation.ResourceRequest, slot string) context.Context {
	return ec2.WithRelationOwner(ctx, r.Type, slot, cfnEC2NativeIdentity(r))
}

func cfnEC2RelationDeletionContext(ctx context.Context, r cloudformation.ResourceRequest, slot string) context.Context {
	if r.CloudControl {
		return ctx
	}
	return ec2.WithRelationDeletion(ctx, r.Type, slot, cfnEC2NativeIdentity(r), r.PhysicalID)
}

func cfnEC2RelationReceipt(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, slot string) (string, bool, error) {
	if r.Token == "" {
		return "", false, fmt.Errorf("EC2 relation recovery requires an incarnation token")
	}
	provider, ok := c.providers["ec2"]
	if !ok {
		return "", false, fmt.Errorf("EC2 relation owner is unavailable")
	}
	owner, ok := provider.executor.(cfnEC2RelationOwner)
	if !ok {
		return "", false, fmt.Errorf("EC2 relation owner does not support private creation recovery")
	}
	return owner.RelationCreation(ctx, r.Type, slot, cfnEC2NativeIdentity(r))
}

func cfnEC2RelationOwned(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, slot, id string) error {
	if r.CloudControl {
		return nil
	}
	admitted, current, err := cfnEC2RelationReceipt(ctx, c, r, slot)
	if err != nil {
		return fmt.Errorf("cannot establish native EC2 relation ownership: %v", err)
	}
	if !current || admitted != id {
		return fmt.Errorf("EC2 relation is not the current admitted resource incarnation")
	}
	return nil
}

// cfnEC2RelationRecover proves creation from the private native receipt and the
// exact live edge. A missing receipt certifies nonadmission; no public tag is
// written or removed, so foreign edges cannot be adopted.
func cfnEC2RelationRecover(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, slot, liveID string) (cloudformation.ResourceResult, error) {
	id, current, err := cfnEC2RelationReceipt(ctx, c, r, slot)
	if errors.Is(err, ec2.ErrNotFound) {
		return cloudformation.ResourceResult{}, cfnEC2NotFound("EC2 relation creation incarnation")
	}
	if err != nil {
		return cfnEC2IDResult(id), err
	}
	result := cfnEC2IDResult(id)
	if !current || liveID != id {
		return result, fmt.Errorf("the admitted EC2 relation is no longer the exact current native edge")
	}
	return result, nil
}

func cfnEC2RelationFailedCreate(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, recover func(context.Context, cloudformation.ResourceRequest) (cloudformation.ResourceResult, error), cause error) (cloudformation.ResourceResult, error) {
	result, err := recover(ctx, r)
	if err != nil && !cfnEC2Missing(err) {
		return result, fmt.Errorf("%w; native EC2 creation recovery: %v", cause, err)
	}
	return result, cause
}
