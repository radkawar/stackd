package integrations

import (
	"context"
	"fmt"

	"stackd/internal/services/cloudformation"
	"stackd/internal/services/kms"
)

// Alias ownership is private KMS state, not tags: aliases are stack-only Resource
// Groups resources and cannot inherit either key tags or historical CFN ownership.
func (r ResourceGroupsResources) kmsAliasOwners(ctx context.Context, scope cloudformation.Scope, candidates []cloudformation.ResourceRecord) (map[string]kms.AliasOwner, error) {
	needed := false
	for _, candidate := range candidates {
		if candidate.Current && candidate.Type == "AWS::KMS::Alias" && candidate.PhysicalID != "" && candidate.Status != "DELETE_COMPLETE" {
			needed = true
			break
		}
	}
	if !needed {
		return nil, nil
	}
	if r.Tagging.Backends.KMS == nil {
		return nil, fmt.Errorf("resource groups requires KMS alias storage")
	}
	var owners map[string]kms.AliasOwner
	prefix := "arn:" + scope.Partition + ":kms:" + scope.Region + ":" + scope.Account + ":"
	err := r.Tagging.Backends.KMS.View(ctx, func(tx kms.Reader) error {
		aliases, err := tx.Aliases(kms.StorageScope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region})
		if err != nil {
			return err
		}
		for _, alias := range aliases {
			if alias.Owner.StackID != "" && alias.Owner.LogicalID != "" && alias.Owner.Token != "" {
				if owners == nil {
					owners = make(map[string]kms.AliasOwner)
				}
				owners[prefix+alias.Name] = alias.Owner
			}
		}
		return nil
	})
	return owners, err
}
