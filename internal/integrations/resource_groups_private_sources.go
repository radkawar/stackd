package integrations

import (
	"context"
	"errors"
	"strings"

	"stackd/internal/services/cloudformation"
	"stackd/storage/resourcegroups"
	"stackd/storage/sesv2"
)

// The other registered tagging sources (AppConfig, Config and AppRegistry) expose
// no stack-query-eligible types. SES identities are likewise not stack eligible.
func (r ResourceGroupsResources) privateSourceOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if owners.needs("AWS::SES::ConfigurationSet") {
		if err := r.Tagging.Backends.SESv2.View(ctx, func(reader sesv2.Reader) error {
			nativeScope := sesv2.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
			prefix := "arn:" + scope.Partition + ":ses:" + scope.Region + ":" + scope.Account + ":configuration-set/"
			for resourceARN, request := range owners.requests {
				if request.Type != "AWS::SES::ConfigurationSet" {
					continue
				}
				name, canonical := strings.CutPrefix(resourceARN, prefix)
				if !canonical || name == "" {
					continue
				}
				set, err := reader.ConfigurationSet(sesv2.ResourceKey{Scope: nativeScope, Name: name})
				if errors.Is(err, sesv2.ErrNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				if set.Key.Scope == nativeScope && set.Key.Name == request.PhysicalID && set.Key.ARN("configuration-set") == resourceARN {
					owners.claim(resourceARN, set.Owner, func(request cloudformation.ResourceRequest) string {
						return cfnTrustClaim(request, "sesconfiguration")
					})
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if owners.needs("AWS::ResourceGroups::Group") {
		if err := r.Tagging.Backends.ResourceGroups.View(ctx, func(reader resourcegroups.Reader) error {
			nativeScope := resourcegroups.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
			prefix := "arn:" + scope.Partition + ":resource-groups:" + scope.Region + ":" + scope.Account + ":group/"
			for resourceARN, request := range owners.requests {
				if request.Type != "AWS::ResourceGroups::Group" || !strings.HasPrefix(resourceARN, prefix) {
					continue
				}
				group, found, err := reader.Group(nativeScope, resourceARN)
				if err != nil {
					return err
				}
				if found && group.Scope == nativeScope && group.ARN == resourceARN && group.Name != "" && group.Name == request.PhysicalID && prefix+group.Name == resourceARN {
					owners.claim(resourceARN, group.CloudFormationClaim, cfnRGroupClaim)
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}
