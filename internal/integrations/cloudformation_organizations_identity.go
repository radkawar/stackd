package integrations

import (
	"context"
	"fmt"
	"strings"

	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/identitystore"
)

// CloudFormationOrganizationIdentityHandlers exposes only resources with concrete
// Organizations, directory, Identity Center and RAM owner commands.
// Schemas: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/resource-type-schemas.html
func CloudFormationOrganizationIdentityHandlers(c StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{
		"AWS::IdentityStore::Group":              cfnIdentityGroup{c},
		"AWS::IdentityStore::GroupMembership":    cfnIdentityMembership{c},
		"AWS::Organizations::Organization":       cfnOrganization{c},
		"AWS::Organizations::Account":            cfnOrganizationAccount{c},
		"AWS::Organizations::OrganizationalUnit": cfnOrganizationUnit{c},
		"AWS::Organizations::Policy":             cfnOrganizationPolicy{c},
		"AWS::Organizations::ResourcePolicy":     cfnOrganizationResourcePolicy{c},
		"AWS::SSO::Instance":                     cfnSSOInstance{c},
		"AWS::SSO::PermissionSet":                cfnSSOPermissionSet{c},
		"AWS::SSO::Assignment":                   cfnSSOAssignment{c},
		"AWS::RAM::ResourceShare":                cfnRAMResourceShare{c},
		"AWS::RAM::Permission":                   cfnRAMPermission{c},
		"AWS::RAM::PermissionAssociation":        cfnRAMPermissionAssociation{c},
		"AWS::RAM::PrincipalAssociation":         cfnRAMPrincipalAssociation{c},
		"AWS::RAM::ResourceAssociation":          cfnRAMResourceAssociation{c},
	}
}
func cfnOrgIdentityContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl && r.PhysicalID != "" {
		return ctx
	}
	return cfnOrgIdentityClaim(ctx, r)
}

// cfnOrgIdentityClaim always carries this exact incarnation. Creation recovery
// observes only rows committed under it, including Cloud Control creations.
func cfnOrgIdentityClaim(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	return identitystore.WithCloudFormationOwner(ctx, r.StackID+"/"+r.LogicalID+"/"+r.Token)
}

// cfnOrgIdentityTags are customer tags only; ownership is a private native claim.
func cfnOrgIdentityTags(r cloudformation.ResourceRequest) map[string]string {
	tags := make(map[string]string, len(r.Tags))
	for k, v := range r.Tags {
		tags[k] = v
	}
	resource, _ := cfnComputeTags(r.Properties)
	for k, v := range resource {
		tags[k] = v
	}
	return tags
}
func cfnOrgIdentityPublicTags(tags map[string]string) []any {
	out := make([]any, 0, len(tags))
	for _, key := range cfnMessagingKeys(tags) {
		out = append(out, map[string]any{"Key": key, "Value": tags[key]})
	}
	return out
}

// cfnOrgIdentityUnobserved keeps dependency absence from certifying that this
// incarnation was never admitted.
func cfnOrgIdentityUnobserved(e error) error {
	if e == nil {
		return nil
	}
	return fmt.Errorf("creation of this incarnation cannot be observed: %v", e)
}
func cfnOrgIdentityID(parts ...string) string { return strings.Join(parts, "|") }
func cfnOrgIdentityParts(id string, count int) ([]string, error) {
	parts := strings.Split(id, "|")
	if len(parts) != count {
		return nil, fmt.Errorf("invalid resource identifier %q", id)
	}
	return parts, nil
}
func cfnOrgIdentityResult(id string, p cloudformation.Properties) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: p}
}

// AWS paginated operations distinguish omission from an invalid empty token.
// Inputs are newly owned command maps, so normalization needs no copy.
func cfnOrgIdentityCall[T any](ctx context.Context, c StepFunctionsCommands, service, operation string, input map[string]any) (*T, error) {
	for _, key := range []string{"NextToken", "nextToken"} {
		if token, ok := input[key].(string); ok && token == "" {
			delete(input, key)
		}
	}
	return cfnComputeCall[T](ctx, c, service, operation, input)
}

func cfnOrgIdentityRefreshResult(ctx context.Context, h cloudformation.ResourceResultReader, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result, err := h.Result(ctx, r)
	if err != nil && result.PhysicalID == "" {
		result = cfnOrgIdentityResult(r.PhysicalID, cloudformation.Properties{})
	}
	return result, err
}

func cfnOrgIdentityNotFound(message string) error {
	return &awswire.Error{Code: "ResourceNotFoundException", Message: message, StatusCode: 400}
}
