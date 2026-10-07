package ram

import (
	"context"
	api "stackd/internal/awsapi/ram"
	"stackd/internal/services/identitystore"
	"testing"
)

func TestCloudFormationPrincipalClaimDoesNotSurviveDirectRecreation(t *testing.T) {
	s, _, resource := testRAM(t)
	ctx := rootContext(resource.AccountID)
	share := invoke[api.CreateResourceShareResponse](t, s, ctx, "CreateResourceShare", &api.CreateResourceShareRequest{Name: new(api.String("ClaimedAssociation"))})
	owned := identitystore.WithCloudFormationOwner(ctx, "stack/logical/incarnation-one")
	associate := &api.AssociateResourceShareRequest{ResourceShareArn: share.ResourceShare.ResourceShareArn, Principals: api.PrincipalArnOrIdList{"222222222222"}}
	disassociate := &api.DisassociateResourceShareRequest{ResourceShareArn: share.ResourceShare.ResourceShareArn, Principals: api.PrincipalArnOrIdList{"222222222222"}}
	invoke[api.AssociateResourceShareResponse](t, s, owned, "AssociateResourceShare", associate)
	// Recovery is idempotent and retains the same invitation/association.
	invoke[api.AssociateResourceShareResponse](t, s, owned, "AssociateResourceShare", associate)
	other := identitystore.WithCloudFormationOwner(ctx, "stack/logical/incarnation-two")
	if _, rejected := execute(s, other, "DisassociateResourceShare", disassociate); rejected == nil || rejected.Code != "OperationNotPermittedException" {
		t.Fatalf("another incarnation removed association: %v", rejected)
	}
	// A direct authorized deletion clears source ownership in the same transaction.
	invoke[api.DisassociateResourceShareResponse](t, s, ctx, "DisassociateResourceShare", disassociate)
	invoke[api.AssociateResourceShareResponse](t, s, ctx, "AssociateResourceShare", associate)
	if _, rejected := execute(s, owned, "DisassociateResourceShare", disassociate); rejected == nil || rejected.Code != "OperationNotPermittedException" {
		t.Fatalf("old incarnation removed a direct recreation: %v", rejected)
	}
	out := invoke[api.GetResourceShareAssociationsResponse](t, s, ctx, "GetResourceShareAssociations", &api.GetResourceShareAssociationsRequest{AssociationType: new(api.ResourceShareAssociationTypePRINCIPAL), ResourceShareArns: api.ResourceShareArnList{*share.ResourceShare.ResourceShareArn}})
	if len(out.ResourceShareAssociations) != 1 || value(out.ResourceShareAssociations[0].Status) != "ASSOCIATING" {
		t.Fatalf("direct recreation was not preserved: %#v", out.ResourceShareAssociations)
	}
}

func TestCloudFormationShareAuthorityCannotReplaceSeparatelyOwnedPermission(t *testing.T) {
	s, _, resource := testRAM(t)
	ctx := rootContext(resource.AccountID)
	shareOwner := identitystore.WithCloudFormationOwner(ctx, "stack/Share/one")
	share := invoke[api.CreateResourceShareResponse](t, s, shareOwner, "CreateResourceShare", &api.CreateResourceShareRequest{Name: new(api.String("OwnedShare"))})
	arn := share.ResourceShare.ResourceShareArn
	permission := func(name string) *api.String {
		out := invoke[api.CreatePermissionResponse](t, s, ctx, "CreatePermission", &api.CreatePermissionRequest{Name: new(api.PermissionName(name)), ResourceType: new(api.String(resource.ResourceType)), PolicyTemplate: new(api.Policy(`{"Effect":"Allow","Action":["ssm:GetParameter"]}`))})
		return out.Permission.Arn
	}
	separate, replacement := permission("Separate"), permission("Replacement")
	association := identitystore.WithCloudFormationOwner(ctx, "stack/Association/one")
	invoke[api.AssociateResourceSharePermissionResponse](t, s, association, "AssociateResourceSharePermission", &api.AssociateResourceSharePermissionRequest{ResourceShareArn: arn, PermissionArn: separate})
	authority := WithShareAuthority(shareOwner)
	if _, rejected := execute(s, authority, "AssociateResourceSharePermission", &api.AssociateResourceSharePermissionRequest{ResourceShareArn: arn, PermissionArn: replacement, Replace: new(api.Boolean(true))}); rejected == nil || rejected.Code != "OperationNotPermittedException" {
		t.Fatalf("share replaced a separately owned permission: %v", rejected)
	}
	if _, rejected := execute(s, authority, "DisassociateResourceSharePermission", &api.DisassociateResourceSharePermissionRequest{ResourceShareArn: arn, PermissionArn: separate}); rejected == nil || rejected.Code != "OperationNotPermittedException" {
		t.Fatalf("share removed a separately owned permission: %v", rejected)
	}
	other := WithShareAuthority(identitystore.WithCloudFormationOwner(ctx, "stack/Share/two"))
	if _, rejected := execute(s, other, "UpdateResourceShare", &api.UpdateResourceShareRequest{ResourceShareArn: arn, Name: new(api.String("Taken"))}); rejected == nil || rejected.Code != "OperationNotPermittedException" {
		t.Fatalf("another incarnation updated the share: %v", rejected)
	}
	list := func(ctx context.Context) int {
		return len(invoke[api.ListResourceSharePermissionsResponse](t, s, WithOwnedView(ctx), "ListResourceSharePermissions", &api.ListResourceSharePermissionsRequest{ResourceShareArn: arn}).Permissions)
	}
	if list(authority) != 0 || list(association) != 1 || list(ctx) != 0 {
		t.Fatalf("owned views did not separate permission owners: share=%d association=%d unowned=%d", list(authority), list(association), list(ctx))
	}
	invoke[api.DisassociateResourceSharePermissionResponse](t, s, association, "DisassociateResourceSharePermission", &api.DisassociateResourceSharePermissionRequest{ResourceShareArn: arn, PermissionArn: separate})
	invoke[api.AssociateResourceSharePermissionResponse](t, s, authority, "AssociateResourceSharePermission", &api.AssociateResourceSharePermissionRequest{ResourceShareArn: arn, PermissionArn: replacement})
	if list(authority) != 1 {
		t.Fatal("share authority did not own the permission it admitted")
	}
}
