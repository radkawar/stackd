package ram

import (
	"testing"
	"time"

	api "stackd/internal/awsapi/ram"
)

func TestPermissionClientTokensMatchNativeOmissionAndReplay(t *testing.T) {
	s, _, r := testRAM(t)
	owner := rootContext(r.AccountID)
	permission := invoke[api.CreatePermissionResponse](t, s, owner, "CreatePermission", &api.CreatePermissionRequest{Name: new(api.PermissionName("PermissionTokens")), ResourceType: new(api.String(r.ResourceType)), PolicyTemplate: new(api.Policy(`{"Effect":"Allow","Action":["ssm:GetParameter"]}`))})
	if permission.ClientToken != nil {
		t.Fatalf("CreatePermission exposed an omitted client token: %q", value(permission.ClientToken))
	}
	in := &api.CreatePermissionVersionRequest{PermissionArn: permission.Permission.Arn, PolicyTemplate: new(api.Policy(`{"Effect":"Allow","Action":["ssm:GetParameters"]}`)), ClientToken: new(api.String("version-token"))}
	created := invoke[api.CreatePermissionVersionResponse](t, s, owner, "CreatePermissionVersion", in)
	replayed := invoke[api.CreatePermissionVersionResponse](t, s, owner, "CreatePermissionVersion", in)
	if value(replayed.Permission.Arn) != value(created.Permission.Arn) || value(replayed.Permission.Version) != "2" || value(replayed.Permission.Permission) != value(created.Permission.Permission) || value(replayed.ClientToken) != "version-token" {
		t.Fatalf("explicit token did not replay the original version: %#v", replayed)
	}
	in.PolicyTemplate = new(api.Policy(`{"Effect":"Allow","Action":["ssm:GetParameterHistory"]}`))
	_, rejected := execute(s, owner, "CreatePermissionVersion", in)
	if rejected == nil || rejected.Code != "IdempotentParameterMismatchException" {
		t.Fatalf("explicit token accepted changed template: %v", rejected)
	}
	in.ClientToken = nil
	withoutToken := invoke[api.CreatePermissionVersionResponse](t, s, owner, "CreatePermissionVersion", in)
	if withoutToken.ClientToken != nil || value(withoutToken.Permission.Version) != "3" {
		t.Fatalf("CreatePermissionVersion did not match omitted-token creation: %#v", withoutToken)
	}
	versions := invoke[api.ListPermissionVersionsResponse](t, s, owner, "ListPermissionVersions", &api.ListPermissionVersionsRequest{PermissionArn: permission.Permission.Arn})
	if len(versions.Permissions) != 3 || value(versions.Permissions[0].Version) != "1" || value(versions.Permissions[1].Version) != "2" || value(versions.Permissions[2].Version) != "3" {
		t.Fatalf("replay allocated another version: %#v", versions.Permissions)
	}
}

func TestReassociateExpiredInvitationRequiresFreshAcceptance(t *testing.T) {
	s, c, r := testRAM(t)
	owner, recipient := rootContext(r.AccountID), rootContext("222222222222")
	share := createShared(t, s, r, "")
	invitations := invoke[api.GetResourceShareInvitationsResponse](t, s, recipient, "GetResourceShareInvitations", &api.GetResourceShareInvitationsRequest{})
	if len(invitations.ResourceShareInvitations) != 1 {
		t.Fatalf("expected one original invitation: %#v", invitations)
	}
	old := invitations.ResourceShareInvitations[0].ResourceShareInvitationArn
	if e := c.Advance(12 * time.Hour); e != nil {
		t.Fatal(e)
	}
	rejectOld := func() {
		t.Helper()
		_, rejected := execute(s, recipient, "AcceptResourceShareInvitation", &api.AcceptResourceShareInvitationRequest{ResourceShareInvitationArn: old})
		if rejected == nil || rejected.Code != "ResourceShareInvitationExpiredException" {
			t.Fatalf("old invitation did not remain expired: %v", rejected)
		}
	}
	rejectOld()
	requireGrant(t, s, recipient, r, "ssm:GetParameter", false)
	associations := invoke[api.GetResourceShareAssociationsResponse](t, s, owner, "GetResourceShareAssociations", &api.GetResourceShareAssociationsRequest{AssociationType: new(api.ResourceShareAssociationTypePRINCIPAL), ResourceShareArns: api.ResourceShareArnList{*share.ResourceShare.ResourceShareArn}})
	if len(associations.ResourceShareAssociations) != 1 || value(associations.ResourceShareAssociations[0].Status) != "DISASSOCIATED" {
		t.Fatalf("expired principal was not disassociated: %#v", associations)
	}
	associated := invoke[api.AssociateResourceShareResponse](t, s, owner, "AssociateResourceShare", &api.AssociateResourceShareRequest{ResourceShareArn: share.ResourceShare.ResourceShareArn, Principals: api.PrincipalArnOrIdList{"222222222222"}})
	if len(associated.ResourceShareAssociations) != 1 || value(associated.ResourceShareAssociations[0].Status) != "ASSOCIATING" {
		t.Fatalf("reassociation did not await fresh acceptance: %#v", associated)
	}
	invitations = invoke[api.GetResourceShareInvitationsResponse](t, s, recipient, "GetResourceShareInvitations", &api.GetResourceShareInvitationsRequest{})
	if len(invitations.ResourceShareInvitations) != 2 {
		t.Fatalf("reassociation did not preserve old and fresh invitations: %#v", invitations)
	}
	var fresh *api.String
	for _, invitation := range invitations.ResourceShareInvitations {
		if value(invitation.ResourceShareInvitationArn) == value(old) {
			if value(invitation.Status) != "EXPIRED" {
				t.Fatalf("old invitation revived: %#v", invitation)
			}
			continue
		}
		if value(invitation.Status) != "PENDING" || invitation.InvitationTimestamp == nil || !invitation.InvitationTimestamp.Equal(c.Now()) {
			t.Fatalf("replacement invitation is not fresh: %#v", invitation)
		}
		fresh = invitation.ResourceShareInvitationArn
	}
	if fresh == nil {
		t.Fatal("reassociation reused the expired invitation identity")
	}
	rejectOld()
	requireGrant(t, s, recipient, r, "ssm:GetParameter", false)
	accepted := invoke[api.AcceptResourceShareInvitationResponse](t, s, recipient, "AcceptResourceShareInvitation", &api.AcceptResourceShareInvitationRequest{ResourceShareInvitationArn: fresh})
	if value(accepted.ResourceShareInvitation.Status) != "ACCEPTED" {
		t.Fatalf("fresh invitation was not accepted: %#v", accepted)
	}
	requireGrant(t, s, recipient, r, "ssm:GetParameter", true)
	rejectOld()
	requireGrant(t, s, recipient, r, "ssm:GetParameter", true)
}

// Native deletion/reuse results are retained in testdata/native-permission-
// version-deletion.json: numbered tombstones are readable, then replaced in place.
func TestPermissionVersionReceiptResolvesDeletedThenReusedNumber(t *testing.T) {
	s, c, r := testRAM(t)
	owner := rootContext(r.AccountID)
	initial := invoke[api.CreatePermissionResponse](t, s, owner, "CreatePermission", &api.CreatePermissionRequest{Name: new(api.PermissionName("VersionReuse")), ResourceType: new(api.String(r.ResourceType)), PolicyTemplate: new(api.Policy(`{"Effect":"Allow","Action":["ssm:GetParameter"]}`)), ClientToken: new(api.String("create-permission"))})
	replayedCreate := invoke[api.CreatePermissionResponse](t, s, owner, "CreatePermission", &api.CreatePermissionRequest{Name: new(api.PermissionName("VersionReuse")), ResourceType: new(api.String(r.ResourceType)), PolicyTemplate: new(api.Policy(`{"Effect":"Allow","Action":["ssm:GetParameter"]}`)), ClientToken: new(api.String("create-permission"))})
	if value(replayedCreate.Permission.Arn) != value(initial.Permission.Arn) || value(replayedCreate.Permission.Version) != "1" || value(replayedCreate.ClientToken) != "create-permission" {
		t.Fatalf("explicit permission creation token did not replay: %#v", replayedCreate)
	}
	advance := func() {
		t.Helper()
		if e := c.Advance(time.Minute); e != nil {
			t.Fatal(e)
		}
	}
	advance()
	in := &api.CreatePermissionVersionRequest{PermissionArn: initial.Permission.Arn, ClientToken: new(api.String("version-a")), PolicyTemplate: new(api.Policy(`{"Effect":"Allow","Action":["ssm:GetParameters"]}`))}
	a := invoke[api.CreatePermissionVersionResponse](t, s, owner, "CreatePermissionVersion", in)
	createdAt := c.Now()
	advance()
	invoke[api.SetDefaultPermissionVersionResponse](t, s, owner, "SetDefaultPermissionVersion", &api.SetDefaultPermissionVersionRequest{PermissionArn: initial.Permission.Arn, PermissionVersion: new(api.Integer(1))})
	defaultedAt := c.Now()
	advance()
	invoke[api.DeletePermissionVersionResponse](t, s, owner, "DeletePermissionVersion", &api.DeletePermissionVersionRequest{PermissionArn: initial.Permission.Arn, PermissionVersion: new(api.Integer(2))})
	deletedAt := c.Now()
	deleted := invoke[api.GetPermissionResponse](t, s, owner, "GetPermission", &api.GetPermissionRequest{PermissionArn: initial.Permission.Arn, PermissionVersion: new(api.Integer(2))})
	if value(deleted.Permission.Status) != "DELETED" || value(deleted.Permission.Permission) != value(a.Permission.Permission) || deleted.Permission.DefaultVersion == nil || bool(*deleted.Permission.DefaultVersion) || deleted.Permission.LastUpdatedTime == nil || !deleted.Permission.LastUpdatedTime.Equal(deletedAt) {
		t.Fatalf("deleted version lost its template or deletion state: %#v", deleted)
	}
	versions := invoke[api.ListPermissionVersionsResponse](t, s, owner, "ListPermissionVersions", &api.ListPermissionVersionsRequest{PermissionArn: initial.Permission.Arn})
	if len(versions.Permissions) != 2 || value(versions.Permissions[0].Version) != "1" || value(versions.Permissions[0].Status) != "ATTACHABLE" || versions.Permissions[0].LastUpdatedTime == nil || !versions.Permissions[0].LastUpdatedTime.Equal(defaultedAt) || value(versions.Permissions[1].Version) != "2" || value(versions.Permissions[1].Status) != "DELETED" || versions.Permissions[1].LastUpdatedTime == nil || !versions.Permissions[1].LastUpdatedTime.Equal(deletedAt) {
		t.Fatalf("version listing did not preserve independent lifecycle states: %#v", versions)
	}
	_, rejected := execute(s, owner, "SetDefaultPermissionVersion", &api.SetDefaultPermissionVersionRequest{PermissionArn: initial.Permission.Arn, PermissionVersion: new(api.Integer(2))})
	if rejected == nil {
		t.Fatal("deleted version became the default")
	}
	replayed := invoke[api.CreatePermissionVersionResponse](t, s, owner, "CreatePermissionVersion", in)
	if value(replayed.Permission.Version) != "2" || value(replayed.Permission.Status) != "DELETED" || value(replayed.Permission.Permission) != value(a.Permission.Permission) || replayed.Permission.LastUpdatedTime == nil || !replayed.Permission.LastUpdatedTime.Equal(createdAt) {
		t.Fatalf("deleted creation replay diverged from native tombstone response: %#v", replayed)
	}
	// A deleted creation replay must not grant its old actions or restore default.
	share := createShared(t, s, r, value(initial.Permission.Arn))
	accept(t, s)
	recipient := rootContext("222222222222")
	requireGrant(t, s, recipient, r, "ssm:GetParameter", true)
	requireGrant(t, s, recipient, r, "ssm:GetParameters", false)
	advance()
	b := invoke[api.CreatePermissionVersionResponse](t, s, owner, "CreatePermissionVersion", &api.CreatePermissionVersionRequest{PermissionArn: initial.Permission.Arn, ClientToken: new(api.String("version-b")), PolicyTemplate: new(api.Policy(`{"Effect":"Allow","Action":["ssm:GetParameterHistory"]}`))})
	if value(b.Permission.Version) != "2" {
		t.Fatalf("deleted highest version number was not reused: %#v", b)
	}
	replayed = invoke[api.CreatePermissionVersionResponse](t, s, owner, "CreatePermissionVersion", in)
	if value(replayed.Permission.Version) != "2" || value(replayed.Permission.Status) != "ATTACHABLE" || value(replayed.Permission.Permission) != value(b.Permission.Permission) || value(replayed.ClientToken) != "version-a" || replayed.Permission.CreationTime == nil || !replayed.Permission.CreationTime.Equal(c.Now()) {
		t.Fatalf("old token did not resolve the native current numbered version: %#v", replayed)
	}
	current := invoke[api.GetPermissionResponse](t, s, owner, "GetPermission", &api.GetPermissionRequest{PermissionArn: initial.Permission.Arn, PermissionVersion: new(api.Integer(2))})
	if value(current.Permission.Permission) != value(b.Permission.Permission) || value(current.Permission.Status) != "ATTACHABLE" {
		t.Fatalf("receipt replay changed the replacement version: %#v", current)
	}
	versions = invoke[api.ListPermissionVersionsResponse](t, s, owner, "ListPermissionVersions", &api.ListPermissionVersionsRequest{PermissionArn: initial.Permission.Arn})
	if len(versions.Permissions) != 2 || value(versions.Permissions[1].Version) != "2" || value(versions.Permissions[1].Status) != "ATTACHABLE" {
		t.Fatalf("version reuse left duplicate live or deleted identities: %#v", versions)
	}
	invoke[api.AssociateResourceSharePermissionResponse](t, s, owner, "AssociateResourceSharePermission", &api.AssociateResourceSharePermissionRequest{ResourceShareArn: share.ResourceShare.ResourceShareArn, PermissionArn: initial.Permission.Arn, Replace: new(api.Boolean(true))})
	requireGrant(t, s, recipient, r, "ssm:GetParameterHistory", true)
	requireGrant(t, s, recipient, r, "ssm:GetParameters", false)
}

func TestDeletedPermissionVersionDoesNotConsumeActiveQuota(t *testing.T) {
	s, _, r := testRAM(t)
	owner := rootContext(r.AccountID)
	permission := invoke[api.CreatePermissionResponse](t, s, owner, "CreatePermission", &api.CreatePermissionRequest{Name: new(api.PermissionName("VersionQuota")), ResourceType: new(api.String(r.ResourceType)), PolicyTemplate: new(api.Policy(`{"Effect":"Allow","Action":["ssm:GetParameter"]}`))})
	in := &api.CreatePermissionVersionRequest{PermissionArn: permission.Permission.Arn}
	for _, template := range []api.Policy{
		`{"Effect":"Allow","Action":["ssm:GetParameters"]}`,
		`{"Effect":"Allow","Action":["ssm:GetParameterHistory"]}`,
		`{"Effect":"Allow","Action":["ssm:DescribeParameters"]}`,
		`{"Effect":"Allow","Action":["ssm:GetParameter","ssm:GetParameters"]}`,
	} {
		in.PolicyTemplate = &template
		invoke[api.CreatePermissionVersionResponse](t, s, owner, "CreatePermissionVersion", in)
	}
	invoke[api.DeletePermissionVersionResponse](t, s, owner, "DeletePermissionVersion", &api.DeletePermissionVersionRequest{PermissionArn: permission.Permission.Arn, PermissionVersion: new(api.Integer(4))})
	in.PolicyTemplate = new(api.Policy(`{"Effect":"Allow","Action":["ssm:GetParameter","ssm:GetParameterHistory"]}`))
	replacement := invoke[api.CreatePermissionVersionResponse](t, s, owner, "CreatePermissionVersion", in)
	if value(replacement.Permission.Version) != "6" {
		t.Fatalf("allocation filled a deleted hole below the highest active version: %#v", replacement)
	}
	in.PolicyTemplate = new(api.Policy(`{"Effect":"Allow","Action":["ssm:GetParameters","ssm:GetParameterHistory"]}`))
	_, rejected := execute(s, owner, "CreatePermissionVersion", in)
	if rejected == nil || rejected.Code != "PermissionVersionsLimitExceededException" {
		t.Fatalf("active-version quota was not enforced: %v", rejected)
	}
	versions := invoke[api.ListPermissionVersionsResponse](t, s, owner, "ListPermissionVersions", &api.ListPermissionVersionsRequest{PermissionArn: permission.Permission.Arn})
	if len(versions.Permissions) != 6 || value(versions.Permissions[3].Version) != "4" || value(versions.Permissions[3].Status) != "DELETED" || value(versions.Permissions[5].Version) != "6" || value(versions.Permissions[5].Status) != "ATTACHABLE" {
		t.Fatalf("deleted quota slot did not retain its visible tombstone: %#v", versions)
	}
}

func TestDuplicatePermissionTemplateOnlyRejectsActiveVersions(t *testing.T) {
	s, _, r := testRAM(t)
	owner := rootContext(r.AccountID)
	template := new(api.Policy(`{"Effect":"Allow","Action":["ssm:GetParameter"]}`))
	permission := invoke[api.CreatePermissionResponse](t, s, owner, "CreatePermission", &api.CreatePermissionRequest{Name: new(api.PermissionName("DuplicateTemplate")), ResourceType: new(api.String(r.ResourceType)), PolicyTemplate: template})
	in := &api.CreatePermissionVersionRequest{PermissionArn: permission.Permission.Arn, PolicyTemplate: template, ClientToken: new(api.String("duplicate-template"))}
	_, rejected := execute(s, owner, "CreatePermissionVersion", in)
	if rejected == nil || rejected.Code != "InvalidParameterException" {
		t.Fatalf("duplicate active template was accepted: %v", rejected)
	}
	versions := invoke[api.ListPermissionVersionsResponse](t, s, owner, "ListPermissionVersions", &api.ListPermissionVersionsRequest{PermissionArn: permission.Permission.Arn})
	if len(versions.Permissions) != 1 || value(versions.Permissions[0].Version) != "1" || value(versions.Permissions[0].Status) != "ATTACHABLE" {
		t.Fatalf("duplicate template changed version state: %#v", versions)
	}
	in.PolicyTemplate = new(api.Policy(`{"Effect":"Allow","Action":["ssm:GetParameters"]}`))
	created := invoke[api.CreatePermissionVersionResponse](t, s, owner, "CreatePermissionVersion", in)
	if value(created.Permission.Version) != "2" || value(created.ClientToken) != "duplicate-template" {
		t.Fatalf("failed creation consumed the supplied token or version: %#v", created)
	}
	invoke[api.SetDefaultPermissionVersionResponse](t, s, owner, "SetDefaultPermissionVersion", &api.SetDefaultPermissionVersionRequest{PermissionArn: permission.Permission.Arn, PermissionVersion: new(api.Integer(1))})
	invoke[api.DeletePermissionVersionResponse](t, s, owner, "DeletePermissionVersion", &api.DeletePermissionVersionRequest{PermissionArn: permission.Permission.Arn, PermissionVersion: new(api.Integer(2))})
	in.ClientToken = new(api.String("reuse-deleted-template"))
	reused := invoke[api.CreatePermissionVersionResponse](t, s, owner, "CreatePermissionVersion", in)
	if value(reused.Permission.Version) != "2" || value(reused.Permission.Status) != "ATTACHABLE" || value(reused.Permission.Permission) != value(created.Permission.Permission) || value(reused.ClientToken) != "reuse-deleted-template" {
		t.Fatalf("deleted template was not reusable under a new token: %#v", reused)
	}
}
