package ram

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ram"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type resourceOwner map[string]ResourceIdentity

func (o resourceOwner) ResolveResource(_ context.Context, arn string) (ResourceIdentity, error) {
	v, ok := o[arn]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}

type organizationMembership struct{ enabled bool }

func (o *organizationMembership) Eligible(_ context.Context, owner, principal, recipient string) (bool, error) {
	return o.enabled, nil
}
func (o *organizationMembership) EnableSharing(_ context.Context, _ string) (bool, error) {
	o.enabled = true
	return true, nil
}
func rootContext(account string) context.Context {
	return awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", Region: "us-east-1", AccountID: account, PrincipalARN: "arn:aws:iam::" + account + ":root", PrincipalID: account, TransportKnown: true, SecureTransport: true, SourceIP: "192.0.2.10"})
}
func invoke[O any](t *testing.T, s *Service, ctx context.Context, operation string, input any) *O {
	t.Helper()
	out, rejected := execute(s, ctx, operation, input)
	if rejected != nil {
		t.Fatalf("%s rejected: %v", operation, rejected)
	}
	typed, ok := out.(*O)
	if !ok {
		t.Fatalf("%s returned %T", operation, out)
	}
	return typed
}
func execute(s *Service, ctx context.Context, operation string, input any) (any, *awswire.Error) {
	model, _ := awscatalog.LookupService("ram")
	op, _ := model.Operation(operation)
	return s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Input: input})
}
func testRAM(t *testing.T) (*Service, *clock.Manual, ResourceIdentity) {
	t.Helper()
	c := clock.NewManual(time.Date(2032, 1, 2, 3, 4, 5, 0, time.UTC))
	r := ResourceIdentity{ARN: "arn:aws:ssm:us-east-1:111111111111:parameter/application", ResourceType: "ssm:Parameter", Partition: "aws", Region: "us-east-1", AccountID: "111111111111", SupportsIAMPrincipals: true}
	s := New(Config{Clock: c, Resources: resourceOwner{r.ARN: r}, ResourceTypes: []string{"ssm:Parameter"}})
	return s, c, r
}
func createShared(t *testing.T, s *Service, r ResourceIdentity, permission string) *api.CreateResourceShareResponse {
	t.Helper()
	in := &api.CreateResourceShareRequest{Name: new(api.String("application")), ResourceArns: api.ResourceArnList{api.String(r.ARN)}, Principals: api.PrincipalArnOrIdList{"222222222222"}}
	if permission != "" {
		in.PermissionArns = api.PermissionArnList{api.String(permission)}
	}
	return invoke[api.CreateResourceShareResponse](t, s, rootContext(r.AccountID), "CreateResourceShare", in)
}
func accept(t *testing.T, s *Service) {
	t.Helper()
	ctx := rootContext("222222222222")
	invitations := invoke[api.GetResourceShareInvitationsResponse](t, s, ctx, "GetResourceShareInvitations", &api.GetResourceShareInvitationsRequest{})
	if len(invitations.ResourceShareInvitations) != 1 {
		t.Fatalf("expected exact invitation: %#v", invitations)
	}
	invoke[api.AcceptResourceShareInvitationResponse](t, s, ctx, "AcceptResourceShareInvitation", &api.AcceptResourceShareInvitationRequest{ResourceShareInvitationArn: invitations.ResourceShareInvitations[0].ResourceShareInvitationArn})
}
func requireGrant(t *testing.T, s *Service, ctx context.Context, r ResourceIdentity, action string, want bool) {
	t.Helper()
	got, e := s.ResourcePermission(ctx, PermissionQuery{ResourceARN: r.ARN, AccountID: awsctx.FromContext(ctx).AccountID, Action: action})
	if e != nil || got != want {
		t.Fatalf("%s grant=%v err=%v want=%v", action, got, e, want)
	}
}
func TestNativePermissionVersionsRemainPinnedUntilReplacement(t *testing.T) {
	data, e := os.ReadFile("testdata/native-controls.json")
	if e != nil {
		t.Fatal(e)
	}
	var evidence struct {
		Captures []struct {
			Args   []string
			Result json.RawMessage
			Status int
		}
	}
	if e = json.Unmarshal(data, &evidence); e != nil {
		t.Fatal(e)
	}
	var nativeVersions []string
	for _, capture := range evidence.Captures {
		if capture.Status == 0 && len(capture.Args) > 0 && capture.Args[0] == "list-resource-share-permissions" {
			var result struct{ Permissions []struct{ Version string } }
			if e = json.Unmarshal(capture.Result, &result); e != nil {
				t.Fatal(e)
			}
			nativeVersions = append(nativeVersions, result.Permissions[0].Version)
		}
	}
	if len(nativeVersions) != 2 {
		t.Fatalf("native version transitions missing: %#v", nativeVersions)
	}
	s, _, r := testRAM(t)
	owner := rootContext(r.AccountID)
	recipient := rootContext("222222222222")
	permission := invoke[api.CreatePermissionResponse](t, s, owner, "CreatePermission", &api.CreatePermissionRequest{Name: new(api.PermissionName("ReadParameter")), ResourceType: new(api.String(r.ResourceType)), PolicyTemplate: new(api.Policy(`{"Effect":"Allow","Action":["ssm:GetParameter"]}`))})
	share := createShared(t, s, r, value(permission.Permission.Arn))
	requireGrant(t, s, recipient, r, "ssm:GetParameter", false)
	accept(t, s)
	requireGrant(t, s, recipient, r, "ssm:GetParameter", true)
	invoke[api.CreatePermissionVersionResponse](t, s, owner, "CreatePermissionVersion", &api.CreatePermissionVersionRequest{PermissionArn: permission.Permission.Arn, PolicyTemplate: new(api.Policy(`{"Effect":"Allow","Action":["ssm:GetParameter","ssm:GetParameterHistory"]}`))})
	pinned := invoke[api.ListResourceSharePermissionsResponse](t, s, owner, "ListResourceSharePermissions", &api.ListResourceSharePermissionsRequest{ResourceShareArn: share.ResourceShare.ResourceShareArn})
	if value(pinned.Permissions[0].Version) != nativeVersions[0] {
		t.Fatalf("version changed without replacement: %#v", pinned.Permissions)
	}
	requireGrant(t, s, recipient, r, "ssm:GetParameterHistory", false)
	invoke[api.AssociateResourceSharePermissionResponse](t, s, owner, "AssociateResourceSharePermission", &api.AssociateResourceSharePermissionRequest{ResourceShareArn: share.ResourceShare.ResourceShareArn, PermissionArn: permission.Permission.Arn, Replace: new(api.Boolean(true))})
	replaced := invoke[api.ListResourceSharePermissionsResponse](t, s, owner, "ListResourceSharePermissions", &api.ListResourceSharePermissionsRequest{ResourceShareArn: share.ResourceShare.ResourceShareArn})
	if value(replaced.Permissions[0].Version) != nativeVersions[1] {
		t.Fatalf("replacement version=%s", value(replaced.Permissions[0].Version))
	}
	requireGrant(t, s, recipient, r, "ssm:GetParameterHistory", true)
	invoke[api.DisassociateResourceShareResponse](t, s, owner, "DisassociateResourceShare", &api.DisassociateResourceShareRequest{ResourceShareArn: share.ResourceShare.ResourceShareArn, Principals: api.PrincipalArnOrIdList{"222222222222"}})
	requireGrant(t, s, recipient, r, "ssm:GetParameter", false)
}
func TestInvitationExpiryAndDeletionDoNotReviveGrants(t *testing.T) {
	s, c, r := testRAM(t)
	share := createShared(t, s, r, "")
	recipient := rootContext("222222222222")
	owner := rootContext(r.AccountID)
	invitations := invoke[api.GetResourceShareInvitationsResponse](t, s, recipient, "GetResourceShareInvitations", &api.GetResourceShareInvitationsRequest{})
	if e := c.Advance(12 * time.Hour); e != nil {
		t.Fatal(e)
	}
	_, rejected := execute(s, recipient, "AcceptResourceShareInvitation", &api.AcceptResourceShareInvitationRequest{ResourceShareInvitationArn: invitations.ResourceShareInvitations[0].ResourceShareInvitationArn})
	if rejected == nil || rejected.Code != "ResourceShareInvitationExpiredException" {
		t.Fatalf("expired invitation accepted: %v", rejected)
	}
	associations := invoke[api.GetResourceShareAssociationsResponse](t, s, owner, "GetResourceShareAssociations", &api.GetResourceShareAssociationsRequest{AssociationType: new(api.ResourceShareAssociationTypePRINCIPAL), ResourceShareArns: api.ResourceShareArnList{*share.ResourceShare.ResourceShareArn}})
	if value(associations.ResourceShareAssociations[0].Status) != "DISASSOCIATED" {
		t.Fatalf("expired principal remains active: %#v", associations)
	}
	requireGrant(t, s, recipient, r, "ssm:GetParameter", false)
	s, _, r = testRAM(t)
	createShared(t, s, r, "")
	accept(t, s)
	requireGrant(t, s, recipient, r, "ssm:GetParameter", true)
	aborted := errors.New("owner transaction rejected")
	e := s.repository.Update(owner, func(tx Transaction) error {
		if e := s.ResourceDeleted(tx.Context(), r.ARN); e != nil {
			return e
		}
		return aborted
	})
	if !errors.Is(e, aborted) {
		t.Fatal(e)
	}
	requireGrant(t, s, recipient, r, "ssm:GetParameter", true)
	if e = s.ResourceDeleted(owner, r.ARN); e != nil {
		t.Fatal(e)
	}
	// ResolveResource still returns the same ARN, as after owner deletion/recreation.
	requireGrant(t, s, recipient, r, "ssm:GetParameter", false)
}
func TestPermissionConditionsAndOrganizationMembershipRemainLive(t *testing.T) {
	s, _, r := testRAM(t)
	org := &organizationMembership{enabled: true}
	s.organization = org
	owner := rootContext(r.AccountID)
	recipient := rootContext("222222222222")
	p := invoke[api.CreatePermissionResponse](t, s, owner, "CreatePermission", &api.CreatePermissionRequest{Name: new(api.PermissionName("NetworkRestricted")), ResourceType: new(api.String(r.ResourceType)), PolicyTemplate: new(api.Policy(`{"Effect":"Allow","Action":["ssm:getparameter"],"Condition":{"IpAddress":{"aws:SourceIp":"192.0.2.0/24"}}}`))})
	createShared(t, s, r, value(p.Permission.Arn))
	requireGrant(t, s, recipient, r, "ssm:GetParameter", true)
	metadata := awsctx.FromContext(recipient)
	metadata.SourceIP = "198.51.100.1"
	requireGrant(t, s, awsctx.WithMetadata(recipient, metadata), r, "ssm:GetParameter", false)
	org.enabled = false
	requireGrant(t, s, recipient, r, "ssm:GetParameter", false)
	org.enabled = true
	requireGrant(t, s, recipient, r, "ssm:GetParameter", true)
}
func TestPaginationTokensCannotCrossCallerScopeOrFilters(t *testing.T) {
	s, _, r := testRAM(t)
	ctx := rootContext(r.AccountID)
	for _, name := range []api.String{"first", "second"} {
		invoke[api.CreateResourceShareResponse](t, s, ctx, "CreateResourceShare", &api.CreateResourceShareRequest{Name: &name})
	}
	first := invoke[api.GetResourceSharesResponse](t, s, ctx, "GetResourceShares", &api.GetResourceSharesRequest{ResourceOwner: new(api.ResourceOwnerSELF), MaxResults: new(api.MaxResults(1))})
	if first.NextToken == nil {
		t.Fatal("first page lacks continuation")
	}
	for _, tc := range []struct {
		ctx  context.Context
		name *api.String
	}{{rootContext("222222222222"), nil}, {ctx, new(api.String("first"))}} {
		_, e := execute(s, tc.ctx, "GetResourceShares", &api.GetResourceSharesRequest{ResourceOwner: new(api.ResourceOwnerSELF), MaxResults: new(api.MaxResults(1)), NextToken: first.NextToken, Name: tc.name})
		if e == nil || e.Code != "InvalidNextTokenException" {
			t.Fatalf("token crossed query boundary: %v", e)
		}
	}
	next := invoke[api.GetResourceSharesResponse](t, s, ctx, "GetResourceShares", &api.GetResourceSharesRequest{ResourceOwner: new(api.ResourceOwnerSELF), MaxResults: new(api.MaxResults(1)), NextToken: first.NextToken})
	if value(first.ResourceShares[0].ResourceShareArn) == value(next.ResourceShares[0].ResourceShareArn) || next.NextToken != nil {
		t.Fatalf("continuation repeated a share: %#v", next)
	}
}

func TestOwnerFailureAndCustomerPermissionBoundary(t *testing.T) {
	s, _, r := testRAM(t)
	ctx := rootContext(r.AccountID)
	_, rejected := execute(s, ctx, "CreatePermission", &api.CreatePermissionRequest{Name: new(api.PermissionName("InvalidWrite")), ResourceType: new(api.String(r.ResourceType)), PolicyTemplate: new(api.Policy(`{"Effect":"Allow","Action":["ssm:PutParameter"]}`))})
	if rejected == nil || rejected.Code != "InvalidPolicyException" {
		t.Fatalf("unsupported write action accepted: %v", rejected)
	}
	share := invoke[api.CreateResourceShareResponse](t, s, ctx, "CreateResourceShare", &api.CreateResourceShareRequest{Name: new(api.String("owner-account")), ResourceArns: api.ResourceArnList{api.String(r.ARN)}, Principals: api.PrincipalArnOrIdList{api.String(r.AccountID)}})
	associations := invoke[api.GetResourceShareAssociationsResponse](t, s, ctx, "GetResourceShareAssociations", &api.GetResourceShareAssociationsRequest{AssociationType: new(api.ResourceShareAssociationTypeRESOURCE), ResourceShareArns: api.ResourceShareArnList{*share.ResourceShare.ResourceShareArn}})
	if len(associations.ResourceShareAssociations) != 1 || value(associations.ResourceShareAssociations[0].Status) != "FAILED" {
		t.Fatalf("owner-account resource did not fail association: %#v", associations)
	}
	requireGrant(t, s, ctx, r, "ssm:GetParameter", false)
}

func TestIdempotencyBindsParametersWithoutRepeatingMutation(t *testing.T) {
	s, _, r := testRAM(t)
	ctx := rootContext(r.AccountID)
	in := &api.CreateResourceShareRequest{Name: new(api.String("original")), ClientToken: new(api.String("same-command"))}
	created := invoke[api.CreateResourceShareResponse](t, s, ctx, "CreateResourceShare", in)
	invoke[api.UpdateResourceShareResponse](t, s, ctx, "UpdateResourceShare", &api.UpdateResourceShareRequest{ResourceShareArn: created.ResourceShare.ResourceShareArn, Name: new(api.String("updated"))})
	replay := invoke[api.CreateResourceShareResponse](t, s, ctx, "CreateResourceShare", in)
	if *replay.ResourceShare.ResourceShareArn != *created.ResourceShare.ResourceShareArn || value(replay.ResourceShare.Name) != "updated" {
		t.Fatalf("retry did not resolve current original share: %#v", replay)
	}
	in.Name = new(api.String("different"))
	_, rejected := execute(s, ctx, "CreateResourceShare", in)
	if rejected == nil || rejected.Code != "IdempotentParameterMismatchException" {
		t.Fatalf("token accepted different request: %v", rejected)
	}
	shares := invoke[api.GetResourceSharesResponse](t, s, ctx, "GetResourceShares", &api.GetResourceSharesRequest{ResourceOwner: new(api.ResourceOwnerSELF)})
	if len(shares.ResourceShares) != 1 || *shares.ResourceShares[0].ResourceShareArn != *created.ResourceShare.ResourceShareArn {
		t.Fatalf("retry created another share: %#v", shares)
	}
}
