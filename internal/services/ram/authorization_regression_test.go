package ram

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"stackd/iam/policy"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ram"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

type ramIdentityPolicies struct{ set authorization.PolicySet }

func (p ramIdentityPolicies) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	return p.set, nil
}

type ramControlPolicies []policy.PolicyLevel

func (p ramControlPolicies) ServiceControlPolicies(context.Context) ([]policy.PolicyLevel, error) {
	return p, nil
}

func ramUserContext(account string) context.Context {
	ctx := rootContext(account)
	m := awsctx.FromContext(ctx)
	m.PrincipalARN = "arn:aws:iam::" + account + ":user/auditor"
	m.PrincipalID = "AIDARAMAUDITOR"
	m.UserName = "auditor"
	return awsctx.WithMetadata(ctx, m)
}

func ramPolicy(t *testing.T, effect, action string, resources []string, condition map[string]any) policy.Policy {
	t.Helper()
	statement := map[string]any{"Effect": effect, "Action": "ram:" + action, "Resource": resources}
	if condition != nil {
		statement["Condition"] = condition
	}
	document, e := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statement})
	if e != nil {
		t.Fatal(e)
	}
	return policy.Policy{Document: string(document)}
}

func ramAuthPermission(t *testing.T, s *Service, r ResourceIdentity, name string) *api.String {
	t.Helper()
	p := invoke[api.CreatePermissionResponse](t, s, rootContext(r.AccountID), "CreatePermission", &api.CreatePermissionRequest{Name: new(api.PermissionName(name)), ResourceType: new(api.String(r.ResourceType)), PolicyTemplate: new(api.Policy(`{"Effect":"Allow","Action":["ssm:GetParameter"]}`))})
	return p.Permission.Arn
}

func ramTag(t *testing.T, s *Service, account string, arn *api.String, value string) {
	t.Helper()
	invoke[api.TagResourceResponse](t, s, rootContext(account), "TagResource", &api.TagResourceRequest{ResourceArn: arn, Tags: api.TagList{{Key: new(api.TagKey("access")), Value: new(api.TagValue(value))}}})
}

func ramRequireRejected(t *testing.T, s *Service, ctx context.Context, op string, in any, code string) {
	t.Helper()
	_, rejected := execute(s, ctx, op, in)
	if rejected == nil || rejected.Code != code {
		t.Fatalf("%s error=%v, want %s", op, rejected, code)
	}
}

func TestPermissionListingsAuthorizeExactResourcesAndCurrentTags(t *testing.T) {
	s, _, r := testRAM(t)
	p := ramAuthPermission(t, s, r, "ListScoped")
	share := createShared(t, s, r, value(p))
	ctx := ramUserContext(r.AccountID)
	for _, tc := range []struct {
		op    string
		arn   *api.String
		input any
	}{
		{"ListResourceSharePermissions", share.ResourceShare.ResourceShareArn, &api.ListResourceSharePermissionsRequest{ResourceShareArn: share.ResourceShare.ResourceShareArn}},
		{"ListPermissionAssociations", p, &api.ListPermissionAssociationsRequest{PermissionArn: p}},
	} {
		t.Run(tc.op, func(t *testing.T) {
			allow := ramPolicy(t, "Allow", tc.op, []string{value(tc.arn)}, nil)
			s.authorizer = authorization.New(ramIdentityPolicies{authorization.PolicySet{Identity: []policy.Policy{allow}}}, nil)
			out, rejected := execute(s, ctx, tc.op, tc.input)
			if rejected != nil {
				t.Fatal(rejected)
			}
			switch result := out.(type) {
			case *api.ListResourceSharePermissionsResponse:
				if len(result.Permissions) != 1 || value(result.Permissions[0].Arn) != value(p) {
					t.Fatalf("wrong share permissions: %#v", result.Permissions)
				}
			case *api.ListPermissionAssociationsResponse:
				if len(result.Permissions) != 1 || value(result.Permissions[0].ResourceShareArn) != value(share.ResourceShare.ResourceShareArn) {
					t.Fatalf("wrong associations: %#v", result.Permissions)
				}
			}
			deny := ramPolicy(t, "Deny", tc.op, []string{value(tc.arn)}, nil)
			s.authorizer = authorization.New(ramIdentityPolicies{authorization.PolicySet{Identity: []policy.Policy{allow, deny}}}, nil)
			ramRequireRejected(t, s, ctx, tc.op, tc.input, "AccessDeniedException")
			ramTag(t, s, r.AccountID, tc.arn, "blocked")
			deny = ramPolicy(t, "Deny", tc.op, []string{"*"}, map[string]any{"StringEquals": map[string]string{"aws:ResourceTag/access": "blocked"}})
			s.authorizer = authorization.New(ramIdentityPolicies{authorization.PolicySet{Identity: []policy.Policy{allow, deny}}}, nil)
			ramRequireRejected(t, s, ctx, tc.op, tc.input, "AccessDeniedException")
		})
	}
}

func TestPermissionAssociationCollectionFiltersDeniedPermissions(t *testing.T) {
	s, _, r := testRAM(t)
	allowed := ramAuthPermission(t, s, r, "VisibleAssociation")
	denied := ramAuthPermission(t, s, r, "HiddenAssociation")
	visibleShare := createShared(t, s, r, value(allowed))
	createShared(t, s, r, value(denied))
	ramTag(t, s, r.AccountID, denied, "blocked")
	ctx := ramUserContext(r.AccountID)
	deny := ramPolicy(t, "Deny", "ListPermissionAssociations", []string{"*"}, map[string]any{"StringEquals": map[string]string{"aws:ResourceTag/access": "blocked"}})
	for _, resource := range []string{value(allowed), "*"} {
		s.authorizer = authorization.New(ramIdentityPolicies{authorization.PolicySet{Identity: []policy.Policy{ramPolicy(t, "Allow", "ListPermissionAssociations", []string{resource}, nil), deny}}}, nil)
		result := invoke[api.ListPermissionAssociationsResponse](t, s, ctx, "ListPermissionAssociations", &api.ListPermissionAssociationsRequest{})
		if len(result.Permissions) != 1 || value(result.Permissions[0].Arn) != value(allowed) || value(result.Permissions[0].ResourceShareArn) != value(visibleShare.ResourceShare.ResourceShareArn) {
			t.Fatalf("collection exposed denied association: %#v", result.Permissions)
		}
		ramRequireRejected(t, s, ctx, "ListPermissionAssociations", &api.ListPermissionAssociationsRequest{PermissionArn: denied}, "AccessDeniedException")
	}
	s.authorizer = authorization.New(ramIdentityPolicies{}, nil)
	ramRequireRejected(t, s, ctx, "ListPermissionAssociations", &api.ListPermissionAssociationsRequest{}, "AccessDeniedException")
}

func TestGetPermissionUsesCurrentAuthoritativeTags(t *testing.T) {
	s, _, r := testRAM(t)
	p := ramAuthPermission(t, s, r, "TaggedRead")
	ctx := ramUserContext(r.AccountID)
	allow := ramPolicy(t, "Allow", "GetPermission", []string{value(p)}, map[string]any{"StringEquals": map[string]string{"aws:ResourceTag/access": "readable", "ram:PermissionResourceType": r.ResourceType}})
	deny := ramPolicy(t, "Deny", "GetPermission", []string{value(p)}, map[string]any{"StringEquals": map[string]string{"aws:ResourceTag/access": "blocked"}})
	s.authorizer = authorization.New(ramIdentityPolicies{authorization.PolicySet{Identity: []policy.Policy{allow, deny}}}, nil)
	for _, tag := range []string{"readable", "blocked", "readable"} {
		ramTag(t, s, r.AccountID, p, tag)
		if tag == "blocked" {
			ramRequireRejected(t, s, ctx, "GetPermission", &api.GetPermissionRequest{PermissionArn: p}, "AccessDeniedException")
			continue
		}
		result := invoke[api.GetPermissionResponse](t, s, ctx, "GetPermission", &api.GetPermissionRequest{PermissionArn: p})
		if value(result.Permission.Arn) != value(p) || len(result.Permission.Tags) != 1 || value(result.Permission.Tags[0].Value) != tag {
			t.Fatalf("permission did not reflect current tags: %#v", result.Permission)
		}
	}
}

func TestReplacementAuthorizesBothCurrentPermissionsBeforeMutationAndReplay(t *testing.T) {
	for _, side := range []string{"source", "target"} {
		for _, tagged := range []bool{false, true} {
			t.Run(side+map[bool]string{false: "ResourceDeny", true: "TagDeny"}[tagged], func(t *testing.T) {
				s, _, r := testRAM(t)
				from := ramAuthPermission(t, s, r, "ReplaceSource")
				to := ramAuthPermission(t, s, r, "ReplaceTarget")
				share := createShared(t, s, r, value(from))
				invoke[api.CreatePermissionVersionResponse](t, s, rootContext(r.AccountID), "CreatePermissionVersion", &api.CreatePermissionVersionRequest{PermissionArn: from, PolicyTemplate: new(api.Policy(`{"Effect":"Allow","Action":["ssm:GetParameters"]}`))})
				protected := from
				if side == "target" {
					protected = to
				}
				ramTag(t, s, r.AccountID, protected, "blocked")
				allow := ramPolicy(t, "Allow", "ReplacePermissionAssociations", []string{value(from), value(to)}, nil)
				var condition map[string]any
				if tagged {
					condition = map[string]any{"StringEquals": map[string]string{"aws:ResourceTag/access": "blocked"}}
				}
				deny := ramPolicy(t, "Deny", "ReplacePermissionAssociations", []string{value(protected)}, condition)
				s.authorizer = authorization.New(ramIdentityPolicies{authorization.PolicySet{Identity: []policy.Policy{allow, deny}}}, nil)
				ctx := ramUserContext(r.AccountID)
				input := &api.ReplacePermissionAssociationsRequest{FromPermissionArn: from, ToPermissionArn: to, ClientToken: new(api.String("replace-scoped"))}
				ramRequireRejected(t, s, ctx, "ReplacePermissionAssociations", input, "AccessDeniedException")
				pinned := invoke[api.ListResourceSharePermissionsResponse](t, s, rootContext(r.AccountID), "ListResourceSharePermissions", &api.ListResourceSharePermissionsRequest{ResourceShareArn: share.ResourceShare.ResourceShareArn})
				if len(pinned.Permissions) != 1 || value(pinned.Permissions[0].Arn) != value(from) || value(pinned.Permissions[0].Version) != "1" {
					t.Fatalf("denied replacement changed pinned permission: %#v", pinned.Permissions)
				}
				s.authorizer = authorization.New(ramIdentityPolicies{authorization.PolicySet{Identity: []policy.Policy{allow}}}, nil)
				invoke[api.ReplacePermissionAssociationsResponse](t, s, ctx, "ReplacePermissionAssociations", input)
				replaced := invoke[api.ListResourceSharePermissionsResponse](t, s, rootContext(r.AccountID), "ListResourceSharePermissions", &api.ListResourceSharePermissionsRequest{ResourceShareArn: share.ResourceShare.ResourceShareArn})
				if len(replaced.Permissions) != 1 || value(replaced.Permissions[0].Arn) != value(to) || value(replaced.Permissions[0].Version) != "1" {
					t.Fatalf("exact-resource replacement failed: %#v", replaced.Permissions)
				}
				s.authorizer = authorization.New(ramIdentityPolicies{authorization.PolicySet{Identity: []policy.Policy{allow, deny}}}, nil)
				ramRequireRejected(t, s, ctx, "ReplacePermissionAssociations", input, "AccessDeniedException")
			})
		}
	}
}

func TestRecipientSharePermissionListingUsesCurrentVisibilityAndIdentityCeilings(t *testing.T) {
	for _, organization := range []bool{false, true} {
		t.Run(map[bool]string{false: "AcceptedInvitation", true: "Organization"}[organization], func(t *testing.T) {
			s, _, r := testRAM(t)
			org := &organizationMembership{enabled: true}
			if organization {
				s.organization = org
			}
			share := createShared(t, s, r, "")
			input := &api.ListResourceSharePermissionsRequest{ResourceShareArn: share.ResourceShare.ResourceShareArn}
			ctx := ramUserContext("222222222222")
			if !organization {
				ramRequireRejected(t, s, ctx, "ListResourceSharePermissions", input, "UnknownResourceException")
				accept(t, s)
			}
			allow := ramPolicy(t, "Allow", "ListResourceSharePermissions", []string{value(share.ResourceShare.ResourceShareArn)}, nil)
			s.authorizer = authorization.New(ramIdentityPolicies{authorization.PolicySet{Identity: []policy.Policy{allow}}}, nil)
			listed := invoke[api.ListResourceSharePermissionsResponse](t, s, ctx, "ListResourceSharePermissions", input)
			if len(listed.Permissions) != 1 || value(listed.Permissions[0].ResourceType) != r.ResourceType || value(listed.Permissions[0].PermissionType) != "AWS_MANAGED" {
				t.Fatalf("recipient received incorrect permissions: %#v", listed.Permissions)
			}
			for _, ceiling := range []string{"identity", "explicit", "tag", "boundary", "session", "scp"} {
				set := authorization.PolicySet{Identity: []policy.Policy{allow}}
				var controls authorization.ControlSource
				current := ctx
				switch ceiling {
				case "identity":
					set.Identity = nil
				case "explicit":
					set.Identity = append(set.Identity, ramPolicy(t, "Deny", "ListResourceSharePermissions", []string{value(share.ResourceShare.ResourceShareArn)}, nil))
				case "tag":
					ramTag(t, s, r.AccountID, share.ResourceShare.ResourceShareArn, "blocked")
					set.Identity = append(set.Identity, ramPolicy(t, "Deny", "ListResourceSharePermissions", []string{"*"}, map[string]any{"StringEquals": map[string]string{"aws:ResourceTag/access": "blocked"}}))
				case "boundary":
					set.HasBoundary = true
				case "session":
					m := awsctx.FromContext(ctx)
					m.PrincipalARN = "arn:aws:sts::222222222222:assumed-role/auditor/session"
					m.PrincipalID = "AROARAMAUDITOR:session"
					m.IssuerARN = "arn:aws:iam::222222222222:role/auditor"
					m.IssuerID = "AROARAMAUDITOR"
					m.UserName = ""
					m.SessionType = "AssumeRole"
					m.HasSessionPolicy = true
					current = awsctx.WithMetadata(ctx, m)
				case "scp":
					controls = ramControlPolicies{{Documents: []policy.Policy{ramPolicy(t, "Deny", "ListResourceSharePermissions", []string{"*"}, nil)}}}
				}
				s.authorizer = authorization.New(ramIdentityPolicies{set}, controls)
				ramRequireRejected(t, s, current, "ListResourceSharePermissions", input, "AccessDeniedException")
			}
			s.authorizer = authorization.New(ramIdentityPolicies{authorization.PolicySet{Identity: []policy.Policy{allow}}}, nil)
			if organization {
				org.enabled = false
			} else {
				invoke[api.DisassociateResourceShareResponse](t, s, rootContext(r.AccountID), "DisassociateResourceShare", &api.DisassociateResourceShareRequest{ResourceShareArn: share.ResourceShare.ResourceShareArn, Principals: api.PrincipalArnOrIdList{"222222222222"}})
			}
			ramRequireRejected(t, s, ctx, "ListResourceSharePermissions", input, "UnknownResourceException")
		})
	}
}

func TestScopedPermissionOperationsPreserveMissingResourceAndCallerScope(t *testing.T) {
	s, _, r := testRAM(t)
	p := ramAuthPermission(t, s, r, "ScopedMissing")
	share := createShared(t, s, r, value(p))
	allow := ramPolicy(t, "Allow", "*", []string{"*"}, nil)
	s.authorizer = authorization.New(ramIdentityPolicies{authorization.PolicySet{Identity: []policy.Policy{allow}}}, nil)
	missingPermission := new(api.String("arn:aws:ram:us-east-1:111111111111:permission/missing"))
	missingShare := new(api.String("arn:aws:ram:us-east-1:111111111111:resource-share/missing"))
	owner := ramUserContext(r.AccountID)
	for _, tc := range []struct {
		op string
		in any
	}{
		{"GetPermission", &api.GetPermissionRequest{PermissionArn: missingPermission}},
		{"ListResourceSharePermissions", &api.ListResourceSharePermissionsRequest{ResourceShareArn: missingShare}},
		{"ListPermissionAssociations", &api.ListPermissionAssociationsRequest{PermissionArn: missingPermission}},
		{"ReplacePermissionAssociations", &api.ReplacePermissionAssociationsRequest{FromPermissionArn: missingPermission, ToPermissionArn: p}},
		{"ReplacePermissionAssociations", &api.ReplacePermissionAssociationsRequest{FromPermissionArn: p, ToPermissionArn: missingPermission}},
	} {
		ramRequireRejected(t, s, owner, tc.op, tc.in, "UnknownResourceException")
	}
	otherRegion := awsctx.FromContext(owner)
	otherRegion.Region = "us-west-2"
	for _, ctx := range []context.Context{ramUserContext("333333333333"), awsctx.WithMetadata(owner, otherRegion)} {
		ramRequireRejected(t, s, ctx, "GetPermission", &api.GetPermissionRequest{PermissionArn: p}, "UnknownResourceException")
		ramRequireRejected(t, s, ctx, "ListPermissionAssociations", &api.ListPermissionAssociationsRequest{PermissionArn: p}, "UnknownResourceException")
		ramRequireRejected(t, s, ctx, "ListResourceSharePermissions", &api.ListResourceSharePermissionsRequest{ResourceShareArn: share.ResourceShare.ResourceShareArn}, "UnknownResourceException")
	}
}

// Applicable resource-side denials still compose in the ordinary evaluator.
type ramResourceDenyAuthorizer struct {
	authorization.Authorizer
	policy authorization.BoundPolicy
}

func (a ramResourceDenyAuthorizer) Authorize(ctx context.Context, request authorization.Request) *awswire.Error {
	request.ResourcePolicies = append(request.ResourcePolicies, a.policy)
	return a.Authorizer.Authorize(ctx, request)
}

func TestRecipientGetResourceSharesRetainsEveryAuthorizationCeiling(t *testing.T) {
	s, _, r := testRAM(t)
	share := createShared(t, s, r, "")
	accept(t, s)
	input := &api.GetResourceSharesRequest{ResourceOwner: new(api.ResourceOwnerOTHER_ACCOUNTS), ResourceShareArns: api.ResourceShareArnList{*share.ResourceShare.ResourceShareArn}}
	ctx := ramUserContext("222222222222")
	allow := ramPolicy(t, "Allow", "GetResourceShares", []string{"*"}, nil)
	for _, ceiling := range []string{"allow", "identity", "explicit", "arn-only", "arn-deny", "boundary", "session", "scp", "resource"} {
		t.Run(ceiling, func(t *testing.T) {
			set := authorization.PolicySet{Identity: []policy.Policy{allow}}
			var controls authorization.ControlSource
			current := ctx
			switch ceiling {
			case "identity":
				set.Identity = nil
			case "explicit":
				set.Identity = append(set.Identity, ramPolicy(t, "Deny", "GetResourceShares", []string{"*"}, nil))
			case "arn-only":
				set.Identity = []policy.Policy{ramPolicy(t, "Allow", "GetResourceShares", []string{value(share.ResourceShare.ResourceShareArn)}, nil)}
			case "arn-deny":
				set.Identity = append(set.Identity, ramPolicy(t, "Deny", "GetResourceShares", []string{value(share.ResourceShare.ResourceShareArn)}, nil))
			case "boundary":
				set.HasBoundary = true
			case "session":
				m := awsctx.FromContext(ctx)
				m.PrincipalARN = "arn:aws:sts::222222222222:assumed-role/auditor/session"
				m.PrincipalID = "AROARAMAUDITOR:session"
				m.IssuerARN = "arn:aws:iam::222222222222:role/auditor"
				m.IssuerID = "AROARAMAUDITOR"
				m.UserName = ""
				m.SessionType = "AssumeRole"
				m.HasSessionPolicy = true
				current = awsctx.WithMetadata(ctx, m)
			case "scp":
				controls = ramControlPolicies{{Documents: []policy.Policy{ramPolicy(t, "Deny", "GetResourceShares", []string{"*"}, nil)}}}
			}
			s.authorizer = authorization.New(ramIdentityPolicies{set}, controls)
			if ceiling == "resource" {
				document := `{"Statement":{"Effect":"Deny","Principal":"*","Action":"ram:GetResourceShares","Resource":"*"}}`
				s.authorizer = ramResourceDenyAuthorizer{Authorizer: s.authorizer, policy: authorization.BoundPolicy{Document: document}}
			}
			if ceiling != "allow" && ceiling != "arn-deny" {
				ramRequireRejected(t, s, current, "GetResourceShares", input, "AccessDeniedException")
				return
			}
			result := invoke[api.GetResourceSharesResponse](t, s, current, "GetResourceShares", input)
			if len(result.ResourceShares) != 1 || value(result.ResourceShares[0].ResourceShareArn) != value(share.ResourceShare.ResourceShareArn) || len(result.ResourceShares[0].Tags) != 0 {
				t.Fatalf("recipient share read: %#v", result)
			}
		})
	}
}

func TestRecipientShareReadsUseCurrentVisibilityAndScope(t *testing.T) {
	for _, transition := range []string{"pending", "reject", "expire", "principal-revoked", "deleted", "organization-left", "principal-recreated"} {
		t.Run(transition, func(t *testing.T) {
			s, c, r := testRAM(t)
			org := &organizationMembership{enabled: true}
			if transition == "organization-left" {
				s.organization = org
			}
			share := createShared(t, s, r, "")
			arn := share.ResourceShare.ResourceShareArn
			recipient := ramUserContext("222222222222")
			if transition != "pending" && transition != "reject" && transition != "expire" && transition != "organization-left" {
				accept(t, s)
			}
			switch transition {
			case "reject":
				invitations := invoke[api.GetResourceShareInvitationsResponse](t, s, rootContext("222222222222"), "GetResourceShareInvitations", &api.GetResourceShareInvitationsRequest{})
				invoke[api.RejectResourceShareInvitationResponse](t, s, rootContext("222222222222"), "RejectResourceShareInvitation", &api.RejectResourceShareInvitationRequest{ResourceShareInvitationArn: invitations.ResourceShareInvitations[0].ResourceShareInvitationArn})
			case "expire":
				if err := c.Advance(12 * time.Hour); err != nil {
					t.Fatal(err)
				}
			case "principal-revoked":
				invoke[api.DisassociateResourceShareResponse](t, s, rootContext(r.AccountID), "DisassociateResourceShare", &api.DisassociateResourceShareRequest{ResourceShareArn: arn, Principals: api.PrincipalArnOrIdList{"222222222222"}})
			case "deleted":
				invoke[api.DeleteResourceShareResponse](t, s, rootContext(r.AccountID), "DeleteResourceShare", &api.DeleteResourceShareRequest{ResourceShareArn: arn})
			case "organization-left":
				org.enabled = false
			case "principal-recreated":
				if err := s.repository.Attempt(rootContext(r.AccountID), func(tx Transaction) error {
					current, err := tx.Share(value(arn))
					if err != nil {
						return err
					}
					current.Principals[0].PrincipalID = "AIDAORIGINAL"
					return tx.PutShare(current)
				}); err != nil {
					t.Fatal(err)
				}
			}
			s.authorizer = authorization.New(ramIdentityPolicies{authorization.PolicySet{Identity: []policy.Policy{ramPolicy(t, "Allow", "*", []string{"*"}, nil)}}}, nil)
			region := awsctx.FromContext(recipient)
			region.Region = "us-west-2"
			partition := awsctx.FromContext(recipient)
			partition.Partition = "aws-cn"
			partition.Region = "cn-north-1"
			partition.PrincipalARN = "arn:aws-cn:iam::222222222222:user/auditor"
			for _, ctx := range []context.Context{recipient, ramUserContext("333333333333"), awsctx.WithMetadata(recipient, region), awsctx.WithMetadata(recipient, partition)} {
				for _, filter := range []api.ResourceShareArnList{nil, {*arn}, {"arn:aws:ram:us-east-1:111111111111:resource-share/missing"}} {
					listed := invoke[api.GetResourceSharesResponse](t, s, ctx, "GetResourceShares", &api.GetResourceSharesRequest{ResourceOwner: new(api.ResourceOwnerOTHER_ACCOUNTS), ResourceShareArns: filter})
					if len(listed.ResourceShares) != 0 {
						t.Fatalf("inactive/foreign share exposed: %#v", listed)
					}
				}
				resources := invoke[api.ListResourcesResponse](t, s, ctx, "ListResources", &api.ListResourcesRequest{ResourceOwner: new(api.ResourceOwnerOTHER_ACCOUNTS), ResourceShareArns: api.ResourceShareArnList{*arn}})
				if len(resources.Resources) != 0 {
					t.Fatalf("inactive/foreign resource exposed: %#v", resources)
				}
				ramRequireRejected(t, s, ctx, "ListResourceSharePermissions", &api.ListResourceSharePermissionsRequest{ResourceShareArn: arn}, "UnknownResourceException")
			}
		})
	}
}

func TestRecipientSharePaginationReevaluatesLiveAuthority(t *testing.T) {
	s, _, r := testRAM(t)
	createShared(t, s, r, "")
	createShared(t, s, r, "")
	recipient := rootContext("222222222222")
	invitations := invoke[api.GetResourceShareInvitationsResponse](t, s, recipient, "GetResourceShareInvitations", &api.GetResourceShareInvitationsRequest{})
	for _, invitation := range invitations.ResourceShareInvitations {
		invoke[api.AcceptResourceShareInvitationResponse](t, s, recipient, "AcceptResourceShareInvitation", &api.AcceptResourceShareInvitationRequest{ResourceShareInvitationArn: invitation.ResourceShareInvitationArn})
	}
	ctx := ramUserContext("222222222222")
	allow := ramPolicy(t, "Allow", "GetResourceShares", []string{"*"}, nil)
	s.authorizer = authorization.New(ramIdentityPolicies{authorization.PolicySet{Identity: []policy.Policy{allow}}}, nil)
	first := invoke[api.GetResourceSharesResponse](t, s, ctx, "GetResourceShares", &api.GetResourceSharesRequest{ResourceOwner: new(api.ResourceOwnerOTHER_ACCOUNTS), MaxResults: new(api.MaxResults(1))})
	if len(first.ResourceShares) != 1 || first.NextToken == nil {
		t.Fatalf("missing recipient continuation: %#v", first)
	}
	nextInput := &api.GetResourceSharesRequest{ResourceOwner: new(api.ResourceOwnerOTHER_ACCOUNTS), MaxResults: new(api.MaxResults(1)), NextToken: first.NextToken}
	next := invoke[api.GetResourceSharesResponse](t, s, ctx, "GetResourceShares", nextInput)
	if len(next.ResourceShares) != 1 || value(next.ResourceShares[0].ResourceShareArn) == value(first.ResourceShares[0].ResourceShareArn) || next.NextToken != nil {
		t.Fatalf("recipient continuation repeated share: %#v", next)
	}
	ramRequireRejected(t, s, ramUserContext("333333333333"), "GetResourceShares", nextInput, "InvalidNextTokenException")
	changedQuery := *nextInput
	changedQuery.ResourceOwner = new(api.ResourceOwnerSELF)
	ramRequireRejected(t, s, ctx, "GetResourceShares", &changedQuery, "InvalidNextTokenException")
	deny := ramPolicy(t, "Deny", "GetResourceShares", []string{"*"}, nil)
	s.authorizer = authorization.New(ramIdentityPolicies{authorization.PolicySet{Identity: []policy.Policy{allow, deny}}}, nil)
	ramRequireRejected(t, s, ctx, "GetResourceShares", nextInput, "AccessDeniedException")
	s.authorizer = authorization.New(ramIdentityPolicies{authorization.PolicySet{Identity: []policy.Policy{allow}}}, nil)
	invoke[api.DisassociateResourceShareResponse](t, s, rootContext(r.AccountID), "DisassociateResourceShare", &api.DisassociateResourceShareRequest{ResourceShareArn: next.ResourceShares[0].ResourceShareArn, Principals: api.PrincipalArnOrIdList{"222222222222"}})
	after := invoke[api.GetResourceSharesResponse](t, s, ctx, "GetResourceShares", nextInput)
	if len(after.ResourceShares) != 0 || after.NextToken != nil {
		t.Fatalf("continuation retained revoked share: %#v", after)
	}
}

type ramReadAudit struct {
	calls          []journal.APICallCompleted
	failWithdrawal bool
}

func (a *ramReadAudit) Record(_ context.Context, _ journal.Envelope, call journal.APICallCompleted) error {
	if a.failWithdrawal && call.EventName == "DisassociateResourceShare" && call.ErrorCode == "" {
		a.failWithdrawal = false
		return errors.New("retained event unavailable")
	}
	a.calls = append(a.calls, call)
	return nil
}

func TestRecipientWithdrawalIsScopedAuthorizedAndAtomic(t *testing.T) {
	s, _, r := testRAM(t)
	owner := rootContext(r.AccountID)
	share := createShared(t, s, r, "")
	accept(t, s)
	arn := share.ResourceShare.ResourceShareArn
	recipient := ramUserContext("222222222222")
	input := &api.DisassociateResourceShareRequest{ResourceShareArn: arn, Principals: api.PrincipalArnOrIdList{"222222222222"}, ClientToken: new(api.String("recipient-leave"))}
	allow := ramPolicy(t, "Allow", "*", []string{"*"}, nil)
	s.authorizer = authorization.New(ramIdentityPolicies{authorization.PolicySet{Identity: []policy.Policy{allow}}}, nil)
	// The official leave contract excludes SSM parameters; owner revocation is
	// required unless the owner first removes the unsupported resource.
	ramRequireRejected(t, s, recipient, "DisassociateResourceShare", input, "OperationNotPermittedException")
	invoke[api.DisassociateResourceShareResponse](t, s, owner, "DisassociateResourceShare", &api.DisassociateResourceShareRequest{ResourceShareArn: arn, ResourceArns: api.ResourceArnList{api.String(r.ARN)}})
	invoke[api.AssociateResourceShareResponse](t, s, owner, "AssociateResourceShare", &api.AssociateResourceShareRequest{ResourceShareArn: arn, Principals: api.PrincipalArnOrIdList{"333333333333"}})
	for _, principals := range []api.PrincipalArnOrIdList{nil, {"333333333333"}, {"222222222222", "333333333333"}, {"arn:aws:iam::222222222222:role/auditor"}} {
		wrong := *input
		wrong.Principals = principals
		ramRequireRejected(t, s, recipient, "DisassociateResourceShare", &wrong, "OperationNotPermittedException")
	}
	resourceMutation := *input
	resourceMutation.ResourceArns = api.ResourceArnList{api.String(r.ARN)}
	ramRequireRejected(t, s, recipient, "DisassociateResourceShare", &resourceMutation, "OperationNotPermittedException")
	ramRequireRejected(t, s, ramUserContext("444444444444"), "DisassociateResourceShare", &api.DisassociateResourceShareRequest{ResourceShareArn: arn, Principals: api.PrincipalArnOrIdList{"444444444444"}}, "UnknownResourceException")
	for _, ceiling := range []string{"identity", "explicit", "tag", "boundary", "session", "scp", "resource"} {
		set := authorization.PolicySet{Identity: []policy.Policy{allow}}
		var controls authorization.ControlSource
		current := recipient
		switch ceiling {
		case "identity":
			set.Identity = nil
		case "explicit":
			set.Identity = append(set.Identity, ramPolicy(t, "Deny", "DisassociateResourceShare", []string{value(arn)}, nil))
		case "tag":
			ramTag(t, s, r.AccountID, arn, "blocked")
			set.Identity = append(set.Identity, ramPolicy(t, "Deny", "DisassociateResourceShare", []string{"*"}, map[string]any{"StringEquals": map[string]string{"aws:ResourceTag/access": "blocked"}}))
		case "boundary":
			set.HasBoundary = true
		case "session":
			set.ManagedSession = []policy.Policy{ramPolicy(t, "Deny", "DisassociateResourceShare", []string{"*"}, nil)}
			m := awsctx.FromContext(recipient)
			m.PrincipalARN = "arn:aws:sts::222222222222:assumed-role/auditor/session"
			m.PrincipalID = "AROARAMAUDITOR:session"
			m.IssuerARN = "arn:aws:iam::222222222222:role/auditor"
			m.IssuerID = "AROARAMAUDITOR"
			m.UserName = ""
			m.SessionType = "AssumeRole"
			m.HasSessionPolicy = true
			current = awsctx.WithMetadata(recipient, m)
		case "scp":
			controls = ramControlPolicies{{Documents: []policy.Policy{ramPolicy(t, "Deny", "DisassociateResourceShare", []string{"*"}, nil)}}}
		}
		s.authorizer = authorization.New(ramIdentityPolicies{set}, controls)
		if ceiling == "resource" {
			s.authorizer = ramResourceDenyAuthorizer{Authorizer: s.authorizer, policy: authorization.BoundPolicy{Document: `{"Statement":{"Effect":"Deny","Principal":"*","Action":"ram:DisassociateResourceShare","Resource":"` + value(arn) + `"}}`}}
		}
		ramRequireRejected(t, s, current, "DisassociateResourceShare", input, "AccessDeniedException")
	}
	s.authorizer = authorization.New(ramIdentityPolicies{authorization.PolicySet{Identity: []policy.Policy{allow}}}, nil)
	audit := &ramReadAudit{failWithdrawal: true}
	s.recorder = audit
	ramRequireRejected(t, s, recipient, "DisassociateResourceShare", input, "ServerInternalException")
	read := &api.GetResourceSharesRequest{ResourceOwner: new(api.ResourceOwnerOTHER_ACCOUNTS), ResourceShareArns: api.ResourceShareArnList{*arn}}
	before := invoke[api.GetResourceSharesResponse](t, s, recipient, "GetResourceShares", read)
	if len(before.ResourceShares) != 1 {
		t.Fatal("failed event consumed withdrawal or accepted invitation")
	}
	left := invoke[api.DisassociateResourceShareResponse](t, s, recipient, "DisassociateResourceShare", input)
	if len(left.ResourceShareAssociations) != 1 || value(left.ResourceShareAssociations[0].Status) != "DISASSOCIATED" {
		t.Fatalf("recipient withdrawal: %#v", left)
	}
	invoke[api.DisassociateResourceShareResponse](t, s, recipient, "DisassociateResourceShare", input)
	after := invoke[api.GetResourceSharesResponse](t, s, recipient, "GetResourceShares", read)
	if len(after.ResourceShares) != 0 {
		t.Fatal("withdrawn recipient still sees share")
	}
	invitations := invoke[api.GetResourceShareInvitationsResponse](t, s, rootContext("222222222222"), "GetResourceShareInvitations", &api.GetResourceShareInvitationsRequest{ResourceShareArns: api.ResourceShareArnList{*arn}})
	if len(invitations.ResourceShareInvitations) != 1 || value(invitations.ResourceShareInvitations[0].Status) != "REJECTED" {
		t.Fatalf("withdrawal retained accepted invitation: %#v", invitations)
	}
	associations := invoke[api.GetResourceShareAssociationsResponse](t, s, owner, "GetResourceShareAssociations", &api.GetResourceShareAssociationsRequest{AssociationType: new(api.ResourceShareAssociationTypePRINCIPAL), ResourceShareArns: api.ResourceShareArnList{*arn}, Principal: new(api.String("333333333333"))})
	if len(associations.ResourceShareAssociations) != 1 || value(associations.ResourceShareAssociations[0].Status) != "ASSOCIATING" {
		t.Fatalf("withdrawal changed another principal: %#v", associations)
	}
	deny := ramPolicy(t, "Deny", "DisassociateResourceShare", []string{value(arn)}, nil)
	s.authorizer = authorization.New(ramIdentityPolicies{authorization.PolicySet{Identity: []policy.Policy{allow, deny}}}, nil)
	ramRequireRejected(t, s, recipient, "DisassociateResourceShare", input, "AccessDeniedException")
	var successfulReads, successfulWrites, failedWrites int
	for _, call := range audit.calls {
		switch call.EventName {
		case "GetResourceShares":
			if !call.ReadOnly || call.Category != journal.CategoryManagement || call.ErrorCode != "" {
				t.Fatalf("share read event classification: %#v", call)
			}
			successfulReads++
		case "DisassociateResourceShare":
			if call.ReadOnly || call.Category != journal.CategoryManagement {
				t.Fatalf("withdrawal event classification: %#v", call)
			}
			if call.ErrorCode == "" {
				successfulWrites++
			} else {
				failedWrites++
			}
		}
	}
	if successfulReads != 2 || successfulWrites != 2 || failedWrites != 2 {
		t.Fatalf("retained events: reads=%d writes=%d failures=%d", successfulReads, successfulWrites, failedWrites)
	}
}

func TestRecipientCannotWithdrawOrganizationOrIAMPrincipalShare(t *testing.T) {
	for _, kind := range []string{"organization", "organization-now-enabled", "iam-principal"} {
		t.Run(kind, func(t *testing.T) {
			s, _, r := testRAM(t)
			org := &organizationMembership{enabled: true}
			if kind == "organization" {
				s.organization = org
			}
			share := createShared(t, s, r, "")
			if kind != "organization" {
				accept(t, s)
			}
			invoke[api.DisassociateResourceShareResponse](t, s, rootContext(r.AccountID), "DisassociateResourceShare", &api.DisassociateResourceShareRequest{ResourceShareArn: share.ResourceShare.ResourceShareArn, ResourceArns: api.ResourceArnList{api.String(r.ARN)}})
			if kind == "organization-now-enabled" {
				s.organization = org
			}
			if kind == "iam-principal" {
				if err := s.repository.Attempt(rootContext(r.AccountID), func(tx Transaction) error {
					current, err := tx.Share(value(share.ResourceShare.ResourceShareArn))
					if err != nil {
						return err
					}
					current.Principals[0].Principal = "arn:aws:iam::222222222222:user/auditor"
					current.Principals[0].PrincipalID = "AIDARAMAUDITOR"
					return tx.PutShare(current)
				}); err != nil {
					t.Fatal(err)
				}
			}
			s.authorizer = authorization.New(ramIdentityPolicies{authorization.PolicySet{Identity: []policy.Policy{ramPolicy(t, "Allow", "*", []string{"*"}, nil)}}}, nil)
			code := "OperationNotPermittedException"
			ramRequireRejected(t, s, ramUserContext("222222222222"), "DisassociateResourceShare", &api.DisassociateResourceShareRequest{ResourceShareArn: share.ResourceShare.ResourceShareArn, Principals: api.PrincipalArnOrIdList{"222222222222"}}, code)
		})
	}
}

func TestRecipientCanWithdrawSupportedLiveResourceWithoutOwnerAuthority(t *testing.T) {
	s, _, r := testRAM(t)
	r.ARN = "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-shared"
	r.ResourceType = "ec2:Subnet"
	s.resources = resourceOwner{r.ARN: r}
	s.resourceTypes = []string{r.ResourceType}
	share := createShared(t, s, r, "")
	accept(t, s)
	arn := share.ResourceShare.ResourceShareArn
	ctx := ramUserContext("222222222222")
	allow := ramPolicy(t, "Allow", "DisassociateResourceShare", []string{value(arn)}, map[string]any{"StringEquals": map[string]string{"ram:Principal": "222222222222"}})
	s.authorizer = authorization.New(ramIdentityPolicies{authorization.PolicySet{Identity: []policy.Policy{allow}}}, nil)
	invoke[api.DisassociateResourceShareResponse](t, s, ctx, "DisassociateResourceShare", &api.DisassociateResourceShareRequest{ResourceShareArn: arn, Principals: api.PrincipalArnOrIdList{"222222222222"}})
	resources := invoke[api.GetResourceShareAssociationsResponse](t, s, rootContext(r.AccountID), "GetResourceShareAssociations", &api.GetResourceShareAssociationsRequest{AssociationType: new(api.ResourceShareAssociationTypeRESOURCE), ResourceShareArns: api.ResourceShareArnList{*arn}})
	if len(resources.ResourceShareAssociations) != 1 || value(resources.ResourceShareAssociations[0].Status) != "ASSOCIATED" {
		t.Fatalf("recipient withdrawal changed owner resource: %#v", resources)
	}
}
