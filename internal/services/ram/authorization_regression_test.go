package ram

import (
	"context"
	"encoding/json"
	"testing"

	"stackd/iam/policy"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ram"
	"stackd/internal/awsctx"
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
