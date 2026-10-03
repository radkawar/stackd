package authorization_test

import (
	"context"
	"fmt"
	"testing"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	ramapi "stackd/internal/awsapi/ram"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/services/ram"
)

func TestAWSManagedPolicyNamespaceRequiresIdentityPermissions(t *testing.T) {
	const document = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:GetPolicy","Resource":"arn:aws:iam::aws:policy/ReadOnlyAccess"}}`
	const denied = `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"iam:GetPolicy","Resource":"*"}}`
	for _, tc := range []struct {
		name             string
		root             bool
		set              authorization.PolicySet
		controls         controlSource
		session          bool
		resource, action string
		allowed          bool
	}{
		{name: "root", root: true, allowed: true},
		{name: "implicit deny"},
		{name: "exact identity grant", set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: document}}}, allowed: true},
		{name: "identity explicit deny", set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: document}, {Document: denied}}}},
		{name: "boundary implicit deny", set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: document}}, HasBoundary: true, Boundary: []iampolicy.Policy{{Document: other}}}},
		{name: "session restriction", set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: document}}}, session: true},
		{name: "SCP restriction", root: true, controls: controlSource{{Documents: []iampolicy.Policy{{Document: denied}}}}},
		{name: "customer remains cross-account", root: true, resource: "arn:aws:iam::999999999999:policy/ReadOnlyAccess"},
		{name: "different partition", root: true, resource: "arn:aws-cn:iam::aws:policy/ReadOnlyAccess"},
		{name: "different action service", root: true, action: "sqs:SendMessage"},
		{name: "AWS template root", root: true, resource: "arn:aws:iam::aws:role-template/iam.amazonaws.com/PowerUserRoleTemplate:1", action: "iam:GetRoleTemplateVersion", allowed: true},
		{name: "AWS template requires permission", resource: "arn:aws:iam::aws:role-template/iam.amazonaws.com/PowerUserRoleTemplate:1", action: "iam:GetRoleTemplateVersion"},
		{name: "customer template remains cross-account", root: true, resource: "arn:aws:iam::999999999999:role-template/iam.amazonaws.com/PowerUserRoleTemplate:1", action: "iam:GetRoleTemplateVersion"},
		{name: "template exemption only applies to read", root: true, resource: "arn:aws:iam::aws:role-template/iam.amazonaws.com/PowerUserRoleTemplate:1", action: "iam:CreateRole"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resource, action := tc.resource, tc.action
			if resource == "" {
				resource = "arn:aws:iam::aws:policy/ReadOnlyAccess"
			}
			if action == "" {
				action = "iam:GetPolicy"
			}
			m := metadata(tc.root)
			m.HasSessionPolicy = tc.session
			evaluator := authorization.New(identitySource{set: tc.set}, tc.controls)
			err := evaluator.Authorize(awsctx.WithMetadata(context.Background(), m), authorization.Request{Action: action, ResourceARN: resource})
			if (err == nil) != tc.allowed {
				t.Fatalf("authorization error = %v; allowed = %v", err, tc.allowed)
			}
		})
	}
}

func TestResolvedResourceOwnerCannotOverrideARNOrVerifiedContext(t *testing.T) {
	const policy = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:GetPolicy","Resource":"*","Condition":{"StringEquals":{"aws:ResourceAccount":"639982225848"}}}}`
	ctx := awsctx.WithMetadata(context.Background(), metadata(false))
	evaluator := authorization.New(identitySource{set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: policy}}}}, nil)
	request := authorization.Request{Action: "iam:GetPolicy", ResourceARN: "arn:aws:iam::aws:policy/ReadOnlyAccess", ResourceAccountID: "639982225848"}
	if err := evaluator.Authorize(ctx, request); err != nil {
		t.Fatal(err)
	}
	request.Context = map[string][]string{"aws:ResourceAccount": {account}}
	if err := evaluator.Authorize(ctx, request); err == nil {
		t.Fatal("service context replaced the resolved resource owner")
	}
	request.Context = nil
	request.ResourceAccountID = "aws"
	if err := evaluator.Authorize(ctx, request); err == nil {
		t.Fatal("alias accepted as numeric resource account")
	}
	request.ResourceAccountID = "639982225848"
	request.ResourceARN = "arn:aws:iam::" + account + ":policy/local"
	if err := evaluator.Authorize(ctx, request); err == nil {
		t.Fatal("resolved owner contradicted account encoded in ARN")
	}
}

func TestAWSManagedRAMPermissionAssociationRetainsCallerCeilings(t *testing.T) {
	const permission = "arn:aws:ram::aws:permission/AWSRAMPermissionSSMParameterReadOnlyWithHistory"
	const action = "ram:AssociateResourceSharePermission"
	allow := func(resource string) iampolicy.Policy {
		return iampolicy.Policy{Document: fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":%q,"Resource":%q}}`, action, resource)}
	}
	deny := iampolicy.Policy{Document: fmt.Sprintf(`{"Statement":{"Effect":"Deny","Action":%q,"Resource":%q}}`, action, permission)}
	for _, tc := range []struct {
		name                                                                                     string
		root, identity, shareOnly, permissionOnly, explicitDeny, boundary, session, scp, allowed bool
	}{
		{name: "owner root", root: true, allowed: true},
		{name: "implicit identity denial"},
		{name: "share permission alone", shareOnly: true},
		{name: "managed permission alone", permissionOnly: true},
		{name: "both authorized resources", identity: true, allowed: true},
		{name: "managed permission explicit denial", identity: true, explicitDeny: true},
		{name: "boundary restriction", identity: true, boundary: true},
		{name: "session restriction", identity: true, session: true},
		{name: "SCP restriction", root: true, scp: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repository := ram.NewMemoryRepository(nil)
			root := ram.New(ram.Config{Repository: repository, ResourceTypes: []string{"ssm:Parameter"}})
			model, _ := awscatalog.LookupService("ram")
			create, _ := model.Operation("CreateResourceShare")
			created, rejected := root.ExecuteCommand(awsctx.WithMetadata(t.Context(), metadata(true)), awsapi.DecodedRequest{Operation: create, Input: &ramapi.CreateResourceShareRequest{Name: new(ramapi.String("managed-permission"))}})
			if rejected != nil {
				t.Fatal(rejected)
			}
			share := created.(*ramapi.CreateResourceShareResponse).ResourceShare.ResourceShareArn
			set := authorization.PolicySet{HasBoundary: tc.boundary}
			if tc.identity {
				set.Identity = []iampolicy.Policy{allow(string(*share)), allow(permission)}
			}
			if tc.shareOnly {
				set.Identity = []iampolicy.Policy{allow(string(*share))}
			}
			if tc.permissionOnly {
				set.Identity = []iampolicy.Policy{allow(permission)}
			}
			if tc.explicitDeny {
				set.Identity = append(set.Identity, deny)
			}
			var controls controlSource
			if tc.scp {
				controls = controlSource{{Documents: []iampolicy.Policy{deny}}}
			}
			service := ram.New(ram.Config{Repository: repository, ResourceTypes: []string{"ssm:Parameter"}, Authorizer: authorization.New(identitySource{set: set}, controls)})
			m := metadata(tc.root)
			m.HasSessionPolicy = tc.session
			op, _ := model.Operation("AssociateResourceSharePermission")
			_, rejected = service.ExecuteCommand(awsctx.WithMetadata(t.Context(), m), awsapi.DecodedRequest{Operation: op, Input: &ramapi.AssociateResourceSharePermissionRequest{ResourceShareArn: share, PermissionArn: new(ramapi.String(permission)), Replace: new(ramapi.Boolean(true))}})
			if tc.allowed {
				if rejected != nil {
					t.Fatal(rejected)
				}
			} else if rejected == nil || rejected.Code != "AccessDeniedException" {
				t.Fatalf("expected caller authority denial, got %v", rejected)
			}
			var associated bool
			if err := repository.View(t.Context(), func(reader ram.Reader) error {
				record, err := reader.Share(string(*share))
				for _, current := range record.Permissions {
					associated = associated || current.ARN == permission
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if associated != tc.allowed {
				t.Fatalf("permission mutation committed=%v, allowed=%v", associated, tc.allowed)
			}
		})
	}
}
