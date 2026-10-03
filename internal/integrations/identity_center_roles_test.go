package integrations

import (
	"context"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	"stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
	"stackd/internal/services/identitycenter"
	orgservice "stackd/internal/services/organizations"
	"stackd/storage/memory"
	"stackd/storage/organizations"
)

type identityCenterOrganizationControls struct{ *orgservice.Service }

func (c identityCenterOrganizationControls) ServiceControlPolicies(ctx context.Context) ([]policy.PolicyLevel, error) {
	return c.Service.ServiceControlPolicies(ctx, awsctx.FromContext(ctx).AccountID)
}

func TestIdentityCenterIssuedCredentialsUseCurrentAuthority(t *testing.T) {
	domain := memory.NewDomain()
	repository := iam.NewMemoryRepository(domain)
	orgs := organizations.NewMemory(domain)
	now := clock.NewManual(time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC))
	store := identity.NewWithConfig(identity.Config{AccountID: "111111111111", Repository: iam.NewCredentialRepository(repository, nil), Clock: now})
	iamService := iam.NewWithConfig(iam.Config{Repository: repository, Credentials: store, Clock: now})
	controls := identityCenterOrganizationControls{orgservice.NewWithConfig(orgservice.Config{Storage: orgs, Clock: now})}
	authorizer := authorization.NewWithClock(iamService, controls, now)
	adapter := IdentityCenterRoles{IAM: iamService, Sessions: ServiceRoles{IAM: iamService, Credentials: store, Authorizer: authorizer}}
	scope := iam.Scope{Partition: "aws", AccountID: "222222222222"}
	instance := identitycenter.Instance{Scope: identitycenter.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, ARN: "arn:aws:sso:::instance/ssoins-0123456789abcdef"}
	const send = `{"Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}}`
	const receive = `{"Statement":{"Effect":"Allow","Action":"sqs:ReceiveMessage","Resource":"*"}}`
	permissionSet := identitycenter.PermissionSet{InstanceARN: instance.ARN, ARN: "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/ps-0123456789abcdef", Name: "QueuePublisher", Duration: 2 * time.Hour, InlinePolicy: send}
	spec := identitycenter.RoleSpec{Instance: instance, PermissionSet: permissionSet, AccountID: scope.AccountID}
	provisioning, err := adapter.Provision(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	pending := spec.PermissionSet
	pending.Duration = 5 * time.Hour
	issued, err := adapter.Credentials(t.Context(), instance, pending, provisioning, "alice")
	if err != nil {
		t.Fatal(err)
	}
	retained, err := store.Resolve(t.Context(), issued.AccessKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if retained.IssuerID != provisioning.RoleID || retained.IssuerARN != provisioning.RoleARN || retained.AccountID != scope.AccountID || retained.PrincipalARN != "arn:aws:sts::222222222222:assumed-role/"+provisioning.RoleName+"/alice" || retained.SessionToken == "" || retained.Expiration.Sub(retained.CreateDate) != 2*time.Hour || len(retained.SessionPolicies) != 0 || len(retained.SessionPolicyARNs) != 0 {
		t.Fatalf("issued credentials lost role authority or copied permissions: %+v", retained.PrincipalARN)
	}
	metadata, err := identity.RequestMetadata(retained, retained.AccessKeyID, instance.Region, "identity-center-request")
	if err != nil {
		t.Fatal(err)
	}
	requestCtx := awsctx.WithMetadata(t.Context(), metadata)
	assertPermission := func(action string, allowed bool) {
		t.Helper()
		err := authorizer.Authorize(requestCtx, authorization.Request{Action: action, ResourceARN: "arn:aws:sqs:us-east-1:222222222222:out"})
		if (err == nil) != allowed {
			t.Fatalf("%s allowed=%t, want=%t: %v", action, err == nil, allowed, err)
		}
	}
	assertPermission("sqs:SendMessage", true)
	spec.PermissionSet.InlinePolicy = receive
	spec.PermissionSet.Duration = 4 * time.Hour
	if _, err := adapter.Provision(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	assertPermission("sqs:SendMessage", false)
	assertPermission("sqs:ReceiveMessage", true)
	resized, err := adapter.Credentials(t.Context(), instance, spec.PermissionSet, provisioning, "alice")
	if err != nil || resized.Expiration.Sub(resized.CreateDate) != 4*time.Hour {
		t.Fatalf("new credentials did not use provisioned IAM session duration: %v", err)
	}
	customerARN, boundaryARN := "arn:aws:iam::222222222222:policy/access/Queue", "arn:aws:iam::222222222222:policy/access/Boundary"
	setPolicy := func(arn, name, document string) {
		t.Helper()
		if err := repository.Update(t.Context(), func(tx iam.WriteTx) error {
			p, err := tx.ManagedPolicy(scope, arn)
			if err != nil && err != iam.ErrRecordNotFound {
				return err
			}
			p.Arn, p.PolicyName, p.Path, p.IsAttachable = arn, name, "/access/", true
			p.DefaultVersionId, p.Versions = "v1", map[string]*iam.PolicyVersion{"v1": {Document: document}}
			return tx.PutManagedPolicy(scope, p)
		}); err != nil {
			t.Fatal(err)
		}
	}
	setPolicy(customerARN, "Queue", send)
	setPolicy(boundaryARN, "Boundary", receive)
	spec.PermissionSet.InlinePolicy = ""
	spec.PermissionSet.CustomerManagedPolicies = []identitycenter.PolicyReference{{Name: "Queue", Path: "/access/"}}
	if _, err := adapter.Provision(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	assertPermission("sqs:SendMessage", true)
	setPolicy(customerARN, "Queue", receive)
	assertPermission("sqs:SendMessage", false)
	assertPermission("sqs:ReceiveMessage", true)
	setPolicy(customerARN, "Queue", send)
	spec.PermissionSet.Boundary = identitycenter.PolicyReference{Name: "Boundary", Path: "/access/"}
	if _, err := adapter.Provision(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	assertPermission("sqs:SendMessage", false)
	spec.PermissionSet.Boundary = identitycenter.PolicyReference{}
	if _, err := adapter.Provision(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	assertPermission("sqs:SendMessage", true)
	// Current Organizations controls apply to ordinary issued role credentials;
	// Identity Center roles are not service-linked-role exemptions.
	const full = `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	const fullRCP = `{"Statement":{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}}`
	state := organizations.PartitionRecord{Organizations: []organizations.OrganizationRecord{{
		Organization: organizations.OrganizationDetails{ID: "o-example", MasterAccountID: instance.AccountID, FeatureSet: "ALL"},
		Root:         organizations.RootRecord{ID: "r-root", PolicyTypes: []organizations.PolicyTypeRecord{{Type: "SERVICE_CONTROL_POLICY", Status: "ENABLED"}, {Type: "RESOURCE_CONTROL_POLICY", Status: "ENABLED"}}},
		Accounts:     []organizations.AccountRecord{{ID: instance.AccountID, State: "ACTIVE"}, {ID: scope.AccountID, State: "ACTIVE"}},
		Parents:      []organizations.ParentRecord{{ChildID: scope.AccountID, ParentID: "r-root"}},
		Policies: []organizations.PolicyRecord{
			{PolicySummary: organizations.PolicySummaryRecord{ID: "p-full", Type: "SERVICE_CONTROL_POLICY"}, Content: full},
			{PolicySummary: organizations.PolicySummaryRecord{ID: "p-rcp-full", Type: "RESOURCE_CONTROL_POLICY"}, Content: fullRCP},
			{PolicySummary: organizations.PolicySummaryRecord{ID: "p-deny", Type: "SERVICE_CONTROL_POLICY"}, Content: `{"Statement":{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}}`},
		},
		Attachments: []organizations.PolicyAttachment{{TargetID: "r-root", PolicyID: "p-full"}, {TargetID: scope.AccountID, PolicyID: "p-full"}, {TargetID: "r-root", PolicyID: "p-rcp-full"}, {TargetID: scope.AccountID, PolicyID: "p-rcp-full"}, {TargetID: scope.AccountID, PolicyID: "p-deny"}},
	}}}
	saveControls := func() {
		t.Helper()
		_, revision, err := orgs.Load(t.Context(), "aws")
		if err != nil {
			t.Fatal(err)
		}
		ok, err := orgs.CompareAndSwap(t.Context(), "aws", revision, state, nil)
		if err != nil || !ok {
			t.Fatalf("save Organizations controls: %t %v", ok, err)
		}
	}
	saveControls()
	assertPermission("sqs:SendMessage", false)
	state.Organizations[0].Policies[2].PolicySummary.Type = "RESOURCE_CONTROL_POLICY"
	state.Organizations[0].Policies[2].Content = `{"Statement":{"Effect":"Deny","Principal":"*","Action":"sqs:SendMessage","Resource":"*"}}`
	saveControls()
	assertPermission("sqs:SendMessage", false)
	state.Organizations[0].Attachments = state.Organizations[0].Attachments[:4]
	saveControls()
	assertPermission("sqs:SendMessage", true)
	if _, rejected := adapter.Sessions.assume(awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws"}), awsctx.ServicePrincipal{Name: "sso.amazonaws.com", SourceARN: instance.ARN + "-other", Type: "AWSService"}, provisioning.RoleARN, identity.RoleSessionSpec{Role: identity.Principal{ID: provisioning.RoleID}, SessionName: "alice", Duration: time.Hour}, ""); rejected == nil {
		t.Fatal("role trust admitted another Identity Center instance")
	}
	if err := repository.Update(t.Context(), func(tx iam.WriteTx) error {
		role, err := tx.Role(scope, provisioning.RoleName)
		if err != nil {
			return err
		}
		role.AssumeRolePolicyDocument = `{"Statement":{"Effect":"Deny","Principal":{"Service":"sso.amazonaws.com"},"Action":"sts:AssumeRole"}}`
		return tx.PutRole(scope, role)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Credentials(t.Context(), instance, spec.PermissionSet, provisioning, "alice"); err == nil {
		t.Fatal("revoked current role trust issued credentials")
	}
	assertPermission("sqs:SendMessage", true)
	if err := adapter.Remove(t.Context(), provisioning); err != nil {
		t.Fatal(err)
	}
	replacement, err := adapter.Provision(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	assertPermission("sqs:SendMessage", false)
	if _, err := adapter.Credentials(t.Context(), instance, spec.PermissionSet, provisioning, "alice"); err == nil {
		t.Fatal("deleted provisioning acquired the replacement role")
	}
	renewed, err := adapter.Credentials(t.Context(), instance, spec.PermissionSet, replacement, "alice")
	if err != nil || renewed.IssuerID == retained.IssuerID || !strings.Contains(renewed.PrincipalARN, replacement.RoleName) {
		t.Fatalf("replacement session did not follow current incarnation: %v", err)
	}
}
