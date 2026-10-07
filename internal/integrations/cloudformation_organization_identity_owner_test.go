package integrations

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"stackd/clock"
	"stackd/internal/authorization"
	iamapi "stackd/internal/awsapi/iam"
	orgapi "stackd/internal/awsapi/organizations"
	ssoapi "stackd/internal/awsapi/ssoadmin"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	iamservice "stackd/internal/services/iam"
	"stackd/internal/services/identitycenter"
	"stackd/internal/services/identitystore"
	orgservice "stackd/internal/services/organizations"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqlidentity "stackd/storage/sqlite/iam"
	sqlcenter "stackd/storage/sqlite/identitycenter"
	sqldirectory "stackd/storage/sqlite/identitystore"
	sqlorg "stackd/storage/sqlite/organizations"
)

// The fixture runs the real Organizations, Identity Center and Identity Store
// owners over memory or SQLite; restart rebuilds them from persisted state only.
type cfnOrgSSOOwnerFixture struct {
	ctx       context.Context
	path      string
	db        *sql.DB
	source    clock.Clock
	orgs      orgservice.Storage
	center    identitycenter.Repository
	identity  iamservice.Repository
	iam       *iamservice.Service
	org       *orgservice.Service
	directory identitystore.Repository
	commands  StepFunctionsCommands
}

func newCFNOrgSSOOwnerFixture(t *testing.T, backend string) *cfnOrgSSOOwnerFixture {
	t.Helper()
	f := &cfnOrgSSOOwnerFixture{ctx: cfnWorkflowOwnerContext(t)}
	if backend == "sqlite" {
		f.path = filepath.Join(t.TempDir(), "organization-identity.sqlite")
		f.open(t)
	} else {
		domain := memory.NewDomain()
		f.orgs, f.center, f.directory = orgservice.NewMemoryStorage(domain), identitycenter.NewMemoryRepository(domain), identitystore.NewMemoryRepository(domain)
		f.identity = iamservice.NewMemoryRepository(domain)
	}
	f.start(t)
	t.Cleanup(func() {
		_ = f.iam.Close()
		_ = f.org.Close()
		if f.db != nil {
			_ = f.db.Close()
		}
	})
	return f
}

func (f *cfnOrgSSOOwnerFixture) open(t *testing.T) {
	t.Helper()
	db, err := sqlite.Open(f.ctx, f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.db, f.orgs, f.center, f.directory = db, sqlorg.New(db), sqlcenter.New(db), sqldirectory.New(db)
	f.identity = sqlidentity.New(db)
}

// Account initialization delegates to IAM's native joined transaction. These
// fixtures create management organizations only, so no member contact is copied.
type cfnOrgSSOAccountProvisioner struct{ identity *iamservice.Service }

func (p cfnOrgSSOAccountProvisioner) WithAccountProvisioning(ctx context.Context, in orgservice.AccountProvisioning, commit func(context.Context) error) error {
	return p.identity.WithAccountRoles(ctx, in, commit)
}

type cfnOrgSSORoleUsage struct {
	organization *orgservice.Service
	repository   iamservice.Repository
}

func (u cfnOrgSSORoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref iamservice.ServiceLinkedRoleReference, fn func(context.Context, []iamservice.ServiceLinkedRoleUsage) error) error {
	return u.repository.Update(ctx, func(tx iamservice.WriteTx) error {
		ctx = tx.Context()
		arn, err := u.organization.ServiceRoleDependency(ctx, ref.Scope.Partition, ref.Scope.AccountID)
		if err != nil {
			return err
		}
		var usage []iamservice.ServiceLinkedRoleUsage
		if arn != "" {
			usage = []iamservice.ServiceLinkedRoleUsage{{Region: "us-east-1", ResourceARNs: []string{arn}}}
		}
		return fn(ctx, usage)
	})
}

func (f *cfnOrgSSOOwnerFixture) start(t *testing.T) {
	t.Helper()
	directory := identitystore.NewWithConfig(identitystore.Config{Repository: f.directory})
	center := identitycenter.New(identitycenter.Config{Repository: f.center, Directory: directory})
	f.org = orgservice.NewWithConfig(orgservice.Config{Storage: f.orgs, Clock: f.source})
	f.iam = iamservice.NewWithConfig(iamservice.Config{Repository: f.identity})
	f.org.SetRoleInspector(f.iam)
	f.iam.SetAccountIdentitySource(f.org)
	if err := f.iam.RegisterServiceLinkedRole(iamservice.ServiceLinkedRoleTemplate{
		Partition: "aws", ServiceName: orgservice.ServicePrincipal, RoleName: orgservice.ServiceLinkedRoleName,
		TrustPolicy:        `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"organizations.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
		DefaultDescription: "Service-linked role used by AWS Organizations to enable integration of other AWS services with Organizations.",
		ManagedPolicyARNs:  []string{"arn:aws:iam::aws:policy/aws-service-role/AWSOrganizationsServiceTrustPolicy"},
		Sources:            []string{"https://docs.aws.amazon.com/organizations/latest/userguide/orgs_integrate_services.html#orgs_integrate_services-using_slrs", "testdata/aws/iam/organizations_roles.json"},
	}, cfnOrgSSORoleUsage{f.org, f.identity}); err != nil {
		t.Fatal(err)
	}
	authorizer := authorization.New(f.iam, identityCenterOrganizationControls{f.org})
	f.iam.SetAuthorizer(authorizer)
	f.org.SetAuthorizer(authorizer)
	f.org.SetAccountProvisioner(cfnOrgSSOAccountProvisioner{f.iam})
	f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{
		"iam":           f.iam,
		"organizations": f.org,
		"ssoadmin":      center.Frontend("ssoadmin"),
	})
}

func (f *cfnOrgSSOOwnerFixture) restart(t *testing.T) {
	t.Helper()
	if err := f.iam.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.org.Close(); err != nil {
		t.Fatal(err)
	}
	if f.db != nil {
		if err := f.db.Close(); err != nil {
			t.Fatal(err)
		}
		f.open(t)
	}
	f.start(t)
}

func (f *cfnOrgSSOOwnerFixture) run(t *testing.T, service, operation string, input map[string]any) {
	t.Helper()
	if err := cfnComputeRun(f.ctx, f.commands, service, operation, input); err != nil {
		t.Fatalf("%s %s: %v", service, operation, err)
	}
}

// cfnOrgSSOCounterfeit is the formerly authoritative public marker set for r,
// which any caller permitted to tag can attach to an unrelated resource.
func cfnOrgSSOCounterfeit(r cloudformation.ResourceRequest) []map[string]string {
	return cfnComputeTagList(map[string]string{cfnComputeTagPrefix + "stack-id": r.StackID, cfnComputeTagPrefix + "logical-id": r.LogicalID, cfnComputeTagPrefix + "incarnation": r.Token})
}

func cfnOrgSSONotAdmitted(t *testing.T, label string, result cloudformation.ResourceResult, err error) {
	t.Helper()
	if !cfnComputeMissing(err) || result.PhysicalID != "" {
		t.Fatalf("%s: recovery did not certify nonadmission: %+v %v", label, result, err)
	}
}

func cfnOrgSSOSame(t *testing.T, label, want string, result cloudformation.ResourceResult, err error) {
	t.Helper()
	if err != nil || result.PhysicalID != want {
		t.Fatalf("%s: want %s, got %+v %v", label, want, result, err)
	}
}

func cfnOrgSSONoPublicClaim(t *testing.T, label string, tags map[string]string) {
	t.Helper()
	for key := range tags {
		if strings.HasPrefix(strings.ToLower(key), cfnComputeTagPrefix) {
			t.Fatalf("%s published an ownership marker %s", label, key)
		}
	}
}

func cfnOrgSSOOther(r cloudformation.ResourceRequest) cloudformation.ResourceRequest {
	r.Token = "other-incarnation"
	return r
}

func TestCFNOrganizationsUnitPrivateClaimRejectsCounterfeitAndForeignRecreation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNOrgSSOOwnerFixture(t, backend)
			f.run(t, "organizations", "CreateOrganization", map[string]any{"FeatureSet": "ALL"})
			root, err := cfnOrganizationsRoot(f.ctx, f.commands)
			if err != nil {
				t.Fatal(err)
			}
			native := func(name string, tags []map[string]string) string {
				t.Helper()
				out, err := cfnOrgIdentityCall[orgapi.CreateOrganizationalUnitOutput](f.ctx, f.commands, "organizations", "CreateOrganizationalUnit", map[string]any{"Name": name, "ParentId": root, "Tags": append([]map[string]string{}, tags...)})
				if err != nil {
					t.Fatal(err)
				}
				return cfnComputeValue(out.OrganizationalUnit.Id)
			}
			unit := cfnOrganizationUnit{f.commands}
			r := cfnWorkflowOwnerRequest("AWS::Organizations::OrganizationalUnit", "Unit", cloudformation.Properties{"Name": "owned", "ParentId": root, "Tags": []any{map[string]any{"Key": "team", "Value": "a"}}})

			// A direct same-name unit carrying every published marker is not r's.
			counterfeit := native("owned", cfnOrgSSOCounterfeit(r))
			result, err := unit.RecoverCreation(f.ctx, r)
			cfnOrgSSONotAdmitted(t, "counterfeit unit", result, err)
			if result, err = unit.Create(f.ctx, r); err == nil || result.PhysicalID != "" {
				t.Fatalf("create adopted a counterfeit unit: %+v %v", result, err)
			}
			stale := r
			stale.PhysicalID = counterfeit
			if _, err = unit.Update(f.ctx, stale); err == nil {
				t.Fatal("marker-matching incarnation renamed a direct unit")
			}
			if err = unit.Delete(f.ctx, stale); err == nil {
				t.Fatal("marker-matching incarnation deleted a direct unit")
			}
			// Cloud Control direct access stays IAM-only and never becomes a claim.
			direct := stale
			direct.CloudControl, direct.Properties = true, cloudformation.Properties{"Name": "direct", "ParentId": root}
			if _, err = unit.Update(f.ctx, direct); err != nil {
				t.Fatalf("direct Cloud Control update was fenced: %v", err)
			}
			if err = unit.Delete(f.ctx, stale); err == nil {
				t.Fatal("direct Cloud Control update transferred the unit to an incarnation")
			}
			if p, err := unit.Read(f.ctx, stale); err != nil || p["Name"] != "direct" {
				t.Fatalf("direct unit was damaged: %#v %v", p, err)
			}
			f.run(t, "organizations", "DeleteOrganizationalUnit", map[string]any{"OrganizationalUnitId": counterfeit})

			created, err := unit.Create(f.ctx, r)
			if err != nil || created.PhysicalID == "" || created.PhysicalID == counterfeit {
				t.Fatalf("create failed or reused a direct unit: %+v %v", created, err)
			}
			r.PhysicalID = created.PhysicalID
			tags, err := cfnOrganizationsTags(f.ctx, f.commands, r.PhysicalID)
			if err != nil || tags["team"] != "a" {
				t.Fatalf("unit tags did not converge: %v %v", tags, err)
			}
			cfnOrgSSONoPublicClaim(t, "unit", tags)

			// A native rename and an owner restart do not hide the committed incarnation.
			f.run(t, "organizations", "UpdateOrganizationalUnit", map[string]any{"OrganizationalUnitId": r.PhysicalID, "Name": "renamed"})
			f.restart(t)
			unit = cfnOrganizationUnit{f.commands}
			replay := r
			replay.PhysicalID = ""
			result, err = unit.RecoverCreation(f.ctx, replay)
			cfnOrgSSOSame(t, "unit recovery", r.PhysicalID, result, err)
			result, err = unit.Create(f.ctx, replay)
			cfnOrgSSOSame(t, "unit replay", r.PhysicalID, result, err)

			// Forged markers for another incarnation transfer nothing.
			other := cfnOrgSSOOther(r)
			f.run(t, "organizations", "TagResource", map[string]any{"ResourceId": r.PhysicalID, "Tags": cfnOrgSSOCounterfeit(other)})
			if _, err = unit.Update(f.ctx, other); err == nil {
				t.Fatal("forged markers let another incarnation update the unit")
			}
			if err = unit.Delete(f.ctx, other); err == nil {
				t.Fatal("forged markers let another incarnation delete the unit")
			}
			r.Previous, r.Properties = r.Properties, cloudformation.Properties{"Name": "updated", "ParentId": root}
			if _, err = unit.Update(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			if p, err := unit.Read(f.ctx, r); err != nil || p["Name"] != "updated" || len(p["Tags"].([]any)) != 0 {
				t.Fatalf("owned update did not converge: %#v %v", p, err)
			}

			if err = unit.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			foreign := native("updated", nil)
			result, err = unit.RecoverCreation(f.ctx, replay)
			cfnOrgSSONotAdmitted(t, "unit foreign recreation", result, err)
			if err = unit.Delete(f.ctx, r); err != nil {
				t.Fatalf("absent incarnation delete failed: %v", err)
			}
			if _, err = unit.Read(f.ctx, cloudformation.ResourceRequest{PhysicalID: foreign}); err != nil {
				t.Fatalf("foreign recreation was damaged: %v", err)
			}
		})
	}
}

func TestCFNOrganizationsPolicyPrivateClaimsRejectCounterfeitAndForeignRecreation(t *testing.T) {
	const content = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	const delegation = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"123456789012"},"Action":"organizations:DescribeOrganization","Resource":"*"}]}`
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNOrgSSOOwnerFixture(t, backend)
			f.run(t, "organizations", "CreateOrganization", map[string]any{"FeatureSet": "ALL"})

			// Service control policies.
			nativePolicy := func(name string, tags []map[string]string) string {
				t.Helper()
				out, err := cfnOrgIdentityCall[orgapi.CreatePolicyOutput](f.ctx, f.commands, "organizations", "CreatePolicy", map[string]any{"Name": name, "Type": "SERVICE_CONTROL_POLICY", "Description": "", "Content": content, "Tags": append([]map[string]string{}, tags...)})
				if err != nil {
					t.Fatal(err)
				}
				return cfnComputeValue(out.Policy.PolicySummary.Id)
			}
			policy := cfnOrganizationPolicy{f.commands}
			r := cfnWorkflowOwnerRequest("AWS::Organizations::Policy", "Guard", cloudformation.Properties{"Name": "guard", "Type": "SERVICE_CONTROL_POLICY", "Content": content})
			counterfeit := nativePolicy("guard", cfnOrgSSOCounterfeit(r))
			result, err := policy.RecoverCreation(f.ctx, r)
			cfnOrgSSONotAdmitted(t, "counterfeit policy", result, err)
			if result, err = policy.Create(f.ctx, r); err == nil || result.PhysicalID != "" {
				t.Fatalf("create adopted a counterfeit policy: %+v %v", result, err)
			}
			stale := r
			stale.PhysicalID = counterfeit
			if err = policy.Delete(f.ctx, stale); err == nil {
				t.Fatal("marker-matching incarnation deleted a direct policy")
			}
			if _, err = policy.Read(f.ctx, stale); err != nil {
				t.Fatalf("direct policy was damaged: %v", err)
			}
			f.run(t, "organizations", "DeletePolicy", map[string]any{"PolicyId": counterfeit})
			created, err := policy.Create(f.ctx, r)
			if err != nil || created.PhysicalID == "" || created.PhysicalID == counterfeit {
				t.Fatalf("policy create failed or reused a direct policy: %+v %v", created, err)
			}
			r.PhysicalID = created.PhysicalID
			tags, err := cfnOrganizationsTags(f.ctx, f.commands, r.PhysicalID)
			if err != nil {
				t.Fatal(err)
			}
			cfnOrgSSONoPublicClaim(t, "policy", tags)

			// Delegation policy singleton.
			nativeDelegation := func(tags []map[string]string) string {
				t.Helper()
				out, err := cfnOrgIdentityCall[orgapi.PutResourcePolicyOutput](f.ctx, f.commands, "organizations", "PutResourcePolicy", map[string]any{"Content": delegation, "Tags": append([]map[string]string{}, tags...)})
				if err != nil {
					t.Fatal(err)
				}
				return cfnComputeValue(out.ResourcePolicy.ResourcePolicySummary.Id)
			}
			resource := cfnOrganizationResourcePolicy{f.commands}
			rp := cfnWorkflowOwnerRequest("AWS::Organizations::ResourcePolicy", "Delegation", cloudformation.Properties{"Content": delegation})
			direct := nativeDelegation(cfnOrgSSOCounterfeit(rp))
			result, err = resource.RecoverCreation(f.ctx, rp)
			cfnOrgSSONotAdmitted(t, "counterfeit delegation", result, err)
			if result, err = resource.Create(f.ctx, rp); err == nil || result.PhysicalID != "" {
				t.Fatalf("create adopted a counterfeit delegation policy: %+v %v", result, err)
			}
			staleRP := rp
			staleRP.PhysicalID = direct
			if err = resource.Delete(f.ctx, staleRP); err == nil {
				t.Fatal("marker-matching incarnation deleted a direct delegation policy")
			}
			if _, err = resource.Read(f.ctx, staleRP); err != nil {
				t.Fatalf("direct delegation policy was damaged: %v", err)
			}
			f.run(t, "organizations", "DeleteResourcePolicy", map[string]any{})
			created, err = resource.Create(f.ctx, rp)
			if err != nil || created.PhysicalID == "" || created.PhysicalID == direct {
				t.Fatalf("delegation create failed or reused a direct policy: %+v %v", created, err)
			}
			rp.PhysicalID = created.PhysicalID
			tags, err = cfnOrganizationsTags(f.ctx, f.commands, rp.PhysicalID)
			if err != nil {
				t.Fatal(err)
			}
			cfnOrgSSONoPublicClaim(t, "delegation policy", tags)

			// Same-token recovery survives restart and native renames.
			f.run(t, "organizations", "UpdatePolicy", map[string]any{"PolicyId": r.PhysicalID, "Name": "renamed"})
			f.restart(t)
			policy, resource = cfnOrganizationPolicy{f.commands}, cfnOrganizationResourcePolicy{f.commands}
			replay, replayRP := r, rp
			replay.PhysicalID, replayRP.PhysicalID = "", ""
			result, err = policy.RecoverCreation(f.ctx, replay)
			cfnOrgSSOSame(t, "policy recovery", r.PhysicalID, result, err)
			result, err = policy.Create(f.ctx, replay)
			cfnOrgSSOSame(t, "policy replay", r.PhysicalID, result, err)
			result, err = resource.RecoverCreation(f.ctx, replayRP)
			cfnOrgSSOSame(t, "delegation recovery", rp.PhysicalID, result, err)
			result, err = resource.Create(f.ctx, replayRP)
			cfnOrgSSOSame(t, "delegation replay", rp.PhysicalID, result, err)

			// Forged markers for another incarnation transfer nothing.
			for _, id := range []string{r.PhysicalID, rp.PhysicalID} {
				f.run(t, "organizations", "TagResource", map[string]any{"ResourceId": id, "Tags": cfnOrgSSOCounterfeit(cfnOrgSSOOther(r))})
			}
			if err = policy.Delete(f.ctx, cfnOrgSSOOther(r)); err == nil {
				t.Fatal("forged markers let another incarnation delete the policy")
			}
			if _, err = resource.Update(f.ctx, cfnOrgSSOOther(rp)); err == nil {
				t.Fatal("forged markers let another incarnation replace the delegation policy")
			}
			if err = resource.Delete(f.ctx, cfnOrgSSOOther(rp)); err == nil {
				t.Fatal("forged markers let another incarnation delete the delegation policy")
			}
			if _, err = policy.Update(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			if p, err := policy.Read(f.ctx, r); err != nil || p["Name"] != "guard" || len(p["Tags"].([]any)) != 0 {
				t.Fatalf("owned policy update did not converge: %#v %v", p, err)
			}

			// Deleted incarnations never observe or delete foreign recreations.
			if err = policy.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			if err = resource.Delete(f.ctx, rp); err != nil {
				t.Fatal(err)
			}
			foreign, foreignRP := nativePolicy("guard", nil), nativeDelegation(nil)
			result, err = policy.RecoverCreation(f.ctx, replay)
			cfnOrgSSONotAdmitted(t, "policy foreign recreation", result, err)
			result, err = resource.RecoverCreation(f.ctx, replayRP)
			cfnOrgSSONotAdmitted(t, "delegation foreign recreation", result, err)
			if err = policy.Delete(f.ctx, r); err != nil {
				t.Fatalf("absent policy incarnation delete failed: %v", err)
			}
			if err = resource.Delete(f.ctx, rp); err != nil {
				t.Fatalf("absent delegation incarnation delete failed: %v", err)
			}
			if _, err = policy.Read(f.ctx, cloudformation.ResourceRequest{PhysicalID: foreign}); err != nil {
				t.Fatalf("foreign policy was damaged: %v", err)
			}
			if _, err = resource.Read(f.ctx, cloudformation.ResourceRequest{PhysicalID: foreignRP}); err != nil {
				t.Fatalf("foreign delegation policy was damaged: %v", err)
			}
		})
	}
}

func TestCFNSSOInstanceAndPermissionSetPrivateClaimsRejectCounterfeitAndForeignRecreation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNOrgSSOOwnerFixture(t, backend)
			instance := cfnSSOInstance{f.commands}
			ir := cfnWorkflowOwnerRequest("AWS::SSO::Instance", "Instance", cloudformation.Properties{"Name": "workforce"})

			// A direct instance reusing the published client token and markers is not ir's.
			out, err := cfnOrgIdentityCall[ssoapi.CreateInstanceOutput](f.ctx, f.commands, "ssoadmin", "CreateInstance", map[string]any{"Name": "workforce", "ClientToken": ir.Token, "Tags": cfnOrgSSOCounterfeit(ir)})
			if err != nil {
				t.Fatal(err)
			}
			counterfeit := cfnComputeValue(out.InstanceArn)
			result, err := instance.RecoverCreation(f.ctx, ir)
			cfnOrgSSONotAdmitted(t, "counterfeit instance", result, err)
			if result, err = instance.Create(f.ctx, ir); err == nil || result.PhysicalID != "" {
				t.Fatalf("create adopted a counterfeit instance: %+v %v", result, err)
			}
			stale := ir
			stale.PhysicalID = counterfeit
			if err = instance.Delete(f.ctx, stale); err == nil {
				t.Fatal("marker-matching incarnation deleted a direct instance")
			}
			if _, err = instance.Read(f.ctx, stale); err != nil {
				t.Fatalf("direct instance was damaged: %v", err)
			}
			f.run(t, "ssoadmin", "DeleteInstance", map[string]any{"InstanceArn": counterfeit})
			created, err := instance.Create(f.ctx, ir)
			if err != nil || created.PhysicalID == "" || created.PhysicalID == counterfeit {
				t.Fatalf("instance create failed or reused a direct instance: %+v %v", created, err)
			}
			ir.PhysicalID = created.PhysicalID
			arn := ir.PhysicalID

			nativeSet := func(name string, tags []map[string]string) string {
				t.Helper()
				out, err := cfnOrgIdentityCall[ssoapi.CreatePermissionSetOutput](f.ctx, f.commands, "ssoadmin", "CreatePermissionSet", map[string]any{"Name": name, "InstanceArn": arn, "Tags": append([]map[string]string{}, tags...)})
				if err != nil {
					t.Fatal(err)
				}
				return cfnComputeValue(out.PermissionSet.PermissionSetArn)
			}
			set := cfnSSOPermissionSet{f.commands}
			pr := cfnWorkflowOwnerRequest("AWS::SSO::PermissionSet", "Operators", cloudformation.Properties{"Name": "Operators", "InstanceArn": arn, "SessionDuration": "PT2H", "Tags": []any{map[string]any{"Key": "team", "Value": "a"}}})
			direct := nativeSet("Operators", cfnOrgSSOCounterfeit(pr))
			result, err = set.RecoverCreation(f.ctx, pr)
			cfnOrgSSONotAdmitted(t, "counterfeit permission set", result, err)
			if result, err = set.Create(f.ctx, pr); err == nil || result.PhysicalID != "" {
				t.Fatalf("create adopted a counterfeit permission set: %+v %v", result, err)
			}
			staleSet := pr
			staleSet.PhysicalID = cfnOrgIdentityID(direct, arn)
			if _, err = set.Update(f.ctx, staleSet); err == nil {
				t.Fatal("marker-matching incarnation mutated a direct permission set")
			}
			if err = set.Delete(f.ctx, staleSet); err == nil {
				t.Fatal("marker-matching incarnation deleted a direct permission set")
			}
			if p, err := set.Read(f.ctx, staleSet); err != nil || p["SessionDuration"] != "PT3600S" {
				t.Fatalf("direct permission set was damaged: %#v %v", p, err)
			}
			f.run(t, "ssoadmin", "DeletePermissionSet", map[string]any{"InstanceArn": arn, "PermissionSetArn": direct})
			created, err = set.Create(f.ctx, pr)
			if err != nil || created.PhysicalID == "" || created.PhysicalID == staleSet.PhysicalID {
				t.Fatalf("permission set create failed or reused a direct set: %+v %v", created, err)
			}
			pr.PhysicalID = created.PhysicalID
			setARN := created.Attributes["PermissionSetArn"].(string)
			tags, err := cfnSSOTags(f.ctx, f.commands, arn, setARN)
			if err != nil || tags["team"] != "a" {
				t.Fatalf("permission set tags did not converge: %v %v", tags, err)
			}
			cfnOrgSSONoPublicClaim(t, "permission set", tags)
			if tags, err = cfnSSOTags(f.ctx, f.commands, arn, arn); err != nil {
				t.Fatal(err)
			}
			cfnOrgSSONoPublicClaim(t, "instance", tags)

			// Same-token recovery survives restart; ARNs remain the only identity.
			f.restart(t)
			instance, set = cfnSSOInstance{f.commands}, cfnSSOPermissionSet{f.commands}
			replayInstance, replaySet := ir, pr
			replayInstance.PhysicalID, replaySet.PhysicalID = "", ""
			result, err = instance.RecoverCreation(f.ctx, replayInstance)
			cfnOrgSSOSame(t, "instance recovery", ir.PhysicalID, result, err)
			result, err = instance.Create(f.ctx, replayInstance)
			cfnOrgSSOSame(t, "instance replay", ir.PhysicalID, result, err)
			result, err = set.RecoverCreation(f.ctx, replaySet)
			cfnOrgSSOSame(t, "permission set recovery", pr.PhysicalID, result, err)
			result, err = set.Create(f.ctx, replaySet)
			cfnOrgSSOSame(t, "permission set replay", pr.PhysicalID, result, err)

			// Forged markers for another incarnation transfer nothing.
			f.run(t, "ssoadmin", "TagResource", map[string]any{"InstanceArn": arn, "ResourceArn": setARN, "Tags": cfnOrgSSOCounterfeit(cfnOrgSSOOther(pr))})
			f.run(t, "ssoadmin", "TagResource", map[string]any{"InstanceArn": arn, "ResourceArn": arn, "Tags": cfnOrgSSOCounterfeit(cfnOrgSSOOther(ir))})
			if _, err = set.Update(f.ctx, cfnOrgSSOOther(pr)); err == nil {
				t.Fatal("forged markers let another incarnation update the permission set")
			}
			if err = set.Delete(f.ctx, cfnOrgSSOOther(pr)); err == nil {
				t.Fatal("forged markers let another incarnation delete the permission set")
			}
			if err = instance.Delete(f.ctx, cfnOrgSSOOther(ir)); err == nil {
				t.Fatal("forged markers let another incarnation delete the instance")
			}
			pr.Previous, pr.Properties = pr.Properties, cloudformation.Properties{"Name": "Operators", "InstanceArn": arn, "SessionDuration": "PT3H", "Description": "on call"}
			if _, err = set.Update(f.ctx, pr); err != nil {
				t.Fatal(err)
			}
			if p, err := set.Read(f.ctx, pr); err != nil || p["Description"] != "on call" || len(p["Tags"].([]any)) != 0 {
				t.Fatalf("owned permission set update did not converge: %#v %v", p, err)
			}

			// Deleted incarnations never observe or delete foreign recreations.
			if err = set.Delete(f.ctx, pr); err != nil {
				t.Fatal(err)
			}
			foreign := nativeSet("Operators", nil)
			result, err = set.RecoverCreation(f.ctx, replaySet)
			cfnOrgSSONotAdmitted(t, "permission set foreign recreation", result, err)
			if err = set.Delete(f.ctx, pr); err != nil {
				t.Fatalf("absent permission set incarnation delete failed: %v", err)
			}
			if _, err = set.Read(f.ctx, cloudformation.ResourceRequest{PhysicalID: cfnOrgIdentityID(foreign, arn)}); err != nil {
				t.Fatalf("foreign permission set was damaged: %v", err)
			}
			f.run(t, "ssoadmin", "DeletePermissionSet", map[string]any{"InstanceArn": arn, "PermissionSetArn": foreign})
			if err = instance.Delete(f.ctx, ir); err != nil {
				t.Fatal(err)
			}
			result, err = instance.RecoverCreation(f.ctx, replayInstance)
			cfnOrgSSONotAdmitted(t, "deleted instance", result, err)
		})
	}
}

func TestCFNOrganizationsSetupUsesNativeIAMProvisioningAndAtomicDenial(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNOrgSSOOwnerFixture(t, backend)
			f.run(t, "iam", "CreateUser", map[string]any{"UserName": "organization-creator"})
			creator, err := cfnComputeCall[iamapi.GetUserOutput](f.ctx, f.commands, "iam", "GetUser", map[string]any{"UserName": "organization-creator"})
			if err != nil || creator.User == nil {
				t.Fatalf("native creator identity: %+v %v", creator, err)
			}
			f.run(t, "iam", "PutUserPolicy", map[string]any{
				"UserName": "organization-creator", "PolicyName": "create-organization",
				"PolicyDocument": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"organizations:CreateOrganization","Resource":"*"}]}`,
			})
			metadata := awsctx.FromContext(f.ctx)
			metadata.PrincipalARN = cfnComputeValue(creator.User.Arn)
			metadata.PrincipalID = cfnComputeValue(creator.User.UserId)
			ctx := awsctx.WithMetadata(f.ctx, metadata)
			if err := cfnComputeRun(ctx, f.commands, "organizations", "CreateOrganization", map[string]any{"FeatureSet": "ALL"}); !cfnMessagingMissing(err, "AccessDeniedForDependencyException") {
				t.Fatalf("missing current IAM dependency permission was not rejected: %v", err)
			}
			record, _, err := f.orgs.Load(f.ctx, "aws")
			if err != nil || len(record.Organizations) != 0 {
				t.Fatalf("dependency denial committed organization membership: %+v %v", record, err)
			}
			roleARN := "arn:aws:iam::" + metadata.AccountID + ":role/aws-service-role/organizations.amazonaws.com/" + orgservice.ServiceLinkedRoleName
			if _, err := cfnComputeCall[iamapi.GetRoleOutput](f.ctx, f.commands, "iam", "GetRole", map[string]any{"RoleName": orgservice.ServiceLinkedRoleName}); !cfnComputeMissing(err) {
				t.Fatalf("dependency denial committed an IAM role: %v", err)
			}
			f.run(t, "iam", "PutUserPolicy", map[string]any{
				"UserName": "organization-creator", "PolicyName": "create-service-role",
				"PolicyDocument": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":"` + roleARN + `","Condition":{"StringEquals":{"iam:AWSServiceName":"organizations.amazonaws.com"}}}]}`,
			})
			if err := cfnComputeRun(ctx, f.commands, "organizations", "CreateOrganization", map[string]any{"FeatureSet": "ALL"}); err != nil {
				t.Fatal(err)
			}
			f.restart(t)
			role, err := cfnComputeCall[iamapi.GetRoleOutput](f.ctx, f.commands, "iam", "GetRole", map[string]any{"RoleName": orgservice.ServiceLinkedRoleName})
			if err != nil || role.Role == nil || cfnComputeValue(role.Role.Arn) != roleARN {
				t.Fatalf("native joined role was not persisted: %+v %v", role, err)
			}
		})
	}
}

func TestCFNSSOPermissionSetUpdateOmitsAbsentNativeOptionalFields(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNOrgSSOOwnerFixture(t, backend)
			instance := cfnSSOInstance{f.commands}
			ir := cfnWorkflowOwnerRequest("AWS::SSO::Instance", "OptionalInstance", cloudformation.Properties{"Name": "optional-instance"})
			created, err := instance.Create(f.ctx, ir)
			if err != nil {
				t.Fatal(err)
			}
			set := cfnSSOPermissionSet{f.commands}
			pr := cfnWorkflowOwnerRequest("AWS::SSO::PermissionSet", "OptionalSet", cloudformation.Properties{
				"Name": "OptionalSet", "InstanceArn": created.PhysicalID, "Description": "operators",
				"RelayStateType": "https://example.com/console", "SessionDuration": "PT2H",
			})
			created, err = set.Create(f.ctx, pr)
			if err != nil {
				t.Fatal(err)
			}
			pr.PhysicalID = created.PhysicalID
			pr.Previous, pr.Properties = pr.Properties, cloudformation.Properties{"Name": "OptionalSet", "InstanceArn": pr.Properties["InstanceArn"]}
			if _, err := set.Update(f.ctx, pr); err != nil {
				t.Fatalf("omitted optional fields rejected: %v", err)
			}
			model, err := set.Read(f.ctx, pr)
			if err != nil || model["Description"] != "operators" || model["RelayStateType"] != "https://example.com/console" || model["SessionDuration"] != "PT7200S" {
				t.Fatalf("omission reset native optional configuration: %#v %v", model, err)
			}
			pr.Properties["Description"] = "must-not-commit"
			pr.Properties["RelayStateType"] = ""
			if _, err := set.Update(f.ctx, pr); !cfnMessagingMissing(err, "ValidationException") {
				t.Fatalf("explicit empty relay state bypassed native minimum: %v", err)
			}
			model, err = set.Read(f.ctx, pr)
			if err != nil || model["Description"] != "operators" || model["RelayStateType"] != "https://example.com/console" {
				t.Fatalf("native validation rejection partially mutated permission set: %#v %v", model, err)
			}
			if err := set.Delete(f.ctx, pr); err != nil {
				t.Fatal(err)
			}
			ir.PhysicalID = pr.Properties["InstanceArn"].(string)
			if err := instance.Delete(f.ctx, ir); err != nil {
				t.Fatal(err)
			}
		})
	}
}
