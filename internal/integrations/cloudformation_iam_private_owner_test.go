package integrations

import (
	"context"
	"database/sql"
	"path/filepath"
	"time"

	"stackd/clock"
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/iam"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	iamowner "stackd/internal/services/iam"
	"stackd/storage/sqlite"
	iamstore "stackd/storage/sqlite/iam"
)

type cfnIAMPrivateFixture struct {
	t             *testing.T
	ctx           context.Context
	backend, path string
	db            *sql.DB
	repository    iamowner.Repository
	owner         *iamowner.Service
	commands      StepFunctionsCommands
}

func newCFNIAMPrivateFixture(t *testing.T, backend string) *cfnIAMPrivateFixture {
	t.Helper()
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-2", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	f := &cfnIAMPrivateFixture{t: t, ctx: ctx, backend: backend, path: filepath.Join(t.TempDir(), "iam.sqlite"), repository: iamowner.NewMemoryRepository(nil)}
	f.open()
	t.Cleanup(func() {
		_ = f.owner.Close()
		if f.db != nil {
			_ = f.db.Close()
		}
	})
	return f
}
func (f *cfnIAMPrivateFixture) open() {
	if f.backend == "sqlite" {
		var err error
		f.db, err = sqlite.Open(f.ctx, f.path)
		if err != nil {
			f.t.Fatal(err)
		}
		f.repository = iamstore.New(f.db)
	}
	f.owner = iamowner.NewWithConfig(iamowner.Config{Repository: f.repository, Clock: clock.NewManual(time.Date(2027, 1, 2, 3, 4, 0, 0, time.UTC))})
	f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"iam": f.owner})
}
func (f *cfnIAMPrivateFixture) reopen() {
	f.t.Helper()
	if err := f.owner.Close(); err != nil {
		f.t.Fatal(err)
	}
	if f.db != nil {
		if err := f.db.Close(); err != nil {
			f.t.Fatal(err)
		}
	}
	f.open()
}
func (f *cfnIAMPrivateFixture) run(op string, in map[string]any) {
	f.t.Helper()
	if err := cfnComputeRun(f.ctx, f.commands, "iam", op, in); err != nil {
		f.t.Fatal(err)
	}
}
func cfnIAMPrivateHandler(c StepFunctionsCommands, kind string) cloudformation.ResourceHandler {
	switch kind {
	case "Role":
		return cfnIAMRole{c}
	case "User":
		return cfnIAMUser{c}
	case "Group":
		return cfnIAMGroup{c}
	case "ManagedPolicy":
		return cfnIAMManagedPolicy{c}
	}
	panic("unsupported test kind")
}

const cfnIAMPrivateTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
const cfnIAMPrivatePolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`

func TestCFNIAMPrivateRootRecoveryAndCounterfeitRecreation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, kind := range []string{"Role", "User", "Group", "ManagedPolicy"} {
			t.Run(backend+"/"+kind, func(t *testing.T) {
				f := newCFNIAMPrivateFixture(t, backend)
				name := "private-" + kind
				p := cloudformation.Properties{kind + "Name": name}
				if kind == "Role" {
					p["AssumeRolePolicyDocument"] = cfnIAMPrivateTrust
				}
				if kind == "ManagedPolicy" {
					p["PolicyDocument"] = cfnIAMPrivatePolicy
				}
				r := cfnIAMOwnerRequest(kind, kind, p)
				r.CloudControl = true
				h := cfnIAMPrivateHandler(f.commands, kind)
				created, err := h.Create(f.ctx, r)
				if err != nil || created.PhysicalID == "" {
					t.Fatalf("create: %+v %v", created, err)
				}
				f.reopen()
				h = cfnIAMPrivateHandler(f.commands, kind)
				recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r)
				if err != nil || recovered.PhysicalID != created.PhysicalID {
					t.Fatalf("reopen recovery: %+v %v", recovered, err)
				}
				replay, err := h.Create(f.ctx, r)
				if err != nil || replay.PhysicalID != created.PhysicalID {
					t.Fatalf("same-token create: %+v %v", replay, err)
				}
				r.PhysicalID = created.PhysicalID
				owned := r
				owned.CloudControl = false
				if err := h.Delete(f.ctx, owned); err != nil {
					t.Fatal(err)
				}
				tags := cfnComputeTagList(cfnComputeOwnedTags(r))
				op, key := "Create"+kind, kind+"Name"
				in := map[string]any{key: name}
				switch kind {
				case "Role":
					in["AssumeRolePolicyDocument"] = cfnIAMPrivateTrust
					in["Tags"] = tags
				case "User":
					in["Tags"] = tags
				case "ManagedPolicy":
					op, key = "CreatePolicy", "PolicyName"
					in = map[string]any{key: name, "PolicyDocument": cfnIAMPrivatePolicy, "Tags": tags}
				}
				f.run(op, in)
				if _, err := h.(cloudformation.ResourceReader).Read(f.ctx, owned); err == nil {
					t.Fatal("public marker adopted foreign incarnation")
				}
				owned.Previous = owned.Properties
				if _, err := h.Update(f.ctx, owned); err == nil {
					t.Fatal("stale owner updated foreign incarnation")
				}
				if err := h.Delete(f.ctx, owned); err == nil {
					t.Fatal("stale owner deleted foreign incarnation")
				}
				failed, err := h.Create(f.ctx, r)
				if err == nil || failed.PhysicalID != "" {
					t.Fatalf("CC CREATE adopted foreign row: %+v %v", failed, err)
				}
				absent, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r)
				if !cfnComputeMissing(err) || absent.PhysicalID != "" {
					t.Fatalf("foreign row was recovered, or nonadmission not certified: %+v %v", absent, err)
				}
				if _, err := h.(cloudformation.ResourceReader).Read(f.ctx, r); err != nil {
					t.Fatalf("ordinary CC read lost IAM-permitted access: %v", err)
				}
			})
		}
	}
}

func TestCFNIAMMultiStepCreateErrorRecoversActualNativeIdentity(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, kind := range []string{"Role", "User", "Group", "ManagedPolicy"} {
			t.Run(backend+"/"+kind, func(t *testing.T) {
				f := newCFNIAMPrivateFixture(t, backend)
				p := cloudformation.Properties{kind + "Name": "failed-" + kind}
				if kind == "Role" {
					p["AssumeRolePolicyDocument"] = cfnIAMPrivateTrust
				}
				if kind == "ManagedPolicy" {
					p["PolicyDocument"] = cfnIAMPrivatePolicy
					p["Users"] = []any{"missing-target"}
				} else {
					p["ManagedPolicyArns"] = []any{"arn:aws:iam::123456789012:policy/missing-target"}
				}
				r := cfnIAMOwnerRequest(kind, "Failed"+kind, p)
				r.CloudControl = true
				h := cfnIAMPrivateHandler(f.commands, kind)
				admitted, err := h.Create(f.ctx, r)
				if err == nil || admitted.PhysicalID == "" {
					t.Fatalf("postadmission error discarded real ID: %+v %v", admitted, err)
				}
				f.reopen()
				h = cfnIAMPrivateHandler(f.commands, kind)
				recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r)
				if err != nil || recovered.PhysicalID != admitted.PhysicalID {
					t.Fatalf("posterror recovery: %+v %v", recovered, err)
				}
				replay, err := h.Create(f.ctx, r)
				if err == nil || replay.PhysicalID != admitted.PhysicalID {
					t.Fatalf("failed convergence replaced native identity: %+v %v", replay, err)
				}
				r.PhysicalID = admitted.PhysicalID
				r.CloudControl = false
				if err := h.Delete(f.ctx, r); err != nil {
					t.Fatal(err)
				}
				if _, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r); !cfnComputeMissing(err) {
					t.Fatalf("rollback retained admitted row: %v", err)
				}
				// A failure before native admission must not invent a physical identity.
				r.PhysicalID = ""
				r.Token = "never-admitted"
				r.Properties = cloudformation.Properties{kind + "Name": "rejected-" + kind, "Path": "not-a-path"}
				if kind == "Role" {
					r.Properties["AssumeRolePolicyDocument"] = cfnIAMPrivateTrust
				}
				if kind == "ManagedPolicy" {
					r.Properties["Path"] = "/"
					r.Properties["PolicyDocument"] = `{}`
				}
				rejected, err := h.Create(f.ctx, r)
				if err == nil || rejected.PhysicalID != "" {
					t.Fatalf("native rejection invented ID: %+v %v", rejected, err)
				}
				if result, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r); !cfnComputeMissing(err) || result.PhysicalID != "" {
					t.Fatalf("native nonadmission not certified: %+v %v", result, err)
				}
			})
		}
	}
}

type cfnIAMLostCreateReply struct {
	*iamowner.Service
	operation string
}

func (e *cfnIAMLostCreateReply) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	out, err := e.Service.ExecuteCommand(ctx, r)
	if err == nil && string(r.Operation.Name) == e.operation {
		e.operation = ""
		return nil, &awswire.Error{Code: "InternalFailure", Message: "lost admitted native reply", StatusCode: 500}
	}
	return out, err
}
func TestCFNIAMLostRootCreateReplyRetainsAuthenticIdentity(t *testing.T) {
	for _, kind := range []string{"Role", "User", "Group", "ManagedPolicy"} {
		t.Run(kind, func(t *testing.T) {
			f := newCFNIAMPrivateFixture(t, "memory")
			op := "Create" + kind
			if kind == "ManagedPolicy" {
				op = "CreatePolicy"
			}
			commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"iam": &cfnIAMLostCreateReply{f.owner, op}})
			p := cloudformation.Properties{kind + "Name": "lost-" + kind}
			if kind == "Role" {
				p["AssumeRolePolicyDocument"] = cfnIAMPrivateTrust
			}
			if kind == "ManagedPolicy" {
				p["PolicyDocument"] = cfnIAMPrivatePolicy
			}
			r := cfnIAMOwnerRequest(kind, "Lost"+kind, p)
			h := cfnIAMPrivateHandler(commands, kind)
			actual, err := h.Create(f.ctx, r)
			if err == nil || actual.PhysicalID == "" {
				t.Fatalf("lost reply forgot actual admission: %+v %v", actual, err)
			}
			recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r)
			if err != nil || recovered.PhysicalID != actual.PhysicalID {
				t.Fatalf("lost reply recovery: %+v %v", recovered, err)
			}
		})
	}
}

func TestCFNIAMPublicInlineAndAttachedMarkersCannotClaimNativeEdges(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNIAMPrivateFixture(t, backend)
			r := cfnIAMOwnerRequest("Role", "Edges", cloudformation.Properties{"RoleName": "edge-role", "AssumeRolePolicyDocument": cfnIAMPrivateTrust})
			h := cfnIAMRole{f.commands}
			created, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = created.PhysicalID
			f.run("CreatePolicy", map[string]any{"PolicyName": "edge-policy", "PolicyDocument": cfnIAMPrivatePolicy})
			arn := "arn:aws:iam::123456789012:policy/edge-policy"
			f.run("PutRolePolicy", map[string]any{"RoleName": r.PhysicalID, "PolicyName": "external-inline", "PolicyDocument": cfnIAMPrivatePolicy})
			f.run("AttachRolePolicy", map[string]any{"RoleName": r.PhysicalID, "PolicyArn": arn})
			marker := cfnComputeOwnedTags(r)
			marker[cfnComputeTagPrefix+"policy-"+cfnComputeHash("external-inline")] = cfnComputeHash(cfnIAMPolicyOwner(r))
			f.run("TagRole", map[string]any{"RoleName": r.PhysicalID, "Tags": cfnComputeTagList(marker)})
			f.reopen()
			h = cfnIAMRole{f.commands}
			r.Previous = r.Properties
			for _, p := range []cloudformation.Properties{
				{"RoleName": "edge-role", "AssumeRolePolicyDocument": cfnIAMPrivateTrust, "Policies": []any{map[string]any{"PolicyName": "external-inline", "PolicyDocument": cfnIAMPrivatePolicy}}},
				{"RoleName": "edge-role", "AssumeRolePolicyDocument": cfnIAMPrivateTrust, "ManagedPolicyArns": []any{arn}},
			} {
				r.Properties = p
				if _, err := h.Update(f.ctx, r); err == nil {
					t.Fatal("public markers claimed an external edge")
				}
			}
			f.run("GetRolePolicy", map[string]any{"RoleName": "edge-role", "PolicyName": "external-inline"})
			out, err := cfnComputeCall[api.ListAttachedRolePoliciesOutput](f.ctx, f.commands, "iam", "ListAttachedRolePolicies", map[string]any{"RoleName": "edge-role"})
			if err != nil {
				t.Fatal(err)
			}
			if len(out.AttachedPolicies) != 1 || cfnComputeValue(out.AttachedPolicies[0].PolicyArn) != arn {
				t.Fatal("foreign attachment damaged")
			}
		})
	}
}

type cfnIAMReplaceBeforeMutation struct {
	*iamowner.Service
	ctx      context.Context
	commands StepFunctionsCommands
	request  cloudformation.ResourceRequest
	replace  bool
}

func (e *cfnIAMReplaceBeforeMutation) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	if e.replace && string(r.Operation.Name) == "UpdateAssumeRolePolicy" {
		e.replace = false
		name := cfnComputeString(e.request.Properties, "RoleName")
		if err := cfnComputeRun(e.ctx, e.commands, "iam", "DeleteRole", map[string]any{"RoleName": name}); err != nil {
			return nil, &awswire.Error{Code: "InternalFailure", Message: err.Error(), StatusCode: 500}
		}
		if err := cfnComputeRun(e.ctx, e.commands, "iam", "CreateRole", map[string]any{"RoleName": name, "AssumeRolePolicyDocument": cfnIAMPrivateTrust, "Description": "foreign-replacement", "Tags": cfnComputeTagList(cfnComputeOwnedTags(e.request))}); err != nil {
			return nil, &awswire.Error{Code: "InternalFailure", Message: err.Error(), StatusCode: 500}
		}
	}
	return e.Service.ExecuteCommand(ctx, r)
}
func TestCFNIAMMutationFencesPrivateIncarnationAfterAuthorizedRead(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNIAMPrivateFixture(t, backend)
			r := cfnIAMOwnerRequest("Role", "Race", cloudformation.Properties{"RoleName": "race-role", "AssumeRolePolicyDocument": cfnIAMPrivateTrust})
			created, err := (cfnIAMRole{f.commands}).Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = created.PhysicalID
			r.Previous = r.Properties
			replacement := &cfnIAMReplaceBeforeMutation{Service: f.owner, ctx: f.ctx, commands: f.commands, request: r, replace: true}
			h := cfnIAMRole{NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"iam": replacement})}
			if _, err := h.Update(f.ctx, r); err == nil {
				t.Fatal("read-before-write race mutated foreign incarnation")
			}
			native, err := cfnComputeCall[api.GetRoleOutput](f.ctx, f.commands, "iam", "GetRole", map[string]any{"RoleName": "race-role"})
			if err != nil {
				t.Fatal(err)
			}
			if cfnComputeValue(native.Role.Description) != "foreign-replacement" {
				t.Fatal("private transaction fence failed to preserve foreign replacement")
			}
		})
	}
}

func TestCFNIAMAccessKeyPrivateRecoveryReopensSecretAndNativeStatus(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNIAMPrivateFixture(t, backend)
			f.run("CreateUser", map[string]any{"UserName": "key-owner"})
			r := cfnIAMOwnerRequest("AccessKey", "PrivateKey", cloudformation.Properties{"UserName": "key-owner", "Status": "Inactive"})
			r.CloudControl = true
			h := cfnIAMAccessKey{f.commands}
			created, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			f.reopen()
			h = cfnIAMAccessKey{f.commands}
			recovered, err := h.RecoverCreation(f.ctx, r)
			if err != nil || recovered.PhysicalID != created.PhysicalID || recovered.Attributes["SecretAccessKey"] != created.Attributes["SecretAccessKey"] {
				t.Fatalf("private credential recovery changed key or secret: %+v %v", recovered, err)
			}
			r.PhysicalID = created.PhysicalID
			model, err := h.Read(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			if model["Status"] != "Inactive" {
				t.Fatal("recovery changed native key status")
			}
			if _, ok := model["SecretAccessKey"]; ok {
				t.Fatal("read disclosed creation-only secret")
			}
			// Recovery is observation, not desired-state convergence: stale creation
			// properties must not reactivate an inactive native credential.
			r.Properties = cloudformation.Properties{"UserName": "key-owner", "Status": "Active"}
			recovered, err = h.RecoverCreation(f.ctx, r)
			if err != nil || recovered.PhysicalID != created.PhysicalID {
				t.Fatalf("native status recovery: %+v %v", recovered, err)
			}
			model, err = h.Read(f.ctx, r)
			if err != nil || model["Status"] != "Inactive" {
				t.Fatalf("recovery reapplied stale creation status: %#v %v", model, err)
			}
			r.Properties = cloudformation.Properties{"UserName": "key-owner"}
			replay, err := h.Create(f.ctx, r)
			if err != nil || replay.PhysicalID != created.PhysicalID {
				t.Fatalf("private create replay: %+v %v", replay, err)
			}
			model, err = h.Read(f.ctx, r)
			if err != nil || model["Status"] != "Inactive" {
				t.Fatalf("create replay reset an omitted status: %#v %v", model, err)
			}
			if _, err := h.RecoverCreation(f.ctx, func() cloudformation.ResourceRequest { foreign := r; foreign.Token = "foreign-key"; return foreign }()); !cfnComputeMissing(err) {
				t.Fatal("foreign token recovered native secret")
			}
		})
	}
}

func TestCFNIAMDeletedNativeEdgesCannotReusePrivateClaims(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNIAMPrivateFixture(t, backend)
			r := cfnIAMOwnerRequest("Role", "RecreatedEdges", cloudformation.Properties{"RoleName": "recreated-edges", "AssumeRolePolicyDocument": cfnIAMPrivateTrust})
			root := cfnIAMRole{f.commands}
			created, err := root.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = created.PhysicalID
			f.run("CreatePolicy", map[string]any{"PolicyName": "recreated-policy", "PolicyDocument": cfnIAMPrivatePolicy})
			arn := "arn:aws:iam::123456789012:policy/recreated-policy"
			r.Previous = r.Properties
			r.Properties = cloudformation.Properties{"RoleName": "recreated-edges", "AssumeRolePolicyDocument": cfnIAMPrivateTrust, "Policies": []any{map[string]any{"PolicyName": "managed-inline", "PolicyDocument": cfnIAMPrivatePolicy}}, "ManagedPolicyArns": []any{arn}}
			if _, err := root.Update(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			f.run("DeleteRolePolicy", map[string]any{"RoleName": r.PhysicalID, "PolicyName": "managed-inline"})
			f.run("PutRolePolicy", map[string]any{"RoleName": r.PhysicalID, "PolicyName": "managed-inline", "PolicyDocument": cfnIAMPrivatePolicy})
			f.run("DetachRolePolicy", map[string]any{"RoleName": r.PhysicalID, "PolicyArn": arn})
			f.run("AttachRolePolicy", map[string]any{"RoleName": r.PhysicalID, "PolicyArn": arn})
			f.run("TagRole", map[string]any{"RoleName": r.PhysicalID, "Tags": cfnComputeTagList(cfnComputeOwnedTags(r))})
			f.reopen()
			root = cfnIAMRole{f.commands}
			r.Previous = r.Properties
			if _, err := root.Update(f.ctx, r); err == nil {
				t.Fatal("native edge recreation reused stale private claims")
			}
			r.Properties = cloudformation.Properties{"RoleName": "recreated-edges", "AssumeRolePolicyDocument": cfnIAMPrivateTrust}
			if _, err := root.Update(f.ctx, r); err == nil {
				t.Fatal("stale edge claim removed a foreign recreation")
			}
			f.run("GetRolePolicy", map[string]any{"RoleName": r.PhysicalID, "PolicyName": "managed-inline"})
			attached, err := cfnComputeCall[api.ListAttachedRolePoliciesOutput](f.ctx, f.commands, "iam", "ListAttachedRolePolicies", map[string]any{"RoleName": r.PhysicalID})
			if err != nil {
				t.Fatal(err)
			}
			if len(attached.AttachedPolicies) != 1 {
				t.Fatal("foreign recreated attachment removed")
			}
		})
	}
}

func TestCFNIAMAccessKeyStatusAdmissionFailureRetainsNativeKeyForRollback(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNIAMPrivateFixture(t, backend)
			f.run("CreateUser", map[string]any{"UserName": "restricted-key-owner"})
			user, err := cfnComputeCall[api.GetUserOutput](f.ctx, f.commands, "iam", "GetUser", map[string]any{"UserName": "restricted-key-owner"})
			if err != nil || user.User == nil {
				t.Fatalf("native identity: %+v %v", user, err)
			}
			arn := cfnComputeValue(user.User.Arn)
			f.run("PutUserPolicy", map[string]any{"UserName": "restricted-key-owner", "PolicyName": "key-lifecycle", "PolicyDocument": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreateAccessKey","iam:ListAccessKeys","iam:DeleteAccessKey"],"Resource":"` + arn + `"}]}`})
			metadata := awsctx.FromContext(f.ctx)
			metadata.PrincipalARN = arn
			metadata.PrincipalID = cfnComputeValue(user.User.UserId)
			ctx := awsctx.WithMetadata(f.ctx, metadata)
			r := cfnIAMOwnerRequest("AccessKey", "RestrictedKey", cloudformation.Properties{"UserName": "restricted-key-owner", "Status": "Inactive"})
			r.CloudControl = true
			h := cfnIAMAccessKey{f.commands}
			created, err := h.Create(ctx, r)
			if !cfnMessagingMissing(err, "AccessDenied") || created.PhysicalID == "" || created.Attributes["SecretAccessKey"] == "" {
				t.Fatalf("status authorization failure lost native admission: %+v %v", created, err)
			}
			f.reopen()
			h = cfnIAMAccessKey{f.commands}
			recovered, err := h.RecoverCreation(ctx, r)
			if err != nil || recovered.PhysicalID != created.PhysicalID || recovered.Attributes["SecretAccessKey"] != created.Attributes["SecretAccessKey"] {
				t.Fatalf("post-admission recovery: %+v %v", recovered, err)
			}
			r.PhysicalID = created.PhysicalID
			model, err := h.Read(ctx, r)
			if err != nil || model["Status"] != "Active" {
				t.Fatalf("denied status mutation changed native state: %#v %v", model, err)
			}
			foreignScope := metadata
			foreignScope.AccountID = "999999999999"
			foreignScope.PrincipalARN = "arn:aws:iam::999999999999:root"
			foreignScope.PrincipalID = foreignScope.AccountID
			if result, err := h.RecoverCreation(awsctx.WithMetadata(ctx, foreignScope), r); !cfnComputeMissing(err) || result.PhysicalID != "" {
				t.Fatalf("private claim escaped account scope: %+v %v", result, err)
			}
			r.CloudControl = false
			if err := h.Delete(ctx, r); err != nil {
				t.Fatal(err)
			}
			if result, err := h.RecoverCreation(ctx, r); !cfnComputeMissing(err) || result.PhysicalID != "" {
				t.Fatalf("rollback retained native credential claim: %+v %v", result, err)
			}
		})
	}
}
