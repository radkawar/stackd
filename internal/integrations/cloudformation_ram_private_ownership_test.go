package integrations

import (
	"testing"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ram"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ram"
	"stackd/internal/services/ssm"
	"stackd/storage/memory"
	sqlram "stackd/storage/sqlite/ram"
	sqlssm "stackd/storage/sqlite/ssm"
)

type cfnRAMPrivateFixture struct {
	*cfnOrgSSOOwnerFixture
	backend        string
	repository     ram.Repository
	parameters     ssm.Repository
	owner          *ram.Service
	parameterOwner *ssm.Service
	commands       StepFunctionsCommands
}

func newCFNRAMPrivateFixture(t *testing.T, backend string) *cfnRAMPrivateFixture {
	t.Helper()
	f := &cfnRAMPrivateFixture{cfnOrgSSOOwnerFixture: newCFNOrgSSOOwnerFixture(t, backend), backend: backend}
	if backend == "memory" {
		domain := memory.NewDomain()
		f.repository = ram.NewMemoryRepository(domain)
		f.parameters = ssm.NewMemoryRepository(domain)
	}
	f.startRAM(t)
	t.Cleanup(func() { _ = f.parameterOwner.Close() })
	return f
}
func (f *cfnRAMPrivateFixture) startRAM(t *testing.T) {
	t.Helper()
	if f.backend == "sqlite" {
		f.repository = sqlram.New(f.db)
		f.parameters = sqlssm.New(f.db)
	}
	auth := authorization.New(f.iam, nil)
	f.parameterOwner = ssm.New(ssm.Config{Repository: f.parameters, Authorizer: auth})
	f.owner = ram.New(ram.Config{Repository: f.repository, Authorizer: auth, Resources: RAMResources{SSM: f.parameterOwner}, ResourceTypes: []string{"ssm:Parameter"}})
	f.parameterOwner.SetSharing(RAMParameters{RAM: f.owner})
	f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ram": f.owner, "ssm": f.parameterOwner, "iam": f.iam})
}
func (f *cfnRAMPrivateFixture) reopen(t *testing.T) {
	t.Helper()
	if e := f.parameterOwner.Close(); e != nil {
		t.Fatal(e)
	}
	f.cfnOrgSSOOwnerFixture.restart(t)
	f.startRAM(t)
}
func (f *cfnRAMPrivateFixture) native(t *testing.T, action string, input map[string]any) {
	t.Helper()
	if e := cfnComputeRun(f.ctx, f.commands, "ram", action, input); e != nil {
		t.Fatalf("native RAM %s: %v", action, e)
	}
}
func (f *cfnRAMPrivateFixture) permission(t *testing.T, arn string) ram.Permission {
	t.Helper()
	var p ram.Permission
	if e := f.repository.View(f.ctx, func(r ram.Reader) error { var e error; p, e = r.Permission(arn); return e }); e != nil {
		t.Fatal(e)
	}
	return p
}

func TestCFNRAMPermissionPrivateClaimAndSameARNRecreation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNRAMPrivateFixture(t, backend)
			user, policy := cfnGovernanceUser(t, f.cfnOrgSSOOwnerFixture, "ram-permission-controller")
			h := cfnRAMPermission{f.commands}
			r := cfnWorkflowOwnerRequest("AWS::RAM::Permission", "Permission", cloudformation.Properties{"Name": "private-permission", "ResourceType": "ssm:Parameter", "PolicyTemplate": map[string]any{"Effect": "Allow", "Action": []any{"ssm:GetParameter"}}, "Tags": []any{map[string]any{"Key": "team", "Value": "one"}}})
			native, e := cfnOrgIdentityCall[api.CreatePermissionResponse](f.ctx, f.commands, "ram", "CreatePermission", map[string]any{"name": "private-permission", "resourceType": "ssm:Parameter", "policyTemplate": `{"Effect":"Allow","Action":["ssm:GetParameter"]}`, "clientToken": "native-counterfeit", "tags": cfnRAMWireTags(map[string]string{cfnComputeTagPrefix + "stack-id": r.StackID, cfnComputeTagPrefix + "logical-id": r.LogicalID, cfnComputeTagPrefix + "incarnation": r.Token})})
			if e != nil {
				t.Fatal(e)
			}
			counterfeit := cfnComputeValue(native.Permission.Arn)
			result, e := h.RecoverCreation(user, r)
			cfnOrgSSONotAdmitted(t, "counterfeit permission", result, e)
			if result, e = h.Create(user, r); e == nil || result.PhysicalID != "" {
				t.Fatalf("create adopted public markers: %+v %v", result, e)
			}
			stale := r
			stale.PhysicalID = counterfeit
			if _, e = h.Update(user, stale); e == nil {
				t.Fatal("no-op update adopted native permission")
			}
			if e = h.Delete(user, stale); e == nil {
				t.Fatal("native permission deleted through forged markers")
			}
			direct := stale
			direct.CloudControl = true
			direct.Previous = direct.Properties
			if _, e = h.Update(user, direct); e != nil {
				t.Fatal(e)
			}
			if e = h.Delete(user, stale); e == nil {
				t.Fatal("Cloud Control update adopted native permission")
			}
			f.native(t, "DeletePermission", map[string]any{"permissionArn": counterfeit})

			r.CloudControl = true
			lossy := cfnRAMPermission{NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ram": &cfnDeveloperLostReply{owner: f.owner, action: "CreatePermission"}})}
			admitted, e := lossy.Create(user, r)
			if e == nil || admitted.PhysicalID == "" {
				t.Fatalf("lost native reply discarded private identity: %+v %v", admitted, e)
			}
			r.PhysicalID = admitted.PhysicalID
			r.CloudControl = false
			// Native AWS captures prove permission/<Name>; the lifetime ID is private.
			if r.PhysicalID != counterfeit {
				t.Fatalf("public permission ARN stopped being name-derived: %s", r.PhysicalID)
			}
			before := f.permission(t, r.PhysicalID)
			if before.CloudFormationOwner == "" || before.ObjectID == "" {
				t.Fatal("native permission lacks an atomically admitted private claim/lifetime")
			}
			cfnOrgSSONoPublicClaim(t, "RAM permission", before.Tags)
			f.native(t, "UntagResource", map[string]any{"resourceArn": r.PhysicalID, "tagKeys": []string{"team"}})
			f.native(t, "TagResource", map[string]any{"resourceArn": r.PhysicalID, "tags": cfnRAMWireTags(map[string]string{cfnComputeTagPrefix + "incarnation": "counterfeit"})})
			f.reopen(t)
			h = cfnRAMPermission{f.commands}
			result, e = h.RecoverCreation(user, r)
			cfnOrgSSOSame(t, "permission recovery after public tag mutation/reopen", r.PhysicalID, result, e)
			result, e = h.Create(user, r)
			cfnOrgSSOSame(t, "permission create replay", r.PhysicalID, result, e)
			r.Previous = r.Properties
			if _, e = h.Update(user, r); e != nil {
				t.Fatal(e)
			}
			direct = r
			direct.CloudControl = true
			if _, e = h.Update(user, direct); e != nil {
				t.Fatal(e)
			}
			if after := f.permission(t, r.PhysicalID); after.ObjectID != before.ObjectID || after.CloudFormationOwner != before.CloudFormationOwner {
				t.Fatal("ordinary mutation changed native lifetime/claim")
			}
			foreign := cfnOrgSSOOther(r)
			if _, e = h.Update(user, foreign); e == nil {
				t.Fatal("foreign no-op update passed private claim")
			}
			if e = h.Delete(user, foreign); e == nil {
				t.Fatal("foreign delete passed private claim")
			}
			regional := awsctx.FromContext(user)
			regional.Region = "us-west-2"
			result, e = h.RecoverCreation(awsctx.WithMetadata(user, regional), r)
			cfnOrgSSONotAdmitted(t, "permission different region", result, e)
			policy("ram:GetPermission", "ram:ListPermissions")
			if result, e = h.RecoverCreation(user, r); e == nil || result.PhysicalID != "" {
				t.Fatalf("IAM-denied recovery exposed an identity: %+v %v", result, e)
			}
			if _, e = h.Update(user, r); e == nil {
				t.Fatal("IAM-denied no-op update succeeded")
			}
			if e = h.Delete(user, r); e == nil {
				t.Fatal("IAM-denied delete succeeded")
			}
			policy()

			// Both stale controller requests and stale native token receipts are fenced
			// from a new lifetime at the same native ARN, including after SQL reopening.
			f.native(t, "DeletePermission", map[string]any{"permissionArn": r.PhysicalID, "clientToken": "native-delete-old"})
			recreated, e := cfnOrgIdentityCall[api.CreatePermissionResponse](f.ctx, f.commands, "ram", "CreatePermission", map[string]any{"name": "private-permission", "resourceType": "ssm:Parameter", "policyTemplate": `{"Effect":"Allow","Action":["ssm:GetParameter"]}`, "clientToken": "native-recreated"})
			if e != nil {
				t.Fatal(e)
			}
			if cfnComputeValue(recreated.Permission.Arn) != r.PhysicalID {
				t.Fatal("native same-name recreation changed the public ARN")
			}
			f.reopen(t)
			h = cfnRAMPermission{f.commands}
			after := f.permission(t, r.PhysicalID)
			if after.ObjectID == before.ObjectID || after.CloudFormationOwner != "" {
				t.Fatal("recreation retained old lifetime/claim")
			}
			result, e = h.RecoverCreation(user, r)
			cfnOrgSSONotAdmitted(t, "permission stale creation", result, e)
			if e = h.Delete(user, r); e == nil {
				t.Fatal("stale private controller deleted replacement permission")
			}
			if _, e = cfnOrgIdentityCall[api.DeletePermissionResponse](f.ctx, f.commands, "ram", "DeletePermission", map[string]any{"permissionArn": r.PhysicalID, "clientToken": "native-delete-old"}); e == nil {
				t.Fatal("old delete receipt silently acknowledged replacement lifetime")
			}
			if f.permission(t, r.PhysicalID).Status == "DELETED" {
				t.Fatal("replacement permission was damaged")
			}
		})
	}
}

func TestCFNRAMShareAndEveryRelationshipPrivateRecovery(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, kind := range []string{"ResourceShare", "PrincipalAssociation", "ResourceAssociation", "PermissionAssociation"} {
			t.Run(backend+"/"+kind, func(t *testing.T) {
				f := newCFNRAMPrivateFixture(t, backend)
				user, policy := cfnGovernanceUser(t, f.cfnOrgSSOOwnerFixture, "ram-edge-controller")
				props := cloudformation.Properties{"Name": "private-share", "Tags": []any{map[string]any{"Key": "team", "Value": "one"}}}
				createAction := "CreateResourceShare"
				if kind != "ResourceShare" {
					base, e := cfnOrgIdentityCall[api.CreateResourceShareResponse](f.ctx, f.commands, "ram", "CreateResourceShare", map[string]any{"name": "native-dependency", "clientToken": "base"})
					if e != nil {
						t.Fatal(e)
					}
					props = cloudformation.Properties{"ResourceShareArn": cfnComputeValue(base.ResourceShare.ResourceShareArn)}
					switch kind {
					case "PrincipalAssociation":
						props["Principal"] = "222222222222"
						createAction = "AssociateResourceShare"
					case "ResourceAssociation":
						if e := cfnComputeRun(f.ctx, f.commands, "ssm", "PutParameter", map[string]any{"Name": "private-ram-resource", "Value": "live", "Type": "String", "Tier": "Advanced"}); e != nil {
							t.Fatal(e)
						}
						m := awsctx.FromContext(f.ctx)
						props["ResourceArn"] = "arn:" + m.Partition + ":ssm:" + m.Region + ":" + m.AccountID + ":parameter/private-ram-resource"
						createAction = "AssociateResourceShare"
					case "PermissionAssociation":
						p, e := cfnOrgIdentityCall[api.CreatePermissionResponse](f.ctx, f.commands, "ram", "CreatePermission", map[string]any{"name": "native-edge-permission", "resourceType": "ssm:Parameter", "policyTemplate": `{"Effect":"Allow","Action":["ssm:GetParameter"]}`, "clientToken": "edge-permission"})
						if e != nil {
							t.Fatal(e)
						}
						props["PermissionArn"] = cfnComputeValue(p.Permission.Arn)
						createAction = "AssociateResourceSharePermission"
					}
				}
				r := cfnWorkflowOwnerRequest("AWS::RAM::"+kind, kind, props)
				r.CloudControl = true
				commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ram": &cfnDeveloperLostReply{owner: f.owner, action: createAction}})
				h := CloudFormationOrganizationIdentityHandlers(commands)[r.Type]
				admitted, e := h.Create(user, r)
				if e == nil || admitted.PhysicalID == "" {
					t.Fatalf("lost edge/share admission: %+v %v", admitted, e)
				}
				r.PhysicalID = admitted.PhysicalID
				r.CloudControl = false
				f.reopen(t)
				h = CloudFormationOrganizationIdentityHandlers(f.commands)[r.Type]
				result, e := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(user, r)
				cfnOrgSSOSame(t, "RAM private recovery", r.PhysicalID, result, e)
				if _, e = h.Update(user, r); e != nil {
					t.Fatal(e)
				}
				foreign := cfnOrgSSOOther(r)
				if _, e = h.Update(user, foreign); e == nil {
					t.Fatal("foreign no-op update succeeded")
				}
				if e = h.Delete(user, foreign); e == nil {
					t.Fatal("foreign deletion succeeded")
				}
				policy("ram:GetResourceShares", "ram:GetResourceShareAssociations", "ram:ListPermissionAssociations")
				if result, e = h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(user, r); e == nil || result.PhysicalID != "" {
					t.Fatalf("IAM-denied private recovery: %+v %v", result, e)
				}
				if _, e = h.Update(user, r); e == nil {
					t.Fatal("IAM-denied no-op update succeeded")
				}
				policy()
				if kind == "ResourceShare" {
					f.native(t, "UntagResource", map[string]any{"resourceArn": r.PhysicalID, "tagKeys": []string{"team"}})
					f.native(t, "TagResource", map[string]any{"resourceArn": r.PhysicalID, "tags": cfnRAMWireTags(map[string]string{cfnComputeTagPrefix + "incarnation": "foreign"})})
					if _, e = h.Update(user, r); e != nil {
						t.Fatal(e)
					}
					if e = h.Delete(user, r); e != nil {
						t.Fatal(e)
					}
					result, e = h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(user, r)
					cfnOrgSSONotAdmitted(t, "deleted share", result, e)
					return
				}
				// A direct same-edge no-op preserves the existing private owner. Removing
				// then recreating that native edge clears it rather than adopting it again.
				share := props["ResourceShareArn"]
				associate := map[string]any{"resourceShareArn": share}
				disassociate := map[string]any{"resourceShareArn": share}
				addAction, removeAction := "AssociateResourceShare", "DisassociateResourceShare"
				switch kind {
				case "PrincipalAssociation":
					associate["principals"] = []any{props["Principal"]}
					disassociate["principals"] = []any{props["Principal"]}
				case "ResourceAssociation":
					associate["resourceArns"] = []any{props["ResourceArn"]}
					disassociate["resourceArns"] = []any{props["ResourceArn"]}
				case "PermissionAssociation":
					associate["permissionArn"] = props["PermissionArn"]
					associate["replace"] = true
					disassociate["permissionArn"] = props["PermissionArn"]
					addAction = "AssociateResourceSharePermission"
					removeAction = "DisassociateResourceSharePermission"
				}
				f.native(t, addAction, associate)
				if _, e = h.Update(user, r); e != nil {
					t.Fatalf("ordinary same-edge mutation lost claim: %v", e)
				}
				if kind == "ResourceAssociation" {
					if e := cfnComputeRun(f.ctx, f.commands, "ssm", "DeleteParameter", map[string]any{"Name": "private-ram-resource"}); e != nil {
						t.Fatal(e)
					}
					if e := cfnComputeRun(f.ctx, f.commands, "ssm", "PutParameter", map[string]any{"Name": "private-ram-resource", "Value": "replacement", "Type": "String", "Tier": "Advanced"}); e != nil {
						t.Fatal(e)
					}
				} else {
					f.native(t, removeAction, disassociate)
				}
				f.native(t, addAction, associate)
				f.reopen(t)
				h = CloudFormationOrganizationIdentityHandlers(f.commands)[r.Type]
				result, e = h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(user, r)
				cfnOrgSSONotAdmitted(t, "recreated native edge", result, e)
				if e = h.Delete(user, r); e == nil {
					t.Fatal("stale incarnation removed replacement edge")
				}
				if _, e := h.(cloudformation.ResourceReader).Read(f.ctx, r); e != nil {
					t.Fatalf("replacement native edge was damaged: %v", e)
				}
			})
		}
	}
}
