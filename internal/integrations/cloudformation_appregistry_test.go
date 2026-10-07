package integrations

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/servicecatalogappregistry"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/resourcegroups"
	appregistry "stackd/internal/services/servicecatalogappregistry"
	"stackd/storage/sqlite"
	sqlappregistry "stackd/storage/sqlite/servicecatalogappregistry"
)

const cfnAppRegTestStack = "arn:aws:cloudformation:us-east-1:123456789012:stack/workload/0001"

// The Resource Groups collaborators only acknowledge collection effects; the
// AppRegistry owner, its repositories and its private claims are real.
type cfnAppRegTestGroups struct{}

func (cfnAppRegTestGroups) CreateApplicationGroups(_ context.Context, application, _, _, _ string) (string, string, error) {
	return application + "/collection", application + "/tags", nil
}
func (cfnAppRegTestGroups) UpdateApplicationGroups(context.Context, string, string) error { return nil }
func (cfnAppRegTestGroups) DeleteApplicationGroups(context.Context, string) error         { return nil }
func (cfnAppRegTestGroups) AssociateApplicationStack(_ context.Context, _, _ string, stack resourcegroups.ApplicationResource) (string, error) {
	return stack.ARN, nil
}
func (cfnAppRegTestGroups) DisassociateApplicationCollection(context.Context, string, string) error {
	return nil
}
func (cfnAppRegTestGroups) AssociateApplicationTagValue(context.Context, string, string, string, string) (string, error) {
	return "", errors.New("tag-value collections are outside this regression")
}
func (cfnAppRegTestGroups) ApplicationTagValueResources(context.Context, string) ([]resourcegroups.ApplicationResource, error) {
	return nil, nil
}
func (cfnAppRegTestGroups) ApplyApplicationTags(context.Context, string, []resourcegroups.ApplicationResource, bool) error {
	return nil
}

type cfnAppRegTestStacks struct{}

func (cfnAppRegTestStacks) Resolve(_ context.Context, ref string) (resourcegroups.ApplicationResource, bool, error) {
	if ref != "workload" && ref != cfnAppRegTestStack {
		return resourcegroups.ApplicationResource{}, false, nil
	}
	return resourcegroups.ApplicationResource{ARN: cfnAppRegTestStack, Type: "AWS::CloudFormation::Stack", Name: "workload", Incarnation: cfnAppRegTestStack}, true, nil
}
func (s cfnAppRegTestStacks) StackResources(ctx context.Context, ref string) (resourcegroups.ApplicationResource, []resourcegroups.ApplicationResource, error) {
	root, found, err := s.Resolve(ctx, ref)
	if err == nil && !found {
		err = errors.New("stack does not exist")
	}
	return root, nil, err
}
func (cfnAppRegTestStacks) List(context.Context) ([]resourcegroups.ApplicationResource, error) {
	return nil, nil
}
func (cfnAppRegTestStacks) Tag(context.Context, resourcegroups.ApplicationResource, map[string]string) error {
	return nil
}
func (cfnAppRegTestStacks) Untag(context.Context, resourcegroups.ApplicationResource, []string) error {
	return nil
}

type cfnAppRegTestRoles struct{}

func (cfnAppRegTestRoles) Context(ctx context.Context, _ string, _ bool) (context.Context, error) {
	return ctx, nil
}

// cfnAppRegLostResponse loses one committed owner response.
type cfnAppRegLostResponse struct {
	*appregistry.Service
	operation string
}

func (o *cfnAppRegLostResponse) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	out, err := o.Service.ExecuteCommand(ctx, r)
	if err == nil && o.operation != "" && string(r.Operation.Name) == o.operation {
		o.operation = ""
		return nil, &awswire.Error{Code: "InternalServerException", Message: "response lost after native admission", StatusCode: 500}
	}
	return out, err
}

type cfnAppRegFixture struct {
	ctx      context.Context
	owner    *cfnAppRegLostResponse
	commands StepFunctionsCommands
	reopen   func()
}

func newCfnAppRegFixture(t *testing.T, backend string) *cfnAppRegFixture {
	t.Helper()
	f := &cfnAppRegFixture{ctx: awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})}
	var repository appregistry.Repository = appregistry.NewMemoryRepository(nil)
	var db *sql.DB
	path := filepath.Join(t.TempDir(), "appregistry.sqlite")
	open := func() {
		if backend == "sqlite" {
			var err error
			if db, err = sqlite.Open(f.ctx, path); err != nil {
				t.Fatal(err)
			}
			repository = sqlappregistry.New(db)
		}
		f.owner = &cfnAppRegLostResponse{Service: appregistry.New(appregistry.Config{Repository: repository, Groups: cfnAppRegTestGroups{}, Resources: cfnAppRegTestStacks{}, Roles: cfnAppRegTestRoles{}})}
		f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"servicecatalogappregistry": f.owner})
	}
	open()
	t.Cleanup(func() {
		if db != nil {
			_ = db.Close()
		}
	})
	f.reopen = func() {
		if db != nil {
			_ = db.Close()
		}
		open()
	}
	return f
}

func cfnAppRegRequest(kind, logical, token string, p cloudformation.Properties) cloudformation.ResourceRequest {
	return cloudformation.ResourceRequest{StackID: "arn:aws:cloudformation:us-east-1:123456789012:stack/registry/0002", StackName: "registry", LogicalID: logical, Type: "AWS::ServiceCatalogAppRegistry::" + kind, Token: token, Properties: p}
}

// direct issues an ordinary IAM-authorized API call without any controller claim.
func (f *cfnAppRegFixture) direct(t *testing.T, operation string, in map[string]any) {
	t.Helper()
	if err := cfnComputeRun(f.ctx, f.commands, "servicecatalogappregistry", operation, in); err != nil {
		t.Fatalf("%s: %v", operation, err)
	}
}

func (f *cfnAppRegFixture) attributeLinked(t *testing.T, application, group string) bool {
	t.Helper()
	ids, err := cfnAppRegPages(f.ctx, f.commands, "ListAttributeGroupsForApplication", map[string]any{"Application": application}, func(o *api.ListAttributeGroupsForApplicationOutput) ([]api.AttributeGroupDetails, *api.NextToken) {
		return o.AttributeGroupsDetails, o.NextToken
	})
	if err != nil {
		t.Fatal(err)
	}
	return slices.ContainsFunc(ids, func(d api.AttributeGroupDetails) bool { return cfnComputeValue(d.Arn) == group })
}

func TestCloudFormationAppRegistryPrivateEdgeClaims(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCfnAppRegFixture(t, backend)
			ctx := f.ctx
			appReq := cfnAppRegRequest("Application", "App", "app-token", cloudformation.Properties{"Name": "workload"})
			app, err := (cfnAppRegApplication{f.commands}).Create(ctx, appReq)
			if err != nil {
				t.Fatal(err)
			}
			appReq.PhysicalID = app.PhysicalID
			appARN := app.Attributes["Arn"].(string)
			groupReq := cfnAppRegRequest("AttributeGroup", "Settings", "group-token", cloudformation.Properties{"Name": "settings", "Attributes": map[string]any{"tier": "gold"}})
			group, err := (cfnAppRegAttributeGroup{f.commands}).Create(ctx, groupReq)
			if err != nil {
				t.Fatal(err)
			}
			groupReq.PhysicalID = group.PhysicalID
			groupARN := group.Attributes["Arn"].(string)
			edgeReq := cfnAppRegRequest("AttributeGroupAssociation", "Link", "link-token", cloudformation.Properties{"Application": app.PhysicalID, "AttributeGroup": group.PhysicalID})
			edgeID := appARN + "|" + groupARN

			// An independent direct edge carrying the former public marker is never adopted.
			f.direct(t, "AssociateAttributeGroup", map[string]any{"Application": appARN, "AttributeGroup": groupARN})
			f.direct(t, "TagResource", map[string]any{"ResourceArn": appARN, "Tags": map[string]string{cfnComputeTagPrefix + "attribute-group-" + cfnMessagingHash(groupARN)[:20]: cfnMessagingMarker(edgeReq)}})
			if out, err := (cfnAppRegAttributeAssociation{f.commands}).Create(ctx, edgeReq); err == nil || out.PhysicalID != "" {
				t.Fatalf("CloudFormation adopted an independent edge: %+v %v", out, err)
			}
			if out, err := (cfnAppRegAttributeAssociation{f.commands}).RecoverCreation(ctx, edgeReq); !cfnAppRegMissing(err) || out.PhysicalID != "" {
				t.Fatalf("recovery adopted an independent edge: %+v %v", out, err)
			}
			counterfeit := edgeReq
			counterfeit.PhysicalID = edgeID
			counterfeit.Previous = counterfeit.Properties
			if _, err := (cfnAppRegAttributeAssociation{f.commands}).Update(ctx, counterfeit); err == nil {
				t.Fatal("counterfeit marker authorized no-op attribute association update")
			}
			if err := (cfnAppRegAttributeAssociation{f.commands}).Delete(ctx, counterfeit); err != nil || !f.attributeLinked(t, appARN, groupARN) {
				t.Fatalf("counterfeit public marker deleted an independent edge: %v", err)
			}
			// Cloud Control acts under current IAM authority without a claim.
			direct := counterfeit
			direct.CloudControl = true
			if err := (cfnAppRegAttributeAssociation{f.commands}).Delete(ctx, direct); err != nil || f.attributeLinked(t, appARN, groupARN) {
				t.Fatalf("Cloud Control disassociation: %v", err)
			}

			// Genuine creation admits a private claim; a lost response keeps its authentic identity.
			f.owner.operation = "AssociateAttributeGroup"
			out, err := (cfnAppRegAttributeAssociation{f.commands}).Create(ctx, edgeReq)
			if err == nil || out.PhysicalID != edgeID {
				t.Fatalf("post-admission failure lost authentic identity: %+v %v", out, err)
			}
			if replay, err := (cfnAppRegAttributeAssociation{f.commands}).Create(ctx, edgeReq); err != nil || replay.PhysicalID != edgeID {
				t.Fatalf("exact-token replay: %+v %v", replay, err)
			}
			f.reopen()
			if recovered, err := (cfnAppRegAttributeAssociation{f.commands}).RecoverCreation(ctx, edgeReq); err != nil || recovered.PhysicalID != edgeID {
				t.Fatalf("private edge claim did not survive reopen: %+v %v", recovered, err)
			}
			other := edgeReq
			other.Token = "never-admitted"
			if recovered, err := (cfnAppRegAttributeAssociation{f.commands}).RecoverCreation(ctx, other); !cfnAppRegMissing(err) || recovered.PhysicalID != "" {
				t.Fatalf("another incarnation recovered this edge: %+v %v", recovered, err)
			}
			read := edgeReq
			read.PhysicalID, read.CloudControl = edgeID, true
			props, err := (cfnAppRegAttributeAssociation{f.commands}).Read(ctx, read)
			if err != nil {
				t.Fatal(err)
			}
			for key := range props {
				if !slices.Contains([]string{"Application", "AttributeGroup", "ApplicationArn", "AttributeGroupArn"}, key) {
					t.Fatalf("Read exposed private state %q", key)
				}
			}

			// A direct recreation after a direct removal is foreign to the stack.
			f.direct(t, "DisassociateAttributeGroup", map[string]any{"Application": appARN, "AttributeGroup": groupARN})
			f.direct(t, "AssociateAttributeGroup", map[string]any{"Application": appARN, "AttributeGroup": groupARN})
			f.reopen()
			if recovered, err := (cfnAppRegAttributeAssociation{f.commands}).RecoverCreation(ctx, edgeReq); !cfnAppRegMissing(err) || recovered.PhysicalID != "" {
				t.Fatalf("foreign recreation was recovered as owned: %+v %v", recovered, err)
			}
			owned := edgeReq
			owned.PhysicalID = edgeID
			if err := (cfnAppRegAttributeAssociation{f.commands}).Delete(ctx, owned); err != nil || !f.attributeLinked(t, appARN, groupARN) {
				t.Fatalf("stale incarnation deleted a foreign recreation: %v", err)
			}
			f.direct(t, "DisassociateAttributeGroup", map[string]any{"Application": appARN, "AttributeGroup": groupARN})
			if _, err := (cfnAppRegAttributeAssociation{f.commands}).Create(ctx, edgeReq); err != nil {
				t.Fatal(err)
			}
			if err := (cfnAppRegAttributeAssociation{f.commands}).Delete(ctx, owned); err != nil || f.attributeLinked(t, appARN, groupARN) {
				t.Fatalf("owning incarnation could not disassociate: %v", err)
			}

			// Resource associations: same private-claim contract on the edge itself.
			stackReq := cfnAppRegRequest("ResourceAssociation", "Stack", "stack-token", cloudformation.Properties{"Application": app.PhysicalID, "Resource": "workload", "ResourceType": "CFN_STACK"})
			stackID := appARN + "|" + cfnAppRegTestStack + "|CFN_STACK"
			stackLinked := func() bool {
				t.Helper()
				r := stackReq
				r.PhysicalID, r.CloudControl = stackID, true
				_, err := (cfnAppRegResourceAssociation{f.commands}).Read(ctx, r)
				if err != nil && !cfnAppRegMissing(err) {
					t.Fatal(err)
				}
				return err == nil
			}
			f.direct(t, "AssociateResource", map[string]any{"Application": appARN, "Resource": "workload", "ResourceType": "CFN_STACK"})
			f.direct(t, "TagResource", map[string]any{"ResourceArn": appARN, "Tags": map[string]string{cfnComputeTagPrefix + "resource-" + cfnMessagingHash("CFN_STACK/workload")[:20]: cfnMessagingMarker(stackReq)}})
			if out, err := (cfnAppRegResourceAssociation{f.commands}).Create(ctx, stackReq); err == nil || out.PhysicalID != "" {
				t.Fatalf("CloudFormation adopted an independent resource edge: %+v %v", out, err)
			}
			stackOwned := stackReq
			stackOwned.PhysicalID = stackID
			stackOwned.Previous = stackOwned.Properties
			if _, err := (cfnAppRegResourceAssociation{f.commands}).Update(ctx, stackOwned); err == nil {
				t.Fatal("counterfeit marker authorized no-op resource association update")
			}
			if err := (cfnAppRegResourceAssociation{f.commands}).Delete(ctx, stackOwned); err != nil || !stackLinked() {
				t.Fatalf("stack incarnation deleted an independent resource edge: %v", err)
			}
			f.direct(t, "DisassociateResource", map[string]any{"Application": appARN, "Resource": cfnAppRegTestStack, "ResourceType": "CFN_STACK"})
			f.owner.operation = "AssociateResource"
			if out, err := (cfnAppRegResourceAssociation{f.commands}).Create(ctx, stackReq); err == nil || out.PhysicalID != stackID {
				t.Fatalf("post-admission failure lost authentic resource identity: %+v %v", out, err)
			}
			f.reopen()
			if recovered, err := (cfnAppRegResourceAssociation{f.commands}).RecoverCreation(ctx, stackReq); err != nil || recovered.PhysicalID != stackID {
				t.Fatalf("private resource claim did not survive reopen: %+v %v", recovered, err)
			}
			if replay, err := (cfnAppRegResourceAssociation{f.commands}).Create(ctx, stackReq); err != nil || replay.PhysicalID != stackID {
				t.Fatalf("exact-token resource replay: %+v %v", replay, err)
			}
			f.direct(t, "DisassociateResource", map[string]any{"Application": appARN, "Resource": cfnAppRegTestStack, "ResourceType": "CFN_STACK"})
			f.direct(t, "AssociateResource", map[string]any{"Application": appARN, "Resource": "workload", "ResourceType": "CFN_STACK"})
			if recovered, err := (cfnAppRegResourceAssociation{f.commands}).RecoverCreation(ctx, stackReq); !cfnAppRegMissing(err) || recovered.PhysicalID != "" {
				t.Fatalf("foreign resource recreation was recovered as owned: %+v %v", recovered, err)
			}
			if err := (cfnAppRegResourceAssociation{f.commands}).Delete(ctx, stackOwned); err != nil || !stackLinked() {
				t.Fatalf("stale incarnation deleted a foreign resource recreation: %v", err)
			}
			f.direct(t, "DisassociateResource", map[string]any{"Application": appARN, "Resource": cfnAppRegTestStack, "ResourceType": "CFN_STACK"})
		})
	}
}

func TestCloudFormationAppRegistryParentReceipts(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCfnAppRegFixture(t, backend)
			ctx := f.ctx
			appReq := cfnAppRegRequest("Application", "App", "app-token", cloudformation.Properties{"Name": "workload"})
			f.owner.operation = "CreateApplication"
			app, err := (cfnAppRegApplication{f.commands}).Create(ctx, appReq)
			if err == nil || app.PhysicalID == "" {
				t.Fatalf("post-admission failure lost authentic application: %+v %v", app, err)
			}
			f.reopen()
			if recovered, err := (cfnAppRegApplication{f.commands}).RecoverCreation(ctx, appReq); err != nil || recovered.PhysicalID != app.PhysicalID {
				t.Fatalf("application receipt did not survive reopen: %+v %v", recovered, err)
			}
			other := appReq
			other.Token = "never-admitted"
			if recovered, err := (cfnAppRegApplication{f.commands}).RecoverCreation(ctx, other); !cfnAppRegMissing(err) || recovered.PhysicalID != "" {
				t.Fatalf("another incarnation recovered the application: %+v %v", recovered, err)
			}

			// A directly created application carrying counterfeit public markers is never owned.
			forged, err := cfnComputeCall[api.CreateApplicationOutput](ctx, f.commands, "servicecatalogappregistry", "CreateApplication", map[string]any{"Name": "forged", "ClientToken": "direct-token", "Tags": map[string]string{
				cfnComputeTagPrefix + "stack-id": appReq.StackID, cfnComputeTagPrefix + "logical-id": appReq.LogicalID, cfnComputeTagPrefix + "incarnation": appReq.Token,
			}})
			if err != nil {
				t.Fatal(err)
			}
			counterfeit := appReq
			counterfeit.PhysicalID = cfnComputeValue(forged.Application.Id)
			counterfeit.Previous = appReq.Properties
			counterfeit.Properties = cloudformation.Properties{"Name": "forged", "Description": "hijacked"}
			if _, err := (cfnAppRegApplication{f.commands}).Update(ctx, counterfeit); err == nil {
				t.Fatal("counterfeit tags authorized an application update")
			}
			if err := (cfnAppRegApplication{f.commands}).Delete(ctx, counterfeit); err != nil {
				t.Fatal(err)
			}
			got, err := (cfnAppRegApplication{f.commands}).get(ctx, counterfeit.PhysicalID)
			if err != nil || cfnComputeValue(got.Description) != "" {
				t.Fatalf("counterfeit tags mutated a foreign application: %+v %v", got, err)
			}
			// Cloud Control remains governed by current IAM alone.
			direct := counterfeit
			direct.CloudControl = true
			if err := (cfnAppRegApplication{f.commands}).Delete(ctx, direct); err != nil {
				t.Fatal(err)
			}

			owned := appReq
			owned.PhysicalID = app.PhysicalID
			owned.Previous = appReq.Properties
			owned.Properties = cloudformation.Properties{"Name": "workload", "Description": "updated"}
			if _, err := (cfnAppRegApplication{f.commands}).Update(ctx, owned); err != nil {
				t.Fatal(err)
			}

			groupReq := cfnAppRegRequest("AttributeGroup", "Settings", "group-token", cloudformation.Properties{"Name": "settings", "Attributes": map[string]any{"tier": "gold"}})
			group, err := (cfnAppRegAttributeGroup{f.commands}).Create(ctx, groupReq)
			if err != nil {
				t.Fatal(err)
			}
			f.reopen()
			if recovered, err := (cfnAppRegAttributeGroup{f.commands}).RecoverCreation(ctx, groupReq); err != nil || recovered.PhysicalID != group.PhysicalID {
				t.Fatalf("attribute group receipt did not survive reopen: %+v %v", recovered, err)
			}
			stale := groupReq
			stale.Token, stale.PhysicalID = "previous-incarnation", group.PhysicalID
			if err := (cfnAppRegAttributeGroup{f.commands}).Delete(ctx, stale); err != nil {
				t.Fatal(err)
			}
			if _, err := (cfnAppRegAttributeGroup{f.commands}).get(ctx, group.PhysicalID); err != nil {
				t.Fatalf("another incarnation deleted the attribute group: %v", err)
			}
			groupReq.PhysicalID = group.PhysicalID
			if err := (cfnAppRegAttributeGroup{f.commands}).Delete(ctx, groupReq); err != nil {
				t.Fatal(err)
			}
			if err := (cfnAppRegApplication{f.commands}).Delete(ctx, owned); err != nil {
				t.Fatal(err)
			}
			if _, err := (cfnAppRegApplication{f.commands}).get(ctx, app.PhysicalID); !cfnAppRegMissing(err) {
				t.Fatalf("owning incarnation did not delete its application: %v", err)
			}
		})
	}
}

func TestCloudFormationAppRegistryClientTokenPayloadNeverClaims(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCfnAppRegFixture(t, backend)
			for _, kind := range []string{"Application", "AttributeGroup"} {
				for _, cloudControl := range []bool{false, true} {
					mode := "stack"
					if cloudControl {
						mode = "cloudcontrol"
					}
					t.Run(kind+"/"+mode, func(t *testing.T) {
						properties := cloudformation.Properties{"Name": "counterfeit-" + kind + "-" + mode}
						if kind == "AttributeGroup" {
							properties["Attributes"] = map[string]any{"tier": "gold"}
						}
						r := cfnAppRegRequest(kind, kind+"-"+mode, "public-request-token-"+mode, properties)
						r.CloudControl = cloudControl
						in := map[string]any{"Name": properties["Name"], "ClientToken": cfnAppRegClaim(r), "Tags": map[string]string{}}
						if kind == "AttributeGroup" {
							in["Attributes"], _ = cfnComputeDocument(properties["Attributes"])
						}
						// Matching every payload field, including the hashed ClientToken,
						// must still confer no provenance on a direct SDK-created parent.
						f.direct(t, "Create"+kind, in)
						f.reopen()
						var h cloudformation.ResourceHandler = cfnAppRegApplication{f.commands}
						if kind == "AttributeGroup" {
							h = cfnAppRegAttributeGroup{f.commands}
						}
						if out, err := h.Create(f.ctx, r); err == nil || out.PhysicalID != "" {
							t.Fatalf("matching ClientToken payload adopted independent parent: %+v %v", out, err)
						}
						if recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r); !cfnAppRegMissing(err) || recovered.PhysicalID != "" {
							t.Fatalf("ClientToken payload authorized recovery: %+v %v", recovered, err)
						}
						// Ordinary native ClientToken replay stays intact and yields the
						// foreign ID, without adding or borrowing a controller claim.
						var id string
						if kind == "Application" {
							out, err := cfnComputeCall[api.CreateApplicationOutput](f.ctx, f.commands, "servicecatalogappregistry", "CreateApplication", in)
							if err != nil {
								t.Fatal(err)
							}
							id = cfnComputeValue(out.Application.Id)
						} else {
							out, err := cfnComputeCall[api.CreateAttributeGroupOutput](f.ctx, f.commands, "servicecatalogappregistry", "CreateAttributeGroup", in)
							if err != nil {
								t.Fatal(err)
							}
							id = cfnComputeValue(out.AttributeGroup.Id)
						}
						r.PhysicalID, r.CloudControl = id, false
						r.Previous = r.Properties
						if _, err := h.Update(f.ctx, r); err == nil {
							t.Fatal("matching ClientToken payload authorized stack mutation")
						}
						if err := h.Delete(f.ctx, r); err != nil {
							t.Fatal(err)
						}
						// SDK and Cloud Control can read/delete the intact foreign parent.
						direct := r
						direct.CloudControl = true
						if _, err := h.(cloudformation.ResourceReader).Read(f.ctx, direct); err != nil {
							t.Fatal(err)
						}
						if err := h.Delete(f.ctx, direct); err != nil {
							t.Fatal(err)
						}
						// Cloud Control Create must now privately claim, just as stack
						// Create does, and exact-token recovery survives SQLite reopen.
						r.PhysicalID, r.CloudControl = "", cloudControl
						out, err := h.Create(f.ctx, r)
						if err != nil || out.PhysicalID == "" {
							t.Fatalf("trusted admission: %+v %v", out, err)
						}
						f.reopen()
						h = cfnAppRegApplication{f.commands}
						if kind == "AttributeGroup" {
							h = cfnAppRegAttributeGroup{f.commands}
						}
						if recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r); err != nil || recovered.PhysicalID != out.PhysicalID {
							t.Fatalf("trusted parent provenance lost after reopen: %+v %v", recovered, err)
						}
						denied := awsctx.WithMetadata(f.ctx, awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:user/no-permissions", PrincipalID: "no-permissions"})
						if recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(denied, r); err == nil || cfnAppRegMissing(err) || recovered.PhysicalID != "" {
							t.Fatalf("private provenance bypassed current IAM: %+v %v", recovered, err)
						}
					})
				}
			}
		})
	}
}
