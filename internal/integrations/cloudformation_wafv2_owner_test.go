package integrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/wafv2"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/wafv2"
	"stackd/storage/sqlite"
	wafstore "stackd/storage/sqlite/wafv2"
)

// This authorizer preserves real root IAM evaluation, with a deterministic
// current-policy denial after native creation has already committed.
type wafOwnerPolicy struct {
	base authorization.Authorizer
	deny string
}

func (p *wafOwnerPolicy) Authorize(ctx context.Context, r authorization.Request) *awswire.Error {
	if r.Action == p.deny {
		return &awswire.Error{Code: "AccessDenied", Message: "current policy denies observation", StatusCode: 403}
	}
	return p.base.Authorize(ctx, r)
}

type wafOwnerFixture struct {
	t          *testing.T
	ctx        context.Context
	scope      cloudformation.Scope
	repository wafv2.Repository
	service    *wafv2.Service
	commands   StepFunctionsCommands
	handlers   map[string]cloudformation.ResourceHandler
	policy     *wafOwnerPolicy
	db         *sql.DB
	path       string
	backend    string
	clock      *clock.Manual
}

func newWAFOwnerFixture(t *testing.T, backend string) *wafOwnerFixture {
	t.Helper()
	f := &wafOwnerFixture{t: t, backend: backend, path: filepath.Join(t.TempDir(), "owners.sqlite"), scope: cloudformation.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, clock: clock.NewManual(time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC))}
	f.ctx = awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: f.scope.Partition, AccountID: f.scope.Account, Region: f.scope.Region, PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: f.scope.Account})
	f.policy = &wafOwnerPolicy{base: authorization.NewWithClock(nil, nil, f.clock)}
	f.repository = wafv2.NewMemoryRepository(nil)
	f.open()
	t.Cleanup(func() {
		_ = f.service.Close()
		if f.db != nil {
			_ = f.db.Close()
		}
	})
	return f
}

func (f *wafOwnerFixture) open() {
	f.t.Helper()
	if f.backend == "sqlite" {
		var err error
		f.db, err = sqlite.Open(f.ctx, f.path)
		if err != nil {
			f.t.Fatal(err)
		}
		f.repository = wafstore.New(f.db)
	}
	f.service = wafv2.New(wafv2.Config{Repository: f.repository, Clock: f.clock, Authorizer: f.policy})
	f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"wafv2": f.service})
	f.handlers = CloudFormationWAFHandlers(f.commands)
}

func wafOwnerProperties(kind, name, description string) cloudformation.Properties {
	p := cloudformation.Properties{"Name": name, "Scope": "REGIONAL", "Description": description}
	if kind == "WebACL" {
		p["DefaultAction"] = map[string]any{"Allow": map[string]any{}}
		p["VisibilityConfig"] = map[string]any{"MetricName": "owner", "CloudWatchMetricsEnabled": false, "SampledRequestsEnabled": false}
	} else {
		p["IPAddressVersion"] = "IPV4"
		p["Addresses"] = []any{"198.51.100.0/24"}
	}
	return p
}

func (f *wafOwnerFixture) nativeCreate(kind string, p cloudformation.Properties, tags map[string]string) cloudformation.ResourceResult {
	f.t.Helper()
	name := cfnComputeString(p, "Name")
	if kind == "WebACL" {
		v, err := (cfnWAFWebACL{}).decode(p)
		if err != nil {
			f.t.Fatal(err)
		}
		out, err := cfnMessagingCall[api.CreateWebACLOutput](f.ctx, f.commands, "wafv2", "CreateWebACL", &api.CreateWebACLInput{Name: new(api.EntityName(name)), Scope: new(api.Scope("REGIONAL")), Description: v.Description, DefaultAction: v.DefaultAction, VisibilityConfig: v.VisibilityConfig, Tags: cfnWAFTagList(tags)})
		if err != nil {
			f.t.Fatal(err)
		}
		return cloudformation.ResourceResult{PhysicalID: name + "|" + string(*out.Summary.Id) + "|REGIONAL", Attributes: map[string]any{"Arn": string(*out.Summary.ARN)}}
	}
	v, err := (cfnWAFIPSet{}).decode(p)
	if err != nil {
		f.t.Fatal(err)
	}
	out, err := cfnMessagingCall[api.CreateIPSetOutput](f.ctx, f.commands, "wafv2", "CreateIPSet", &api.CreateIPSetInput{Name: new(api.EntityName(name)), Scope: new(api.Scope("REGIONAL")), Description: v.Description, IPAddressVersion: v.IPAddressVersion, Addresses: v.Addresses, Tags: cfnWAFTagList(tags)})
	if err != nil {
		f.t.Fatal(err)
	}
	return cloudformation.ResourceResult{PhysicalID: name + "|" + string(*out.Summary.Id) + "|REGIONAL", Attributes: map[string]any{"Arn": string(*out.Summary.ARN)}}
}

func (f *wafOwnerFixture) nativeRead(kind, physical string) (string, any) {
	f.t.Helper()
	name, id, err := cfnWAFIdentity(physical)
	if err != nil {
		f.t.Fatal(err)
	}
	if kind == "WebACL" {
		out, err := cfnMessagingCall[api.GetWebACLOutput](f.ctx, f.commands, "wafv2", "GetWebACL", &api.GetWebACLInput{Name: new(api.EntityName(name)), Id: new(api.EntityId(id)), Scope: new(api.Scope("REGIONAL"))})
		if err != nil {
			f.t.Fatal(err)
		}
		return cfnComputeValue(out.WebACL.Description), out
	}
	out, err := cfnMessagingCall[api.GetIPSetOutput](f.ctx, f.commands, "wafv2", "GetIPSet", &api.GetIPSetInput{Name: new(api.EntityName(name)), Id: new(api.EntityId(id)), Scope: new(api.Scope("REGIONAL"))})
	if err != nil {
		f.t.Fatal(err)
	}
	return cfnComputeValue(out.IPSet.Description), out
}

func (f *wafOwnerFixture) nativeDelete(kind, physical string) {
	f.t.Helper()
	if err := f.nativeMutation(f.ctx, kind, physical, "", true); err != nil {
		f.t.Fatal(err)
	}
}

func (f *wafOwnerFixture) nativeMutation(ctx context.Context, kind, physical, description string, deleting bool) error {
	f.t.Helper()
	name, id, err := cfnWAFIdentity(physical)
	if err != nil {
		f.t.Fatal(err)
	}
	_, current := f.nativeRead(kind, physical)
	if kind == "WebACL" {
		out := current.(*api.GetWebACLOutput)
		if deleting {
			return cfnMessagingExec(ctx, f.commands, "wafv2", "DeleteWebACL", &api.DeleteWebACLInput{Name: new(api.EntityName(name)), Id: new(api.EntityId(id)), Scope: new(api.Scope("REGIONAL")), LockToken: out.LockToken})
		}
		return cfnMessagingExec(ctx, f.commands, "wafv2", "UpdateWebACL", &api.UpdateWebACLInput{Name: new(api.EntityName(name)), Id: new(api.EntityId(id)), Scope: new(api.Scope("REGIONAL")), LockToken: out.LockToken, Description: new(api.EntityDescription(description)), DefaultAction: out.WebACL.DefaultAction, Rules: out.WebACL.Rules, VisibilityConfig: out.WebACL.VisibilityConfig, CustomResponseBodies: out.WebACL.CustomResponseBodies, AssociationConfig: out.WebACL.AssociationConfig})
	}
	out := current.(*api.GetIPSetOutput)
	if deleting {
		return cfnMessagingExec(ctx, f.commands, "wafv2", "DeleteIPSet", &api.DeleteIPSetInput{Name: new(api.EntityName(name)), Id: new(api.EntityId(id)), Scope: new(api.Scope("REGIONAL")), LockToken: out.LockToken})
	}
	return cfnMessagingExec(ctx, f.commands, "wafv2", "UpdateIPSet", &api.UpdateIPSetInput{Name: new(api.EntityName(name)), Id: new(api.EntityId(id)), Scope: new(api.Scope("REGIONAL")), LockToken: out.LockToken, Description: new(api.EntityDescription(description)), Addresses: out.IPSet.Addresses})
}

func (f *wafOwnerFixture) owner(kind string, result cloudformation.ResourceResult) wafv2.ResourceOwner {
	f.t.Helper()
	var owner wafv2.ResourceOwner
	sc := wafv2.Scope{Partition: f.scope.Partition, AccountID: f.scope.Account, Region: f.scope.Region}
	err := f.repository.View(f.ctx, func(r wafv2.Reader) error {
		if kind == "WebACL" {
			row, err := r.WebACL(sc, result.Attributes["Arn"].(string))
			owner = row.Owner
			return err
		}
		row, err := r.IPSet(sc, result.Attributes["Arn"].(string))
		owner = row.Owner
		return err
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return owner
}

func TestWAFPrivateResourceOwnersRejectCounterfeitTagsAndRecoverAfterReopen(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, kind := range []string{"WebACL", "IPSet"} {
			for _, cloudControl := range []bool{false, true} {
				mode := "cfn"
				if cloudControl {
					mode = "cc"
				}
				t.Run(backend+"/"+kind+"/"+mode, func(t *testing.T) {
					f := newWAFOwnerFixture(t, backend)
					r := cloudformation.ResourceRequest{StackID: "private-stack", StackName: "stack", LogicalID: kind, Token: "private-create-token", Type: "AWS::WAFv2::" + kind, Scope: f.scope, CloudControl: cloudControl, Properties: wafOwnerProperties(kind, "owner-resource", "foreign")}
					h := f.handlers[r.Type]
					recoverer := h.(cloudformation.ResourceCreationRecoverer)
					foreign := f.nativeCreate(kind, r.Properties, cfnComputeOwnedTags(r))
					if _, err := h.Create(f.ctx, r); !cfnMessagingMissing(err, "WAFDuplicateItemException") {
						t.Fatalf("counterfeit Create: %v", err)
					}
					if _, err := recoverer.RecoverCreation(f.ctx, r); !cfnMessagingMissing(err, "NotFound") {
						t.Fatalf("counterfeit recovery: %v", err)
					}
					if got := f.owner(kind, foreign); got != (wafv2.ResourceOwner{}) {
						t.Fatalf("native tags acquired private claim: %+v", got)
					}
					constrained := r
					constrained.CloudControl, constrained.PhysicalID = false, foreign.PhysicalID
					constrained.Properties = wafOwnerProperties(kind, "owner-resource", "stolen")
					if _, err := h.Update(f.ctx, constrained); !cfnMessagingMissing(err, "AccessDeniedException") {
						t.Fatalf("counterfeit Update: %v", err)
					}
					if err := h.Delete(f.ctx, constrained); !cfnMessagingMissing(err, "AccessDeniedException") {
						t.Fatalf("counterfeit Delete: %v", err)
					}
					if got, _ := f.nativeRead(kind, foreign.PhysicalID); got != "foreign" {
						t.Fatalf("foreign mutation: %q", got)
					}
					// Direct CC writes and deletes remain normal current-IAM operations.
					constrained.CloudControl = true
					if _, err := h.Update(f.ctx, constrained); err != nil {
						t.Fatal(err)
					}
					if got, _ := f.nativeRead(kind, foreign.PhysicalID); got != "stolen" {
						t.Fatalf("direct update: %q", got)
					}
					if err := h.Delete(f.ctx, constrained); err != nil {
						t.Fatal(err)
					}

					r.Properties = wafOwnerProperties(kind, "owner-resource", "owned")
					owned, err := h.Create(f.ctx, r)
					if err != nil {
						t.Fatal(err)
					}
					r.PhysicalID = owned.PhysicalID
					wantOwner := wafv2.ResourceOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token}
					if got := f.owner(kind, owned); got != wantOwner {
						t.Fatalf("fresh Create did not privately claim: %+v", got)
					}
					// Public tags can be added, removed and counterfeited independently.
					other := r
					other.Token = "different-token"
					if err := cfnMessagingExec(f.ctx, f.commands, "wafv2", "TagResource", &api.TagResourceInput{ResourceARN: new(api.ResourceArn(owned.Attributes["Arn"].(string))), Tags: cfnWAFTagList(cfnComputeOwnedTags(other))}); err != nil {
						t.Fatal(err)
					}
					keys := api.TagKeyList{}
					for key := range cfnComputeOwnedTags(other) {
						keys = append(keys, api.TagKey(key))
					}
					if err := cfnMessagingExec(f.ctx, f.commands, "wafv2", "UntagResource", &api.UntagResourceInput{ResourceARN: new(api.ResourceArn(owned.Attributes["Arn"].(string))), TagKeys: keys}); err != nil {
						t.Fatal(err)
					}
					if backend == "sqlite" {
						_ = f.service.Close()
						if err := f.db.Close(); err != nil {
							t.Fatal(err)
						}
						f.open()
						h = f.handlers[r.Type]
						recoverer = h.(cloudformation.ResourceCreationRecoverer)
					}
					if got := f.owner(kind, owned); got != wantOwner {
						t.Fatalf("persisted claim: %+v", got)
					}
					for _, create := range []func(context.Context, cloudformation.ResourceRequest) (cloudformation.ResourceResult, error){h.Create, recoverer.RecoverCreation} {
						out, err := create(f.ctx, r)
						if err != nil || out.PhysicalID != owned.PhysicalID {
							t.Fatalf("exact-token recovery = %+v, %v", out, err)
						}
					}
					other.CloudControl = false
					if _, err := h.Update(f.ctx, other); !cfnMessagingMissing(err, "AccessDeniedException") {
						t.Fatalf("other token Update: %v", err)
					}
					if err := h.Delete(f.ctx, other); !cfnMessagingMissing(err, "AccessDeniedException") {
						t.Fatalf("other token Delete: %v", err)
					}
					// The native transition itself must fence the claim, even when
					// the lock token was obtained through an authorized direct read.
					wrongOwner := wafv2.WithResourceOwner(f.ctx, wafv2.ResourceOwner{StackID: other.StackID, LogicalID: other.LogicalID, Token: other.Token})
					for _, deleting := range []bool{false, true} {
						if err := f.nativeMutation(wrongOwner, kind, owned.PhysicalID, "stolen", deleting); !cfnMessagingMissing(err, "AccessDeniedException") {
							t.Fatalf("native claim fence: %v", err)
						}
					}
					if err := f.nativeMutation(f.ctx, kind, owned.PhysicalID, "sdk-update", false); err != nil {
						t.Fatal(err)
					}
					if got, _ := f.nativeRead(kind, owned.PhysicalID); got != "sdk-update" {
						t.Fatalf("native SDK update: %q", got)
					}
					if got := f.owner(kind, owned); got != wantOwner {
						t.Fatalf("native SDK update changed private claim: %+v", got)
					}
					constrained = r
					constrained.CloudControl = false
					constrained.Properties = wafOwnerProperties(kind, "owner-resource", "owner-update")
					if _, err := h.Update(f.ctx, constrained); err != nil {
						t.Fatal(err)
					}
					if got, _ := f.nativeRead(kind, owned.PhysicalID); got != "owner-update" {
						t.Fatalf("owned update: %q", got)
					}
					// Neither native nor CC public projections include the private claim.
					_, native := f.nativeRead(kind, owned.PhysicalID)
					read, err := h.(cloudformation.ResourceReader).Read(f.ctx, r)
					if err != nil {
						t.Fatal(err)
					}
					list, err := h.(cloudformation.ResourceReader).List(f.ctx, r)
					if err != nil {
						t.Fatal(err)
					}
					data, err := json.Marshal([]any{native, read, list})
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(string(data), r.Token) || strings.Contains(string(data), "Owner") || strings.Contains(string(data), r.StackID) {
						t.Fatalf("private claim leaked: %s", data)
					}

					f.nativeDelete(kind, owned.PhysicalID)
					foreign = f.nativeCreate(kind, wafOwnerProperties(kind, "owner-resource", "recreated-foreign"), cfnComputeOwnedTags(r))
					if foreign.PhysicalID == owned.PhysicalID {
						t.Fatal("native recreation reused actual ID")
					}
					if _, err := recoverer.RecoverCreation(f.ctx, r); !cfnMessagingMissing(err, "NotFound") {
						t.Fatalf("foreign recreation recovery: %v", err)
					}
					if err := h.Delete(f.ctx, constrained); err != nil {
						t.Fatalf("stale physical Delete: %v", err)
					}
					constrained.PhysicalID = foreign.PhysicalID
					if _, err := h.Update(f.ctx, constrained); !cfnMessagingMissing(err, "AccessDeniedException") {
						t.Fatalf("recreated foreign Update: %v", err)
					}
					if err := h.Delete(f.ctx, constrained); !cfnMessagingMissing(err, "AccessDeniedException") {
						t.Fatalf("recreated foreign Delete: %v", err)
					}
					if got, _ := f.nativeRead(kind, foreign.PhysicalID); got != "recreated-foreign" {
						t.Fatalf("foreign recreation mutated: %q", got)
					}
				})
			}
		}
	}
}

func TestWAFCreateReturnsAuthenticIDOnPostAdmissionIAMFailure(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, kind := range []string{"WebACL", "IPSet"} {
			t.Run(backend+"/"+kind, func(t *testing.T) {
				f := newWAFOwnerFixture(t, backend)
				r := cloudformation.ResourceRequest{StackID: "stack", LogicalID: kind, Token: "private-token", Type: "AWS::WAFv2::" + kind, Scope: f.scope, CloudControl: true, Properties: wafOwnerProperties(kind, "admitted", "owned")}
				f.policy.deny = "wafv2:Get" + kind
				h := f.handlers[r.Type]
				out, err := h.Create(f.ctx, r)
				if !cfnMessagingMissing(err, "AccessDeniedException") || out.PhysicalID == "" {
					t.Fatalf("post-admission result = %+v, %v", out, err)
				}
				// Recovery denial is not an absence certificate and creates no replacement.
				recoverer := h.(cloudformation.ResourceCreationRecoverer)
				if _, err := recoverer.RecoverCreation(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") {
					t.Fatalf("denied recovery: %v", err)
				}
				f.policy.deny = ""
				if backend == "sqlite" {
					_ = f.service.Close()
					if err := f.db.Close(); err != nil {
						t.Fatal(err)
					}
					f.open()
					recoverer = f.handlers[r.Type].(cloudformation.ResourceCreationRecoverer)
				}
				recovered, err := recoverer.RecoverCreation(f.ctx, r)
				if err != nil || recovered.PhysicalID != out.PhysicalID {
					t.Fatalf("recover admitted ID = %+v, %v; want %s", recovered, err, out.PhysicalID)
				}
				if got, _ := f.nativeRead(kind, recovered.PhysicalID); got != "owned" {
					t.Fatalf("admitted native state: %q", got)
				}
				h = f.handlers[r.Type]
				r.PhysicalID, r.CloudControl = recovered.PhysicalID, false
				f.policy.deny = "wafv2:Create" + kind
				if _, err := h.Create(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") {
					t.Fatalf("exact-token Create bypassed current IAM: %v", err)
				}
				f.policy.deny = "wafv2:Update" + kind
				r.Properties = wafOwnerProperties(kind, "admitted", "denied-write")
				if _, err := h.Update(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") {
					t.Fatalf("owned Update bypassed current IAM: %v", err)
				}
				f.policy.deny = "wafv2:Delete" + kind
				if err := h.Delete(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") {
					t.Fatalf("owned Delete bypassed current IAM: %v", err)
				}
				f.policy.deny = ""
				if got, _ := f.nativeRead(kind, recovered.PhysicalID); got != "owned" {
					t.Fatalf("IAM-rejected mutation changed native state: %q", got)
				}
			})
		}
	}
}
