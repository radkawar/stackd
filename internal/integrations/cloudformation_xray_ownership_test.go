package integrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/xray"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/iam"
	"stackd/internal/services/xray"
	"stackd/storage/sqlite"
	xraystore "stackd/storage/sqlite/xray"
)

type cfnXRayOwnerFixture struct {
	ctx        context.Context
	user       context.Context
	owner      *xray.Service
	repository xray.Repository
	identities iam.Repository
	authorizer authorization.Authorizer
	commands   StepFunctionsCommands
	db         *sql.DB
	path       string
	source     *clock.Manual
}

func newCFNXRayOwnerFixture(t *testing.T, backend string) *cfnXRayOwnerFixture {
	t.Helper()
	f := &cfnXRayOwnerFixture{ctx: cfnWorkflowOwnerContext(t), source: clock.NewManual(time.Date(2031, 1, 2, 3, 4, 0, 0, time.UTC)), repository: xray.NewMemoryRepository(nil), identities: iam.NewMemoryRepository(nil)}
	identityOwner := iam.NewWithConfig(iam.Config{Repository: f.identities, Clock: f.source})
	t.Cleanup(func() { _ = identityOwner.Close() })
	f.authorizer = authorization.NewWithClock(identityOwner, nil, f.source)
	f.user = awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:user/xray-owner", PrincipalID: "AIDAXRAYOWNER"})
	f.policy(t, `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"xray:*","Resource":"*"}}`)
	if backend == "sqlite" {
		f.path = filepath.Join(t.TempDir(), "xray.sqlite")
		f.open(t)
	}
	f.start()
	t.Cleanup(func() {
		_ = f.owner.Close()
		if f.db != nil {
			_ = f.db.Close()
		}
	})
	return f
}
func (f *cfnXRayOwnerFixture) policy(t *testing.T, document string) {
	t.Helper()
	user := iam.User{UserName: "xray-owner", UserId: "AIDAXRAYOWNER", Arn: "arn:aws:iam::123456789012:user/xray-owner", IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{"native": document}}}
	if err := f.identities.Update(f.ctx, func(tx iam.WriteTx) error {
		return tx.PutUser(iam.Scope{Partition: "aws", AccountID: "123456789012"}, user)
	}); err != nil {
		t.Fatal(err)
	}
}
func (f *cfnXRayOwnerFixture) open(t *testing.T) {
	t.Helper()
	var err error
	f.db, err = sqlite.Open(f.ctx, f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.repository = xraystore.New(f.db)
}
func (f *cfnXRayOwnerFixture) start() {
	f.owner = xray.New(xray.Config{Repository: f.repository, Clock: f.source, Authorizer: f.authorizer})
	f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"xray": f.owner})
}
func (f *cfnXRayOwnerFixture) reopen(t *testing.T) {
	t.Helper()
	if f.path == "" {
		return
	}
	if err := f.owner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	f.open(t)
	f.start()
}

type cfnXRayOwnerCase struct {
	kind           string
	properties     cloudformation.Properties
	create, update string
}

func cfnXRayOwnerCases() []cfnXRayOwnerCase {
	return []cfnXRayOwnerCase{
		{"Group", cloudformation.Properties{"GroupName": "owned-group", "FilterExpression": "service(\"initial\")", "Tags": []any{map[string]any{"Key": "team", "Value": "initial"}}}, "CreateGroup", "UpdateGroup"},
		{"SamplingRule", cloudformation.Properties{"SamplingRule": map[string]any{"RuleName": "owned-rule", "Version": 1, "Priority": 1, "FixedRate": 0.1, "ReservoirSize": 1, "Host": "*", "HTTPMethod": "*", "ResourceARN": "*", "ServiceName": "*", "ServiceType": "*", "URLPath": "*"}, "Tags": []any{map[string]any{"Key": "team", "Value": "initial"}}}, "CreateSamplingRule", "UpdateSamplingRule"},
	}
}
func (c cfnXRayOwnerCase) handler(commands StepFunctionsCommands) cloudformation.ResourceHandler {
	if c.kind == "Group" {
		return cfnXRayGroup{commands}
	}
	return cfnXRaySamplingRule{commands}
}
func (c cfnXRayOwnerCase) input(tags map[string]string) map[string]any {
	if c.kind == "Group" {
		in := cfnComputeCopy(c.properties, "GroupName", "FilterExpression")
		in["Tags"] = cfnComputeTagList(tags)
		return in
	}
	return map[string]any{"SamplingRule": c.properties["SamplingRule"], "Tags": cfnComputeTagList(tags)}
}
func (c cfnXRayOwnerCase) nativeCreate(t *testing.T, f *cfnXRayOwnerFixture, tags map[string]string) string {
	t.Helper()
	if c.kind == "Group" {
		out, err := cfnComputeCall[api.CreateGroupResult](f.user, f.commands, "xray", c.create, c.input(tags))
		if err != nil {
			t.Fatal(err)
		}
		return cfnComputeValue(out.Group.GroupARN)
	}
	out, err := cfnComputeCall[api.CreateSamplingRuleResult](f.user, f.commands, "xray", c.create, c.input(tags))
	if err != nil {
		t.Fatal(err)
	}
	return cfnComputeValue(out.SamplingRuleRecord.SamplingRule.RuleARN)
}
func cfnXRayReject(t *testing.T, result cloudformation.ResourceResult, err error) {
	t.Helper()
	if err == nil || result.PhysicalID != "" || cfnComputeMissing(err) {
		t.Fatalf("foreign resource adopted or falsely certified absent: %+v %v", result, err)
	}
}

func TestCFNXRayPrivateClaimsRejectCounterfeitAndForeignRecreation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, c := range cfnXRayOwnerCases() {
			t.Run(backend+"/"+c.kind, func(t *testing.T) {
				f := newCFNXRayOwnerFixture(t, backend)
				h := c.handler(f.commands)
				r := cfnWorkflowOwnerRequest("AWS::XRay::"+c.kind, c.kind, c.properties)
				admitted, err := h.Create(f.user, r)
				if err != nil {
					t.Fatal(err)
				}
				r.PhysicalID = admitted.PhysicalID
				tags, err := cfnXRayTags(f.user, f.commands, r.PhysicalID)
				if err != nil {
					t.Fatal(err)
				}
				for key := range tags {
					if len(key) >= len(cfnComputeTagPrefix) && key[:len(cfnComputeTagPrefix)] == cfnComputeTagPrefix {
						t.Fatalf("adapter published claim tag %q", key)
					}
				}
				foreign := r
				foreign.Token = "counterfeit-incarnation"
				forged := cfnComputeOwnedTags(foreign)
				forged["stackd:cloudformation:owner"] = cfnLogsMarker(foreign)
				if err := cfnComputeRun(f.user, f.commands, "xray", "TagResource", map[string]any{"ResourceARN": r.PhysicalID, "Tags": cfnComputeTagList(forged)}); err != nil {
					t.Fatal(err)
				}
				f.reopen(t)
				h = c.handler(f.commands)
				out, err := h.Create(f.user, foreign)
				cfnXRayReject(t, out, err)
				out, err = h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.user, foreign)
				cfnXRayReject(t, out, err)
				if _, err := h.Update(f.user, foreign); err == nil {
					t.Fatal("counterfeit tags authorized update")
				}
				if err := h.Delete(f.user, foreign); err == nil {
					t.Fatal("counterfeit tags authorized delete")
				}
				for _, operation := range []string{"TagResource", "UntagResource"} {
					input := map[string]any{"ResourceARN": r.PhysicalID}
					if operation == "TagResource" {
						input["Tags"] = cfnComputeTagList(map[string]string{"team": "forged"})
					} else {
						input["TagKeys"] = []string{"team"}
					}
					if err := cfnComputeRun(cfnXRayContext(f.user, foreign, false), f.commands, "xray", operation, input); err == nil {
						t.Fatalf("counterfeit tags authorized %s", operation)
					}
				}
				// Public tags can be removed without removing the actual private claim.
				if err := cfnComputeRun(f.user, f.commands, "xray", "UntagResource", map[string]any{"ResourceARN": r.PhysicalID, "TagKeys": []string{"stackd:cloudformation:owner", "stackd:cloudformation:stack-id", "stackd:cloudformation:logical-id", "stackd:cloudformation:incarnation"}}); err != nil {
					t.Fatal(err)
				}
				out, err = h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.user, r)
				if err != nil || out.PhysicalID != admitted.PhysicalID {
					t.Fatalf("public tag edits lost exact owner: %+v %v", out, err)
				}
				// CC normal mutations deliberately use current native IAM, not the CFN claim.
				direct := foreign
				direct.CloudControl = true
				if _, err := h.Update(f.user, direct); err != nil {
					t.Fatalf("CC native update was fenced by a CFN claim: %v", err)
				}
				if err := h.Delete(f.user, direct); err != nil {
					t.Fatal(err)
				}
				forged = cfnComputeOwnedTags(r)
				forged["stackd:cloudformation:owner"] = cfnLogsMarker(r)
				recreated := c.nativeCreate(t, f, forged)
				stale := r
				stale.PhysicalID = recreated
				before, err := h.(cloudformation.ResourceReader).Read(f.user, stale)
				if err != nil {
					t.Fatal(err)
				}
				f.reopen(t)
				h = c.handler(f.commands)
				for _, cc := range []bool{false, true} {
					attempt := r
					attempt.CloudControl = cc
					attempt.PhysicalID = ""
					out, err = h.Create(f.user, attempt)
					cfnXRayReject(t, out, err)
					out, err = h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.user, attempt)
					cfnXRayReject(t, out, err)
				}
				if _, err := h.Update(f.user, stale); err == nil {
					t.Fatal("foreign native recreation accepted stale CFN update")
				}
				if err := h.Delete(f.user, stale); err == nil {
					t.Fatal("foreign native recreation accepted stale CFN delete")
				}
				after, err := h.(cloudformation.ResourceReader).Read(f.user, stale)
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Fatalf("foreign recreation damaged: %#v %v", after, err)
				}
				stale.CloudControl = true
				if err := h.Delete(f.user, stale); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

type cfnXRayLostReply struct {
	*xray.Service
	operation string
	lose      bool
}

func (e *cfnXRayLostReply) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	out, err := e.Service.ExecuteCommand(ctx, r)
	if err == nil && e.lose && string(r.Operation.Name) == e.operation {
		e.lose = false
		return nil, &awswire.Error{Code: "InvalidRequestException", Message: "lost admitted native reply", StatusCode: 400}
	}
	return out, err
}

func TestCFNXRayAdmittedErrorsRecoverExactTokenAfterReopen(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, c := range cfnXRayOwnerCases() {
			for _, failure := range []string{"lost-reply", "postadmission-IAM"} {
				t.Run(backend+"/"+c.kind+"/"+failure, func(t *testing.T) {
					f := newCFNXRayOwnerFixture(t, backend)
					if failure == "lost-reply" {
						f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"xray": &cfnXRayLostReply{Service: f.owner, operation: c.create, lose: true}})
					} else {
						document := map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Action": "xray:*", "Resource": "*"}, map[string]any{"Effect": "Deny", "Action": "xray:" + c.update, "Resource": "*"}}}
						body, err := json.Marshal(document)
						if err != nil {
							t.Fatal(err)
						}
						f.policy(t, string(body))
					}
					h := c.handler(f.commands)
					r := cfnWorkflowOwnerRequest("AWS::XRay::"+c.kind, "CC"+c.kind, c.properties)
					r.CloudControl = true
					admitted, err := h.Create(f.user, r)
					if err == nil || admitted.PhysicalID == "" {
						t.Fatalf("postadmission error lost authentic native ID: %+v %v", admitted, err)
					}
					f.reopen(t)
					h = c.handler(f.commands)
					recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.user, r)
					if err != nil || recovered.PhysicalID != admitted.PhysicalID {
						t.Fatalf("reopen lost private receipt: %+v %v", recovered, err)
					}
					f.policy(t, `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"xray:*","Resource":"*"}}`)
					replayed, err := h.Create(f.user, r)
					if err != nil || replayed.PhysicalID != admitted.PhysicalID {
						t.Fatalf("same-token replay changed incarnation: %+v %v", replayed, err)
					}
					scoped := map[string]any{"Version": "2012-10-17", "Statement": map[string]any{"Effect": "Allow", "Action": []string{"xray:" + c.create, "xray:TagResource"}, "Resource": admitted.PhysicalID}}
					body, err := json.Marshal(scoped)
					if err != nil {
						t.Fatal(err)
					}
					f.policy(t, string(body))
					if out, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.user, r); err != nil || out.PhysicalID != admitted.PhysicalID {
						t.Fatalf("recovery authorized a synthetic ARN instead of the actual row: %+v %v", out, err)
					}
					// Recovery and all native/CC mutations continue to use current IAM.
					f.policy(t, `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"xray:*","Resource":"*"}}`)
					if out, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.user, r); err == nil || cfnComputeMissing(err) || out.PhysicalID != "" {
						t.Fatalf("recovery bypassed current IAM: %+v %v", out, err)
					}
					r.PhysicalID = admitted.PhysicalID
					for _, cc := range []bool{false, true} {
						attempt := r
						attempt.CloudControl = cc
						if _, err := h.Update(f.user, attempt); err == nil {
							t.Fatal("CFN/CC update bypassed current IAM")
						}
						if err := h.Delete(f.user, attempt); err == nil {
							t.Fatal("CFN/CC delete bypassed current IAM")
						}
					}
					if err := cfnComputeRun(f.user, f.commands, "xray", "TagResource", map[string]any{"ResourceARN": r.PhysicalID, "Tags": cfnComputeTagList(map[string]string{"team": "denied"})}); err == nil {
						t.Fatal("native tag mutation bypassed current IAM")
					}
					if err := cfnComputeRun(f.user, f.commands, "xray", "UntagResource", map[string]any{"ResourceARN": r.PhysicalID, "TagKeys": []string{"team"}}); err == nil {
						t.Fatal("native untag mutation bypassed current IAM")
					}
					if _, err := h.(cloudformation.ResourceReader).Read(f.user, r); err == nil {
						t.Fatal("native read bypassed current IAM")
					}
					f.policy(t, `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"xray:*","Resource":"*"}}`)
					if err := h.Delete(f.user, r); err != nil {
						t.Fatal(err)
					}
					if out, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.user, r); !cfnComputeMissing(err) || out.PhysicalID != "" {
						t.Fatalf("deleted row falsely recovered: %+v %v", out, err)
					}
				})
			}
		}
	}
}
