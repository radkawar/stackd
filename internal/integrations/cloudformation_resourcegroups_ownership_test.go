package integrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/resourcegroups"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/resourcegroups"
	"stackd/storage/sqlite"
	groupstore "stackd/storage/sqlite/resourcegroups"
)

type cfnGroupAuthorizer struct{ deny string }

func (a *cfnGroupAuthorizer) Authorize(_ context.Context, r authorization.Request) *awswire.Error {
	if r.Action == a.deny {
		return &awswire.Error{Code: "AccessDeniedException", Message: "current IAM denial", StatusCode: 403}
	}
	return nil
}

type cfnGroupCommands struct {
	*resourcegroups.Service
	beforeAction string
	before       func()
	loseCreate   bool
}

func (c *cfnGroupCommands) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	if string(r.Operation.Name) == c.beforeAction && c.before != nil {
		fn := c.before
		c.before = nil
		fn()
	}
	out, err := c.Service.ExecuteCommand(ctx, r)
	if err == nil && c.loseCreate && string(r.Operation.Name) == "CreateGroup" {
		c.loseCreate = false
		return nil, &awswire.Error{Code: "InternalServerErrorException", Message: "lost admitted reply", StatusCode: 500}
	}
	return out, err
}

type cfnGroupFixture struct {
	t          *testing.T
	ctx        context.Context
	repository resourcegroups.Repository
	db         *sql.DB
	path       string
	clock      *clock.Manual
	iam        *cfnGroupAuthorizer
	owner      *resourcegroups.Service
	executor   *cfnGroupCommands
	commands   StepFunctionsCommands
	handler    cfnRGroup
}

func newCFNGroupFixture(t *testing.T, backend string) *cfnGroupFixture {
	t.Helper()
	f := &cfnGroupFixture{t: t, ctx: awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"}), repository: resourcegroups.NewMemoryRepository(nil), clock: clock.NewManual(time.Date(2031, 1, 2, 3, 4, 0, 0, time.UTC)), iam: &cfnGroupAuthorizer{}}
	if backend == "sqlite" {
		f.path = filepath.Join(t.TempDir(), "groups.sqlite")
		f.open()
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
func (f *cfnGroupFixture) open() {
	f.t.Helper()
	var err error
	f.db, err = sqlite.Open(f.ctx, f.path)
	if err != nil {
		f.t.Fatal(err)
	}
	f.repository = groupstore.New(f.db)
}
func (f *cfnGroupFixture) start() {
	f.owner = resourcegroups.New(resourcegroups.Config{Repository: f.repository, Clock: f.clock, Authorizer: f.iam})
	f.executor = &cfnGroupCommands{Service: f.owner}
	f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"resourcegroups": f.executor})
	f.handler = cfnRGroup{f.commands}
}
func (f *cfnGroupFixture) reopen() {
	f.t.Helper()
	if err := f.owner.Close(); err != nil {
		f.t.Fatal(err)
	}
	if f.db != nil {
		if err := f.db.Close(); err != nil {
			f.t.Fatal(err)
		}
		f.open()
	}
	f.start()
}
func cfnGroupRequest(name string) cloudformation.ResourceRequest {
	return cloudformation.ResourceRequest{Type: "AWS::ResourceGroups::Group", StackID: "group-stack", StackName: "group", LogicalID: "Group", Token: "group-incarnation", Properties: cloudformation.Properties{"Name": name, "Description": "original", "ResourceQuery": map[string]any{"Type": "TAG_FILTERS_1_0", "Query": map[string]any{"ResourceTypeFilters": []any{"AWS::AllSupported"}, "TagFilters": []any{map[string]any{"Key": "team", "Values": []any{"blue"}}}}}}}
}
func cfnGroupNativeInput(r cloudformation.ResourceRequest, tags map[string]string) map[string]any {
	query, _ := cfnRGroupQuery(r)
	return map[string]any{"Name": r.Properties["Name"], "Description": "foreign", "ResourceQuery": query, "Tags": tags}
}
func (f *cfnGroupFixture) native(action string, in map[string]any) {
	f.t.Helper()
	// A fresh native executor has no controller provenance and performs real commands.
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"resourcegroups": f.owner})
	if err := cfnComputeRun(f.ctx, commands, "resourcegroups", action, in); err != nil {
		f.t.Fatal(err)
	}
}
func (f *cfnGroupFixture) rejectStale(r cloudformation.ResourceRequest) {
	f.t.Helper()
	if got, err := f.handler.Create(f.ctx, r); err == nil || got.PhysicalID != "" {
		f.t.Fatalf("foreign group adopted: %+v %v", got, err)
	}
	if got, err := f.handler.RecoverCreation(f.ctx, r); err == nil || got.PhysicalID != "" || cfnRGroupMissing(err) {
		f.t.Fatalf("foreign recovery adopted or falsely absent: %+v %v", got, err)
	}
	if _, err := f.handler.Update(f.ctx, r); err == nil {
		f.t.Fatal("stale update admitted")
	}
	if err := f.handler.Delete(f.ctx, r); err == nil {
		f.t.Fatal("stale deletion admitted")
	}
}

func TestCFNGroupCounterfeitTagsAndForeignRecreation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNGroupFixture(t, backend)
			r := cfnGroupRequest("counterfeit-group")
			r.PhysicalID = "counterfeit-group"
			f.native("CreateGroup", cfnGroupNativeInput(r, cfnComputeOwnedTags(r)))
			f.rejectStale(r)
			// CC Create still cannot adopt copied public tags; its other operations use IAM.
			cc := r
			cc.CloudControl = true
			if got, err := f.handler.Create(f.ctx, cc); err == nil || got.PhysicalID != "" {
				t.Fatalf("CC create bypassed private claim: %+v %v", got, err)
			}
			if _, err := f.handler.Read(f.ctx, cc); err != nil {
				t.Fatal(err)
			}
			cc.Previous = cc.Properties
			cc.Properties = cfnGroupRequest("counterfeit-group").Properties
			cc.Properties["Description"] = "IAM update"
			if _, err := f.handler.Update(f.ctx, cc); err != nil {
				t.Fatal(err)
			}
			if err := f.handler.Delete(f.ctx, cc); err != nil {
				t.Fatal(err)
			}
			r = cfnGroupRequest("recreated-group")
			admitted, err := f.handler.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = admitted.PhysicalID
			f.native("DeleteGroup", map[string]any{"Group": r.PhysicalID})
			f.native("CreateGroup", cfnGroupNativeInput(r, cfnComputeOwnedTags(r)))
			f.reopen()
			f.rejectStale(r)
			live, err := f.handler.Read(f.ctx, r)
			if err != nil || live["Description"] != "foreign" {
				t.Fatalf("stale controller damaged native recreation: %#v %v", live, err)
			}
		})
	}
}

func TestCFNGroupPrivateRecoveryReopenAndCurrentIAM(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNGroupFixture(t, backend)
			r := cfnGroupRequest("genuine-group")
			r.CloudControl = true
			tags := make([]any, 50)
			for i := range tags {
				tags[i] = map[string]any{"Key": fmt.Sprintf("customer-%02d", i), "Value": "blue"}
			}
			r.Properties["Tags"] = tags
			f.executor.loseCreate = true
			admitted, err := f.handler.Create(f.ctx, r)
			if err == nil || admitted.PhysicalID != "genuine-group" {
				t.Fatalf("lost admitted reply discarded authentic ID: %+v %v", admitted, err)
			}
			r.PhysicalID = admitted.PhysicalID
			arn := admitted.Attributes["Arn"].(string)
			f.native("Untag", map[string]any{"Arn": arn, "Keys": []any{"customer-00", "customer-01", "customer-02"}})
			f.native("Tag", map[string]any{"Arn": arn, "Tags": cfnComputeOwnedTags(cloudformation.ResourceRequest{StackID: "forged", LogicalID: "forged", Token: "forged"})})
			// Remove counterfeit markers again: private recovery is independent of all public tags.
			f.native("Untag", map[string]any{"Arn": arn, "Keys": []any{cfnComputeTagPrefix + "stack-id", cfnComputeTagPrefix + "logical-id", cfnComputeTagPrefix + "incarnation"}})
			f.native("Tag", map[string]any{"Arn": arn, "Tags": map[string]string{"customer-00": "blue", "customer-01": "blue", "customer-02": "blue"}})
			f.reopen()
			recovered, err := f.handler.RecoverCreation(f.ctx, r)
			if err != nil || recovered.PhysicalID != admitted.PhysicalID {
				t.Fatalf("private recovery failed after reopen: %+v %v", recovered, err)
			}
			replayed, err := f.handler.Create(f.ctx, r)
			if err != nil || replayed.PhysicalID != admitted.PhysicalID {
				t.Fatalf("same-token CC replay failed: %+v %v", replayed, err)
			}
			public, err := f.handler.Read(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			if got := public["Tags"].([]any); len(got) != 50 {
				t.Fatalf("private claims consumed customer tags: %#v", got)
			}
			native, err := cfnComputeCall[api.GetGroupOutput](f.ctx, f.commands, "resourcegroups", "GetGroup", map[string]any{"Group": r.PhysicalID})
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(native)
			if strings.Contains(string(encoded), "group-incarnation") || strings.Contains(string(encoded), "CloudFormationClaim") {
				t.Fatalf("private claim leaked: %s", encoded)
			}
			listed, err := f.handler.List(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ = json.Marshal(listed)
			if strings.Contains(string(encoded), "group-incarnation") || strings.Contains(string(encoded), "CloudFormationClaim") {
				t.Fatalf("private claim leaked from List: %s", encoded)
			}
			f.iam.deny = "resource-groups:GetGroup"
			if _, err := f.handler.RecoverCreation(f.ctx, r); err == nil || cfnRGroupMissing(err) {
				t.Fatalf("recovery bypassed current IAM or certified absence: %v", err)
			}
			f.iam.deny = "resource-groups:UpdateGroup"
			if _, err := f.handler.Update(f.ctx, r); err == nil {
				t.Fatal("CC update bypassed current IAM")
			}
			f.iam.deny = "resource-groups:DeleteGroup"
			if err := f.handler.Delete(f.ctx, r); err == nil {
				t.Fatal("CC delete bypassed current IAM")
			}
			f.iam.deny = ""
			r.CloudControl = false
			if err := f.handler.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCFNGroupMutationFencesAtNativeAdmission(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, action := range []string{"UpdateGroup", "UpdateGroupQuery", "Tag", "Untag", "DeleteGroup"} {
			t.Run(backend+"/"+action, func(t *testing.T) {
				f := newCFNGroupFixture(t, backend)
				r := cfnGroupRequest("racing-group")
				admitted, err := f.handler.Create(f.ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				r.PhysicalID = admitted.PhysicalID
				if action == "Untag" {
					f.native("Tag", map[string]any{"Arn": admitted.Attributes["Arn"], "Tags": map[string]string{"remove": "old"}})
				}
				f.executor.beforeAction = action
				f.executor.before = func() {
					f.native("DeleteGroup", map[string]any{"Group": r.PhysicalID})
					f.native("CreateGroup", cfnGroupNativeInput(r, cfnComputeOwnedTags(r)))
				}
				if action == "DeleteGroup" {
					err = f.handler.Delete(f.ctx, r)
				} else {
					r.Previous = r.Properties
					r.Properties = cfnGroupRequest("racing-group").Properties
					if action == "Tag" {
						r.Properties["Tags"] = []any{map[string]any{"Key": "new", "Value": "tag"}}
					}
					_, err = f.handler.Update(f.ctx, r)
				}
				if err == nil {
					t.Fatal("native admission accepted recreated group after authorized preflight")
				}
				live, err := f.handler.Read(f.ctx, r)
				if err != nil || live["Description"] != "foreign" {
					t.Fatalf("fenced command damaged recreation: %#v %v", live, err)
				}
			})
		}
	}
}

func TestCFNGroupMemberFailureRetainsAuthenticID(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNGroupFixture(t, backend)
			r := cfnGroupRequest("partial-group")
			admitted, err := f.handler.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			// Recover the actual admitted query group, then exercise native rejection
			// during the adapter's second membership step without faking its effects.
			delete(r.Properties, "ResourceQuery")
			r.Properties["Configuration"] = []any{map[string]any{"Type": "AWS::EC2::HostManagement"}}
			r.Properties["Resources"] = []any{"arn:aws:s3:::member"}
			partial, err := f.handler.Create(f.ctx, r)
			if err == nil || partial.PhysicalID != admitted.PhysicalID {
				t.Fatalf("native membership rejection forgot admitted group: %+v %v", partial, err)
			}
			f.reopen()
			recovered, err := f.handler.RecoverCreation(f.ctx, r)
			if err != nil || recovered.PhysicalID != admitted.PhysicalID {
				t.Fatalf("partial native admission not recoverable: %+v %v", recovered, err)
			}
			replayed, err := f.handler.Create(f.ctx, r)
			if err == nil || replayed.PhysicalID != admitted.PhysicalID {
				t.Fatalf("failed same-token convergence discarded ID: %+v %v", replayed, err)
			}
			r.PhysicalID = admitted.PhysicalID
			if err := f.handler.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
		})
	}
}
