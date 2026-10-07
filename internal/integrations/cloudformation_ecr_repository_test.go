package integrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ecr"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ecr"
	"stackd/storage/sqlite"
	ecrstore "stackd/storage/sqlite/ecr"
)

// cfnECRTestService exposes the native registry at its advertised HTTP origin.
// Reopening SQLite constructs a fresh service and reachable registry origin.
func cfnECRTestService(t *testing.T, config ecr.Config) *ecr.Service {
	t.Helper()
	registry := httptest.NewUnstartedServer(nil)
	config.PublicEndpoint = "http://" + registry.Listener.Addr().String()
	service := ecr.New(config)
	registry.Config.Handler = service.RegistryHandler()
	registry.Start()
	t.Cleanup(registry.Close)
	return service
}

func cfnECRRegistrySmoke(t *testing.T, ctx context.Context, commands StepFunctionsCommands, name string) {
	t.Helper()
	out, err := cfnComputeCall[api.GetAuthorizationTokenOutput](ctx, commands, "ecr", "GetAuthorizationToken", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.AuthorizationData) != 1 {
		t.Fatalf("expected one registry authorization, got %+v", out.AuthorizationData)
	}
	auth := out.AuthorizationData[0]
	scope := awsctx.FromContext(ctx)
	repositoryPath := scope.Partition + "/" + scope.AccountID + "/" + scope.Region + "/" + name
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfnComputeValue(auth.ProxyEndpoint)+"/v2/"+repositoryPath+"/tags/list", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Basic "+cfnComputeValue(auth.AuthorizationToken))
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("native registry tags list: HTTP %d", response.StatusCode)
	}
	var tags struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(response.Body).Decode(&tags); err != nil {
		t.Fatal(err)
	}
	if tags.Name != repositoryPath || len(tags.Tags) != 0 {
		t.Fatalf("unexpected native registry tags: %+v", tags)
	}
}

func TestECRRepositoryLifecycleRegistryOwnership(t *testing.T) {
	service := cfnECRTestService(t, ecr.Config{Repository: ecr.NewMemoryRepository(nil)})
	t.Cleanup(func() { _ = service.Close() })
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ecr": service})
	handler := cfnECRRepository{commands: commands}
	const local = "123456789012"
	const foreign = "210987654321"
	const policy = `{"rules":[{"rulePriority":1,"selection":{"tagStatus":"any","countType":"imageCountMoreThan","countNumber":1},"action":{"type":"expire"}}]}`
	ctxFor := func(account string) context.Context {
		return awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", AccountID: account, Region: "us-east-1", PrincipalARN: "arn:aws:iam::" + account + ":root", PrincipalID: account})
	}
	request := func(account string) cloudformation.ResourceRequest {
		return cloudformation.ResourceRequest{StackID: "stack-" + account, StackName: "ecr", LogicalID: "Repository", Type: "AWS::ECR::Repository", Token: "incarnation-" + account, Properties: cloudformation.Properties{"RepositoryName": "same-name", "LifecyclePolicy": map[string]any{"RegistryId": account, "LifecyclePolicyText": policy}}}
	}
	localRequest, foreignRequest := request(local), request(foreign)
	for _, account := range []string{local, foreign} {
		r := request(account)
		result, err := handler.Create(ctxFor(account), r)
		if err != nil {
			t.Fatal(err)
		}
		if result.PhysicalID != "same-name" {
			t.Fatalf("unexpected ID %q", result.PhysicalID)
		}
		cfnECRRegistrySmoke(t, ctxFor(account), commands, "same-name")
	}
	localRequest.PhysicalID = "same-name"
	foreignRequest.PhysicalID = "same-name"
	assertPolicy := func(account string, present bool) {
		t.Helper()
		out, err := cfnComputeCall[api.GetLifecyclePolicyOutput](ctxFor(account), commands, "ecr", "GetLifecyclePolicy", map[string]any{"repositoryName": "same-name"})
		if present {
			if err != nil || cfnComputeValue(out.LifecyclePolicyText) == "" {
				t.Fatalf("%s policy lost: %v", account, err)
			}
		} else if !cfnMessagingMissing(err, "LifecyclePolicyNotFoundException") {
			t.Fatalf("%s policy not removed: %v", account, err)
		}
	}
	fresh := request(local)
	fresh.Properties = cloudformation.Properties{"RepositoryName": "not-admitted", "LifecyclePolicy": map[string]any{"RegistryId": foreign, "LifecyclePolicyText": policy}}
	if result, err := handler.Create(ctxFor(local), fresh); err == nil || result.PhysicalID != "" {
		t.Fatalf("foreign registry admitted new repository: %+v %v", result, err)
	}
	if _, err := handler.get(ctxFor(local), "not-admitted"); !cfnMessagingMissing(err, "RepositoryNotFoundException") {
		t.Fatalf("rejected create left a repository: %v", err)
	}
	bad := localRequest
	bad.Properties = foreignRequest.Properties
	if _, err := handler.Update(ctxFor(local), bad); err == nil {
		t.Fatal("cross-registry update accepted")
	}
	assertPolicy(local, true)
	assertPolicy(foreign, true)
	// A same-token retry must retain its authentic admitted ID even when later
	// convergence rejects the invalid registry, so rollback can target it.
	result, err := handler.Create(ctxFor(local), bad)
	if err == nil || result.PhysicalID != "same-name" {
		t.Fatalf("replay lost admitted ID: %+v %v", result, err)
	}
	removal := localRequest
	removal.Properties = cloudformation.Properties{"RepositoryName": "same-name"}
	removal.Previous = foreignRequest.Properties
	if _, err := handler.Update(ctxFor(local), removal); err == nil {
		t.Fatal("legacy foreign-policy removal accepted")
	}
	assertPolicy(local, true)
	assertPolicy(foreign, true)
	removal.Previous = localRequest.Properties
	if _, err := handler.Update(ctxFor(local), removal); err != nil {
		t.Fatal(err)
	}
	assertPolicy(local, false)
	assertPolicy(foreign, true)
	wrong := localRequest
	wrong.Token = "unrelated-incarnation"
	if _, err := handler.Create(ctxFor(local), wrong); err == nil {
		t.Fatal("foreign incarnation adopted")
	}
	if err := handler.Delete(ctxFor(local), wrong); err == nil {
		t.Fatal("foreign incarnation deleted repository")
	}
	if err := handler.Delete(ctxFor(local), localRequest); err != nil {
		t.Fatal(err)
	}
	assertPolicy(foreign, true)
}

func TestECRRepositoryCreatePolicyFailureRetainsAdmission(t *testing.T) {
	service := cfnECRTestService(t, ecr.Config{Repository: ecr.NewMemoryRepository(nil)})
	t.Cleanup(func() { _ = service.Close() })
	handler := cfnECRRepository{commands: NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ecr": service})}
	ctx := cfnAnalyticsTestContext()
	r := cfnAnalyticsTestRequest("AWS::ECR::Repository", cloudformation.Properties{"RepositoryName": "failed-policy", "LifecyclePolicy": map[string]any{"LifecyclePolicyText": "invalid JSON"}})
	for i := range 2 {
		result, err := handler.Create(ctx, r)
		if err == nil || result.PhysicalID != "failed-policy" {
			t.Fatalf("attempt %d lost admitted repository: %+v %v", i, result, err)
		}
		r.PhysicalID = result.PhysicalID
	}
	cfnECRRegistrySmoke(t, ctx, handler.commands, "failed-policy")
	if err := handler.Delete(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := handler.get(ctx, r.PhysicalID); !cfnMessagingMissing(err, "RepositoryNotFoundException") {
		t.Fatalf("rollback did not remove exact admission: %v", err)
	}
}

type cfnECRDenyAuthorizer struct{ deny string }

func (a *cfnECRDenyAuthorizer) Authorize(_ context.Context, r authorization.Request) *awswire.Error {
	if r.Action == a.deny {
		return &awswire.Error{Code: "AccessDeniedException", Message: "current IAM denial", StatusCode: 403}
	}
	return nil
}

// cfnECRLostReply commits native admission, then loses the response.
type cfnECRLostReply struct {
	owner  awscommands.CommandExecutor
	action string
}

func (e *cfnECRLostReply) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	out, err := e.owner.ExecuteCommand(ctx, r)
	if err == nil && string(r.Operation.Name) == e.action {
		e.action = ""
		return nil, &awswire.Error{Code: "RequestTimeout", Message: "lost admitted create reply", StatusCode: 504}
	}
	return out, err
}

func TestECRRepositoryPrivateIncarnationOwnership(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
			const arn = "arn:aws:ecr:us-east-1:123456789012:repository/owned-repo"
			authorizer := &cfnECRDenyAuthorizer{}
			var repository ecr.Repository = ecr.NewMemoryRepository(nil)
			var db *sql.DB
			path := filepath.Join(t.TempDir(), "ecr.sqlite")
			open := func() {
				var err error
				db, err = sqlite.Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				repository = ecrstore.New(db)
			}
			if backend == "sqlite" {
				open()
			}
			owner := cfnECRTestService(t, ecr.Config{Repository: repository, Authorizer: authorizer})
			t.Cleanup(func() {
				_ = owner.Close()
				if db != nil {
					_ = db.Close()
				}
			})
			commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ecr": &cfnECRLostReply{owner: owner, action: "CreateRepository"}})
			h := cfnECRRepository{commands: commands}
			request := func(token string) cloudformation.ResourceRequest {
				return cloudformation.ResourceRequest{StackID: "ecr-stack", StackName: "ecr", LogicalID: "Repository", Type: "AWS::ECR::Repository", Token: token, Properties: cloudformation.Properties{"RepositoryName": "owned-repo"}}
			}
			markers := func(token string) []map[string]string {
				return cfnECRTags(map[string]string{cfnComputeTagPrefix + "stack-id": "ecr-stack", cfnComputeTagPrefix + "logical-id": "Repository", cfnComputeTagPrefix + "incarnation": token})
			}
			native := func(operation string, input map[string]any) error {
				return cfnComputeRun(ctx, h.commands, "ecr", operation, input)
			}
			first := request("first")
			created, err := h.Create(ctx, first)
			if err == nil || created.PhysicalID != "owned-repo" {
				t.Fatalf("lost reply discarded authentic admission: %+v %v", created, err)
			}
			cfnECRRegistrySmoke(t, ctx, h.commands, "owned-repo")
			if backend == "sqlite" {
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				open()
				owner = cfnECRTestService(t, ecr.Config{Repository: repository, Authorizer: authorizer})
				h = cfnECRRepository{commands: NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ecr": owner})}
			}
			if recovered, err := h.RecoverCreation(ctx, first); err != nil || recovered.PhysicalID != "owned-repo" {
				t.Fatalf("same-token private claim not recovered: %+v %v", recovered, err)
			}
			cfnECRRegistrySmoke(t, ctx, h.commands, "owned-repo")
			authorizer.deny = "ecr:DescribeRepositories"
			if recovered, err := h.RecoverCreation(ctx, first); err == nil || cfnComputeMissing(err) || recovered.PhysicalID != "" {
				t.Fatalf("IAM denial certified or bypassed recovery: %+v %v", recovered, err)
			}
			authorizer.deny = ""
			if replay, err := h.Create(ctx, first); err != nil || replay.PhysicalID != "owned-repo" {
				t.Fatalf("same-token replay lost admission: %+v %v", replay, err)
			}
			// Copying public markers for another incarnation grants it nothing.
			if err := native("TagResource", map[string]any{"resourceArn": arn, "tags": markers("forged")}); err != nil {
				t.Fatal(err)
			}
			forged := request("forged")
			if out, err := h.Create(ctx, forged); err == nil || out.PhysicalID != "" {
				t.Fatalf("forged public tags adopted the repository: %+v %v", out, err)
			}
			if recovered, err := h.RecoverCreation(ctx, forged); err == nil || cfnComputeMissing(err) || recovered.PhysicalID != "" {
				t.Fatalf("forged incarnation recovered as owned: %+v %v", recovered, err)
			}
			forged.PhysicalID = "owned-repo"
			if _, err := h.Update(ctx, forged); err == nil {
				t.Fatal("forged public tags authorized an update")
			}
			if err := h.Delete(ctx, forged); err == nil {
				t.Fatal("forged public tags authorized deletion")
			}
			first.PhysicalID = "owned-repo"
			if _, err := h.Update(ctx, first); err != nil {
				t.Fatalf("authentic owner update rejected: %v", err)
			}
			// A native same-name recreation with copied authentic markers stays foreign.
			if err := native("DeleteRepository", map[string]any{"repositoryName": "owned-repo"}); err != nil {
				t.Fatal(err)
			}
			if err := native("CreateRepository", map[string]any{"repositoryName": "owned-repo", "tags": markers("first")}); err != nil {
				t.Fatal(err)
			}
			if _, err := h.Update(ctx, first); err == nil {
				t.Fatal("retired owner updated a native recreation")
			}
			if err := h.Delete(ctx, first); err == nil {
				t.Fatal("retired owner deleted a native recreation")
			}
			if recovered, err := h.RecoverCreation(ctx, first); err == nil || cfnComputeMissing(err) || recovered.PhysicalID != "" {
				t.Fatalf("native recreation adopted or falsely absent: %+v %v", recovered, err)
			}
			if replay, err := h.Create(ctx, request("first")); err == nil || replay.PhysicalID != "" {
				t.Fatalf("same-token replay adopted a native recreation: %+v %v", replay, err)
			}
			if _, err := h.get(ctx, "owned-repo"); err != nil {
				t.Fatalf("native recreation was damaged: %v", err)
			}
			// Cloud Control Read/Update/Delete remain IAM-governed native calls.
			direct := first
			direct.CloudControl = true
			if _, err := h.Read(ctx, direct); err != nil {
				t.Fatal(err)
			}
			if err := h.Delete(ctx, direct); err != nil {
				t.Fatalf("Cloud Control delete was fenced: %v", err)
			}
			if recovered, err := h.RecoverCreation(ctx, request("first")); !cfnComputeMissing(err) || recovered.PhysicalID != "" {
				t.Fatalf("absent repository not certified as nonadmission: %+v %v", recovered, err)
			}
			// Cloud Control creation always stamps its own private claim.
			control := request("control")
			control.CloudControl = true
			if out, err := h.Create(ctx, control); err != nil || out.PhysicalID != "owned-repo" {
				t.Fatalf("Cloud Control create failed: %+v %v", out, err)
			}
			control.CloudControl = false
			if recovered, err := h.RecoverCreation(ctx, control); err != nil || recovered.PhysicalID != "owned-repo" {
				t.Fatalf("Cloud Control create did not claim: %+v %v", recovered, err)
			}
			if recovered, err := h.RecoverCreation(ctx, request("first")); err == nil || recovered.PhysicalID != "" {
				t.Fatalf("retired incarnation recovered a newer claim: %+v %v", recovered, err)
			}
		})
	}
}
