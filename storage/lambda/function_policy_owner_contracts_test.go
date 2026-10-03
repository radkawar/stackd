package lambda_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"stackd/internal/apievents"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awstest"
	"stackd/internal/awswire"
	service "stackd/internal/services/lambda"
	"stackd/journal"
	"stackd/storage/lambda"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqljournal "stackd/storage/sqlite/journal"
	sqllambda "stackd/storage/sqlite/lambda"
)

func functionOwnerDocument(key lambda.FunctionReference, sid string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Sid":%q,"Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunction","Resource":%q,"Condition":{"StringEquals":{"aws:SourceAccount":"111111111111"}}}]}`, sid, key.ARN())
}

func functionOwnerRead(t *testing.T, repo lambda.Repository, key lambda.FunctionReference) lambda.FunctionPolicy {
	t.Helper()
	var got lambda.FunctionPolicy
	if err := repo.View(t.Context(), func(r lambda.Reader) error { var err error; got, err = r.FunctionPolicy(key); return err }); err != nil {
		t.Fatal(err)
	}
	return got
}

type functionOwnerAuthorizer struct{ denied bool }

func (a *functionOwnerAuthorizer) Authorize(context.Context, authorization.Request) *awswire.Error {
	if a.denied {
		return &awswire.Error{Code: "AccessDeniedException", Message: "current identity denied", StatusCode: 403}
	}
	return nil
}

func TestFunctionPolicyDeploymentRecoveryAndNativeChanges(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		function := deployment()
		key := lambda.FunctionReference{FunctionKey: function.Key}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error { return tx.PutFunction(function) }); err != nil {
			t.Fatal(err)
		}
		ctx := versionOwnerContext(t, function.Key)
		owner := lambda.FunctionPolicyOwner{StackID: "stack", LogicalID: "Policy", Token: "create"}
		owned := service.WithFunctionPolicyDeployment(ctx, lambda.FunctionPolicyDeployment{Owner: owner, CreateOnly: true})
		auth := &functionOwnerAuthorizer{}
		s := service.New(service.Config{Repository: repo, PolicyBinder: authorization.New(nil, nil), Authorizer: auth})
		t.Cleanup(func() { _ = s.Close() })
		put := func(callCtx context.Context, sid string) (*api.PutResourcePolicyResponse, *awswire.Error) {
			out, wire := storedAliasCommand(t, s, callCtx, "PutResourcePolicy", &api.PutResourcePolicyRequest{ResourceArn: new(api.PolicyResourceArn(key.ARN())), Policy: new(api.ResourcePolicy(functionOwnerDocument(key, sid)))})
			if wire != nil {
				return nil, wire
			}
			return out.(*api.PutResourcePolicyResponse), nil
		}
		first, wire := put(owned, "initial")
		if wire != nil {
			t.Fatal(wire)
		}
		initial := functionOwnerRead(t, repo, key)
		if initial.Owner != owner {
			t.Fatalf("missing create owner: %+v", initial)
		}
		for _, other := range []lambda.FunctionPolicyOwner{{}, {StackID: "foreign", LogicalID: owner.LogicalID, Token: owner.Token}, {StackID: owner.StackID, LogicalID: "Other", Token: owner.Token}, {StackID: owner.StackID, LogicalID: owner.LogicalID, Token: "other"}} {
			_, wire := put(service.WithFunctionPolicyDeployment(ctx, lambda.FunctionPolicyDeployment{Owner: other, CreateOnly: true}), "conflict")
			if wire == nil || wire.Code != "ResourceConflictException" {
				t.Fatalf("foreign create: %v", wire)
			}
			if got := functionOwnerRead(t, repo, key); !reflect.DeepEqual(got, initial) {
				t.Fatalf("conflict mutated policy: %+v", got)
			}
		}
		auth.denied = true
		if _, wire := put(owned, "denied"); wire == nil || wire.Code != "AccessDeniedException" {
			t.Fatalf("recovery bypassed current IAM: %v", wire)
		}
		auth.denied = false
		if _, wire := put(service.WithFunctionPolicyDeployment(ctx, lambda.FunctionPolicyDeployment{Owner: lambda.FunctionPolicyOwner{StackID: "partial"}}), "partial"); wire == nil || wire.Code != "AccessDeniedException" {
			t.Fatalf("partial owner accepted: %v", wire)
		}
		recovered, wire := put(owned, "different")
		if wire != nil || !reflect.DeepEqual(recovered, first) {
			t.Fatalf("recovery overwrote policy: %+v %v", recovered, wire)
		}
		_, wire = storedAliasCommand(t, s, ctx, "AddPermission", &api.AddPermissionInput{FunctionName: new(api.NamespacedFunctionName(key.Name)), StatementId: new(api.StatementId("sibling")), Action: new(api.Action("lambda:InvokeFunction")), Principal: new(api.Principal("s3.amazonaws.com"))})
		if wire != nil {
			t.Fatal(wire)
		}
		sibling := functionOwnerRead(t, repo, key)
		if sibling.Owner != owner || !strings.Contains(sibling.Document, `"aws:SourceAccount":"111111111111"`) {
			t.Fatalf("sibling lost owner or condition: %+v", sibling)
		}
		recovered, wire = put(owned, "different")
		if wire != nil || string(*recovered.RevisionId) != sibling.Revision || !strings.Contains(string(*recovered.Policy), "sibling") {
			t.Fatalf("recovery lost native sibling: %+v %v", recovered, wire)
		}
		if _, wire = put(ctx, "native"); wire != nil {
			t.Fatal(wire)
		}
		native := functionOwnerRead(t, repo, key)
		if native.Owner != (lambda.FunctionPolicyOwner{}) || strings.Contains(native.Document, "sibling") {
			t.Fatalf("native overwrite retained private state: %+v", native)
		}
		if _, wire = put(owned, "stale-create"); wire == nil || wire.Code != "ResourceConflictException" {
			t.Fatalf("create adopted native overwrite: %v", wire)
		}
		update := service.WithFunctionPolicyDeployment(ctx, lambda.FunctionPolicyDeployment{Owner: owner})
		if _, wire = put(update, "updated"); wire != nil {
			t.Fatal(wire)
		}
		updated := functionOwnerRead(t, repo, key)
		if updated.Owner != owner || strings.Contains(updated.Document, `"Sid":"native"`) || !strings.Contains(updated.Document, `"Sid":"updated"`) {
			t.Fatalf("update failed to replace native policy: %+v", updated)
		}
		abort := errors.New("abort policy update")
		if err := repo.Update(ctx, func(tx lambda.Transaction) error {
			if _, wire := put(service.WithFunctionPolicyDeployment(tx.Context(), lambda.FunctionPolicyDeployment{Owner: owner}), "rolled-back"); wire != nil {
				return wire
			}
			return abort
		}); !errors.Is(err, abort) {
			t.Fatal(err)
		}
		if got := functionOwnerRead(t, repo, key); !reflect.DeepEqual(got, updated) {
			t.Fatalf("rollback changed policy: %+v", got)
		}
		_, wire = storedAliasCommand(t, s, ctx, "DeleteResourcePolicy", &api.DeleteResourcePolicyRequest{ResourceArn: new(api.PolicyResourceArn(key.ARN()))})
		if wire != nil {
			t.Fatal(wire)
		}
		if err := repo.View(ctx, func(r lambda.Reader) error { _, err := r.FunctionPolicy(key); return err }); !errors.Is(err, lambda.ErrNotFound) {
			t.Fatalf("public delete retained owned policy: %v", err)
		}
		unowned := service.WithFunctionPolicyDeployment(ctx, lambda.FunctionPolicyDeployment{CreateOnly: true})
		if _, wire := put(unowned, "unowned"); wire != nil {
			t.Fatal(wire)
		}
		if _, wire := put(unowned, "must-conflict"); wire == nil || wire.Code != "ResourceConflictException" {
			t.Fatalf("zero owner recovered/adopted policy: %v", wire)
		}
	})
}

func TestFunctionPolicyConcurrentCreateAndQualifierScope(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		function := deployment()
		key := lambda.FunctionReference{FunctionKey: function.Key}
		alias := key
		alias.Qualifier = "live"
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.PutFunction(function); err != nil {
				return err
			}
			function.Version = 1
			if err := tx.PutFunctionVersion(function); err != nil {
				return err
			}
			return tx.PutAlias(lambda.AliasRecord{Key: alias, FunctionVersion: 1, Revision: "alias"})
		}); err != nil {
			t.Fatal(err)
		}
		ctx := versionOwnerContext(t, function.Key)
		s := service.New(service.Config{Repository: repo, PolicyBinder: authorization.New(nil, nil)})
		t.Cleanup(func() { _ = s.Close() })
		var wg sync.WaitGroup
		results := make(chan *awswire.Error, 2)
		for _, token := range []string{"a", "b"} {
			wg.Go(func() {
				owned := service.WithFunctionPolicyDeployment(ctx, lambda.FunctionPolicyDeployment{Owner: lambda.FunctionPolicyOwner{StackID: "stack", LogicalID: "policy", Token: token}, CreateOnly: true})
				_, wire := storedAliasCommand(t, s, owned, "PutResourcePolicy", &api.PutResourcePolicyRequest{ResourceArn: new(api.PolicyResourceArn(key.ARN())), Policy: new(api.ResourcePolicy(functionOwnerDocument(key, token)))})
				results <- wire
			})
		}
		wg.Wait()
		close(results)
		successes, conflicts := 0, 0
		for wire := range results {
			if wire == nil {
				successes++
			} else if wire.Code == "ResourceConflictException" {
				conflicts++
			} else {
				t.Fatal(wire)
			}
		}
		if successes != 1 || conflicts != 1 {
			t.Fatalf("non-atomic create: successes=%d conflicts=%d", successes, conflicts)
		}
		winner := functionOwnerRead(t, repo, key)
		for _, qualified := range []lambda.FunctionReference{alias, {FunctionKey: key.FunctionKey, Qualifier: "1"}} {
			owned := service.WithFunctionPolicyDeployment(ctx, lambda.FunctionPolicyDeployment{Owner: winner.Owner, CreateOnly: true})
			_, wire := storedAliasCommand(t, s, owned, "PutResourcePolicy", &api.PutResourcePolicyRequest{ResourceArn: new(api.PolicyResourceArn(qualified.ARN())), Policy: new(api.ResourcePolicy(functionOwnerDocument(qualified, "qualified")))})
			if wire != nil {
				t.Fatal(wire)
			}
			got := functionOwnerRead(t, repo, qualified)
			if got.Owner != winner.Owner || !strings.Contains(got.Document, qualified.ARN()) {
				t.Fatalf("qualifier crossed policy scope: %+v", got)
			}
		}
		if got := functionOwnerRead(t, repo, key); !reflect.DeepEqual(got, winner) {
			t.Fatalf("qualified create modified base: %+v", got)
		}
	})
}

func TestSQLiteFunctionPolicyOwnerReopenAndMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	function := deployment()
	key := lambda.FunctionReference{FunctionKey: function.Key}
	want := lambda.FunctionPolicy{Key: key, Document: functionOwnerDocument(key, "retained"), Revision: "persisted", Owner: lambda.FunctionPolicyOwner{StackID: "stack", LogicalID: "policy", Token: "create"}, PrincipalIDs: map[string]string{}}
	if err := sqllambda.New(db).Update(t.Context(), func(tx lambda.Transaction) error {
		if err := tx.PutFunction(function); err != nil {
			return err
		}
		return tx.PutFunctionPolicy(want)
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if got := functionOwnerRead(t, sqllambda.New(db), key); !reflect.DeepEqual(got, want) {
		t.Fatalf("reopen lost owner: %+v", got)
	}
	legacyPath := filepath.Join(t.TempDir(), "legacy.sqlite")
	historical := awstest.HistoricalSQLite(t, legacyPath, "../sqlite/schema", 301, path, nil)
	if err := historical.Close(); err != nil {
		t.Fatal(err)
	}
	legacy, err := sqlite.Open(t.Context(), legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = legacy.Close() })
	want.Owner = lambda.FunctionPolicyOwner{}
	repo := sqllambda.New(legacy)
	if got := functionOwnerRead(t, repo, key); !reflect.DeepEqual(got, want) {
		t.Fatalf("migration adopted or changed legacy policy: %+v", got)
	}
	s := service.New(service.Config{Repository: repo, PolicyBinder: authorization.New(nil, nil)})
	t.Cleanup(func() { _ = s.Close() })
	owned := service.WithFunctionPolicyDeployment(versionOwnerContext(t, function.Key), lambda.FunctionPolicyDeployment{Owner: lambda.FunctionPolicyOwner{StackID: "stack", LogicalID: "policy", Token: "create"}, CreateOnly: true})
	_, wire := storedAliasCommand(t, s, owned, "PutResourcePolicy", &api.PutResourcePolicyRequest{ResourceArn: new(api.PolicyResourceArn(key.ARN())), Policy: new(api.ResourcePolicy(functionOwnerDocument(key, "new")))})
	if wire == nil || wire.Code != "ResourceConflictException" {
		t.Fatalf("create adopted migrated legacy policy: %v", wire)
	}
}

func TestFunctionPolicyCreateRecoveryJournalAtomicity(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var repo lambda.Repository
			var events journal.Storage
			if backend == "memory" {
				domain := memory.NewDomain()
				repo, events = lambda.NewMemory(domain), journal.NewMemory(domain)
			} else {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "events.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				repo, events = sqllambda.New(db), sqljournal.New(db)
			}
			function := deployment()
			key := lambda.FunctionReference{FunctionKey: function.Key}
			if err := repo.Update(t.Context(), func(tx lambda.Transaction) error { return tx.PutFunction(function) }); err != nil {
				t.Fatal(err)
			}
			ctx := versionOwnerContext(t, function.Key)
			owner := lambda.FunctionPolicyOwner{StackID: "private-stack", LogicalID: "private-logical", Token: "private-token"}
			owned := service.WithFunctionPolicyDeployment(ctx, lambda.FunctionPolicyDeployment{Owner: owner, CreateOnly: true})
			s := service.New(service.Config{Repository: repo, PolicyBinder: authorization.New(nil, nil), APIEvents: apievents.New(events)})
			t.Cleanup(func() { _ = s.Close() })
			request := &api.PutResourcePolicyRequest{ResourceArn: new(api.PolicyResourceArn(key.ARN())), Policy: new(api.ResourcePolicy(functionOwnerDocument(key, "initial")))}
			abort := errors.New("abort create")
			if err := repo.Update(owned, func(tx lambda.Transaction) error {
				if _, wire := storedAliasCommand(t, s, tx.Context(), "PutResourcePolicy", request); wire != nil {
					return wire
				}
				return abort
			}); !errors.Is(err, abort) {
				t.Fatal(err)
			}
			if err := repo.View(ctx, func(r lambda.Reader) error { _, err := r.FunctionPolicy(key); return err }); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("rolled back create retained policy: %v", err)
			}
			if rows, err := events.Read(ctx, 0, 10); err != nil || len(rows) != 0 {
				t.Fatalf("rolled back create retained event: %+v %v", rows, err)
			}
			first, wire := storedAliasCommand(t, s, owned, "PutResourcePolicy", request)
			if wire != nil {
				t.Fatal(wire)
			}
			request.Policy = new(api.ResourcePolicy(functionOwnerDocument(key, "must-not-replace")))
			recovered, wire := storedAliasCommand(t, s, owned, "PutResourcePolicy", request)
			if wire != nil || !reflect.DeepEqual(first, recovered) {
				t.Fatalf("recovery changed committed policy: %+v %v", recovered, wire)
			}
			rows, err := events.Read(ctx, 0, 10)
			if err != nil || len(rows) != 2 {
				t.Fatalf("create/recovery events: %+v %v", rows, err)
			}
			for _, row := range rows {
				call := row.APICallCompleted
				if call == nil || call.ErrorCode != "" || !strings.Contains(call.EventName, "PutResourcePolicy") {
					t.Fatalf("incorrect policy event: %+v", call)
				}
				for _, private := range []string{owner.StackID, owner.LogicalID, owner.Token} {
					if strings.Contains(string(call.RequestParameters), private) || strings.Contains(string(call.ResponseElements), private) {
						t.Fatal("event leaked private owner")
					}
				}
			}
			if string(rows[0].APICallCompleted.ResponseElements) != string(rows[1].APICallCompleted.ResponseElements) {
				t.Fatal("recovery event did not report current policy/revision")
			}
		})
	}
}
