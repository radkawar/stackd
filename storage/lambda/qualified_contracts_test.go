package lambda_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"stackd/internal/awstest"
	"stackd/storage/lambda"
	"stackd/storage/sqlite"
	sqllambda "stackd/storage/sqlite/lambda"
)

func TestPublishedReadinessRollbackAndScopedAllocation(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		latest := deployment()
		latest.DeploymentRevision = "deployment-one"
		published := latest
		published.Version, published.Description = 1, "published description"
		other := published
		other.Key.Region, other.DeploymentRevision = "us-west-2", "other-deployment"
		newer := published
		newer.Version, newer.DeploymentRevision = 2, "deployment-two"
		abort := errors.New("abort publication")
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.PutFunction(latest); err != nil {
				return err
			}
			if err := tx.PutFunction(other); err != nil {
				return err
			}
			for _, v := range []lambda.FunctionRecord{published, other, newer} {
				n, err := tx.AllocateFunctionVersion(v.Key)
				if err != nil || n != v.Version {
					t.Fatalf("scope allocation: %d %v", n, err)
				}
				if err := tx.PutFunctionVersion(v); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		ready := latest
		ready.State, ready.StateReason, ready.StateReasonCode = "Active", "", ""
		ready.UpdateStatus, ready.UpdateReason = "Successful", ""
		ready.Revision = "published-ready-revision"
		ready.Modified = latest.Modified.Add(time.Hour)
		ready.Description, ready.Variables = "must not overwrite snapshot", map[string]string{"ENV": "changed"}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.SetPublishedDeploymentState(ready); err != nil {
				return err
			}
			if _, err := tx.AllocateFunctionVersion(latest.Key); err != nil {
				return err
			}
			return abort
		}); !errors.Is(err, abort) {
			t.Fatalf("publication rollback: %v", err)
		}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			key := lambda.FunctionVersionKey{FunctionKey: latest.Key, Version: 1}
			snapshot, err := tx.FunctionVersion(key)
			if err != nil || snapshot.State != "Pending" || snapshot.Revision != published.Revision {
				t.Fatalf("readiness escaped rollback: %+v %v", snapshot, err)
			}
			n, err := tx.LastAllocatedVersion(latest.Key)
			if err != nil || n != 2 {
				t.Fatalf("allocation escaped rollback: %d %v", n, err)
			}
			if err := tx.SetPublishedDeploymentState(ready); err != nil {
				return err
			}
			snapshot, err = tx.FunctionVersion(key)
			if err != nil || snapshot.State != "Active" || snapshot.UpdateStatus != "Successful" || snapshot.Revision != ready.Revision || !snapshot.Modified.Equal(published.Modified) || snapshot.Description != published.Description || snapshot.Variables["ENV"] != "old" || len(snapshot.Tags) != 0 {
				t.Fatalf("readiness changed immutable configuration: %+v %v", snapshot, err)
			}
			current, err := tx.Function(latest.Key)
			if err != nil || current.Revision != latest.Revision {
				t.Fatalf("publication readiness changed latest revision: %+v %v", current, err)
			}
			foreign, err := tx.FunctionVersion(lambda.FunctionVersionKey{FunctionKey: other.Key, Version: 1})
			if err != nil || foreign.State != "Pending" {
				t.Fatalf("readiness crossed scope: %+v %v", foreign, err)
			}
			unmatched, err := tx.FunctionVersion(lambda.FunctionVersionKey{FunctionKey: latest.Key, Version: 2})
			if err != nil || unmatched.State != "Pending" {
				t.Fatalf("readiness crossed deployment revision: %+v %v", unmatched, err)
			}
			if err := tx.PutFunctionVersion(ready); err == nil {
				t.Fatal("accepted version zero as a publication")
			}
			if err := tx.PutFunctionVersion(published); err == nil {
				t.Fatal("overwrote immutable publication")
			}
			all, err := tx.AllFunctions()
			if err != nil || len(all) != 2 {
				t.Fatalf("activation scan included snapshots: %+v %v", all, err)
			}
			usage, err := tx.AccountUsage(latest.Key.Scope)
			if err != nil || usage.FunctionCount != 1 || usage.TotalCodeSize != 12 {
				t.Fatalf("published code accounting: %+v %v", usage, err)
			}
			if err := tx.DeleteFunction(latest.Key); err != nil {
				return err
			}
			if err := tx.PutFunction(latest); err != nil {
				return err
			}
			n, err = tx.AllocateFunctionVersion(latest.Key)
			if err != nil || n != 3 {
				t.Fatalf("recreation reset allocation: %d %v", n, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestQualifiedDeletionRetainsAcceptedWorkMetricsAndDownloads(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		latest := deployment()
		published := latest
		published.Version, published.CodeSHA256 = 1, "published-code"
		alias := lambda.FunctionReference{FunctionKey: latest.Key, Qualifier: "live"}
		numeric := lambda.FunctionReference{FunctionKey: latest.Key, Qualifier: "1"}
		base := lambda.FunctionReference{FunctionKey: latest.Key}
		until := latest.Modified.Add(time.Minute)
		archive := lambda.CodeArchiveKey{Scope: latest.Key.Scope, SHA256: published.CodeSHA256}
		sample := []lambda.MetricSample{{Name: "Invocations", Value: 1, SampleCount: 1}}
		settings := lambda.EventInvokeSettings{MaxAgeSeconds: 120, MaxRetries: 1, OnSuccessARN: "arn:aws:sqs:us-east-1:111111111111:success", OnFailureARN: "arn:aws:sqs:us-east-1:111111111111:failure"}
		dlq := "arn:aws:sqs:us-east-1:111111111111:dlq"
		metricKeys := []lambda.MetricPublicationKey{
			{Function: latest.Key, Minute: latest.Modified},
			{Function: latest.Key, Minute: latest.Modified, Resource: latest.Key.Name + ":live", ExecutedVersion: "1"},
			{Function: latest.Key, Minute: latest.Modified, Resource: latest.Key.Name + ":live", ExecutedVersion: "2"},
		}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.PutFunction(latest); err != nil {
				return err
			}
			if _, err := tx.AllocateFunctionVersion(latest.Key); err != nil {
				return err
			}
			if err := tx.PutFunctionVersion(published); err != nil {
				return err
			}
			if err := tx.PutCodeArchive(lambda.CodeArchive{Key: archive, Code: []byte("published ZIP"), CreatedAt: latest.Modified, RetainUntil: until}); err != nil {
				return err
			}
			if err := tx.PutAlias(lambda.AliasRecord{Key: alias, FunctionVersion: 1}); err != nil {
				return err
			}
			for _, ref := range []lambda.FunctionReference{numeric, alias, base} {
				if err := tx.PutFunctionPolicy(lambda.FunctionPolicy{Key: ref, Document: "{}", Revision: ref.ARN()}); err != nil {
					return err
				}
				if err := tx.PutEventInvokeConfig(lambda.EventInvokeConfig{Key: ref, Modified: latest.Modified, AppliesAt: &until, Version: 1}); err != nil {
					return err
				}
			}
			if err := tx.PutInvocation(lambda.InvocationRecord{ID: "accepted", Key: latest.Key, FunctionARN: alias.ARN(), Payload: []byte("{}"), Accepted: latest.Modified, Due: until, State: "in-flight", RoleARN: latest.Role, Settings: settings, DeadLetterARN: dlq}); err != nil {
				return err
			}
			for _, key := range metricKeys {
				if err := tx.AddMetricSamples(key, sample); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			configs, err := tx.EventInvokeConfigs(latest.Key)
			if err != nil || len(configs) != 3 || configs[0].Key != base || configs[1].Key != numeric || configs[2].Key != alias {
				t.Fatalf("qualified listing: %+v %v", configs, err)
			}
			job, found, err := tx.NextEventInvokeConfigChange()
			if err != nil || !found || job.Key != base.ARN() {
				t.Fatalf("config ordering: %+v %v %v", job, found, err)
			}
			if err := tx.DeleteAlias(alias); err != nil {
				return err
			}
			if _, err := tx.FunctionPolicy(alias); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("alias policy survived deletion: %v", err)
			}
			if _, err := tx.EventInvokeConfig(alias); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("alias config survived deletion: %v", err)
			}
			// The version, rather than latest, keeps its archive reachable past expiration.
			n, err := tx.DeleteExpiredCodeArchives(until.Add(time.Second))
			if err != nil || n != 0 {
				t.Fatalf("published archive collected: %d %v", n, err)
			}
			if err := tx.DeleteFunctionVersion(lambda.FunctionVersionKey{FunctionKey: latest.Key, Version: 1}); err != nil {
				return err
			}
			if _, err := tx.EventInvokeConfig(numeric); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("numeric config survived deletion: %v", err)
			}
			return tx.DeleteFunction(latest.Key)
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			v, err := r.Invocation("accepted")
			if err != nil || v.FunctionARN != alias.ARN() || v.State != "in-flight" || v.Settings != settings || v.RoleARN != latest.Role || v.DeadLetterARN != dlq {
				t.Fatalf("deletion revoked accepted work or delivery authority: %+v %v", v, err)
			}
			for _, key := range metricKeys {
				samples, err := r.MetricSamples(key)
				if err != nil || len(samples) != 1 || samples[0].SampleCount != 1 {
					t.Fatalf("metric series merged or deleted: %+v %v", samples, err)
				}
			}
			retained, err := r.CodeArchive(archive)
			if err != nil || string(retained.Code) != "published ZIP" {
				t.Fatalf("deletion revoked download: %+v %v", retained, err)
			}
			configs, err := r.EventInvokeConfigs(latest.Key)
			if err != nil || len(configs) != 0 {
				t.Fatalf("whole deletion retained controls: %+v %v", configs, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSQLiteVersionAllocationSurvivesDeletedFunctionReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "versions.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	latest := deployment()
	settings := lambda.EventInvokeSettings{MaxAgeSeconds: 900, MaxRetries: 0, OnSuccessARN: "arn:aws:sqs:us-east-1:111111111111:success", OnFailureARN: "arn:aws:sqs:us-east-1:111111111111:failure"}
	dlq := "arn:aws:sqs:us-east-1:111111111111:dlq"
	if err := sqllambda.New(db).Update(t.Context(), func(tx lambda.Transaction) error {
		if err := tx.PutFunction(latest); err != nil {
			return err
		}
		n, err := tx.AllocateFunctionVersion(latest.Key)
		if err != nil || n != 1 {
			t.Fatalf("initial allocation: %d %v", n, err)
		}
		invocation := lambda.InvocationRecord{ID: "retained", Key: latest.Key, FunctionARN: latest.Key.ARN(), Payload: []byte("{}"), Accepted: latest.Modified, Due: latest.Modified, State: "queued", RoleARN: latest.Role, Settings: lambda.EventInvokeSettings{MaxAgeSeconds: 21600, MaxRetries: 2}}
		if err := tx.PutInvocation(invocation); err != nil {
			return err
		}
		invocation.State, invocation.RoleARN, invocation.Settings, invocation.DeadLetterARN = "in-flight", "attempt-role", settings, dlq
		if err := tx.PutInvocation(invocation); err != nil {
			return err
		}
		return tx.DeleteFunction(latest.Key)
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
	if err := sqllambda.New(db).Update(t.Context(), func(tx lambda.Transaction) error {
		invocation, err := tx.Invocation("retained")
		if err != nil || invocation.Settings != settings || invocation.RoleARN != "attempt-role" || invocation.DeadLetterARN != dlq || invocation.State != "in-flight" {
			t.Fatalf("reopen/deletion lost latest attempt authority: %+v %v", invocation, err)
		}
		if err := tx.PutFunction(latest); err != nil {
			return err
		}
		n, err := tx.AllocateFunctionVersion(latest.Key)
		if err != nil || n != 2 {
			t.Fatalf("reopen reused allocated version: %d %v", n, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestQualifiedMigrationRetainsUnqualifiedDeploymentAndHistory(t *testing.T) {
	source := filepath.Join(t.TempDir(), "current.sqlite")
	db, err := sqlite.Open(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	latest := deployment()
	latest.DeadLetterARN = "arn:aws:sqs:us-east-1:111111111111:historical-dlq"
	applied := lambda.EventInvokeSettings{MaxAgeSeconds: 900, MaxRetries: 2, OnSuccessARN: "arn:aws:sqs:us-east-1:111111111111:historical-success", OnFailureARN: "arn:aws:sqs:us-east-1:111111111111:historical-failure"}
	pending := latest
	pending.Variables = map[string]string{"ENV": "pending"}
	base := lambda.FunctionReference{FunctionKey: latest.Key}
	metric := lambda.MetricPublicationKey{Function: latest.Key, Minute: latest.Modified}
	if err := sqllambda.New(db).Update(t.Context(), func(tx lambda.Transaction) error {
		if err := tx.PutFunction(latest); err != nil {
			return err
		}
		if err := tx.PutPendingFunction(pending); err != nil {
			return err
		}
		if err := tx.PutFunctionConcurrency(latest.Key, 7); err != nil {
			return err
		}
		if err := tx.PutFunctionPolicy(lambda.FunctionPolicy{Key: base, Document: "policy", Revision: "before", PrincipalIDs: map[string]string{"principal": "retained-id"}}); err != nil {
			return err
		}
		if err := tx.PutEventInvokeConfig(lambda.EventInvokeConfig{Key: base, Modified: latest.Modified, MaxRetries: 1, HasMaxRetries: true, Effective: applied, AppliesAt: &latest.Modified, Version: 4}); err != nil {
			return err
		}
		if err := tx.PutInvocation(lambda.InvocationRecord{ID: "historical", Key: latest.Key, FunctionARN: base.ARN(), Payload: []byte("{}"), Accepted: latest.Modified, Due: latest.Modified, State: "queued"}); err != nil {
			return err
		}
		if err := tx.PutInvocation(lambda.InvocationRecord{ID: "completed", Key: latest.Key, FunctionARN: base.ARN(), Payload: []byte("{}"), Accepted: latest.Modified, Due: latest.Modified, State: "completed", RoleARN: "recorded-role", Completed: latest.Modified, Completion: "success", ResponsePayload: []byte("historical-result")}); err != nil {
			return err
		}
		orphan := latest.Key
		orphan.Region = "us-west-2"
		if err := tx.PutInvocation(lambda.InvocationRecord{ID: "orphan", Key: orphan, FunctionARN: orphan.ARN(), Payload: []byte("{}"), Accepted: latest.Modified, Due: latest.Modified, State: "queued"}); err != nil {
			return err
		}
		return tx.AddMetricSamples(metric, []lambda.MetricSample{{Name: "Duration", Value: 123, SampleCount: 3}})
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "historical.sqlite")
	historical := awstest.HistoricalSQLite(t, path, "../sqlite/schema", 46, source, nil)
	if err := historical.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := sqllambda.New(db).Update(t.Context(), func(tx lambda.Transaction) error {
		current, err := tx.Function(latest.Key)
		if err != nil || current.Version != 0 || current.Reference != nil || current.Variables["ENV"] != "old" || current.Tags["tag"] != "old" {
			t.Fatalf("upgrade lost current deployment: %+v %v", current, err)
		}
		candidate, err := tx.PendingFunction(latest.Key)
		if err != nil || candidate.Reference != nil || candidate.Variables["ENV"] != "pending" {
			t.Fatalf("upgrade merged pending deployment: %+v %v", candidate, err)
		}
		policy, err := tx.FunctionPolicy(base)
		if err != nil || policy.PrincipalIDs["principal"] != "retained-id" {
			t.Fatalf("upgrade lost policy identity: %+v %v", policy, err)
		}
		config, err := tx.EventInvokeConfig(base)
		if err != nil || config.MaxRetries != 1 || config.Effective.MaxRetries != 2 {
			t.Fatalf("upgrade collapsed propagation state: %+v %v", config, err)
		}
		job, found, err := tx.NextEventInvokeConfigChange()
		if err != nil || !found || job.Key != base.ARN() || job.Version != 4 {
			t.Fatalf("upgrade lost propagation job: %+v %v %v", job, found, err)
		}
		usage, err := tx.AccountUsage(latest.Key.Scope)
		if err != nil || usage.FunctionCount != 1 || usage.TotalCodeSize != latest.CodeSize || usage.ReservedConcurrency != 7 {
			t.Fatalf("upgrade lost base ownership: %+v %v", usage, err)
		}
		if err := tx.DeleteFunction(latest.Key); err != nil {
			return err
		}
		invocation, err := tx.Invocation("historical")
		if err != nil || invocation.Settings != applied || invocation.RoleARN != latest.Role || invocation.DeadLetterARN != latest.DeadLetterARN {
			t.Fatalf("migration/deletion lost admitted authority: %+v %v", invocation, err)
		}
		completed, err := tx.Invocation("completed")
		if err != nil || completed.RoleARN != "recorded-role" || completed.Completion != "success" || string(completed.ResponsePayload) != "historical-result" || !completed.Completed.Equal(latest.Modified) {
			t.Fatalf("migration rewrote completed history: %+v %v", completed, err)
		}
		orphan, err := tx.Invocation("orphan")
		if err != nil || orphan.Settings != (lambda.EventInvokeSettings{MaxAgeSeconds: 21600, MaxRetries: 2}) {
			t.Fatalf("migration lost default controls without target: %+v %v", orphan, err)
		}
		samples, err := tx.MetricSamples(metric)
		if err != nil || len(samples) != 1 || samples[0].Value != 123 || samples[0].SampleCount != 3 {
			t.Fatalf("upgrade/deletion lost historical samples: %+v %v", samples, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
