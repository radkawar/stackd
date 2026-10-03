package configservice_test

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	domain "stackd/storage/configservice"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/configservice"
)

func repositories(t *testing.T, fn func(*testing.T, domain.Repository)) {
	t.Helper()
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "memory" {
				fn(t, domain.NewMemory(memory.NewDomain()))
				return
			}
			db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "config.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := db.Close(); err != nil {
					t.Error(err)
				}
			})
			fn(t, backend.New(db))
		})
	}
}
func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

var testScope = domain.Scope{Partition: "aws", AccountID: "111122223333", Region: "us-east-1"}

func TestScopeAndDeletionRetention(t *testing.T) {
	repositories(t, func(t *testing.T, repo domain.Repository) {
		scopes := []domain.Scope{testScope, {Partition: "aws-cn", AccountID: testScope.AccountID, Region: testScope.Region}, {Partition: "aws", AccountID: "444455556666", Region: testScope.Region}, {Partition: "aws", AccountID: testScope.AccountID, Region: "us-west-2"}}
		check(t, repo.Update(t.Context(), func(tx domain.Transaction) error {
			for i, s := range scopes {
				if err := tx.PutRecorder(domain.Recorder{Scope: s, Name: "default", Recording: true}); err != nil {
					return err
				}
				if err := tx.PutChannel(domain.Channel{Scope: s, Name: "default", Bucket: s.AccountID}); err != nil {
					return err
				}
				item, err := tx.AppendItem(domain.Item{Scope: s, Sequence: 900, ResourceType: "AWS::S3::Bucket", ResourceID: "shared-name", Status: "OK", Configuration: `{"version":1}`})
				if err != nil {
					return err
				}
				if item.Sequence != int64(i+1) {
					t.Fatalf("global sequence = %d, want %d", item.Sequence, i+1)
				}
				if err := tx.PutRule(domain.Rule{Scope: s, Name: "required-tags", ResourceTypes: []string{"AWS::S3::Bucket"}}); err != nil {
					return err
				}
				if err := tx.PutEvaluation(domain.Evaluation{Scope: s, RuleName: "required-tags", ResourceType: "AWS::S3::Bucket", ResourceID: "shared-name", ComplianceType: "NON_COMPLIANT"}); err != nil {
					return err
				}
				if err := tx.PutEvaluationRun(domain.EvaluationRun{Scope: s, Token: "same-token", RuleName: "required-tags", ItemSequence: item.Sequence, Status: "PENDING"}); err != nil {
					return err
				}
				if err := tx.PutAggregator(domain.Aggregator{Scope: s, Name: "same-name", Sources: []domain.AggregationSource{{AccountID: s.AccountID, Region: s.Region}}}); err != nil {
					return err
				}
				if err := tx.PutAggregationAuthorization(domain.AggregationAuthorization{Scope: s, AccountID: "777788889999", Region: "us-east-2"}); err != nil {
					return err
				}
			}
			if err := tx.DeleteRecorder(testScope); err != nil {
				return err
			}
			if err := tx.DeleteChannel(testScope); err != nil {
				return err
			}
			if err := tx.DeleteRule(testScope, "required-tags"); err != nil {
				return err
			}
			if err := tx.DeleteAggregator(testScope, "same-name"); err != nil {
				return err
			}
			return tx.DeleteAggregationAuthorization(testScope, "777788889999", "us-east-2")
		}))
		check(t, repo.View(t.Context(), func(r domain.Reader) error {
			for i, s := range scopes {
				recorder, ok, err := r.Recorder(s)
				if err != nil {
					return err
				}
				if ok != (i != 0) || (ok && recorder.Scope != s) {
					t.Fatalf("recorder scope/deletion mismatch: %+v %v", recorder, ok)
				}
				channel, ok, err := r.Channel(s)
				if err != nil {
					return err
				}
				if ok != (i != 0) || (ok && channel.Bucket != s.AccountID) {
					t.Fatalf("channel scope/deletion mismatch: %+v %v", channel, ok)
				}
				items, err := r.Items(s)
				if err != nil {
					return err
				}
				if len(items) != 1 || items[0].Scope != s || items[0].Sequence != int64(i+1) || items[0].Configuration != `{"version":1}` {
					t.Fatalf("history lost or leaked scope: %+v", items)
				}
				want := 1
				if i == 0 {
					want = 0
				}
				rules, err := r.Rules(s)
				if err != nil {
					return err
				}
				if len(rules) != want {
					t.Fatalf("rules after deletion: %+v", rules)
				}
				evaluations, err := r.Evaluations(s)
				if err != nil {
					return err
				}
				if len(evaluations) != want {
					t.Fatalf("evaluations after deletion: %+v", evaluations)
				}
				aggregators, err := r.Aggregators(s)
				if err != nil {
					return err
				}
				if len(aggregators) != want {
					t.Fatalf("aggregators after deletion: %+v", aggregators)
				}
				authorizations, err := r.AggregationAuthorizations(s)
				if err != nil {
					return err
				}
				if len(authorizations) != want {
					t.Fatalf("authorizations after deletion: %+v", authorizations)
				}
			}
			runs, err := r.EvaluationRuns()
			if err != nil {
				return err
			}
			if len(runs) != 3 {
				t.Fatalf("run deletion crossed scope: %+v", runs)
			}
			for _, run := range runs {
				if run.Scope == testScope {
					t.Fatalf("deleted rule retained run: %+v", run)
				}
			}
			return nil
		}))
		check(t, repo.Update(t.Context(), func(tx domain.Transaction) error {
			item, err := tx.AppendItem(domain.Item{Scope: testScope, ResourceType: "AWS::S3::Bucket", ResourceID: "shared-name", Status: "ResourceDeleted"})
			if err == nil && item.Sequence != 5 {
				t.Fatalf("history sequence restarted after recorder deletion: %d", item.Sequence)
			}
			return err
		}))
	})
}

func TestBorrowedTransactionsAndAttempts(t *testing.T) {
	repositories(t, func(t *testing.T, repo domain.Repository) {
		rejected := errors.New("command rejected")
		write := func(tx domain.Transaction) error {
			return tx.PutRecorder(domain.Recorder{Scope: testScope, Name: "default", ResourceTypes: []string{"AWS::S3::Bucket"}})
		}
		err := repo.Update(t.Context(), func(tx domain.Transaction) error {
			if err := repo.Update(tx.Context(), write); err != nil {
				return err
			}
			return rejected
		})
		if !errors.Is(err, rejected) {
			t.Fatalf("outer rollback: %v", err)
		}
		assertMissing := func() {
			t.Helper()
			check(t, repo.View(t.Context(), func(r domain.Reader) error {
				_, ok, err := r.Recorder(testScope)
				if ok {
					t.Fatal("rejected mutation committed")
				}
				return err
			}))
		}
		assertMissing()
		err = repo.Update(t.Context(), func(tx domain.Transaction) error {
			_ = repo.Update(tx.Context(), func(child domain.Transaction) error {
				if err := write(child); err != nil {
					return err
				}
				return rejected
			})
			return nil
		})
		if !errors.Is(err, rejected) {
			t.Fatalf("caught nested Update must poison owner: %v", err)
		}
		assertMissing()
		check(t, repo.Update(t.Context(), func(tx domain.Transaction) error {
			err := repo.Attempt(tx.Context(), func(child domain.Transaction) error {
				if err := write(child); err != nil {
					return err
				}
				if _, err := child.AppendItem(domain.Item{Scope: testScope}); err != nil {
					return err
				}
				return rejected
			})
			if !errors.Is(err, rejected) {
				t.Fatalf("attempt rejection: %v", err)
			}
			if _, ok, err := tx.Recorder(testScope); err != nil {
				return err
			} else if ok {
				t.Fatal("failed attempt leaked into parent")
			}
			if err := repo.Attempt(tx.Context(), write); err != nil {
				return err
			}
			return repo.View(tx.Context(), func(r domain.Reader) error {
				v, ok, err := r.Recorder(testScope)
				if !ok || v.Name != "default" {
					t.Fatalf("successful attempt invisible to borrowed reader: %+v", v)
				}
				return err
			})
		}))
		check(t, repo.Update(t.Context(), func(tx domain.Transaction) error {
			item, err := tx.AppendItem(domain.Item{Scope: testScope})
			if err == nil && item.Sequence != 1 {
				t.Fatalf("aborted item consumed sequence: %d", item.Sequence)
			}
			return err
		}))
		err = repo.Update(t.Context(), func(tx domain.Transaction) error {
			if err := repo.Attempt(tx.Context(), func(child domain.Transaction) error { return child.DeleteRecorder(testScope) }); err != nil {
				return err
			}
			return rejected
		})
		if !errors.Is(err, rejected) {
			t.Fatalf("accepted attempt outer rollback: %v", err)
		}
		var expired domain.Reader
		check(t, repo.View(t.Context(), func(r domain.Reader) error {
			expired = r
			v, ok, err := r.Recorder(testScope)
			if !ok || v.Name != "default" {
				t.Fatal("successful child committed independently of failed owner")
			}
			return err
		}))
		if _, _, err := expired.Recorder(testScope); err == nil {
			t.Fatal("expired reader remained usable")
		}
		var borrowed context.Context
		check(t, repo.View(t.Context(), func(r domain.Reader) error { borrowed = r.Context(); return nil }))
		if borrowed.Err() == nil {
			t.Fatal("borrowed context outlived transaction")
		}
	})
}

func TestDeepCloneBoundariesAndReplacement(t *testing.T) {
	repositories(t, func(t *testing.T, repo domain.Repository) {
		recorder := domain.Recorder{Scope: testScope, Name: "default", ResourceTypes: []string{"AWS::S3::Bucket"}, ExcludedTypes: []string{"AWS::IAM::Role"}}
		rule := domain.Rule{Scope: testScope, Name: "rule", ResourceTypes: []string{"AWS::S3::Bucket"}, SourceMessages: []string{"ConfigurationItemChangeNotification"}, InputParameters: `{"tag1Key":"Team"}`}
		item := domain.Item{Scope: testScope, ResourceType: "AWS::S3::Bucket", ResourceID: "bucket", Configuration: `{ "version": 1 }`, Tags: map[string]string{"Team": "Blue"}, Supplementary: map[string]string{"Policy": `{ "Statement": [] }`}, Relationships: []domain.Relationship{{ResourceID: "owner", Name: "Owned by"}}}
		aggregator := domain.Aggregator{Scope: testScope, Name: "aggregate", Sources: []domain.AggregationSource{{AccountID: "999900001111", Region: "us-west-2"}}}
		check(t, repo.Update(t.Context(), func(tx domain.Transaction) error {
			if err := tx.PutRecorder(recorder); err != nil {
				return err
			}
			if err := tx.PutRule(rule); err != nil {
				return err
			}
			if err := tx.PutAggregator(aggregator); err != nil {
				return err
			}
			result, err := tx.AppendItem(item)
			if err == nil {
				result.Tags["Team"] = "Returned mutation"
				result.Supplementary["Policy"] = "Returned mutation"
				result.Relationships[0].Name = "Returned mutation"
			}
			return err
		}))
		recorder.ResourceTypes[0] = "mutated"
		recorder.ExcludedTypes[0] = "mutated"
		rule.ResourceTypes[0] = "mutated"
		rule.SourceMessages[0] = "mutated"
		item.Tags["Team"] = "mutated"
		item.Supplementary["Policy"] = "mutated"
		item.Relationships[0].Name = "mutated"
		aggregator.Sources[0].AccountID = "mutated"
		for range 2 {
			check(t, repo.View(t.Context(), func(r domain.Reader) error {
				rec, _, err := r.Recorder(testScope)
				if err != nil {
					return err
				}
				if rec.ResourceTypes[0] != "AWS::S3::Bucket" || rec.ExcludedTypes[0] != "AWS::IAM::Role" {
					t.Fatalf("recorder aliases caller: %+v", rec)
				}
				rec.ResourceTypes[0] = "reader mutation"
				rec.ExcludedTypes[0] = "reader mutation"
				rules, err := r.Rules(testScope)
				if err != nil {
					return err
				}
				if rules[0].ResourceTypes[0] != "AWS::S3::Bucket" || rules[0].SourceMessages[0] != "ConfigurationItemChangeNotification" {
					t.Fatalf("rule aliases caller: %+v", rules)
				}
				rules[0].ResourceTypes[0] = "reader mutation"
				rules[0].SourceMessages[0] = "reader mutation"
				items, err := r.Items(testScope)
				if err != nil {
					return err
				}
				if items[0].Tags["Team"] != "Blue" || items[0].Supplementary["Policy"] != `{ "Statement": [] }` || items[0].Relationships[0].Name != "Owned by" {
					t.Fatalf("snapshot aliases caller: %+v", items)
				}
				items[0].Tags["Team"] = "reader mutation"
				items[0].Supplementary["Policy"] = "reader mutation"
				items[0].Relationships[0].Name = "reader mutation"
				aggregators, err := r.Aggregators(testScope)
				if err != nil {
					return err
				}
				if aggregators[0].Sources[0].AccountID != "999900001111" {
					t.Fatalf("aggregator aliases caller: %+v", aggregators)
				}
				aggregators[0].Sources[0].AccountID = "reader mutation"
				return nil
			}))
		}
		check(t, repo.Update(t.Context(), func(tx domain.Transaction) error {
			if err := tx.PutRecorder(domain.Recorder{Scope: testScope, Name: "default"}); err != nil {
				return err
			}
			if err := tx.PutAggregator(domain.Aggregator{Scope: testScope, Name: "aggregate"}); err != nil {
				return err
			}
			return tx.PutRule(domain.Rule{Scope: testScope, Name: "rule", InputParameters: "{}"})
		}))
		check(t, repo.View(t.Context(), func(r domain.Reader) error {
			rec, _, err := r.Recorder(testScope)
			if err != nil {
				return err
			}
			if len(rec.ResourceTypes) != 0 || len(rec.ExcludedTypes) != 0 {
				t.Fatalf("recorder replacement retained old children: %+v", rec)
			}
			rules, err := r.Rules(testScope)
			if err != nil {
				return err
			}
			if len(rules[0].ResourceTypes) != 0 || len(rules[0].SourceMessages) != 0 || rules[0].InputParameters != "{}" {
				t.Fatalf("rule replacement retained old children: %+v", rules)
			}
			aggregators, err := r.Aggregators(testScope)
			if err != nil {
				return err
			}
			if len(aggregators[0].Sources) != 0 {
				t.Fatalf("aggregator replacement retained old children: %+v", aggregators)
			}
			return nil
		}))
	})
}

func TestSQLitePendingStateAndHistorySurviveReopen(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "config.db")
	db, err := sqlite.Open(ctx, path)
	check(t, err)
	repo := backend.New(db)
	now := time.Date(2026, 9, 28, 12, 30, 0, 123456789, time.UTC)
	item := domain.Item{Scope: testScope, ResourceType: "AWS::S3::Bucket", ResourceID: "bucket", CaptureTime: now, CreationTime: now.Add(-time.Hour), Configuration: `{ "version": 1 }`, Tags: map[string]string{"Team": "Blue"}, Supplementary: map[string]string{"Policy": `{"Statement":[]}`}, Relationships: []domain.Relationship{{ResourceType: "AWS::IAM::Role", ResourceID: "role", Name: "Uses"}}}
	rule := domain.Rule{Scope: testScope, Name: "rule", ID: "config-rule-1", Owner: "CUSTOM_LAMBDA", SourceIdentifier: "arn:aws:lambda:us-east-1:111122223333:function:rule", ResourceTypes: []string{"AWS::S3::Bucket"}, SourceMessages: []string{"ConfigurationItemChangeNotification"}, InputParameters: `{"tag1Key":"Team"}`, CreatedAt: now, LastEvaluation: now.Add(-time.Minute), LastReevaluation: now}
	delivery := domain.Delivery{Scope: testScope, ID: "snapshot-1", ChannelName: "default", Kind: "Snapshot", ObjectKey: "AWSLogs/snapshot.json.gz", Due: now.Add(time.Minute), CreatedAt: now, Status: "PENDING", Attempts: 2, FirstSequence: 1, LastSequence: 1}
	run := domain.EvaluationRun{Scope: testScope, Token: "token-1", RuleName: "rule", ItemSequence: 1, Due: now.Add(time.Second), CreatedAt: now, Status: "PENDING"}
	check(t, repo.Update(ctx, func(tx domain.Transaction) error {
		if err := tx.PutRecorder(domain.Recorder{Scope: testScope, Name: "default", Recording: true}); err != nil {
			return err
		}
		if err := tx.PutChannel(domain.Channel{Scope: testScope, Name: "default", Bucket: "delivery-bucket", KMSKeyARN: "key", NextDelivery: now.Add(time.Hour)}); err != nil {
			return err
		}
		var err error
		item, err = tx.AppendItem(item)
		if err != nil {
			return err
		}
		if err := tx.PutRule(rule); err != nil {
			return err
		}
		if err := tx.PutEvaluationRun(run); err != nil {
			return err
		}
		return tx.PutDelivery(delivery)
	}))
	check(t, db.Close())
	db, err = sqlite.Open(ctx, path)
	check(t, err)
	defer db.Close()
	repo = backend.New(db)
	check(t, repo.View(ctx, func(r domain.Reader) error {
		items, err := r.Items(testScope)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(items, []domain.Item{item}) {
			t.Fatalf("reopened snapshot changed: %#v", items)
		}
		rules, err := r.Rules(testScope)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(rules, []domain.Rule{rule}) {
			t.Fatalf("reopened rule changed: %#v", rules)
		}
		deliveries, err := r.Deliveries()
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(deliveries, []domain.Delivery{delivery}) {
			t.Fatalf("reopened pending delivery changed: %#v", deliveries)
		}
		runs, err := r.EvaluationRuns()
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(runs, []domain.EvaluationRun{run}) {
			t.Fatalf("reopened evaluation run changed: %#v", runs)
		}
		channel, ok, err := r.Channel(testScope)
		if err != nil {
			return err
		}
		if !ok || channel.Bucket != "delivery-bucket" || channel.KMSKeyARN != "key" || !channel.NextDelivery.Equal(now.Add(time.Hour)) {
			t.Fatalf("reopened delivery controls changed: %+v", channel)
		}
		return nil
	}))
	check(t, repo.Update(ctx, func(tx domain.Transaction) error {
		if err := tx.DeleteRecorder(testScope); err != nil {
			return err
		}
		next, err := tx.AppendItem(domain.Item{Scope: testScope, ResourceType: item.ResourceType, ResourceID: item.ResourceID, Status: "ResourceDeleted"})
		if err == nil && next.Sequence != 2 {
			t.Fatalf("reopened global sequence changed: %d", next.Sequence)
		}
		return err
	}))
}
