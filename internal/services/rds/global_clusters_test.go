package rds

import (
	"context"
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/rds"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
)

func globalCommandContext(t *testing.T) context.Context {
	t.Helper()
	return awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root"})
}

func TestEmptyGlobalAdmissionDoesNotAllocateUnsupportedState(t *testing.T) {
	for _, test := range []struct {
		name  string
		input api.CreateGlobalClusterMessage
		code  string
	}{
		{"source", api.CreateGlobalClusterMessage{SourceDBClusterIdentifier: new(api.String("arn:aws:rds:us-east-1:111111111111:cluster:source"))}, "InvalidParameterCombination"},
		{"engine-required", api.CreateGlobalClusterMessage{}, "InvalidParameterValue"},
		{"non-global-engine", api.CreateGlobalClusterMessage{Engine: new(api.String("postgres"))}, "InvalidParameterValue"},
		{"unknown-docdb-version", api.CreateGlobalClusterMessage{Engine: new(api.String("docdb")), EngineVersion: new(api.String("invented"))}, "InvalidParameterCombination"},
		{"aurora-default-unowned", api.CreateGlobalClusterMessage{Engine: new(api.String("aurora-postgresql"))}, "InvalidParameterCombination"},
		{"native-mysql-is-not-aurora", api.CreateGlobalClusterMessage{Engine: new(api.String("aurora-mysql")), EngineVersion: new(api.String("8.4.11"))}, "InvalidParameterCombination"},
		{"invalid-database", api.CreateGlobalClusterMessage{Engine: new(api.String("docdb")), DatabaseName: new(api.String("not-a-database"))}, "InvalidParameterValue"},
		{"wrong-lifecycle-engine", api.CreateGlobalClusterMessage{Engine: new(api.String("docdb")), EngineLifecycleSupport: new(api.String("open-source-rds-extended-support"))}, "InvalidParameterCombination"},
		{"wrong-lifecycle-setting", api.CreateGlobalClusterMessage{Engine: new(api.String("aurora-postgresql")), EngineVersion: new(api.String("16.6")), EngineLifecycleSupport: new(api.String("invented"))}, "InvalidParameterValue"},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := New(Config{})
			t.Cleanup(func() { _ = s.Close() })
			test.input.GlobalClusterIdentifier = new(api.GlobalClusterIdentifier("owned"))
			model, _ := awscatalog.LookupService("rds")
			op, _ := model.Operation("CreateGlobalCluster")
			ctx := globalCommandContext(t)
			_, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Input: &test.input})
			if rejected == nil || rejected.Code != test.code {
				t.Fatalf("unsupported configuration admitted: %v", rejected)
			}
			if err := s.repository.View(ctx, func(r Reader) error {
				all, err := r.GlobalClusters(globalScopeFor(ctx))
				if len(all) != 0 {
					t.Fatalf("rejection allocated metadata: %#v", all)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGlobalRepositoryDoesNotBorrowMutableTags(t *testing.T) {
	repo := NewMemoryRepository(nil)
	key := GlobalKey{GlobalScope: GlobalScope{Partition: "aws", AccountID: "111111111111"}, Name: "owned"}
	original := GlobalCluster{Key: key, ResourceID: "incarnation", Engine: "docdb", EngineVersion: "5.0", Tags: map[string]string{"owner": "original"}}
	if err := repo.Update(t.Context(), func(tx Transaction) error { return tx.PutGlobalCluster(original) }); err != nil {
		t.Fatal(err)
	}
	original.Tags["owner"] = "caller-write"
	if err := repo.View(t.Context(), func(r Reader) error {
		v, err := r.GlobalCluster(key)
		if err != nil {
			return err
		}
		if v.Tags["owner"] != "original" {
			t.Fatal("repository retained caller-owned tags")
		}
		v.Tags["owner"] = "reader-write"
		all, err := r.GlobalClusters(key.GlobalScope)
		if err == nil && (len(all) != 1 || all[0].Tags["owner"] != "original") {
			t.Fatal("reader mutated retained tags")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyGlobalFilterRejectsMissingValues(t *testing.T) {
	s := New(Config{})
	t.Cleanup(func() { _ = s.Close() })
	ctx := globalCommandContext(t)
	err := s.repository.Attempt(ctx, func(tx Transaction) error {
		_, err := s.describeGlobalClusters(tx.Context(), tx, &api.DescribeGlobalClustersMessage{Filters: api.FilterList{{Name: new(api.String("region"))}}})
		return err
	})
	if rejected := wireError(err); err == nil || rejected.Code != "InvalidParameterValue" {
		t.Fatalf("missing filter values reached the metadata query: %v", err)
	}
}
