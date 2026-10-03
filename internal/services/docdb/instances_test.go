package docdb

import (
	"errors"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/docdb"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func TestDeleteWriterSupersedesFailedRetryButNotActiveCreation(t *testing.T) {
	for _, status := range []string{"failed", "creating"} {
		t.Run(status, func(t *testing.T) {
			repository := NewMemoryRepository(nil)
			now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
			service := New(Config{Repository: repository, Clock: clock.NewManual(now)})
			t.Cleanup(func() { _ = service.Close() })
			scope := Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: scope.AccountID})
			clusterKey := Key{Scope: scope, Kind: "cluster", Name: "source"}
			writerKey := Key{Scope: scope, Kind: "db", Name: "writer"}
			retry := now.Add(time.Minute)
			if err := repository.Update(ctx, func(tx Transaction) error {
				if err := tx.PutCluster(Cluster{Key: clusterKey, RuntimeID: "retained-native-owner", Status: status, Operation: "create", Version: 11, Due: retry}); err != nil {
					return err
				}
				return tx.PutInstance(Instance{Key: writerKey, Cluster: clusterKey.Name, Status: status})
			}); err != nil {
				t.Fatal(err)
			}
			var out *api.DeleteDBInstanceOutput
			err := repository.Attempt(ctx, func(tx Transaction) error {
				var err error
				out, err = service.deleteInstance(tx.Context(), tx, &api.DeleteDBInstanceInput{DBInstanceIdentifier: new(api.String(writerKey.Name))})
				return err
			})
			if status == "failed" {
				if err != nil {
					t.Fatal(err)
				}
				if out == nil || out.DBInstance == nil || value(out.DBInstance.DBInstanceStatus) != "deleting" {
					t.Fatalf("failed native writer did not admit deletion: %#v", out)
				}
			} else {
				var state *awswire.Error
				if !errors.As(err, &state) || state.Code != "InvalidDBInstanceState" {
					t.Fatalf("active native creation unexpectedly retired: %v", err)
				}
			}
			if err := repository.View(ctx, func(r Reader) error {
				cluster, err := r.Cluster(clusterKey)
				if err != nil {
					return err
				}
				writer, err := r.Instance(writerKey)
				if err != nil {
					return err
				}
				if status == "failed" {
					if cluster.RuntimeID != "retained-native-owner" || cluster.Operation != "detach" || cluster.Version <= 11 || !cluster.Due.Before(retry) || writer.Status != "deleting" {
						t.Fatalf("failed retry was not replaced with fenced retirement: cluster=%#v writer=%#v", cluster, writer)
					}
				} else if cluster.Operation != "create" || cluster.Version != 11 || !cluster.Due.Equal(retry) || writer.Status != "creating" {
					t.Fatalf("rejected retirement mutated active creation: cluster=%#v writer=%#v", cluster, writer)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
