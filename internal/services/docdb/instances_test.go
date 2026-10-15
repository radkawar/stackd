package docdb

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"stackd/clock"
	engine "stackd/engine/docdb"
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

func TestModifyWriterReassertionsRetainActualOwner(t *testing.T) {
	for _, test := range []struct {
		name      string
		change    func(*api.ModifyDBInstanceInput)
		principal string
		account   string
		region    string
		busy      bool
		wantCode  string
	}{
		{name: "omitted-apply"},
		{name: "apply-now", change: func(in *api.ModifyDBInstanceInput) { in.ApplyImmediately = new(api.Boolean(true)) }},
		{name: "apply-later", change: func(in *api.ModifyDBInstanceInput) { in.ApplyImmediately = new(api.Boolean(false)) }},
		{name: "existing-settings", change: func(in *api.ModifyDBInstanceInput) {
			in.DBInstanceClass = new(api.String("db.r5.large"))
			in.NewDBInstanceIdentifier = new(api.String("writer"))
			in.AutoMinorVersionUpgrade = new(api.BooleanOptional(false))
			in.CopyTagsToSnapshot = new(api.BooleanOptional(false))
			in.EnablePerformanceInsights = new(api.BooleanOptional(false))
			in.PromotionTier = new(api.IntegerOptional(0))
		}},
		{name: "class-change", change: func(in *api.ModifyDBInstanceInput) { in.DBInstanceClass = new(api.String("db.r5.xlarge")) }, wantCode: "InvalidParameterCombination"},
		{name: "rename", change: func(in *api.ModifyDBInstanceInput) { in.NewDBInstanceIdentifier = new(api.String("replacement")) }, wantCode: "InvalidParameterCombination"},
		{name: "upgrade", change: func(in *api.ModifyDBInstanceInput) { in.AutoMinorVersionUpgrade = new(api.BooleanOptional(true)) }, wantCode: "InvalidParameterCombination"},
		{name: "snapshot-tags", change: func(in *api.ModifyDBInstanceInput) { in.CopyTagsToSnapshot = new(api.BooleanOptional(true)) }, wantCode: "InvalidParameterCombination"},
		{name: "monitoring", change: func(in *api.ModifyDBInstanceInput) { in.EnablePerformanceInsights = new(api.BooleanOptional(true)) }, wantCode: "InvalidParameterCombination"},
		{name: "monitoring-key", change: func(in *api.ModifyDBInstanceInput) { in.PerformanceInsightsKMSKeyId = new(api.String("key")) }, wantCode: "InvalidParameterCombination"},
		{name: "certificate", change: func(in *api.ModifyDBInstanceInput) { in.CACertificateIdentifier = new(api.String("ca")) }, wantCode: "InvalidParameterCombination"},
		{name: "certificate-restart", change: func(in *api.ModifyDBInstanceInput) { in.CertificateRotationRestart = new(api.BooleanOptional(false)) }, wantCode: "InvalidParameterCombination"},
		{name: "maintenance", change: func(in *api.ModifyDBInstanceInput) {
			in.PreferredMaintenanceWindow = new(api.String("sun:01:00-sun:02:00"))
		}, wantCode: "InvalidParameterCombination"},
		{name: "promotion", change: func(in *api.ModifyDBInstanceInput) { in.PromotionTier = new(api.IntegerOptional(1)) }, wantCode: "InvalidParameterCombination"},
		{name: "missing", change: func(in *api.ModifyDBInstanceInput) { in.DBInstanceIdentifier = new(api.String("missing")) }, wantCode: "DBInstanceNotFound"},
		{name: "denied", principal: "arn:aws:iam::111111111111:user/untrusted", wantCode: "AccessDenied"},
		{name: "foreign-account", account: "222222222222", wantCode: "DBInstanceNotFound"},
		{name: "foreign-region", region: "us-west-2", wantCode: "DBInstanceNotFound"},
		{name: "busy", busy: true, wantCode: "InvalidDBInstanceState"},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
			repository := NewMemoryRepository(nil)
			service := New(Config{Repository: repository, Clock: clock.NewManual(now)})
			t.Cleanup(func() { _ = service.Close() })
			scope := Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
			cluster := Cluster{Key: Key{Scope: scope, Kind: "cluster", Name: "source"}, RuntimeID: "native-owner", Status: "available", EngineVersion: "5.0", Username: "owner", Version: 23, Created: now, NextBackup: now.Add(time.Hour), BackupRetention: 1, Ciphertext: []byte{1, 2}, Endpoint: engine.Endpoint{Address: "localhost", Port: 27017}}
			writer := Instance{Key: Key{Scope: scope, Kind: "db", Name: "writer"}, Cluster: cluster.Key.Name, Class: "db.r5.large", RuntimeID: "writer-owner", Status: "available", Created: now, Tags: map[string]string{"Revision": "one"}}
			if test.busy {
				cluster.Status, cluster.Operation = "modifying", "password"
			}
			if err := repository.Update(t.Context(), func(tx Transaction) error {
				if err := tx.PutCluster(cluster); err != nil {
					return err
				}
				return tx.PutInstance(writer)
			}); err != nil {
				t.Fatal(err)
			}
			metadata := awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: scope.AccountID}
			if test.principal != "" {
				metadata.PrincipalARN, metadata.PrincipalID = test.principal, "untrusted"
			}
			if test.account != "" {
				metadata.AccountID = test.account
			}
			if test.region != "" {
				metadata.Region = test.region
			}
			ctx := awsctx.WithMetadata(t.Context(), metadata)
			input := &api.ModifyDBInstanceInput{DBInstanceIdentifier: new(api.String(writer.Key.Name))}
			if test.change != nil {
				test.change(input)
			}
			var out *api.ModifyDBInstanceOutput
			err := repository.Attempt(ctx, func(tx Transaction) error {
				var err error
				out, err = service.modifyInstance(tx.Context(), tx, input)
				return err
			})
			if test.wantCode == "" {
				if err != nil || out == nil || !reflect.DeepEqual(out.DBInstance, instanceOutput(writer, cluster)) {
					t.Fatalf("no-change response lost actual retained fields: out=%#v err=%v", out, err)
				}
			} else {
				var rejected *awswire.Error
				if !errors.As(err, &rejected) || rejected.Code != test.wantCode {
					t.Fatalf("error = %v, want %s", err, test.wantCode)
				}
			}
			if err := repository.View(t.Context(), func(reader Reader) error {
				actualCluster, err := reader.Cluster(cluster.Key)
				if err != nil {
					return err
				}
				actualWriter, err := reader.Instance(writer.Key)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(actualCluster, cluster) || !reflect.DeepEqual(actualWriter, writer) {
					t.Fatalf("request changed retained native owner, timestamps, pending work or settings")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
