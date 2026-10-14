package rds

import (
	"context"
	"crypto/rand"
	"os"
	"strings"
	"testing"
	"time"

	engine "stackd/engine/rds"
	api "stackd/internal/awsapi/rds"
	"stackd/internal/awsctx"
)

func TestMasterUsernameAndEnginePasswordBounds(t *testing.T) {
	for _, eng := range []string{"postgres", "mysql", "aurora-postgresql", "aurora-mysql"} {
		t.Run(eng, func(t *testing.T) {
			for _, user := range []string{"lindm_admin", "A", strings.Repeat("a", 16)} {
				if err := validateCredentials(eng, user, "test-password"); err != nil {
					t.Fatalf("valid username %q: %v", user, err)
				}
			}
			for _, user := range []string{"", "_admin", "1admin", "a-b", "a b", "élève", strings.Repeat("a", 17)} {
				if err := validateCredentials(eng, user, "test-password"); err == nil {
					t.Fatalf("invalid username admitted: %q", user)
				}
			}
			maximum := 128
			if strings.Contains(eng, "mysql") {
				maximum = 41
			}
			for _, length := range []int{8, maximum} {
				if err := validateCredentials(eng, "lindm_admin", strings.Repeat("p", length)); err != nil {
					t.Fatal(err)
				}
			}
			for _, password := range []string{strings.Repeat("p", 7), strings.Repeat("p", maximum+1), "bad space", "bad@password", "bad/password", "bad\"password", "bad\npassword"} {
				if err := validateCredentials(eng, "lindm_admin", password); err == nil {
					t.Fatal("invalid master password admitted")
				}
			}
		})
	}
}

func TestAllocatedStorageBoundsAndGrowth(t *testing.T) {
	for _, capacity := range []int32{-1, 0, 19, 65537} {
		if err := validateAllocatedStorage(capacity); err == nil {
			t.Fatalf("invalid capacity admitted: %d", capacity)
		}
	}
	for _, capacity := range []int32{20, 65536} {
		if err := validateAllocatedStorage(capacity); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ current, requested, expected int32 }{{0, 20, 20}, {20, 20, 20}, {20, 21, 22}, {21, 22, 24}, {20, 30, 30}} {
		got, err := modifiedAllocatedStorage(tc.current, tc.requested)
		if err != nil || got != tc.expected {
			t.Fatalf("growth %v: got=%d err=%v", tc, got, err)
		}
	}
	for _, tc := range []struct{ current, requested int32 }{{30, 20}, {65535, 65536}} {
		if _, err := modifiedAllocatedStorage(tc.current, tc.requested); err == nil {
			t.Fatalf("invalid modification admitted: %v", tc)
		}
	}
}

func TestAllocatedStorageLifecycleAndProviderResourceIDRead(t *testing.T) {
	s := New(Config{Runtime: controlledRuntime{}, Cipher: testCipher{}})
	t.Cleanup(func() { _ = s.Close() })
	v := retainedDatabase(time.Now())
	v.Status, v.Operation, v.AllocatedStorage = "available", "", 20
	v.ResourceID = "retained-capacity-incarnation"
	seedDatabase(t, s, v)
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, PrincipalARN: "arn:aws:iam::111111111111:root"})
	for _, capacity := range []int32{19, 65537, 21} {
		err := s.repository.Attempt(ctx, func(tx Transaction) error {
			_, err := s.modifyInstance(ctx, tx, &api.ModifyDBInstanceMessage{DBInstanceIdentifier: new(api.String(v.Key.Name)), AllocatedStorage: new(api.IntegerOptional(capacity)), DeletionProtection: new(api.BooleanOptional(true))})
			return err
		})
		if err == nil {
			t.Fatalf("invalid/deferred capacity admitted: %d", capacity)
		}
		got := readDatabase(t, s, v.Key)
		if got.AllocatedStorage != 20 || got.DeletionProtection || got.Version != v.Version {
			t.Fatalf("rejected request changed retained state: %#v", got)
		}
	}
	if err := s.repository.Attempt(ctx, func(tx Transaction) error {
		result, err := s.modifyInstance(ctx, tx, &api.ModifyDBInstanceMessage{DBInstanceIdentifier: new(api.String(v.Key.Name)), AllocatedStorage: new(api.IntegerOptional(21)), Iops: new(api.IntegerOptional(0)), ApplyImmediately: new(api.Boolean(true))})
		if err == nil && (result.DBInstance.AllocatedStorage == nil || *result.DBInstance.AllocatedStorage != 22) {
			t.Fatal("rounded capacity missing from modification response")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.transition(ctx, tx, "StopDBInstance", "db", v.Key.Name, "stop")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := (databaseJobs{s}).Run(ctx, selectDatabase(t, s)); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.transition(ctx, tx, "StartDBInstance", "db", v.Key.Name, "start")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := (databaseJobs{s}).Run(ctx, selectDatabase(t, s)); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		out, err := s.describeInstances(ctx, tx, &api.DescribeDBInstancesMessage{Filters: api.FilterList{{Name: new(api.String("dbi-resource-id")), Values: api.FilterValueList{api.String("db-" + v.ResourceID)}}}})
		if err == nil && (len(out.DBInstances) != 1 || out.DBInstances[0].AllocatedStorage == nil || *out.DBInstances[0].AllocatedStorage != 22) {
			t.Fatalf("provider resource-ID read lost retained capacity: %#v", out)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStandaloneCreateRequiresCapacityAndSnapshotsPreserveIt(t *testing.T) {
	for _, eng := range []string{"postgres", "mysql"} {
		t.Run(eng, func(t *testing.T) {
			s := New(Config{Runtime: controlledRuntime{}, Cipher: testCipher{}})
			t.Cleanup(func() { _ = s.Close() })
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root"})
			in := &api.CreateDBInstanceMessage{DBInstanceIdentifier: new(api.String("owned")), Engine: new(api.String(eng)), DBInstanceClass: new(api.String("db.t3.micro")), MasterUsername: new(api.String("owner")), MasterUserPassword: new(api.SensitiveString("test-password"))}
			for _, capacity := range []*api.IntegerOptional{nil, new(api.IntegerOptional(0)), new(api.IntegerOptional(19)), new(api.IntegerOptional(65537))} {
				in.AllocatedStorage = capacity
				if err := s.repository.Attempt(ctx, func(tx Transaction) error {
					_, err := s.createInstance(ctx, tx, in)
					return err
				}); err == nil {
					t.Fatal("missing or invalid capacity admitted")
				}
			}
			in.AllocatedStorage = new(api.IntegerOptional(20))
			if err := s.repository.Attempt(ctx, func(tx Transaction) error {
				result, err := s.createInstance(ctx, tx, in)
				if err == nil && (result.DBInstance.AllocatedStorage == nil || *result.DBInstance.AllocatedStorage != 20) {
					t.Fatal("create response dropped capacity")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := (databaseJobs{s}).Run(ctx, selectDatabase(t, s)); err != nil {
				t.Fatal(err)
			}
			if err := s.repository.Attempt(ctx, func(tx Transaction) error {
				snap, err := s.captureSnapshot(ctx, tx, "db", "owned", "owned-snapshot", nil)
				if err != nil {
					return err
				}
				if snap.AllocatedStorage != 20 || snapshotDTO(snap).AllocatedStorage == nil || *snapshotDTO(snap).AllocatedStorage != 20 {
					t.Fatal("snapshot dropped capacity")
				}
				// The restore admission test concerns retained metadata; native
				// backup execution is covered by the existing runtime tests.
				snap.Status = "available"
				if err := tx.PutSnapshot(snap); err != nil {
					return err
				}
				restored, err := s.restoreDatabase(ctx, tx, "db", "restored", snap.Key.Name, "", "", "", "", "", nil, nil)
				if err == nil && restored.AllocatedStorage != 20 {
					t.Fatal("restore dropped capacity")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Test-only cipher: native proof needs the same username/password at admission
// and runtime. Production retained credentials still use the KMS owner.
type storageProofCipher struct{}

func (storageProofCipher) Seal(context.Context, string, string, string) ([]byte, error) {
	return []byte{1}, nil
}
func (storageProofCipher) Open(context.Context, string, []byte) (string, string, error) {
	return "lindm_admin", "local-proof-password", nil
}

func TestNativeAllocatedStorageAndUnderscoreUsername(t *testing.T) {
	if os.Getenv("STACKD_RDS_DOCKER") != "1" {
		t.Skip("set STACKD_RDS_DOCKER=1 for installed pinned native engines")
	}
	for _, eng := range []string{"postgres", "mysql"} {
		t.Run(eng, func(t *testing.T) {
			runtime, err := engine.NewDocker(engine.DockerConfig{Host: os.Getenv("DOCKER_HOST"), Namespace: "rds-capacity-" + rand.Text()})
			if err != nil {
				t.Fatal(err)
			}
			s := New(Config{Runtime: runtime, Cipher: storageProofCipher{}})
			t.Cleanup(func() { _ = s.Close(); _ = runtime.Close() })
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
			defer cancel()
			ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root"})
			if err := s.repository.Attempt(ctx, func(tx Transaction) error {
				_, err := s.createInstance(ctx, tx, &api.CreateDBInstanceMessage{DBInstanceIdentifier: new(api.String("owned")), Engine: new(api.String(eng)), DBInstanceClass: new(api.String("db.t3.micro")), DBName: new(api.String("proof")), MasterUsername: new(api.String("lindm_admin")), MasterUserPassword: new(api.SensitiveString("local-proof-password")), AllocatedStorage: new(api.IntegerOptional(20))})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			k := Key{Scope: Scope{"aws", "111111111111", "us-east-1"}, Kind: "db", Name: "owned"}
			v := readDatabase(t, s, k)
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				if err := runtime.Delete(cleanup, v.RuntimeID); err != nil {
					t.Error(err)
				}
			})
			if err := (databaseJobs{s}).Run(ctx, selectDatabase(t, s)); err != nil {
				t.Fatal(err)
			}
			v = readDatabase(t, s, k)
			if v.Status != "available" || v.AllocatedStorage != 20 || v.Username != "lindm_admin" {
				t.Fatalf("native state: %#v", v)
			}
			db, err := engine.Open(ctx, eng, v.Endpoint, "proof", "lindm_admin", "local-proof-password")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.ExecContext(ctx, "CREATE TABLE capacity_proof (id INTEGER PRIMARY KEY)"); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(ctx, "INSERT INTO capacity_proof VALUES (1)"); err != nil {
				t.Fatal(err)
			}
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.ExecContext(ctx, "INSERT INTO capacity_proof VALUES (2)"); err != nil {
				_ = tx.Rollback()
				t.Fatal(err)
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			before := v.Endpoint
			if err := s.repository.Attempt(ctx, func(tx Transaction) error {
				result, err := s.modifyInstance(ctx, tx, &api.ModifyDBInstanceMessage{DBInstanceIdentifier: new(api.String(k.Name)), AllocatedStorage: new(api.IntegerOptional(30)), ApplyImmediately: new(api.Boolean(true)), Iops: new(api.IntegerOptional(0))})
				if err == nil && (result.DBInstance.AllocatedStorage == nil || *result.DBInstance.AllocatedStorage != 30) {
					t.Fatal("native-backed modification dropped capacity")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			v = readDatabase(t, s, k)
			if v.Endpoint != before {
				t.Fatal("metadata capacity growth replaced native endpoint")
			}
			var count int
			if err := db.QueryRowContext(ctx, "SELECT count(*) FROM capacity_proof").Scan(&count); err != nil || count != 1 {
				t.Fatalf("native committed/rolled back rows: %d %v", count, err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			for _, operation := range []string{"stop", "start"} {
				action := "StopDBInstance"
				if operation == "start" {
					action = "StartDBInstance"
				}
				if err := s.repository.Update(ctx, func(tx Transaction) error {
					_, err := s.transition(ctx, tx, action, "db", k.Name, operation)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				if err := (databaseJobs{s}).Run(ctx, selectDatabase(t, s)); err != nil {
					t.Fatal(err)
				}
			}
			v = readDatabase(t, s, k)
			if v.Status != "available" || v.AllocatedStorage != 30 {
				t.Fatalf("restart lost capacity: %#v", v)
			}
			reopened, err := engine.Open(ctx, eng, v.Endpoint, "proof", "lindm_admin", "local-proof-password")
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if err := reopened.QueryRowContext(ctx, "SELECT count(*) FROM capacity_proof").Scan(&count); err != nil || count != 1 {
				t.Fatalf("restart lost native rows: %d %v", count, err)
			}
		})
	}
}

func TestProductionSecurityControlsRemainRejected(t *testing.T) {
	for name, configure := range map[string]func(*api.CreateDBInstanceMessage){
		"encryption": func(in *api.CreateDBInstanceMessage) { in.StorageEncrypted = new(api.BooleanOptional(true)) },
		"managed-password": func(in *api.CreateDBInstanceMessage) {
			in.ManageMasterUserPassword = new(api.BooleanOptional(true))
			in.MasterUserPassword = nil
		},
		"vpc-security-groups": func(in *api.CreateDBInstanceMessage) {
			in.VpcSecurityGroupIds = api.VpcSecurityGroupIdList{api.String("sg-not-real")}
		},
		"automated-backups": func(in *api.CreateDBInstanceMessage) { in.BackupRetentionPeriod = new(api.IntegerOptional(1)) },
		"provisioned-iops":  func(in *api.CreateDBInstanceMessage) { in.Iops = new(api.IntegerOptional(1000)) },
	} {
		t.Run(name, func(t *testing.T) {
			in := &api.CreateDBInstanceMessage{Engine: new(api.String("postgres")), AllocatedStorage: new(api.IntegerOptional(20)), MasterUsername: new(api.String("lindm_admin")), MasterUserPassword: new(api.SensitiveString("test-password"))}
			configure(in)
			if err := validateCreateDBInstanceMessage(in); err == nil {
				t.Fatal("unenforced cloud control accepted")
			}
		})
	}
}
