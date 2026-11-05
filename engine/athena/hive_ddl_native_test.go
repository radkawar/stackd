package athena

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stackd/compute/docker"
)

// Run after explicitly installing the pinned Trino and Spark images:
// STACKD_ATHENA_NETWORK_DOCKER_HOST=unix:///var/run/docker.sock go test ./engine/athena -run TestHiveDDLNativeFamilies -v
// Spark is only a native parser here: no catalog, credentials or network access.
// The SDK fixture scripts/aws/athena_hive_semantics_smoke.py exercises the same
// SQL through an enabled controller, real Trino, current Glue and S3 owners.
func TestHiveDDLNativeFamilies(t *testing.T) {
	host := os.Getenv("STACKD_ATHENA_NETWORK_DOCKER_HOST")
	if host == "" {
		t.Skip("set STACKD_ATHENA_NETWORK_DOCKER_HOST for pinned native parser fixture")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Minute)
	defer cancel()
	client, err := docker.New(ctx, docker.Config{Host: host})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	runtime, err := NewDocker(ctx, DockerConfig{Client: client, StateDirectory: filepath.Join(t.TempDir(), "athena")})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	for _, test := range []struct {
		sql, kind string
		inspect   func(*testing.T, *HiveDDL)
	}{
		{"ALTER DATABASE fixture SET DBPROPERTIES ('purpose'='native')", "SET_DATABASE_PROPERTIES", nil},
		{"ALTER TABLE fixture.events ADD COLUMNS (payload string COMMENT 'native')", "ADD_COLUMNS", nil},
		{"ALTER TABLE fixture.events PARTITION (day='today') ADD COLUMNS (payload string)", "ADD_COLUMNS", func(t *testing.T, p *HiveDDL) {
			if len(p.Partitions) != 1 || p.Partitions[0].Values["day"] != "today" {
				t.Fatalf("partition add: %+v", p)
			}
		}},
		{"ALTER TABLE fixture.events CHANGE COLUMN payload renamed string COMMENT 'changed' FIRST", "CHANGE_COLUMN", func(t *testing.T, p *HiveDDL) {
			if p.OldColumn != "payload" || p.Columns[0].Name != "renamed" || !p.First {
				t.Fatalf("change projection: %+v", p)
			}
		}},
		{"ALTER TABLE fixture.events REPLACE COLUMNS (id bigint)", "REPLACE_COLUMNS", nil},
		{"ALTER TABLE fixture.events PARTITION (day='today') REPLACE COLUMNS (id bigint)", "REPLACE_COLUMNS", func(t *testing.T, p *HiveDDL) {
			if len(p.Partitions) != 1 || p.Partitions[0].Values["day"] != "today" {
				t.Fatalf("partition replace: %+v", p)
			}
		}},
		{"ALTER TABLE fixture.events ADD IF NOT EXISTS PARTITION (day='today') LOCATION 's3://fixture-data/today/' PARTITION (day='tomorrow')", "ADD_PARTITIONS", func(t *testing.T, p *HiveDDL) {
			if !p.IfNotExists || len(p.Partitions) != 2 {
				t.Fatalf("add partitions: %+v", p)
			}
		}},
		{"ALTER TABLE fixture.events DROP IF EXISTS PARTITION (day='today')", "DROP_PARTITIONS", nil},
		{"ALTER TABLE fixture.events PARTITION (day='old') RENAME TO PARTITION (day='new')", "RENAME_PARTITION", nil},
		{"ALTER TABLE fixture.events PARTITION (day='today') SET LOCATION 's3://fixture-data/moved/'", "SET_LOCATION", nil},
		{"ALTER TABLE fixture.events SET TBLPROPERTIES ('owner'='native')", "SET_TABLE_PROPERTIES", nil},
		{"MSCK REPAIR TABLE fixture.events", "MSCK_REPAIR", nil},
		{"CREATE EXTERNAL TABLE fixture.events (id bigint) CLUSTERED BY (id) INTO 4 BUCKETS STORED AS PARQUET LOCATION 's3://fixture-data/bucketed/'", "CREATE_TABLE", func(t *testing.T, p *HiveDDL) {
			if p.BucketCount != 4 || len(p.BucketColumns) != 1 || p.BucketColumns[0] != "id" {
				t.Fatalf("bucket projection: %+v", p)
			}
		}},
		{"CREATE TABLE fixture.events (id bigint, ts timestamp) PARTITIONED BY (bucket(4,id),day(ts)) LOCATION 's3://fixture-data/iceberg/' TBLPROPERTIES ('table_type'='ICEBERG')", "CREATE_TABLE", func(t *testing.T, p *HiveDDL) {
			sql, err := icebergDDL(p, Request{AccountID: "123456789012", Catalog: "awsdatacatalog", CatalogID: "123456789012", Database: "fixture"})
			if err != nil || !strings.Contains(sql, "bucket(") || !strings.Contains(sql, "day(") {
				t.Fatalf("native transform SQL %q: %v", sql, err)
			}
		}},
	} {
		t.Run(test.kind+"/"+test.sql, func(t *testing.T) {
			handle := "stackd-athena-" + strings.Repeat("a", 64) + "-" + rand.Text()
			plan, err := runtime.parseHiveDDL(ctx, handle, "native-parser-fixture", test.sql)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Kind != test.kind {
				t.Fatalf("kind=%q want %q", plan.Kind, test.kind)
			}
			if test.inspect != nil {
				test.inspect(t, plan)
			}
		})
	}
	for _, sql := range []string{"MSCK REPAIR TABLE fixture.events SYNC PARTITIONS", "CREATE TABLE fixture.events (id bigint) USING parquet", "ALTER TABLE fixture.events ADD COLUMNS (id bigint NOT NULL)", "ALTER TABLE fixture.events ADD PARTITION ("} {
		handle := "stackd-athena-" + strings.Repeat("b", 64) + "-" + rand.Text()
		_, err := runtime.parseHiveDDL(ctx, handle, "native-parser-fixture", sql)
		var queryError *QueryError
		if !errors.As(err, &queryError) || (queryError.ErrorName != "NOT_SUPPORTED" && queryError.ErrorName != "SYNTAX_ERROR") {
			t.Fatalf("invalid/unsupported SQL %q: %v", sql, err)
		}
	}
}
