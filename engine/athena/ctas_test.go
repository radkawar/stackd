package athena

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stackd/compute/docker"
)

func ctasTestString(value string) ctasValue {
	return ctasValue{Kind: "string", Text: value, SQL: quoteSQLString(value)}
}
func ctasTestArray(values ...string) ctasValue {
	array := ctasValue{Kind: "array", SQL: "ARRAY["}
	for i, value := range values {
		if i != 0 {
			array.SQL += ", "
		}
		array.Elements = append(array.Elements, ctasTestString(value))
		array.SQL += quoteSQLString(value)
	}
	array.SQL += "]"
	return array
}
func ctasTestPlan(properties ...ctasProperty) *ctasPlan {
	return &ctasPlan{Identifier: []string{"result"}, Query: "SELECT 7 id, 'west' region", SaveMode: "FAIL", WithData: true, Properties: properties}
}
func ctasTestRequest() Request {
	request := fixtureRequest("ctas")
	request.Catalog, request.Database = "awsdatacatalog", "analytics"
	request.CTASLocation = "s3://results/tables/query-id/"
	return request
}

func TestCTASProperties(t *testing.T) {
	request := ctasTestRequest()
	tests := []struct {
		name       string
		properties []ctasProperty
		contains   []string
		session    string
	}{
		{name: "Athena defaults", contains: []string{`CREATE TABLE "awsdatacatalog"."analytics"."result"`, "external_location = 's3://results/tables/query-id/'", "format = 'PARQUET'", "AS SELECT 7 id, 'west' region"}, session: "awsdatacatalog.compression_codec=GZIP"},
		{name: "Hive partitions buckets compression", properties: []ctasProperty{
			{"table_type", ctasTestString("HIVE")}, {"is_external", ctasValue{Kind: "boolean", Boolean: true}},
			{"external_location", ctasTestString("s3://data/a'quoted/path/")},
			{"partitioned_by", ctasTestArray("region")}, {"bucketed_by", ctasTestArray("id")},
			{"bucket_count", ctasValue{Kind: "integer", Text: "4", SQL: "4"}}, {"write_compression", ctasTestString("SNAPPY")},
		}, contains: []string{"external_location = 's3://data/a''quoted/path/'", "partitioned_by = ARRAY['region']", "bucketed_by = ARRAY['id']", "bucket_count = 4"}, session: "awsdatacatalog.compression_codec=SNAPPY"},
		{name: "ORC ZLIB native codec", properties: []ctasProperty{{"format", ctasTestString("ORC")}, {"orc_compression", ctasTestString("ZLIB")}}, contains: []string{"format = 'ORC'"}, session: "awsdatacatalog.compression_codec=GZIP"},
		{name: "text delimiter", properties: []ctasProperty{{"format", ctasTestString("TEXTFILE")}, {"field_delimiter", ctasTestString("|")}, {"write_compression", ctasTestString("NONE")}}, contains: []string{"textfile_field_separator = '|'"}, session: "awsdatacatalog.compression_codec=NONE"},
		{name: "CSV delimiter", properties: []ctasProperty{{"format", ctasTestString("CSV")}, {"field_delimiter", ctasTestString(";")}}, contains: []string{"csv_separator = ';'"}, session: "awsdatacatalog.compression_codec=GZIP"},
		{name: "Iceberg actual properties", properties: []ctasProperty{
			{"table_type", ctasTestString("ICEBERG")}, {"is_external", ctasValue{Kind: "boolean"}},
			{"location", ctasTestString("s3://iceberg/result/")}, {"partitioning", ctasTestArray("month(created_at)", "bucket(id, 4)")},
			{"sorted_by", ctasTestArray("id DESC")}, {"max_commit_retry", ctasValue{Kind: "integer", Text: "3", SQL: "3"}},
		}, contains: []string{`CREATE TABLE "iceberg"."analytics"."result"`, "format_version = 2", "location = 's3://iceberg/result/'", "partitioning = ARRAY['month(created_at)', 'bucket(id, 4)']", "sorted_by = ARRAY['id DESC']", "max_commit_retry = 3"}, session: "iceberg.compression_codec=ZSTD"},
		{name: "Avro deflate native codec", properties: []ctasProperty{{"format", ctasTestString("AVRO")}, {"write_compression", ctasTestString("DEFLATE")}}, contains: []string{"format = 'AVRO'"}, session: "awsdatacatalog.compression_codec=GZIP"},
		{name: "Iceberg ORC default", properties: []ctasProperty{{"table_type", ctasTestString("ICEBERG")}, {"is_external", ctasValue{Kind: "boolean"}}, {"location", ctasTestString("s3://iceberg/orc/")}, {"format", ctasTestString("ORC")}}, contains: []string{"format = 'ORC'"}, session: "iceberg.compression_codec=ZSTD"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sql, session, err := ctasDDL(ctasTestPlan(test.properties...), request)
			if err != nil {
				t.Fatal(err)
			}
			for _, expected := range test.contains {
				if !strings.Contains(sql, expected) {
					t.Fatalf("missing %q in %s", expected, sql)
				}
			}
			if session != test.session {
				t.Fatalf("session %q, want %q", session, test.session)
			}
			for _, consumed := range []string{"table_type =", "is_external =", "write_compression =", "orc_compression =", "parquet_compression =", "compression_codec ="} {
				if strings.Contains(sql, consumed) {
					t.Fatalf("Athena/session control leaked into native table properties: %s", sql)
				}
			}
		})
	}
}

func TestCTASRejectsExplicitDestinationForEnforcingWorkgroup(t *testing.T) {
	request := ctasTestRequest()
	plan := ctasTestPlan(ctasProperty{"external_location", ctasTestString("s3://data/forbidden/")})
	request.EnforceCTASDestination = true
	if sql, session, err := ctasDDL(plan, request); err == nil || sql != "" || session != "" {
		t.Fatalf("enforced CTAS admitted explicit location: %q %q %v", sql, session, err)
	}
	sql, _, err := ctasDDL(ctasTestPlan(), request)
	if err != nil || !strings.Contains(sql, quoteSQLString(request.CTASLocation)) {
		t.Fatalf("enforced default destination: %q %v", sql, err)
	}
	request.EnforceCTASDestination = false
	if _, _, err := ctasDDL(plan, request); err != nil {
		t.Fatalf("non-enforcing explicit destination rejected: %v", err)
	}
}

func TestCTASInvalidProperties(t *testing.T) {
	for _, test := range []struct {
		name       string
		properties []ctasProperty
	}{
		{"duplicate", []ctasProperty{{"format", ctasTestString("ORC")}, {"FORMAT", ctasTestString("PARQUET")}}},
		{"uppercase format", []ctasProperty{{"FORMAT", ctasTestString("PARQUET")}}},
		{"unknown", []ctasProperty{{"made_up", ctasTestString("x")}}},
		{"unknown table type", []ctasProperty{{"table_type", ctasTestString("DELTA")}}},
		{"nonliteral table type", []ctasProperty{{"table_type", ctasValue{Kind: "expression", SQL: "upper('hive')"}}}},
		{"external type", []ctasProperty{{"is_external", ctasTestString("false")}}},
		{"Iceberg external", []ctasProperty{{"table_type", ctasTestString("ICEBERG")}, {"is_external", ctasValue{Kind: "boolean", Boolean: true}}}},
		{"Iceberg missing location", []ctasProperty{{"table_type", ctasTestString("ICEBERG")}}},
		{"Hive Iceberg partitioning", []ctasProperty{{"partitioning", ctasTestArray("id")}}},
		{"Hive location", []ctasProperty{{"location", ctasTestString("s3://data/a/")}}},
		{"invalid location", []ctasProperty{{"external_location", ctasTestString("file:///data")}}},
		{"managed external location", []ctasProperty{{"is_external", ctasValue{Kind: "boolean"}}, {"external_location", ctasTestString("s3://data/a/")}}},
		{"compression conflict", []ctasProperty{{"write_compression", ctasTestString("SNAPPY")}, {"parquet_compression", ctasTestString("GZIP")}}},
		{"wrong compression format", []ctasProperty{{"orc_compression", ctasTestString("ZLIB")}}},
		{"ORC GZIP is not ZLIB", []ctasProperty{{"format", ctasTestString("ORC")}, {"write_compression", ctasTestString("GZIP")}}},
		{"Iceberg requires explicit nonexternal", []ctasProperty{{"table_type", ctasTestString("ICEBERG")}, {"location", ctasTestString("s3://iceberg/table/")}}},
		{"unwritable codec", []ctasProperty{{"write_compression", ctasTestString("LZ4")}}},
		{"unknown codec", []ctasProperty{{"write_compression", ctasTestString("BZIP2")}}},
		{"empty codec", []ctasProperty{{"write_compression", ctasTestString("")}}},
		{"unwritable format", []ctasProperty{{"format", ctasTestString("ION")}}},
		{"bucket columns missing", []ctasProperty{{"bucket_count", ctasValue{Kind: "integer", Text: "2", SQL: "2"}}}},
		{"bucket count missing", []ctasProperty{{"bucketed_by", ctasTestArray("id")}}},
		{"bucket count zero", []ctasProperty{{"bucketed_by", ctasTestArray("id")}, {"bucket_count", ctasValue{Kind: "integer", Text: "0", SQL: "0"}}}},
		{"partition type", []ctasProperty{{"partitioned_by", ctasTestString("id")}}},
		{"delimiter length", []ctasProperty{{"format", ctasTestString("TEXTFILE")}, {"field_delimiter", ctasTestString("||")}}},
		{"delimiter wrong format", []ctasProperty{{"field_delimiter", ctasTestString(",")}}},
		{"unsupported maintenance property", []ctasProperty{{"table_type", ctasTestString("ICEBERG")}, {"is_external", ctasValue{Kind: "boolean"}}, {"location", ctasTestString("s3://iceberg/table/")}, {"vacuum_min_snapshots_to_keep", ctasValue{Kind: "integer", Text: "3", SQL: "3"}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			sql, session, err := ctasDDL(ctasTestPlan(test.properties...), ctasTestRequest())
			var native *QueryError
			if sql != "" || session != "" || !errors.As(err, &native) || native.ErrorName != "INVALID_TABLE_PROPERTY" {
				t.Fatalf("sql=%q session=%q error=%v", sql, session, err)
			}
		})
	}
}

func TestCTASPreservesNativeQueryAndTableOptions(t *testing.T) {
	plan := ctasTestPlan()
	plan.Identifier = []string{"analytics", `a"table`}
	plan.Aliases = []string{`"id"`, `"region"`}
	plan.SaveMode, plan.WithData = "IGNORE", false
	comment := "not a query: WITH (format = 'ORC')"
	plan.Comment = &comment
	plan.Query = "WITH src AS (SELECT 'WITH (table_type=''ICEBERG'')' AS text) SELECT text FROM src"
	sql, _, err := ctasDDL(plan, ctasTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sql, `CREATE TABLE IF NOT EXISTS "awsdatacatalog"."analytics"."a""table" ("id", "region")`) || !strings.HasSuffix(sql, plan.Query+" WITH NO DATA") || !strings.Contains(sql, "COMMENT "+quoteSQLString(comment)) {
		t.Fatal(sql)
	}
}

func TestCTASPropertyFailurePrecedesNativeWrites(t *testing.T) {
	f, d := newNetworkFixture(t, false)
	close(f.release)
	f.ctasPlan = ctasTestPlan(ctasProperty{"unsupported", ctasTestString("value")})
	request := ctasTestRequest()
	request.SQL = "CREATE TABLE result WITH (unsupported='value') AS SELECT 1 id"
	err := d.Execute(t.Context(), request, func(string) error { return nil }, func(Page) error { return nil })
	var native *QueryError
	if !errors.As(err, &native) || native.ErrorName != "INVALID_TABLE_PROPERTY" {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, container := range f.containers {
		if container.queries != 0 || len(container.statements) != 0 {
			t.Fatal("property rejection reached native customer execution")
		}
	}
}

func TestCTASCompressionSessionIsolation(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		seen = append(seen, request.Header.Get("X-Trino-Session"))
		fmt.Fprint(w, `{"id":"ctas-query","stats":{"state":"FINISHED"}}`)
	}))
	defer server.Close()
	request := ctasTestRequest()
	request.SQL = "SELECT 1"
	client := server.Client()
	if err := executeCTAS(t.Context(), client, server.URL, request, "iceberg.compression_codec=SNAPPY", func(Page) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := executeCTAS(t.Context(), client, server.URL, request, "", func(Page) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 4 || seen[0] != "iceberg.compression_codec=SNAPPY" || seen[1] != seen[0] || seen[2] != "" || seen[3] != "" {
		t.Fatalf("query/session header leakage: %v", seen)
	}
}

// Native fixture (no network downloads, no mocked parser/SQL engine):
//
//	docker pull trinodb/trino@sha256:00125e40d063bc4816d165482f6044872b18b56026fb959d3b28ce1f96ffbbee
//	docker pull apache/spark@sha256:9b0a6c2c860f5e7d18dd5270286fef32a09c7f5a7e2b0dbe5642de8a3a02ab3e
//	STACKD_ATHENA_NETWORK_DOCKER_HOST=unix:///var/run/docker.sock go test ./engine/athena -run '^TestCTASParserNative$' -count=1 -timeout=5m
//
// This proves the installed Trino476 source-launch classpath and typed projection,
// then executes the default non-CTAS path on the real engine. Service-level write
// proof must also run CTAS against ordinary Glue/S3 owners, SELECT its rows, inspect
// native Parquet/ORC compression and Iceberg metadata/partition transforms, reject
// a conflicting compression property before CreateTable/PutObject, and DROP the
// table. Real-write examples for that fixture (distinct empty S3 prefixes):
//
//	CREATE TABLE db.ctas_hive WITH (external_location='s3://bucket/ctas-hive/', partitioned_by=ARRAY['region'], bucketed_by=ARRAY['id'], bucket_count=2, write_compression='SNAPPY') AS SELECT 7 id, 'west' region
//	CREATE TABLE db.ctas_iceberg WITH (table_type='ICEBERG', is_external=false, location='s3://bucket/ctas-iceberg/', partitioning=ARRAY['bucket(id, 2)'], write_compression='ZSTD') AS SELECT 7 id
//
// Native HiveLocationService enforces empty destinations; native write transaction
// rollback and existing manager engine/capability cleanup remain authoritative.
func TestCTASParserNative(t *testing.T) {
	host := os.Getenv("STACKD_ATHENA_NETWORK_DOCKER_HOST")
	if host == "" {
		t.Skip("set STACKD_ATHENA_NETWORK_DOCKER_HOST for native Trino476 parser fixture")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	client, err := docker.New(ctx, docker.Config{Host: host})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	d, err := NewDocker(ctx, DockerConfig{Client: client, StateDirectory: filepath.Join(t.TempDir(), "ctas")})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	request := ctasTestRequest()
	request.SQL = "SELECT 1"
	request.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected callback during parser fixture: %s", r.URL)
		http.Error(w, "unexpected callback", 500)
	})
	if err := d.Execute(ctx, request, func(string) error { return nil }, func(Page) error { return nil }); err != nil {
		t.Fatal(err)
	}
	scope := request.Partition + "\x00" + request.AccountID + "\x00" + request.Region
	d.mu.Lock()
	engine := d.engines[scope]
	d.mu.Unlock()
	if engine == nil {
		t.Fatal("native engine not retained")
	}
	for _, test := range []struct {
		sql  string
		ctas bool
	}{
		{"/* CREATE TABLE decoy AS */ SELECT 'WITH (format=''ORC'')'", false},
		{"CREATE VIEW analytics.v AS SELECT 1 id", false},
		{"CREATE TABLE analytics.hive_external (id bigint) STORED AS PARQUET LOCATION 's3://data/external/'", false},
		{"CREATE TABLE analytics.out WITH (table_type='HIVE', format='PARQUET', partitioned_by=ARRAY['region'], external_location='s3://data/ctas/', write_compression='SNAPPY') AS WITH src AS (SELECT 7 id, 'west' region) SELECT * FROM src WITH NO DATA", true},
		{`CREATE TABLE "analytics"."a""table" ("id") COMMENT 'a comment' WITH (table_type='ICEBERG', is_external=false, location='s3://data/iceberg/', partitioning=ARRAY['bucket(id, 2)']) AS SELECT 7`, true},
	} {
		plan, err := d.parseCTAS(ctx, engine, test.sql)
		if err != nil {
			t.Fatal(err)
		}
		if (plan != nil) != test.ctas {
			t.Fatalf("CTAS=%t for %s: %+v", test.ctas, test.sql, plan)
		}
		if plan == nil {
			continue
		}
		sql, session, err := ctasDDL(plan, request)
		if err != nil {
			t.Fatal(err)
		}
		if sql == "" || session == "" {
			t.Fatalf("native projection did not translate: %+v", plan)
		}
		// Reparse emitted SQL with exactly the same real pinned native parser.
		if projected, err := d.parseCTAS(ctx, engine, sql); err != nil || projected == nil {
			t.Fatalf("emitted SQL is not native CTAS: %s: %v", sql, err)
		}
	}
}
