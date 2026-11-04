package backends_test

import (
	"strings"
	"testing"

	sqls3 "stackd/storage/sqlite/s3"
)

func TestS3PrefixQueriesSeekBoundedBinaryKeyRanges(t *testing.T) {
	db, observations := observedSQLite(t)
	if _, err := sqls3.New(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		column string
		args   []any
	}{
		{"ListObjects", "name", []any{"aws", "bucket", "é/", "é/\xff", 3}},
		{"ListObjectVersions", "name", []any{"aws", "bucket", "é/", "é/\xff", "", nil, "", 3}},
		{"ListMultipartUploads", "object_name", []any{"aws", "bucket", "é/", "é/\xff", "", nil, 3}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var query string
			observations.queries.Range(func(key, _ any) bool {
				candidate := key.(string)
				if strings.HasPrefix(candidate, "-- name: "+test.name+" :many\n") {
					query = candidate
					return false
				}
				return true
			})
			if query == "" {
				t.Fatal("service constructor did not prepare the named generated query")
			}
			rows, err := db.QueryContext(t.Context(), "EXPLAIN QUERY PLAN "+query, test.args...)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var details []string
			for rows.Next() {
				var id, parent, unused int
				var detail string
				if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
					t.Fatal(err)
				}
				details = append(details, detail)
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			plan := strings.Join(details, "\n")
			if !strings.Contains(plan, test.column+">? AND "+test.column+"<?") {
				t.Fatalf("listing must seek both binary key bounds, not filter unrelated bucket names:\n%s", plan)
			}
			if strings.Contains(plan, "USE TEMP B-TREE") {
				t.Fatalf("listing discarded the existing key/order index:\n%s", plan)
			}
		})
	}
}
