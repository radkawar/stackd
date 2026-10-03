package awstest

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite" // Register the driver for historical fixtures.
)

// HistoricalSQLite builds a historical fixture from the authoritative migration
// SQL. An optional source database supplies SDK-created state; selects overrides
// the source SELECT for tables whose historical representation differs. Current
// adapters must only use the returned database after the production upgrade.
// Stop source service workers first and keep their database open until copying
// finishes, so attaching the source does not race its final WAL connection close.
func HistoricalSQLite(t *testing.T, path, schemaDir string, version int, source string, selects map[string]string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(t.Context(), "PRAGMA foreign_keys=ON"); err != nil {
		t.Fatal(err)
	}
	if source != "" {
		fixture := url.URL{Scheme: "file", Path: filepath.ToSlash(source), RawQuery: "mode=ro"}
		if _, err := db.ExecContext(t.Context(), "ATTACH DATABASE ? AS fixture", fixture.String()); err != nil {
			t.Fatalf("attach source fixture: %v", err)
		}
	}
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("begin historical fixture: %v", err)
	}
	defer tx.Rollback()
	for n := 1; n <= version; n++ {
		files, err := filepath.Glob(filepath.Join(schemaDir, fmt.Sprintf("%03d_*.sql", n)))
		if err != nil || len(files) != 1 {
			t.Fatalf("migration %d: files=%v error=%v", n, files, err)
		}
		data, err := os.ReadFile(files[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(t.Context(), string(data)); err != nil {
			t.Fatalf("migration %d: %v", n, err)
		}
	}
	if _, err := tx.ExecContext(t.Context(), fmt.Sprintf("PRAGMA user_version=%d", version)); err != nil {
		t.Fatal(err)
	}
	if source != "" {
		if _, err := tx.ExecContext(t.Context(), "PRAGMA defer_foreign_keys=ON"); err != nil {
			t.Fatal(err)
		}
		tables, err := tx.QueryContext(t.Context(), "SELECT name FROM main.sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for tables.Next() {
			var name string
			if err := tables.Scan(&name); err != nil {
				t.Fatal(err)
			}
			names = append(names, name)
		}
		if err := tables.Err(); err != nil {
			t.Fatal(err)
		}
		if err := tables.Close(); err != nil {
			t.Fatal(err)
		}
		// The SDK snapshot owns seeded counters too. Clear migration defaults
		// before copying any rows so cascades cannot remove restored children.
		for _, name := range names {
			table := `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
			if _, err := tx.ExecContext(t.Context(), "DELETE FROM main."+table); err != nil {
				t.Fatalf("clear historical table %s: %v", name, err)
			}
		}
		for _, name := range names {
			rows, err := tx.QueryContext(t.Context(), "SELECT name FROM pragma_table_info(?) ORDER BY cid", name)
			if err != nil {
				t.Fatal(err)
			}
			var columns []string
			for rows.Next() {
				var column string
				if err := rows.Scan(&column); err != nil {
					t.Fatal(err)
				}
				columns = append(columns, `"`+strings.ReplaceAll(column, `"`, `""`)+`"`)
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if err := rows.Close(); err != nil {
				t.Fatal(err)
			}
			projection := strings.Join(columns, ",")
			selected := "source." + strings.Join(columns, ",source.")
			table := `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
			selection := selects[name]
			if selection == "" && version < 48 {
				// Pre-versioning fixtures retain the null-slot data that the
				// versioning migration moved out of these historical tables.
				switch name {
				case "s3_objects":
					selection = "SELECT * FROM fixture.s3_object_versions WHERE version_id='null' AND delete_marker=false"
				case "s3_object_metadata":
					selection = "SELECT * FROM fixture.s3_object_version_metadata WHERE version_id='null'"
				case "s3_object_data":
					selection = "SELECT * FROM fixture.s3_object_version_data WHERE version_id='null'"
				}
			}
			if selection == "" && name == "sns_confirmation_tokens" && version < 148 {
				// Historical tokens belonged to a live subscription. Retained
				// identities now outlive that row, so only joined tokens existed
				// in the old representation.
				selection = `SELECT c.token, s.arn AS subscription_arn, c.expires
					FROM fixture.sns_confirmation_tokens c
					JOIN fixture.sns_subscriptions s
					ON s.partition=c.partition AND s.account_id=c.account_id
					AND s.region=c.region AND s.topic_name=c.topic_name AND s.id=c.subscription_id`
			}
			if selection == "" {
				selection = "SELECT *"
				if name == "sqs_messages" && version < 43 {
					// Version 43 removed response-only digests. Their historical
					// values do not participate in queue state or the upgrade.
					selection += ", '' AS attributes_md5, '' AS system_md5"
				}
				if name == "lambda_invocations" && version < 44 {
					selection += ", false AS pending, invoke_count AS function_errors"
				}
				selection += " FROM fixture." + table
				if name == "lambda_metric_samples" && version < 47 {
					// Historical metrics contain only the function aggregate,
					// not additional resource/executed-version projections.
					selection += " WHERE resource='' AND executed_version=''"
				}
			}
			if _, err := tx.ExecContext(t.Context(), "INSERT INTO main."+table+" ("+projection+") SELECT "+selected+" FROM ("+selection+") AS source"); err != nil {
				t.Fatalf("historical table %s: %v", name, err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit historical fixture: %v", err)
	}
	if source != "" {
		if _, err := db.ExecContext(t.Context(), "DETACH DATABASE fixture"); err != nil {
			t.Fatalf("detach source fixture: %v", err)
		}
	}
	return db
}
