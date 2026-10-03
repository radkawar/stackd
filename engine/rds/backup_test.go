package rds

import (
	"context"
	"crypto/rand"
	"testing"
	"time"
)

func TestNativeRestoreRetryAfterSnapshotDeletion(t *testing.T) {
	for _, engine := range []string{"postgres", "mysql"} {
		t.Run(engine, func(t *testing.T) {
			d := nativeRuntime(t)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
			defer cancel()
			source := Specification{ID: rand.Text(), Engine: engine, Database: "appdb", Username: "master", Password: rand.Text()}
			target := source
			target.ID = rand.Text()
			snapshot := rand.Text()
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				for _, id := range []string{target.ID, source.ID} {
					if err := d.Delete(cleanup, id); err != nil {
						t.Error(err)
					}
				}
				if err := d.DeleteSnapshot(cleanup, snapshot); err != nil {
					t.Error(err)
				}
			})
			endpoint, err := d.Ensure(ctx, source)
			if err != nil {
				t.Fatal(err)
			}
			db, err := Open(ctx, engine, endpoint, source.Database, source.Username, source.Password)
			if err != nil {
				t.Fatal(err)
			}
			for _, query := range []string{"CREATE TABLE retained (id INTEGER PRIMARY KEY, value INTEGER)", "INSERT INTO retained VALUES (1, 41)"} {
				if _, err := db.ExecContext(ctx, query); err != nil {
					db.Close()
					t.Fatal(err)
				}
			}
			if engine == "mysql" {
				if _, err := db.ExecContext(ctx, "SET GLOBAL innodb_fast_shutdown = 2"); err != nil {
					db.Close()
					t.Fatal(err)
				}
			}
			db.Close()
			if err := d.Snapshot(ctx, source, snapshot); err != nil {
				t.Fatal(err)
			}
			restored, err := d.Restore(ctx, target, snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if err := d.DeleteSnapshot(ctx, snapshot); err != nil {
				t.Fatal(err)
			}
			if err := d.Delete(ctx, source.ID); err != nil {
				t.Fatal(err)
			}
			db, err = Open(ctx, engine, restored, target.Database, target.Username, target.Password)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(ctx, "UPDATE retained SET value = 42 WHERE id = 1"); err != nil {
				db.Close()
				t.Fatal(err)
			}
			db.Close()
			// A controller can lose its completion transaction after the native
			// clone commits. Retrying must use its independent durable bytes,
			// not require or recopy the subsequently retired source snapshot.
			retried, err := d.Restore(ctx, target, snapshot)
			if err != nil {
				t.Fatal(err)
			}
			db, err = Open(ctx, engine, retried, target.Database, target.Username, target.Password)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var value int
			if err := db.QueryRowContext(ctx, "SELECT value FROM retained WHERE id = 1").Scan(&value); err != nil || value != 42 {
				t.Fatalf("restore retry discarded independent bytes: value=%d error=%v", value, err)
			}
		})
	}
}
