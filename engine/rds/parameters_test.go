package rds

import (
	"context"
	"crypto/rand"
	"testing"
	"time"
)

func TestNativeDynamicParametersPreserveSessionsAndRestart(t *testing.T) {
	for _, engine := range []string{"postgres", "mysql"} {
		t.Run(engine, func(t *testing.T) {
			d := nativeRuntime(t)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
			defer cancel()
			spec := Specification{ID: rand.Text(), Engine: engine, Username: "owner", Password: rand.Text(), Database: "appdb"}
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				if err := d.Delete(cleanup, spec.ID); err != nil {
					t.Error(err)
				}
			})
			endpoint, err := d.Ensure(ctx, spec)
			if err != nil {
				t.Fatal(err)
			}
			name, query, expected := "statement_timeout", "SHOW statement_timeout", "7s"
			if engine == "mysql" {
				name, query, expected = "wait_timeout", "SELECT @@SESSION.wait_timeout", "7000"
			}
			read := func() string {
				t.Helper()
				db, err := Open(ctx, engine, endpoint, spec.Database, spec.Username, spec.Password)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				var value string
				if err := db.QueryRowContext(ctx, query).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			original := read()
			db, err := Open(ctx, engine, endpoint, spec.Database, spec.Username, spec.Password)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			held, err := db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			if _, err := held.ExecContext(ctx, "CREATE TEMPORARY TABLE uninterrupted (id INTEGER)"); err != nil {
				t.Fatal(err)
			}
			if _, err := held.ExecContext(ctx, "INSERT INTO uninterrupted VALUES (42)"); err != nil {
				t.Fatal(err)
			}
			spec.Parameters = map[string]string{name: "7000"}
			changed, err := d.Ensure(ctx, spec)
			if err != nil || changed != endpoint {
				t.Fatalf("live application endpoint=%v error=%v", changed, err)
			}
			var retained int
			if err := held.QueryRowContext(ctx, "SELECT id FROM uninterrupted").Scan(&retained); err != nil || retained != 42 {
				t.Fatalf("live application interrupted native session: %d, %v", retained, err)
			}
			if got := read(); got != expected {
				t.Fatalf("live setting=%q want %q", got, expected)
			}
			held.Close()
			if err := d.Stop(ctx, spec.ID); err != nil {
				t.Fatal(err)
			}
			// Start the native process directly: no Ensure/SQL reapplication is
			// allowed to hide a failure to persist the engine configuration.
			state, err := d.inspect(ctx, d.name(spec.ID, "database"))
			if err != nil {
				t.Fatal(err)
			}
			if err := d.start(ctx, state); err != nil {
				t.Fatal(err)
			}
			state, err = d.inspect(ctx, state.ID)
			if err != nil {
				t.Fatal(err)
			}
			endpoint, err = state.endpoint(d.endpointHost, spec.Engine)
			if err != nil {
				t.Fatal(err)
			}
			if err := d.ready(ctx, state.ID, endpoint, spec); err != nil {
				t.Fatal(err)
			}
			if got := read(); got != expected {
				t.Fatalf("native restart lost persisted setting: %q", got)
			}
			spec.Parameters = nil
			if _, err := d.Ensure(ctx, spec); err != nil {
				t.Fatal(err)
			}
			if got := read(); got != original {
				t.Fatalf("reset setting=%q want original %q", got, original)
			}
		})
	}
}
