package logs_test

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	domain "stackd/storage/logs"
	"stackd/storage/sqlite"
	sqllogs "stackd/storage/sqlite/logs"
)

func TestRetentionDeletionAndPolicyChanges(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			repo := domain.NewMemory(nil)
			reopen := func() {}
			if backend == "sqlite" {
				path := filepath.Join(t.TempDir(), "logs.sqlite")
				db, err := sqlite.Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = db.Close() }()
				repo = sqllogs.New(db)
				reopen = func() {
					if err := db.Close(); err != nil {
						t.Fatal(err)
					}
					db, err = sqlite.Open(ctx, path)
					if err != nil {
						t.Fatal(err)
					}
					repo = sqllogs.New(db)
				}
			}
			const day = int64(86400000)
			now := int64(20) * day
			g := domain.GroupRecord{Key: domain.GroupKey{Scope: domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "retained"}, ID: "group", RetentionDays: 1}
			stream := domain.StreamRecord{Key: domain.StreamKey{GroupID: g.ID, Name: "events"}, ID: "stream", EventCount: 3, FirstEvent: now - day - 1, LastEvent: now, LastIngestion: now}
			update := func(fn func(domain.Transaction) error) {
				t.Helper()
				if err := repo.Update(ctx, fn); err != nil {
					t.Fatal(err)
				}
			}
			update(func(tx domain.Transaction) error {
				if err := tx.PutGroup(g); err != nil {
					return err
				}
				if err := tx.PutStream(stream); err != nil {
					return err
				}
				for i, stamp := range []int64{now - day - 1, now - day, now} {
					if err := tx.AppendEvent(domain.EventRecord{EventCursor: domain.EventCursor{Timestamp: stamp, Ingestion: now, Sequence: int64(i)}, GroupID: g.ID, StreamID: stream.ID, StreamName: stream.Key.Name, ID: string(rune('a' + i)), Message: "x"}); err != nil {
						return err
					}
				}
				other := g
				other.ID = "isolated"
				other.Key.AccountID = "222222222222"
				other.RetentionDays = 0
				if err := tx.PutGroup(other); err != nil {
					return err
				}
				otherStream := stream
				otherStream.Key.GroupID = other.ID
				otherStream.ID = "other-stream"
				otherStream.EventCount = 1
				if err := tx.PutStream(otherStream); err != nil {
					return err
				}
				return tx.AppendEvent(domain.EventRecord{EventCursor: domain.EventCursor{Timestamp: now - day - 1}, GroupID: other.ID, StreamID: otherStream.ID, StreamName: otherStream.Key.Name, ID: "other", Message: "untouched"})
			})
			check := func(want []int64, due int64) {
				t.Helper()
				if err := repo.View(ctx, func(r domain.Reader) error {
					rows, err := r.Events(domain.EventQuery{GroupID: g.ID, Start: 0, End: now + 1, Limit: 10})
					if err != nil {
						return err
					}
					got := make([]int64, 0, len(rows))
					for _, v := range rows {
						got = append(got, v.Timestamp)
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("events %v, want %v", got, want)
					}
					s, err := r.Stream(stream.Key)
					if err != nil {
						return err
					}
					if s.EventCount != int64(len(want)) {
						t.Fatalf("stream count %d, want %d", s.EventCount, len(want))
					}
					if len(want) > 0 && (s.FirstEvent != want[0] || s.LastEvent != want[len(want)-1]) {
						t.Fatalf("stream bounds: %+v", s)
					}
					job, found, err := r.NextRetention()
					if err != nil {
						return err
					}
					if found != (due >= 0) || (found && !job.Due.Equal(time.UnixMilli(due))) {
						t.Fatalf("next expiry %+v found %v, want %d", job, found, due)
					}
					bytes, err := r.StoredBytes("isolated", 0)
					if err != nil {
						return err
					}
					if bytes != 9 {
						t.Fatalf("isolated bytes %d", bytes)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			check([]int64{now - day - 1, now - day, now}, now)
			// A stale selected job must use the policy current at deletion, not its old cutoff.
			g.RetentionDays = 3
			update(func(tx domain.Transaction) error { return tx.PutGroup(g) })
			update(func(tx domain.Transaction) error { return tx.ExpireEvents(now) })
			check([]int64{now - day - 1, now - day, now}, now+2*day)
			g.RetentionDays = 1
			update(func(tx domain.Transaction) error { return tx.PutGroup(g) })
			abort := errors.New("rollback")
			if err := repo.Update(ctx, func(tx domain.Transaction) error {
				if err := tx.ExpireEvents(now); err != nil {
					return err
				}
				return abort
			}); !errors.Is(err, abort) {
				t.Fatal(err)
			}
			check([]int64{now - day - 1, now - day, now}, now)
			update(func(tx domain.Transaction) error { return tx.ExpireEvents(now) })
			check([]int64{now - day, now}, now+1)
			reopen()
			g.RetentionDays = 0
			update(func(tx domain.Transaction) error { return tx.PutGroup(g) })
			update(func(tx domain.Transaction) error { return tx.ExpireEvents(now + 100*day) })
			check([]int64{now - day, now}, -1)
			g.RetentionDays = 1
			update(func(tx domain.Transaction) error { return tx.PutGroup(g) })
			update(func(tx domain.Transaction) error { return tx.ExpireEvents(now + day + 1) })
			check([]int64{}, -1)
			reopen()
			g.RetentionDays = 365
			update(func(tx domain.Transaction) error { return tx.PutGroup(g) })
			check([]int64{}, -1)
		})
	}
}
