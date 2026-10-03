package guardduty_test

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	domain "stackd/storage/guardduty"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/guardduty"
)

func ipListRecord(sc domain.Scope, kind domain.IPListKind, id string) domain.IPList {
	d, _, _ := records(sc)
	return domain.IPList{Scope: sc, DetectorID: d.ID, Kind: kind, ID: id, ARN: d.ARN + "/" + string(kind) + "/" + id, Name: "list-" + id, Format: "TXT", Location: "https://s3.amazonaws.com/bucket/list.txt", ExpectedBucketOwner: sc.AccountID, ClientToken: "token-" + id, Status: "ACTIVE", Version: 7, Due: time.Date(2031, 2, 3, 4, 5, 6, 123456789, time.UTC), Tags: map[string]string{"owner": "security"}}
}

func assertIPMatches(t *testing.T, repo domain.Repository, sc domain.Scope, ip uint32, want ...domain.IPList) {
	t.Helper()
	if err := repo.View(t.Context(), func(r domain.Reader) error {
		got, err := r.MatchingIPLists(sc, "detector", ip)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("matching %08x in %+v = %#v, want %#v", ip, sc, got, want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestIPListsRangesRetentionIsolationAndCascade(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			repo, reopen := repository(t, kind)
			scopes := []domain.Scope{
				{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"},
				{Partition: "aws", AccountID: "222222222222", Region: "us-east-1"},
				{Partition: "aws", AccountID: "111111111111", Region: "us-west-2"},
				{Partition: "aws-cn", AccountID: "111111111111", Region: "us-east-1"},
			}
			lists := func(sc domain.Scope) []domain.IPList {
				a := ipListRecord(sc, domain.TrustedIPList, "a")
				b := ipListRecord(sc, domain.TrustedIPList, "b")
				b.Tags = map[string]string{}
				c := ipListRecord(sc, domain.ThreatIPList, "a")
				c.Tags = nil
				d := ipListRecord(sc, domain.ThreatIPList, "inactive")
				d.Status = "INACTIVE"
				e := ipListRecord(sc, domain.ThreatIPList, "pending")
				e.Status = "ACTIVATING"
				return []domain.IPList{a, b, c, d, e}
			}
			ranges := []domain.IPRange{{First: 0, Last: 0}, {First: 10, Last: 20}, {First: 30, Last: 40}, {First: math.MaxUint32 - 1, Last: math.MaxUint32}}
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				for _, sc := range scopes {
					d, _, _ := records(sc)
					if err := tx.PutDetector(d); err != nil {
						return err
					}
					values := lists(sc)
					for i := len(values) - 1; i >= 0; i-- {
						v := values[i]
						if err := tx.PutIPList(v); err != nil {
							return err
						}
						if err := tx.ReplaceIPRanges(sc, v.DetectorID, v.Kind, v.ID, ranges); err != nil {
							return err
						}
						if v.Tags != nil {
							v.Tags["mutation"] = "must not leak"
						}
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			// Caller-owned input must not mutate an ingested snapshot.
			ranges[1] = domain.IPRange{First: 100, Last: 200}
			repo = reopen()
			for _, sc := range scopes {
				want := lists(sc)
				if err := repo.View(t.Context(), func(r domain.Reader) error {
					all, err := r.IPLists(sc, "detector")
					if err != nil {
						return err
					}
					if !reflect.DeepEqual(all, want) {
						t.Fatalf("retained metadata = %#v, want %#v", all, want)
					}
					for _, v := range want {
						got, err := r.IPList(sc, v.DetectorID, v.Kind, v.ID)
						if err != nil {
							return err
						}
						if !reflect.DeepEqual(got, v) {
							t.Fatalf("IPList = %#v, want %#v", got, v)
						}
						if got.Tags != nil {
							got.Tags["mutation"] = "must not leak"
						}
					}
					all[0].Tags["mutation"] = "must not leak"
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				for _, ip := range []uint32{0, 10, 15, 20, 30, 40, math.MaxUint32 - 1, math.MaxUint32} {
					assertIPMatches(t, repo, sc, ip, want[:3]...)
				}
				for _, ip := range []uint32{1, 9, 21, 29, 41, math.MaxUint32 - 2} {
					assertIPMatches(t, repo, sc, ip)
				}
			}
			sc := scopes[0]
			want := lists(sc)
			// Metadata refresh leaves the previous immutable range snapshot intact.
			want[0].Name = "renamed"
			want[0].Version++
			want[0].Due = time.Time{}
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.PutIPList(want[0]) }); err != nil {
				t.Fatal(err)
			}
			assertIPMatches(t, repo, sc, 15, want[:3]...)
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				return tx.ReplaceIPRanges(sc, "detector", domain.TrustedIPList, "a", []domain.IPRange{{First: 100, Last: 110}})
			}); err != nil {
				t.Fatal(err)
			}
			repo = reopen()
			assertIPMatches(t, repo, sc, 15, want[1:3]...)
			assertIPMatches(t, repo, sc, 100, want[0])
			assertIPMatches(t, repo, sc, 110, want[0])
			assertIPMatches(t, repo, sc, 111)
			for _, other := range scopes[1:] {
				assertIPMatches(t, repo, other, 15, lists(other)[:3]...)
				assertIPMatches(t, repo, other, 100)
			}
			// Clearing ranges and changing status independently affect membership.
			want[2].Status = "INACTIVE"
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := tx.ReplaceIPRanges(sc, "detector", domain.TrustedIPList, "b", nil); err != nil {
					return err
				}
				return tx.PutIPList(want[2])
			}); err != nil {
				t.Fatal(err)
			}
			assertIPMatches(t, repo, sc, 15)
			for _, detectorDelete := range []bool{false, true} {
				if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
					if detectorDelete {
						return tx.DeleteDetector(sc, "detector")
					}
					return tx.DeleteIPList(sc, "detector", domain.TrustedIPList, "a")
				}); err != nil {
					t.Fatal(err)
				}
				repo = reopen()
				if err := repo.View(t.Context(), func(r domain.Reader) error {
					if _, err := r.IPList(sc, "detector", domain.TrustedIPList, "a"); !errors.Is(err, domain.ErrNotFound) {
						t.Fatalf("deleted list error = %v", err)
					}
					if detectorDelete {
						all, err := r.IPLists(sc, "detector")
						if err != nil {
							return err
						}
						if len(all) != 0 {
							t.Fatalf("detector children retained: %#v", all)
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				// Reusing the key must not resurrect cascaded ranges or tags.
				fresh := ipListRecord(sc, domain.TrustedIPList, "a")
				fresh.Tags = nil
				if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
					d, _, _ := records(sc)
					if err := tx.PutDetector(d); err != nil {
						return err
					}
					return tx.PutIPList(fresh)
				}); err != nil {
					t.Fatal(err)
				}
				assertIPMatches(t, repo, sc, 100)
				if err := repo.View(t.Context(), func(r domain.Reader) error {
					got, err := r.IPList(sc, "detector", fresh.Kind, fresh.ID)
					if err != nil {
						return err
					}
					if !reflect.DeepEqual(got, fresh) {
						t.Fatalf("recreated list = %#v, want %#v", got, fresh)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
					return tx.ReplaceIPRanges(sc, "detector", fresh.Kind, fresh.ID, []domain.IPRange{{First: 100, Last: 110}})
				}); err != nil {
					t.Fatal(err)
				}
				for _, other := range scopes[1:] {
					assertIPMatches(t, repo, other, 15, lists(other)[:3]...)
				}
			}
		})
	}
}

func TestIPListsSourceRollbackAndMissingParents(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			var repo domain.Repository
			var source func(context.Context, func(context.Context) error) error
			if kind == "memory" {
				d := memory.NewDomain()
				repo = domain.NewMemory(d)
				state := memory.New(d, 0, func(v int) int { return v })
				source = func(ctx context.Context, fn func(context.Context) error) error {
					return state.Update(ctx, func(v *int, tx *memory.Transaction) error {
						*v++
						return fn(tx.Context())
					})
				}
			} else {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				repo = backend.New(db)
				source = func(ctx context.Context, fn func(context.Context) error) error {
					return sqlite.Transact(ctx, db, false, func(ctx context.Context, _ *sql.Tx) error { return fn(ctx) })
				}
			}
			sc := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
			v := ipListRecord(sc, domain.TrustedIPList, "a")
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.PutIPList(v) }); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("missing detector error = %v", err)
			}
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				d, _, _ := records(sc)
				return tx.PutDetector(d)
			}); err != nil {
				t.Fatal(err)
			}
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				return tx.ReplaceIPRanges(sc, "detector", v.Kind, v.ID, nil)
			}); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("missing list error = %v", err)
			}
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := tx.PutIPList(v); err != nil {
					return err
				}
				return tx.ReplaceIPRanges(sc, "detector", v.Kind, v.ID, []domain.IPRange{{First: 10, Last: 20}})
			}); err != nil {
				t.Fatal(err)
			}
			rejected := errors.New("source transaction rejected")
			for _, deletion := range []bool{false, true} {
				err := source(t.Context(), func(ctx context.Context) error {
					if err := repo.Update(ctx, func(tx domain.Transaction) error {
						if deletion {
							return tx.DeleteDetector(sc, "detector")
						}
						changed := v
						changed.Version++
						changed.Tags = map[string]string{"owner": "rejected"}
						if err := tx.PutIPList(changed); err != nil {
							return err
						}
						return tx.ReplaceIPRanges(sc, "detector", v.Kind, v.ID, []domain.IPRange{{First: 100, Last: 200}})
					}); err != nil {
						return err
					}
					return rejected
				})
				if !errors.Is(err, rejected) {
					t.Fatalf("source rollback = %v", err)
				}
				assertIPMatches(t, repo, sc, 10, v)
				assertIPMatches(t, repo, sc, 20, v)
				assertIPMatches(t, repo, sc, 100)
			}
		})
	}
}

func TestIPListMemoryExpiredTransactions(t *testing.T) {
	repo := domain.NewMemory(memory.NewDomain())
	var expired domain.Transaction
	if err := repo.Update(t.Context(), func(tx domain.Transaction) error { expired = tx; return nil }); err != nil {
		t.Fatal(err)
	}
	sc := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	v := ipListRecord(sc, domain.TrustedIPList, "a")
	checks := []func() error{
		func() error { _, err := expired.IPList(sc, "detector", v.Kind, v.ID); return err },
		func() error { _, err := expired.IPLists(sc, "detector"); return err },
		func() error { _, err := expired.MatchingIPLists(sc, "detector", 10); return err },
		func() error { return expired.PutIPList(v) },
		func() error { return expired.DeleteIPList(sc, "detector", v.Kind, v.ID) },
		func() error { return expired.ReplaceIPRanges(sc, "detector", v.Kind, v.ID, nil) },
	}
	for i, check := range checks {
		if err := check(); !errors.Is(err, memory.ErrClosedTransaction) {
			t.Fatalf("expired operation %d = %v", i, err)
		}
	}
}
