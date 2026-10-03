package memory_test

import (
	"context"
	"errors"
	"maps"
	"testing"

	"stackd/storage/memory"
)

func TestDomainCommitsTypedStoresTogether(t *testing.T) {
	for _, outcome := range []string{"commit", "error", "cancel", "nested error", "nested panic"} {
		t.Run(outcome, func(t *testing.T) {
			domain := memory.NewDomain()
			policies := memory.New(domain, map[string]string{"policy": "allow"}, maps.Clone[map[string]string])
			credentials := memory.New(domain, 0, func(n int) int { return n })
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			failure := errors.New("publication failed")
			var escaped context.Context
			err := credentials.Update(ctx, func(count *int, tx *memory.Transaction) error {
				escaped = tx.Context()
				*count = 1
				func() {
					if outcome == "nested panic" {
						defer func() {
							if recover() != failure {
								t.Error("nested panic was not propagated")
							}
						}()
					}
					_ = policies.Update(tx.Context(), func(state *map[string]string, _ *memory.Transaction) error {
						(*state)["policy"] = "deny"
						if outcome == "nested error" {
							return failure
						}
						if outcome == "nested panic" {
							panic(failure)
						}
						return nil
					})
				}()
				if outcome == "error" {
					return failure
				}
				if outcome == "cancel" {
					cancel()
				}
				return nil
			})
			if outcome == "commit" && err != nil || outcome != "commit" && err == nil {
				t.Fatalf("%s: %v", outcome, err)
			}
			if (outcome == "error" || outcome == "nested error") && !errors.Is(err, failure) {
				t.Fatalf("lost callback failure: %v", err)
			}
			if outcome == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation: %v", err)
			}
			if err := credentials.View(t.Context(), func(count *int, tx *memory.Transaction) error {
				return policies.View(tx.Context(), func(state *map[string]string, _ *memory.Transaction) error {
					wantCount, wantPolicy := 0, "allow"
					if outcome == "commit" {
						wantCount, wantPolicy = 1, "deny"
					}
					if *count != wantCount || (*state)["policy"] != wantPolicy {
						t.Fatalf("partial commit: credentials=%d, policy=%s", *count, (*state)["policy"])
					}
					return nil
				})
			}); err != nil {
				t.Fatal(err)
			}
			if err := policies.Update(escaped, func(*map[string]string, *memory.Transaction) error {
				t.Fatal("expired domain context entered another store")
				return nil
			}); !errors.Is(err, context.Canceled) {
				t.Fatalf("expired context: %v", err)
			}
		})
	}
}

func TestDomainReadYourWritesAndReadOnlyBoundary(t *testing.T) {
	domain := memory.NewDomain()
	first := memory.New(domain, 0, func(n int) int { return n })
	second := memory.New(domain, 0, func(n int) int { return n })
	if err := first.Update(t.Context(), func(a *int, tx *memory.Transaction) error {
		*a = 1
		if err := second.Update(tx.Context(), func(b *int, tx *memory.Transaction) error {
			*b = 2
			return first.View(tx.Context(), func(value *int, _ *memory.Transaction) error {
				if *value != 1 {
					t.Fatal("related repository did not read staged IAM state")
				}
				return nil
			})
		}); err != nil {
			return err
		}
		return second.View(tx.Context(), func(b *int, _ *memory.Transaction) error {
			if *b != 2 {
				t.Fatal("outer transaction did not read staged related state")
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := first.View(t.Context(), func(_ *int, tx *memory.Transaction) error {
		err := second.Update(tx.Context(), func(*int, *memory.Transaction) error {
			t.Fatal("read-only domain admitted a write")
			return nil
		})
		if !errors.Is(err, memory.ErrClosedTransaction) {
			t.Fatalf("read-only domain: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
