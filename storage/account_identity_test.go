package storage

import (
	"errors"
	"testing"

	"stackd/storage/memory"
)

func TestMemoryAccountSelectionRetainsIdentityAndRollsBack(t *testing.T) {
	domain := memory.NewDomain()
	resolve := newMemoryAccountResolver(domain)
	abort := errors.New("abort account selection")
	owner := memory.New(domain, false, func(value bool) bool { return value })
	err := owner.Update(t.Context(), func(_ *bool, tx *memory.Transaction) error {
		if _, err := resolve(tx.Context(), "820493716052"); err != nil {
			return err
		}
		return abort
	})
	if !errors.Is(err, abort) {
		t.Fatal(err)
	}
	const account = "609274183506"
	for _, requested := range []string{account, "", account} {
		got, err := resolve(t.Context(), requested)
		if err != nil || got != account {
			t.Fatalf("saved account = %q, %v; want %q", got, err, account)
		}
	}
	for _, requested := range []string{"820493716052", "invalid"} {
		if _, err := resolve(t.Context(), requested); err == nil {
			t.Fatalf("accepted account change %q", requested)
		}
		got, err := resolve(t.Context(), "")
		if err != nil || got != account {
			t.Fatalf("rejected selection changed identity: %q, %v", got, err)
		}
	}
}

func TestMemoryAccountSelectionConcurrent(t *testing.T) {
	for _, name := range []string{"generated", "explicit"} {
		explicit := name == "explicit"
		t.Run(name, func(t *testing.T) {
			resolve := newMemoryAccountResolver(memory.NewDomain())
			type result struct {
				account string
				err     error
			}
			results := make(chan result, 2)
			start := make(chan struct{})
			for _, requested := range []string{"820493716052", "609274183506"} {
				if !explicit {
					requested = ""
				}
				go func() {
					<-start
					account, err := resolve(t.Context(), requested)
					results <- result{account, err}
				}()
			}
			close(start)
			first, second := <-results, <-results
			saved, err := resolve(t.Context(), "")
			if err != nil {
				t.Fatal(err)
			}
			if explicit {
				if (first.err == nil) == (second.err == nil) {
					t.Fatalf("competing choices must have one winner: %+v, %+v", first, second)
				}
				winner := first
				if winner.err != nil {
					winner = second
				}
				if saved != winner.account {
					t.Fatalf("saved account %q differs from winner %q", saved, winner.account)
				}
			} else if first.err != nil || second.err != nil || first.account != saved || second.account != saved {
				t.Fatalf("concurrent starts used different identities: %+v, %+v; saved %q", first, second, saved)
			}
		})
	}
}
