package storage

import (
	"errors"
	"testing"

	"stackd/internal/identity"
	"stackd/storage/memory"
)

func TestMemoryAccountSelectionRetainsOverridesAndRollsBack(t *testing.T) {
	domain := memory.NewDomain()
	resolve := newMemoryAccountResolver(domain)
	check := func(want string) {
		t.Helper()
		got, err := resolve(t.Context(), "")
		if err != nil || got != want {
			t.Fatalf("saved account = %q, %v; want %q", got, err, want)
		}
	}
	check(identity.DefaultAccountID)
	for _, account := range []string{"820493716052", "000000000000"} {
		got, err := resolve(t.Context(), account)
		if err != nil || got != account {
			t.Fatalf("explicit account = %q, %v", got, err)
		}
		check(account)
	}
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
	check("000000000000")
	if _, err := resolve(t.Context(), "invalid"); err == nil {
		t.Fatal("accepted invalid account")
	}
	check("000000000000")
}
