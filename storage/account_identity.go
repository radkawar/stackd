package storage

import (
	"context"
	"fmt"
	"strings"

	"stackd/internal/identity"
	"stackd/storage/memory"
)

func newMemoryAccountResolver(domain *memory.Domain) func(context.Context, string) (string, error) {
	state := memory.New(domain, "", func(account string) string { return account })
	return func(ctx context.Context, requested string) (string, error) {
		if requested != "" && (len(requested) != 12 || strings.Trim(requested, "0123456789") != "") {
			return "", fmt.Errorf("account ID must have 12 digits")
		}
		var account string
		err := state.View(ctx, func(saved *string, _ *memory.Transaction) error {
			account = *saved
			return nil
		})
		if err != nil {
			return "", err
		}
		if account != "" {
			if requested != "" && requested != account {
				return "", fmt.Errorf("sandbox account is %s; cannot select %s in existing state", account, requested)
			}
			return account, nil
		}
		candidate := requested
		if candidate == "" {
			candidate = identity.NewAccountID()
		}
		err = state.Update(ctx, func(saved *string, _ *memory.Transaction) error {
			if *saved == "" {
				*saved = candidate
			} else if requested != "" && requested != *saved {
				return fmt.Errorf("sandbox account is %s; cannot select %s in existing state", *saved, requested)
			}
			account = *saved
			return nil
		})
		return account, err
	}
}
