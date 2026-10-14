package storage

import (
	"context"
	"fmt"
	"strings"

	"stackd/internal/identity"
	"stackd/storage/memory"
)

func newMemoryAccountResolver(domain *memory.Domain) func(context.Context, string) (string, error) {
	state := memory.New(domain, identity.DefaultAccountID, func(account string) string { return account })
	return func(ctx context.Context, requested string) (string, error) {
		if requested != "" && (len(requested) != 12 || strings.Trim(requested, "0123456789") != "") {
			return "", fmt.Errorf("account ID must have 12 digits")
		}
		var account string
		transact := state.View
		if requested != "" {
			transact = state.Update
		}
		err := transact(ctx, func(saved *string, _ *memory.Transaction) error {
			if requested != "" {
				*saved = requested
			}
			account = *saved
			return nil
		})
		return account, err
	}
}
