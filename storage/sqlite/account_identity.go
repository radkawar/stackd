package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// ResolveAccountID retains the first bootstrap account selection. Later explicit
// IDs must match that account. Related calls join the supplied transaction and
// roll back with its owner. Existing resources and ARNs are never rewritten.
func ResolveAccountID(ctx context.Context, db *sql.DB, requested string) (string, error) {
	if requested != "" && (len(requested) != 12 || strings.Trim(requested, "0123456789") != "") {
		return "", fmt.Errorf("account ID must have 12 digits")
	}
	var account string
	err := Transact(ctx, db, false, func(ctx context.Context, tx *sql.Tx) error {
		var selected bool
		if err := tx.QueryRowContext(ctx, "SELECT account_id, selected FROM instance_identity WHERE singleton = 1").Scan(&account, &selected); err != nil {
			return err
		}
		if selected {
			if requested != "" && requested != account {
				return fmt.Errorf("sandbox account is %s; cannot select %s in existing state", account, requested)
			}
			return nil
		}
		if requested != "" {
			account = requested
		}
		_, err := tx.ExecContext(ctx, "UPDATE instance_identity SET account_id = ?, selected = TRUE WHERE singleton = 1", account)
		return err
	})
	return account, err
}
