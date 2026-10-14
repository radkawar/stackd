package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// ResolveAccountID selects the saved bootstrap account or persists an explicit
// override. Changing this alias never rewrites existing resources or ARNs.
// Related calls join the supplied transaction and roll back with its owner.
func ResolveAccountID(ctx context.Context, db *sql.DB, requested string) (string, error) {
	if requested != "" && (len(requested) != 12 || strings.Trim(requested, "0123456789") != "") {
		return "", fmt.Errorf("account ID must have 12 digits")
	}
	var account string
	err := Transact(ctx, db, requested == "", func(ctx context.Context, tx *sql.Tx) error {
		if requested != "" {
			if _, err := tx.ExecContext(ctx, "UPDATE instance_identity SET account_id = ? WHERE singleton = 1", requested); err != nil {
				return err
			}
		}
		return tx.QueryRowContext(ctx, "SELECT account_id FROM instance_identity WHERE singleton = 1").Scan(&account)
	})
	return account, err
}
