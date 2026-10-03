package rds

import (
	"context"
	"database/sql"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
)

// StaticParameter identifies supported settings whose RDS apply contract requires
// a restart, even where the upstream engine can also change the value dynamically.
func StaticParameter(engine, name string) bool {
	if strings.Contains(engine, "postgres") {
		return name == "max_connections" || name == "shared_buffers"
	}
	return name == "character_set_server" || name == "collation_server"
}

// Dynamic parameters live in the native durable configuration, not immutable
// Docker command arguments. PostgreSQL reloads its configuration; MySQL changes
// global defaults (existing sessions retain their session-scoped values).
// The caller holds the runtime gate, outside any control-plane transaction.
func (d *Docker) applyParameters(ctx context.Context, endpoint Endpoint, spec Specification) error {
	db, err := Open(ctx, spec.Engine, endpoint, spec.Database, spec.Username, spec.Password)
	if err != nil {
		return err
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	kind, _ := family(spec.Engine)
	query := "SELECT LOWER(VARIABLE_NAME), VARIABLE_VALUE FROM performance_schema.persisted_variables"
	if kind == "postgres" {
		query = "SELECT lower(name), setting FROM pg_file_settings WHERE sourcefile = current_setting('data_directory') || '/postgresql.auto.conf' AND applied"
	}
	rows, err := conn.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	persisted := map[string]string{}
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			rows.Close()
			return err
		}
		if !StaticParameter(spec.Engine, name) && ValidateParameters(spec.Engine, map[string]string{name: value}) == nil {
			persisted[name] = value
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if kind == "mysql" {
		if _, err := conn.ExecContext(ctx, "SET SESSION sql_mode = 'NO_BACKSLASH_ESCAPES'"); err != nil {
			return err
		}
	}
	for _, name := range slices.Sorted(maps.Keys(persisted)) {
		if _, keep := spec.Parameters[name]; keep {
			continue
		}
		if kind == "postgres" {
			_, err = conn.ExecContext(ctx, "ALTER SYSTEM RESET "+name)
		} else {
			if _, err = conn.ExecContext(ctx, "SET GLOBAL "+name+" = DEFAULT"); err == nil {
				_, err = conn.ExecContext(ctx, "RESET PERSIST "+name)
			}
		}
		if err != nil {
			return err
		}
	}
	for _, name := range slices.Sorted(maps.Keys(spec.Parameters)) {
		value := spec.Parameters[name]
		if StaticParameter(spec.Engine, name) || persisted[name] == value {
			continue
		}
		if kind == "postgres" {
			// Utility statements do not accept bound values. Let the engine
			// quote the literal; parameter names have already been allowlisted.
			var statement string
			if err = conn.QueryRowContext(ctx, "SELECT format('ALTER SYSTEM SET %I = %L', $1::text, $2::text)", name, value).Scan(&statement); err == nil {
				_, err = conn.ExecContext(ctx, statement)
			}
		} else {
			var literal string
			literal, err = mysqlParameterLiteral(name, value)
			if err == nil {
				_, err = conn.ExecContext(ctx, "SET PERSIST "+name+" = "+literal)
			}
		}
		if err != nil {
			return err
		}
	}
	if kind == "postgres" {
		// Also reload on recovery when ALTER SYSTEM committed but the previous
		// controller died before dispatching SIGHUP or recording completion.
		return reloadPostgres(ctx, conn)
	}
	return nil
}

func mysqlParameterLiteral(name, value string) (string, error) {
	switch name {
	case "max_connections", "innodb_buffer_pool_size", "wait_timeout", "interactive_timeout":
		// MySQL SET requires integer expressions, not quoted numeric strings.
		// Preserve the binary suffixes accepted by the former startup flags.
		shift := 0
		if len(value) > 1 {
			if unit := strings.IndexByte("kKmMgGtTpPeE", value[len(value)-1]); unit >= 0 {
				shift = (unit/2 + 1) * 10
				value = value[:len(value)-1]
			}
		}
		number, err := strconv.ParseUint(value, 10, 64)
		if err != nil || number > ^uint64(0)>>shift {
			return "", errors.New("native MySQL parameter requires an unsigned integer within range")
		}
		return strconv.FormatUint(number<<shift, 10), nil
	default:
		return "'" + strings.ReplaceAll(value, "'", "''") + "'", nil
	}
}

func reloadPostgres(ctx context.Context, conn *sql.Conn) error {
	var before time.Time
	if err := conn.QueryRowContext(ctx, "SELECT pg_conf_load_time()").Scan(&before); err != nil {
		return err
	}
	var signaled bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_reload_conf()").Scan(&signaled); err != nil {
		return err
	}
	if !signaled {
		return errors.New("native PostgreSQL configuration reload was not signaled")
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var loaded bool
		if err := conn.QueryRowContext(ctx, "SELECT pg_conf_load_time() > $1", before).Scan(&loaded); err != nil {
			return err
		}
		if loaded {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
