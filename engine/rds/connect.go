package rds

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func family(engine string) (string, error) {
	switch engine {
	case "postgres", "aurora-postgresql":
		return "postgres", nil
	case "mysql", "aurora-mysql":
		return "mysql", nil
	default:
		return "", errors.New("unsupported native RDS engine")
	}
}

// Open authenticates over the native wire protocol and pings. The caller closes
// the pool. Native SQL errors remain available with errors.As; credentials are
// never included in a connection string or diagnostic message.
func Open(ctx context.Context, engine string, endpoint Endpoint, database, username, password string) (*sql.DB, error) {
	kind, err := family(engine)
	if err != nil {
		return nil, err
	}
	if endpoint.Address == "" || endpoint.Port < 1 || endpoint.Port > 65535 {
		return nil, errors.New("invalid native database endpoint")
	}
	var db *sql.DB
	if kind == "postgres" {
		if database == "" {
			database = "postgres"
		}
		// A constant ParseConfig input prevents parser errors from printing a
		// secret DSN. Explicit fields disable ambient libpq credentials/routes.
		config, err := pgx.ParseConfig("postgres://localhost/postgres?sslmode=disable")
		if err != nil {
			return nil, errors.New("initialize PostgreSQL connector")
		}
		config.Host, config.Port = endpoint.Address, uint16(endpoint.Port)
		config.Database, config.User, config.Password = database, username, password
		config.TLSConfig, config.Fallbacks = nil, nil
		config.ConnectTimeout = 5 * time.Second
		config.RuntimeParams = map[string]string{"application_name": "stackd-rds"}
		db = stdlib.OpenDB(*config)
	} else {
		config := mysql.NewConfig()
		config.Net, config.Addr = "tcp", net.JoinHostPort(endpoint.Address, strconv.Itoa(int(endpoint.Port)))
		config.DBName, config.User, config.Passwd = database, username, password
		config.Timeout = 5 * time.Second
		config.ParseTime = true
		config.MultiStatements = false
		// Driver network diagnostics must not go to the global stderr logger.
		config.Logger = silentMySQLLogger{}
		connector, err := mysql.NewConnector(config)
		if err != nil {
			return nil, errors.New("initialize MySQL connector")
		}
		db = sql.OpenDB(connector)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("native database authentication/readiness: %w", err)
	}
	return db, nil
}

type silentMySQLLogger struct{}

func (silentMySQLLogger) Print(...any) {}

func (d *Docker) SetPassword(ctx context.Context, spec Specification, password string) error {
	if err := validateSpecification(spec); err != nil {
		return err
	}
	if password == "" || strings.IndexByte(password, 0) >= 0 {
		return errors.New("native password must be nonempty and contain no NUL")
	}
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	state, err := d.inspect(ctx, d.name(spec.ID, "database"))
	if err != nil {
		return err
	}
	if err := d.checkDatabase(state, spec); err != nil {
		return err
	}
	endpoint, err := state.endpoint(d.endpointHost, spec.Engine)
	if err != nil {
		return err
	}
	// A lost control-plane completion can retry after the native change already
	// committed. Authenticate the desired credential before using the old one.
	if db, err := Open(ctx, spec.Engine, endpoint, spec.Database, spec.Username, password); err == nil {
		return db.Close()
	}
	db, err := Open(ctx, spec.Engine, endpoint, spec.Database, spec.Username, spec.Password)
	if err != nil {
		return err
	}
	defer db.Close()
	kind, _ := family(spec.Engine)
	if kind == "postgres" {
		// Utility statements cannot bind the password. PostgreSQL quotes the
		// literal itself, with statement logging disabled for this owned session.
		conn, err := db.Conn(ctx)
		if err != nil {
			return err
		}
		defer conn.Close()
		if _, err := conn.ExecContext(ctx, "SET log_statement = 'none'; SET log_min_error_statement = 'panic'"); err != nil {
			return err
		}
		var statement string
		if err := conn.QueryRowContext(ctx, "SELECT format('ALTER ROLE %I PASSWORD %L', current_user, $1::text)", password).Scan(&statement); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return errors.New("native PostgreSQL password change failed")
		}
	} else {
		// ALTER USER does not support a bound password in MySQL's prepared
		// statement grammar. Disable backslash escapes on this dedicated
		// connection and quote SQL literals; native logs redact ALTER USER.
		conn, err := db.Conn(ctx)
		if err != nil {
			return err
		}
		defer conn.Close()
		if _, err := conn.ExecContext(ctx, "SET SESSION sql_mode = 'NO_BACKSLASH_ESCAPES'"); err != nil {
			return err
		}
		statement := "ALTER USER CURRENT_USER() IDENTIFIED BY '" + strings.ReplaceAll(password, "'", "''") + "'"
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return errors.New("native MySQL password change failed")
		}
	}
	verified, err := Open(ctx, spec.Engine, endpoint, spec.Database, spec.Username, password)
	if err != nil {
		return err
	}
	return verified.Close()
}
