package rds

import "context"

// Statistics samples the existing running database; it never starts one. The
// monitoring connection is excluded from the returned native client count.
func (d *Docker) Statistics(ctx context.Context, spec Specification) (Statistics, error) {
	if err := validateSpecification(spec); err != nil {
		return Statistics{}, err
	}
	if err := d.lock(ctx); err != nil {
		return Statistics{}, err
	}
	defer d.unlock()
	state, err := d.inspect(ctx, d.name(spec.ID, "database"))
	if err != nil {
		return Statistics{}, err
	}
	if err := d.checkDatabase(state, spec); err != nil {
		return Statistics{}, err
	}
	endpoint, err := state.endpoint(d.endpointHost, spec.Engine)
	if err != nil {
		return Statistics{}, err
	}
	db, err := Open(ctx, spec.Engine, endpoint, spec.Database, spec.Username, spec.Password)
	if err != nil {
		return Statistics{}, err
	}
	defer db.Close()
	var result Statistics
	kind, _ := family(spec.Engine)
	if kind == "postgres" {
		err = db.QueryRowContext(ctx, "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'client backend' AND pid <> pg_backend_pid()").Scan(&result.Connections)
	} else {
		var name string
		err = db.QueryRowContext(ctx, "SHOW GLOBAL STATUS LIKE 'Threads_connected'").Scan(&name, &result.Connections)
		if err == nil {
			result.Connections--
		}
	}
	return result, err
}
