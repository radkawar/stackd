package rdsdata

import (
	"context"
	"database/sql"
	"time"

	engine "stackd/engine/rds"
	api "stackd/internal/awsapi/rdsdata"
)

type sqlSession interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	PrepareContext(context.Context, string) (*sql.Stmt, error)
}

func (s *Service) session(ctx context.Context, t target, id string, checkDatabase bool, fn func(context.Context, sqlSession) error) error {
	if id != "" {
		lease, err := s.acquire(ctx, id, t, checkDatabase)
		if err != nil {
			return err
		}
		defer s.release(id, lease)
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		stop := context.AfterFunc(lease.ctx, cancel)
		defer stop()
		return fn(ctx, lease.tx)
	}
	db, err := engine.Open(ctx, t.cluster.Engine, t.cluster.Endpoint, t.database, t.username, t.password)
	if err != nil {
		return err
	}
	defer db.Close()
	return fn(ctx, db)
}
func (s *Service) execute(ctx context.Context, in *api.ExecuteStatementRequest) (*api.ExecuteStatementResponse, error) {
	if value(in.Schema) != "" {
		return nil, failure("BadRequestException", "The schema parameter is not supported.")
	}
	if err := validateResultOptions(in); err != nil {
		return nil, err
	}
	target, err := s.resolve(ctx, "ExecuteStatement", value(in.ResourceArn), value(in.SecretArn), value(in.Database))
	if err != nil {
		return nil, err
	}
	statement, err := bindSQL(value(in.Sql), target.cluster.Engine, in.Parameters)
	if err != nil {
		return nil, err
	}
	run := func(ctx context.Context) (*api.ExecuteStatementResponse, error) {
		var out *api.ExecuteStatementResponse
		err := s.session(ctx, target, value(in.TransactionId), in.Database != nil, func(ctx context.Context, session sqlSession) error {
			var err error
			out, err = runStatement(ctx, session, statement, target.cluster.Engine, in)
			return err
		})
		return out, err
	}
	// Only native I/O uses wall time. Transaction idle/hard deadlines remain owned
	// by the injected clock and shared scheduler, not per-session timer goroutines.
	if !enabled(in.ContinueAfterTimeout) {
		ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		return run(ctx)
	}
	// ContinueAfterTimeout owns the native session until completion even after the
	// API deadline. Shutdown still cancels and joins it; no result is fabricated.
	workCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(s.lifetime, cancel)
	type result struct {
		out *api.ExecuteStatementResponse
		err error
	}
	done := make(chan result, 1)
	s.work.Add(1)
	go func() {
		defer s.work.Done()
		defer stop()
		defer cancel()
		out, err := run(workCtx)
		done <- result{out, err}
	}()
	timer := time.NewTimer(45 * time.Second)
	defer timer.Stop()
	select {
	case r := <-done:
		return r.out, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, failure("StatementTimeoutException", "The SQL statement continues executing after the API timeout.")
	}
}
func validateResultOptions(in *api.ExecuteStatementRequest) error {
	if f := value(in.FormatRecordsAs); f != "" && f != "NONE" && f != "JSON" {
		return failure("BadRequestException", "Invalid formatRecordsAs.")
	}
	if in.ResultSetOptions != nil {
		if d := value(in.ResultSetOptions.DecimalReturnType); d != "" && d != "STRING" && d != "DOUBLE_OR_LONG" {
			return failure("BadRequestException", "Invalid decimalReturnType.")
		}
		if l := value(in.ResultSetOptions.LongReturnType); l != "" && l != "LONG" && l != "STRING" {
			return failure("BadRequestException", "Invalid longReturnType.")
		}
	}
	return nil
}
func runStatement(ctx context.Context, session sqlSession, statement boundStatement, engine string, in *api.ExecuteStatementRequest) (*api.ExecuteStatementResponse, error) {
	// pgx uses PostgreSQL's simple protocol for zero-argument Exec, which can
	// admit multiple statements. Force native Parse first: session string modes
	// can differ from the lexical binder, but PostgreSQL Parse always admits at
	// most one statement. Parameterized calls already use extended protocol.
	var prepared *sql.Stmt
	var err error
	if engine == "aurora-postgresql" && len(statement.args) == 0 {
		prepared, err = session.PrepareContext(ctx, statement.sql)
		if err != nil {
			return nil, err
		}
		defer prepared.Close()
	}
	if statement.rows {
		var rows *sql.Rows
		if prepared != nil {
			rows, err = prepared.QueryContext(ctx)
		} else {
			rows, err = session.QueryContext(ctx, statement.sql, statement.args...)
		}
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		return readResults(rows, in, statement.mutation)
	}
	var result sql.Result
	if prepared != nil {
		result, err = prepared.ExecContext(ctx)
	} else {
		result, err = session.ExecContext(ctx, statement.sql, statement.args...)
	}
	if err != nil {
		return nil, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	out := &api.ExecuteStatementResponse{NumberOfRecordsUpdated: new(api.RecordsUpdated(count))}
	if engine == "aurora-mysql" {
		if id, err := result.LastInsertId(); err == nil && id != 0 {
			out.GeneratedFields = api.FieldList{{LongValue: new(api.BoxedLong(id))}}
		}
	}
	return out, nil
}
func (s *Service) batch(ctx context.Context, in *api.BatchExecuteStatementRequest) (*api.BatchExecuteStatementResponse, error) {
	if value(in.Schema) != "" {
		return nil, failure("BadRequestException", "The schema parameter is not supported.")
	}
	target, err := s.resolve(ctx, "BatchExecuteStatement", value(in.ResourceArn), value(in.SecretArn), value(in.Database))
	if err != nil {
		return nil, err
	}
	statements := make([]boundStatement, len(in.ParameterSets))
	for i, parameters := range in.ParameterSets {
		statements[i], err = bindSQL(value(in.Sql), target.cluster.Engine, parameters)
		if err != nil {
			return nil, err
		}
		if statements[i].rows || !statements[i].mutation {
			return nil, failure("BadRequestException", "BatchExecuteStatement requires DML without a result set.")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	out := &api.BatchExecuteStatementResponse{UpdateResults: make(api.UpdateResults, 0, len(statements))}
	err = s.session(ctx, target, value(in.TransactionId), in.Database != nil, func(ctx context.Context, session sqlSession) error {
		for _, statement := range statements {
			result, err := runStatement(ctx, session, statement, target.cluster.Engine, &api.ExecuteStatementRequest{})
			if err != nil {
				return err
			}
			out.UpdateResults = append(out.UpdateResults, api.UpdateResult{GeneratedFields: result.GeneratedFields})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
