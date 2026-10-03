// Package cloudwatch persists typed metric identities, dimensions and observations.
package cloudwatch

import (
	"context"
	"database/sql"
	"errors"

	domain "stackd/storage/cloudwatch"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/cloudwatch/internal/sqlcgen"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db: db} }

func (r *Repository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error {
		return fn(reader{ctx: ctx, q: sqlcgen.New(tx)})
	})
}

func (r *Repository) Update(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error {
		return fn(writer{reader{ctx: ctx, q: sqlcgen.New(tx)}})
	})
}

func (r *Repository) Attempt(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, tx *sql.Tx) error {
		return fn(writer{reader{ctx: ctx, q: sqlcgen.New(tx)}})
	})
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}

type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }

func (r reader) Metric(k domain.MetricKey) (domain.MetricRecord, error) {
	row, err := r.q.GetMetric(r.ctx, sqlcgen.GetMetricParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region,
		Namespace: k.Namespace, Name: k.Name, Dimensions: k.Dimensions,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.MetricRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.MetricRecord{}, err
	}
	return r.metric(row)
}

func (r reader) metric(row sqlcgen.CloudwatchMetric) (domain.MetricRecord, error) {
	dimensions, err := r.q.ListDimensions(r.ctx, row.ID)
	if err != nil {
		return domain.MetricRecord{}, err
	}
	out := domain.MetricRecord{
		Key: domain.MetricKey{
			Scope:     domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region},
			Namespace: row.Namespace, Name: row.Name, Dimensions: row.Dimensions,
		},
		ID: row.ID, Created: row.Created, PublishedAt: row.PublishedAt,
		Dimensions: make([]domain.Dimension, len(dimensions)),
	}
	for i, dimension := range dimensions {
		out.Dimensions[i] = domain.Dimension{Name: dimension.Name, Value: dimension.Value}
	}
	return out, nil
}

const readPageSize = 256

func (r reader) Metrics(q domain.MetricQuery) ([]domain.MetricRecord, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	out := make([]domain.MetricRecord, 0, min(max(q.Limit, 0), readPageSize))
	if q.Limit <= 0 {
		return out, nil
	}
	params := sqlcgen.ListMetricsParams{
		Partition: q.Partition, AccountID: q.AccountID, Region: q.Region,
		Namespace: q.Namespace, Name: q.Name, PublishedAfter: q.PublishedAfter.UTC(),
		PageLimit: int64(min(q.Limit, readPageSize)),
	}
	if !q.PublishedAfter.IsZero() {
		params.HasPublishedAfter = 1
	}
	if q.After != nil {
		params.HasAfter = 1
		params.AfterNamespace = q.After.Namespace
		params.AfterName = q.After.Name
		params.AfterDimensions = q.After.Dimensions
	}
	for {
		rows, err := r.q.ListMetrics(r.ctx, params)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if err := r.ctx.Err(); err != nil {
				return nil, err
			}
			metric, err := r.metric(row)
			if err != nil {
				return nil, err
			}
			if matchesDimensions(metric.Dimensions, q.Dimensions) {
				out = append(out, metric)
				if len(out) == q.Limit {
					return out, nil
				}
			}
		}
		if len(rows) < int(params.PageLimit) {
			return out, r.ctx.Err()
		}
		last := rows[len(rows)-1]
		params.HasAfter = 1
		params.AfterNamespace = last.Namespace
		params.AfterName = last.Name
		params.AfterDimensions = last.Dimensions
		params.PageLimit = int64(min(q.Limit-len(out), readPageSize))
	}
}

func matchesDimensions(dimensions []domain.Dimension, filters []domain.DimensionFilter) bool {
	for _, filter := range filters {
		matched := false
		for _, dimension := range dimensions {
			if dimension.Name == filter.Name && (filter.Value == nil || dimension.Value == *filter.Value) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func (r reader) Points(q domain.PointQuery, visit func(domain.Point) error) error {
	params := sqlcgen.ListPointsParams{
		MetricID: q.MetricID, StartTime: q.Start, EndTime: q.End, PageLimit: readPageSize,
	}
	// SQLC's SQLite queries return slices. Keyset pages bound memory while the
	// shared read transaction keeps the publication sequence stable.
	for {
		rows, err := r.q.ListPoints(r.ctx, params)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if err := r.ctx.Err(); err != nil {
				return err
			}
			if err := visit(domain.Point{
				Timestamp: row.Timestamp, Unit: row.Unit, Resolution: int32(row.Resolution),
				SampleCount: row.SampleCount, Sum: row.Sum, Minimum: row.Minimum, Maximum: row.Maximum, Raw: row.Raw,
			}); err != nil {
				return err
			}
		}
		if len(rows) < readPageSize {
			return r.ctx.Err()
		}
		params.AfterSequence = rows[len(rows)-1].Sequence
	}
}

func (w writer) PutMetric(metric domain.MetricRecord) error {
	k := metric.Key
	if err := w.q.PutMetric(w.ctx, sqlcgen.PutMetricParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region,
		Namespace: k.Namespace, Name: k.Name, Dimensions: k.Dimensions,
		ID: metric.ID, Created: metric.Created.UTC(), PublishedAt: metric.PublishedAt.UTC(),
	}); err != nil {
		return err
	}
	if err := w.q.DeleteDimensions(w.ctx, metric.ID); err != nil {
		return err
	}
	for _, dimension := range metric.Dimensions {
		if err := w.q.PutDimension(w.ctx, sqlcgen.PutDimensionParams{
			MetricID: metric.ID, Name: dimension.Name, Value: dimension.Value,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) AppendPoints(metricID string, points []domain.Point) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	for _, point := range points {
		if err := w.q.AppendPoint(w.ctx, sqlcgen.AppendPointParams{
			MetricID: metricID, Timestamp: point.Timestamp, Unit: point.Unit, Resolution: int64(point.Resolution),
			SampleCount: point.SampleCount, Sum: point.Sum, Minimum: point.Minimum, Maximum: point.Maximum, Raw: point.Raw,
		}); err != nil {
			return err
		}
	}
	return nil
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Reader = reader{}
var _ domain.Transaction = writer{}
