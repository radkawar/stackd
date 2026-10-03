package logs

import (
	"database/sql"

	domain "stackd/storage/logs"
	"stackd/storage/sqlite/logs/internal/sqlcgen"
)

func (r reader) metricFilter(v sqlcgen.GetMetricFilterRow) (domain.MetricFilterRecord, error) {
	out := domain.MetricFilterRecord{
		Key: domain.MetricFilterKey{GroupID: v.GroupID, Name: v.Name}, GroupName: v.GroupName,
		Pattern: v.Pattern, MetricNamespace: v.MetricNamespace, MetricName: v.MetricName,
		MetricValue: v.MetricValue, Unit: v.Unit, ApplyOnTransformedLogs: v.ApplyOnTransformedLogs != 0,
		FieldSelection: v.FieldSelection, Created: v.Created,
	}
	if v.DefaultValue.Valid {
		out.DefaultValue = &v.DefaultValue.Float64
	}
	dimensions, err := r.q.MetricFilterDimensions(r.ctx, sqlcgen.MetricFilterDimensionsParams{GroupID: v.GroupID, FilterName: v.Name})
	if err != nil {
		return domain.MetricFilterRecord{}, err
	}
	out.Dimensions = make(map[string]string, len(dimensions))
	for _, dimension := range dimensions {
		out.Dimensions[dimension.Name] = dimension.Value
	}
	out.EmitSystemFieldDimensions, err = r.q.MetricFilterSystemFields(r.ctx, sqlcgen.MetricFilterSystemFieldsParams{GroupID: v.GroupID, FilterName: v.Name})
	return out, err
}

func (r reader) MetricFilter(k domain.MetricFilterKey) (domain.MetricFilterRecord, error) {
	v, err := r.q.GetMetricFilter(r.ctx, sqlcgen.GetMetricFilterParams{GroupID: k.GroupID, Name: k.Name})
	if err != nil {
		return domain.MetricFilterRecord{}, notFound(err)
	}
	return r.metricFilter(v)
}

func (r reader) MetricFilters(q domain.MetricFilterQuery) ([]domain.MetricFilterRecord, error) {
	rows, err := r.q.ListMetricFilters(r.ctx, sqlcgen.ListMetricFiltersParams{
		Partition: q.Partition, AccountID: q.AccountID, Region: q.Region, GroupID: q.GroupID,
		Prefix: q.Prefix, MetricName: q.MetricName, MetricNamespace: q.MetricNamespace,
		AfterName: q.AfterName, AfterGroupName: q.AfterGroupName, PageLimit: int64(q.Limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.MetricFilterRecord, 0, len(rows))
	for _, v := range rows {
		filter, err := r.metricFilter(sqlcgen.GetMetricFilterRow(v))
		if err != nil {
			return nil, err
		}
		out = append(out, filter)
	}
	return out, nil
}

func (w writer) PutMetricFilter(v domain.MetricFilterRecord) error {
	defaultValue := sql.NullFloat64{}
	if v.DefaultValue != nil {
		defaultValue = sql.NullFloat64{Float64: *v.DefaultValue, Valid: true}
	}
	transformed := int64(0)
	if v.ApplyOnTransformedLogs {
		transformed = 1
	}
	if err := w.q.PutMetricFilter(w.ctx, sqlcgen.PutMetricFilterParams{
		GroupID: v.Key.GroupID, Name: v.Key.Name, Pattern: v.Pattern,
		MetricNamespace: v.MetricNamespace, MetricName: v.MetricName, MetricValue: v.MetricValue,
		Unit: v.Unit, DefaultValue: defaultValue, ApplyOnTransformedLogs: transformed,
		FieldSelection: v.FieldSelection, Created: v.Created,
	}); err != nil {
		return err
	}
	if err := w.q.DeleteMetricFilterDimensions(w.ctx, sqlcgen.DeleteMetricFilterDimensionsParams{GroupID: v.Key.GroupID, FilterName: v.Key.Name}); err != nil {
		return err
	}
	for name, value := range v.Dimensions {
		if err := w.q.PutMetricFilterDimension(w.ctx, sqlcgen.PutMetricFilterDimensionParams{GroupID: v.Key.GroupID, FilterName: v.Key.Name, Name: name, Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteMetricFilterSystemFields(w.ctx, sqlcgen.DeleteMetricFilterSystemFieldsParams{GroupID: v.Key.GroupID, FilterName: v.Key.Name}); err != nil {
		return err
	}
	for i, field := range v.EmitSystemFieldDimensions {
		if err := w.q.PutMetricFilterSystemField(w.ctx, sqlcgen.PutMetricFilterSystemFieldParams{GroupID: v.Key.GroupID, FilterName: v.Key.Name, Ordinal: int64(i), Field: field}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteMetricFilter(k domain.MetricFilterKey) error {
	return w.q.DeleteMetricFilter(w.ctx, sqlcgen.DeleteMetricFilterParams{GroupID: k.GroupID, Name: k.Name})
}
