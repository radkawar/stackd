package guardduty

import (
	"database/sql"

	api "stackd/internal/awsapi/guardduty"
	domain "stackd/storage/guardduty"
	"stackd/storage/sqlite/guardduty/internal/sqlcgen"
)

func (r reader) Filter(sc domain.Scope, detector, name string) (domain.Filter, error) {
	row, err := r.q.GetFilter(r.ctx, sqlcgen.GetFilterParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector, Name: name})
	if err != nil {
		return domain.Filter{}, notFound(err)
	}
	return r.filter(row)
}
func (r reader) Filters(sc domain.Scope, detector string) ([]domain.Filter, error) {
	rows, err := r.q.ListFilters(r.ctx, sqlcgen.ListFiltersParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector})
	if err != nil {
		return nil, err
	}
	var out []domain.Filter
	if len(rows) > 0 {
		out = make([]domain.Filter, 0, len(rows))
	}
	for _, row := range rows {
		v, err := r.filter(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) filter(row sqlcgen.GuarddutyFilter) (domain.Filter, error) {
	v := domain.Filter{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, DetectorID: row.DetectorID, Name: row.Name, ARN: row.Arn, Action: row.Action, Description: row.Description, DescriptionSet: row.DescriptionSet, ClientToken: row.ClientToken, Rank: int32(row.Rank), Version: int32(row.Version), Created: row.Created, Updated: row.Updated}
	if row.TagsPresent {
		v.Tags = map[string]string{}
	}
	tags, err := r.q.ListFilterTags(r.ctx, v.ARN)
	if err != nil {
		return v, err
	}
	for _, tag := range tags {
		v.Tags[tag.TagKey] = tag.TagValue
	}
	if row.CriteriaPresent {
		v.Criteria.Criterion = api.Criterion{}
	}
	conditions, err := r.q.ListFilterConditions(r.ctx, v.ARN)
	if err != nil {
		return v, err
	}
	values, err := r.q.ListFilterConditionValues(r.ctx, v.ARN)
	if err != nil {
		return v, err
	}
	next := 0
	for _, c := range conditions {
		condition := api.Condition{
			GreaterThan: integerPointer[api.Long](c.GreaterThan), GreaterThanOrEqual: integerPointer[api.Long](c.GreaterThanOrEqual),
			LessThan: integerPointer[api.Long](c.LessThan), LessThanOrEqual: integerPointer[api.Long](c.LessThanOrEqual),
			Gt: integerPointer[api.Integer](c.Gt), Gte: integerPointer[api.Integer](c.Gte), Lt: integerPointer[api.Integer](c.Lt), Lte: integerPointer[api.Integer](c.Lte),
		}
		if c.EqPresent {
			condition.Eq = api.Eq{}
		}
		if c.EqualsPresent {
			condition.Equals = api.Equals{}
		}
		if c.NeqPresent {
			condition.Neq = api.Neq{}
		}
		if c.NotEqualsPresent {
			condition.NotEquals = api.NotEquals{}
		}
		if c.MatchesPresent {
			condition.Matches = api.Matches{}
		}
		if c.NotMatchesPresent {
			condition.NotMatches = api.NotMatches{}
		}
		for next < len(values) && values[next].Criterion == c.Criterion {
			value := values[next]
			switch value.Operator {
			case "eq":
				condition.Eq = append(condition.Eq, api.String(value.Value))
			case "equals":
				condition.Equals = append(condition.Equals, api.String(value.Value))
			case "neq":
				condition.Neq = append(condition.Neq, api.String(value.Value))
			case "notEquals":
				condition.NotEquals = append(condition.NotEquals, api.String(value.Value))
			case "matches":
				condition.Matches = append(condition.Matches, api.Match(value.Value))
			case "notMatches":
				condition.NotMatches = append(condition.NotMatches, api.NotMatch(value.Value))
			}
			next++
		}
		v.Criteria.Criterion[api.String(c.Criterion)] = condition
	}
	return v, nil
}
func (w writer) PutFilter(v domain.Filter) error {
	if _, err := w.q.GetDetector(w.ctx, sqlcgen.GetDetectorParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ID: v.DetectorID}); err != nil {
		return notFound(err)
	}
	err := w.q.PutFilter(w.ctx, sqlcgen.PutFilterParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, DetectorID: v.DetectorID, Name: v.Name, Arn: v.ARN, Action: v.Action, Description: v.Description, DescriptionSet: v.DescriptionSet, ClientToken: v.ClientToken, Rank: int64(v.Rank), Version: int64(v.Version), Created: v.Created, Updated: v.Updated, CriteriaPresent: v.Criteria.Criterion != nil, TagsPresent: v.Tags != nil})
	if err != nil {
		return err
	}
	if err := w.q.DeleteFilterTags(w.ctx, v.ARN); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutFilterTag(w.ctx, sqlcgen.PutFilterTagParams{Arn: v.ARN, TagKey: key, TagValue: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteFilterConditions(w.ctx, v.ARN); err != nil {
		return err
	}
	for key, c := range v.Criteria.Criterion {
		err := w.q.PutFilterCondition(w.ctx, sqlcgen.PutFilterConditionParams{Arn: v.ARN, Criterion: string(key), GreaterThan: nullableInteger(c.GreaterThan), GreaterThanOrEqual: nullableInteger(c.GreaterThanOrEqual), LessThan: nullableInteger(c.LessThan), LessThanOrEqual: nullableInteger(c.LessThanOrEqual), Gt: nullableInteger(c.Gt), Gte: nullableInteger(c.Gte), Lt: nullableInteger(c.Lt), Lte: nullableInteger(c.Lte), EqPresent: c.Eq != nil, EqualsPresent: c.Equals != nil, NeqPresent: c.Neq != nil, NotEqualsPresent: c.NotEquals != nil, MatchesPresent: c.Matches != nil, NotMatchesPresent: c.NotMatches != nil})
		if err != nil {
			return err
		}
		if err := putConditionValues(w, v.ARN, string(key), "eq", c.Eq); err != nil {
			return err
		}
		if err := putConditionValues(w, v.ARN, string(key), "equals", c.Equals); err != nil {
			return err
		}
		if err := putConditionValues(w, v.ARN, string(key), "neq", c.Neq); err != nil {
			return err
		}
		if err := putConditionValues(w, v.ARN, string(key), "notEquals", c.NotEquals); err != nil {
			return err
		}
		if err := putConditionValues(w, v.ARN, string(key), "matches", c.Matches); err != nil {
			return err
		}
		if err := putConditionValues(w, v.ARN, string(key), "notMatches", c.NotMatches); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteFilter(sc domain.Scope, detector, name string) error {
	return w.q.DeleteFilter(w.ctx, sqlcgen.DeleteFilterParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector, Name: name})
}
func putConditionValues[T ~string](w writer, arn, key, operator string, values []T) error {
	for i, value := range values {
		if err := w.q.PutFilterConditionValue(w.ctx, sqlcgen.PutFilterConditionValueParams{Arn: arn, Criterion: key, Operator: operator, Position: int64(i), Value: string(value)}); err != nil {
			return err
		}
	}
	return nil
}
func nullableInteger[T ~int32 | ~int64](v *T) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*v), Valid: true}
}
func integerPointer[T ~int32 | ~int64](v sql.NullInt64) *T {
	if !v.Valid {
		return nil
	}
	value := T(v.Int64)
	return &value
}
