package apigateway

import (
	"database/sql"
	"time"

	domain "stackd/internal/services/apigateway"
	"stackd/storage/sqlite/apigateway/internal/sqlcgen"
)

func (r reader) usagePlan(row sqlcgen.ApigatewayUsagePlan) (domain.UsagePlanRecord, error) {
	key := domain.PlanKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.PlanID}
	out := domain.UsagePlanRecord{Key: key, Name: row.Name, Description: stringPointer(row.Description)}
	if row.ThrottleBurst.Valid {
		out.Throttle = &domain.UsageThrottle{Burst: int32(row.ThrottleBurst.Int64), Rate: row.ThrottleRate.Float64}
	}
	if row.QuotaPeriod.Valid {
		out.Quota = &domain.UsageQuota{Limit: int32(row.QuotaLimit.Int64), Offset: int32(row.QuotaOffset.Int64), Period: domain.UsagePeriod(row.QuotaPeriod.String)}
	}
	tags, err := r.q.ListUsagePlanTags(r.ctx, sqlcgen.ListUsagePlanTagsParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, PlanID: key.ID})
	if err != nil {
		return domain.UsagePlanRecord{}, err
	}
	if len(tags) != 0 {
		out.Tags = make(map[string]string, len(tags))
		for _, tag := range tags {
			out.Tags[tag.Key] = tag.Value
		}
	}
	stages, err := r.q.ListUsagePlanStages(r.ctx, sqlcgen.ListUsagePlanStagesParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, PlanID: key.ID})
	if err != nil {
		return domain.UsagePlanRecord{}, err
	}
	out.Stages = make([]domain.UsagePlanStage, len(stages))
	for i, stage := range stages {
		out.Stages[i].Key = domain.StageKey{APIKey: domain.APIKey{Scope: key.Scope, ID: stage.ApiID}, Name: stage.StageName}
		if !stage.ThrottlePresent {
			continue
		}
		throttles, err := r.q.ListUsagePlanMethodThrottles(r.ctx, sqlcgen.ListUsagePlanMethodThrottlesParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, PlanID: key.ID, ApiID: stage.ApiID, StageName: stage.StageName})
		if err != nil {
			return domain.UsagePlanRecord{}, err
		}
		out.Stages[i].Throttle = make(map[string]domain.UsageThrottle, len(throttles))
		for _, throttle := range throttles {
			out.Stages[i].Throttle[throttle.MethodPath] = domain.UsageThrottle{Burst: int32(throttle.Burst), Rate: throttle.Rate}
		}
	}
	return out, nil
}

func (r reader) UsagePlan(key domain.PlanKey) (domain.UsagePlanRecord, error) {
	row, err := r.q.GetUsagePlan(r.ctx, sqlcgen.GetUsagePlanParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, PlanID: key.ID})
	if err != nil {
		return domain.UsagePlanRecord{}, missing(err)
	}
	return r.usagePlan(row)
}

func (r reader) usagePlans(rows []sqlcgen.ApigatewayUsagePlan) ([]domain.UsagePlanRecord, error) {
	out := make([]domain.UsagePlanRecord, 0, len(rows))
	for _, row := range rows {
		plan, err := r.usagePlan(row)
		if err != nil {
			return nil, err
		}
		out = append(out, plan)
	}
	return out, nil
}

func (r reader) UsagePlans(scope domain.Scope) ([]domain.UsagePlanRecord, error) {
	rows, err := r.q.ListUsagePlans(r.ctx, sqlcgen.ListUsagePlansParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	return r.usagePlans(rows)
}

func (r reader) UsagePlansForKey(key domain.ClientKey) ([]domain.UsagePlanRecord, error) {
	rows, err := r.q.ListUsagePlansForKey(r.ctx, sqlcgen.ListUsagePlansForKeyParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ClientKeyID: key.ID})
	if err != nil {
		return nil, err
	}
	return r.usagePlans(rows)
}

func (w writer) PutUsagePlan(row domain.UsagePlanRecord) error {
	key := row.Key
	in := sqlcgen.PutUsagePlanParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, PlanID: key.ID, Name: row.Name, Description: stringColumn(row.Description)}
	if row.Throttle != nil {
		in.ThrottleBurst = sql.NullInt64{Int64: int64(row.Throttle.Burst), Valid: true}
		in.ThrottleRate = sql.NullFloat64{Float64: row.Throttle.Rate, Valid: true}
	}
	if row.Quota != nil {
		in.QuotaLimit = sql.NullInt64{Int64: int64(row.Quota.Limit), Valid: true}
		in.QuotaOffset = sql.NullInt64{Int64: int64(row.Quota.Offset), Valid: true}
		in.QuotaPeriod = sql.NullString{String: string(row.Quota.Period), Valid: true}
	}
	if err := w.q.PutUsagePlan(w.ctx, in); err != nil {
		return err
	}
	if err := w.q.DeleteUsagePlanTags(w.ctx, sqlcgen.DeleteUsagePlanTagsParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, PlanID: key.ID}); err != nil {
		return err
	}
	for name, value := range row.Tags {
		if err := w.q.PutUsagePlanTag(w.ctx, sqlcgen.PutUsagePlanTagParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, PlanID: key.ID, Key: name, Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteUsagePlanStages(w.ctx, sqlcgen.DeleteUsagePlanStagesParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, PlanID: key.ID}); err != nil {
		return err
	}
	for i, stage := range row.Stages {
		if err := w.q.PutUsagePlanStage(w.ctx, sqlcgen.PutUsagePlanStageParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, PlanID: key.ID, ApiID: stage.Key.ID, StageName: stage.Key.Name, Ordinal: int64(i), ThrottlePresent: stage.Throttle != nil}); err != nil {
			return err
		}
		for path, throttle := range stage.Throttle {
			if err := w.q.PutUsagePlanMethodThrottle(w.ctx, sqlcgen.PutUsagePlanMethodThrottleParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, PlanID: key.ID, ApiID: stage.Key.ID, StageName: stage.Key.Name, MethodPath: path, Burst: int64(throttle.Burst), Rate: throttle.Rate}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w writer) DeleteUsagePlan(key domain.PlanKey) error {
	return w.q.DeleteUsagePlan(w.ctx, sqlcgen.DeleteUsagePlanParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, PlanID: key.ID})
}

func (r reader) UsagePlanMembership(plan domain.PlanKey, clientKeyID string) (domain.UsagePlanMembership, error) {
	created, err := r.q.GetUsagePlanMembership(r.ctx, sqlcgen.GetUsagePlanMembershipParams{Partition: plan.Partition, AccountID: plan.AccountID, Region: plan.Region, PlanID: plan.ID, ClientKeyID: clientKeyID})
	if err != nil {
		return domain.UsagePlanMembership{}, missing(err)
	}
	return domain.UsagePlanMembership{Plan: plan, ClientKeyID: clientKeyID, Created: created}, nil
}

func (r reader) UsagePlanKeys(plan domain.PlanKey) ([]domain.ClientKeyRecord, error) {
	rows, err := r.q.ListUsagePlanKeys(r.ctx, sqlcgen.ListUsagePlanKeysParams{Partition: plan.Partition, AccountID: plan.AccountID, Region: plan.Region, PlanID: plan.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ClientKeyRecord, 0, len(rows))
	for _, row := range rows {
		key, err := r.clientKey(row)
		if err != nil {
			return nil, err
		}
		out = append(out, key)
	}
	return out, nil
}

func (w writer) PutUsagePlanMembership(row domain.UsagePlanMembership) error {
	key := row.Plan
	return w.q.PutUsagePlanMembership(w.ctx, sqlcgen.PutUsagePlanMembershipParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, PlanID: key.ID, ClientKeyID: row.ClientKeyID, Created: row.Created})
}

func (w writer) DeleteUsagePlanMembership(plan domain.PlanKey, clientKeyID string) error {
	return w.q.DeleteUsagePlanMembership(w.ctx, sqlcgen.DeleteUsagePlanMembershipParams{Partition: plan.Partition, AccountID: plan.AccountID, Region: plan.Region, PlanID: plan.ID, ClientKeyID: clientKeyID})
}

func (r reader) UsageCount(plan domain.PlanKey, clientKeyID string, start, end time.Time) (int64, error) {
	return r.q.UsageCount(r.ctx, sqlcgen.UsageCountParams{Partition: plan.Partition, AccountID: plan.AccountID, Region: plan.Region, PlanID: plan.ID, ClientKeyID: clientKeyID, Start: start, End: end})
}

func (w writer) IncrementUsage(plan domain.PlanKey, clientKeyID string, day time.Time) error {
	return w.q.IncrementUsage(w.ctx, sqlcgen.IncrementUsageParams{Partition: plan.Partition, AccountID: plan.AccountID, Region: plan.Region, PlanID: plan.ID, ClientKeyID: clientKeyID, Day: day})
}
