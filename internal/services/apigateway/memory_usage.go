package apigateway

import (
	"cmp"
	"maps"
	"slices"
	"time"
)

func cloneUsagePlan(row UsagePlanRecord) UsagePlanRecord {
	if row.Description != nil {
		row.Description = new(*row.Description)
	}
	if row.Throttle != nil {
		row.Throttle = new(*row.Throttle)
	}
	if row.Quota != nil {
		row.Quota = new(*row.Quota)
	}
	row.Tags = maps.Clone(row.Tags)
	row.Stages = slices.Clone(row.Stages)
	for i := range row.Stages {
		row.Stages[i].Throttle = maps.Clone(row.Stages[i].Throttle)
	}
	return row
}

func (r memoryReader) UsagePlan(key PlanKey) (UsagePlanRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return UsagePlanRecord{}, err
	}
	row, ok := r.s.usagePlans[key]
	if !ok {
		return UsagePlanRecord{}, ErrNotFound
	}
	return cloneUsagePlan(row), nil
}

func (r memoryReader) UsagePlans(scope Scope) ([]UsagePlanRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]UsagePlanRecord, 0)
	for key, row := range r.s.usagePlans {
		if key.Scope == scope {
			rows = append(rows, cloneUsagePlan(row))
		}
	}
	slices.SortFunc(rows, func(a, b UsagePlanRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return rows, nil
}

func (r memoryReader) UsagePlansForKey(key ClientKey) ([]UsagePlanRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	memberships := r.s.usageMemberships[key]
	rows := make([]UsagePlanRecord, 0, len(memberships))
	for plan := range memberships {
		rows = append(rows, cloneUsagePlan(r.s.usagePlans[plan]))
	}
	slices.SortFunc(rows, func(a, b UsagePlanRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return rows, nil
}

func (r memoryReader) UsagePlanMembership(plan PlanKey, clientKeyID string) (UsagePlanMembership, error) {
	if err := r.tx.Check(false); err != nil {
		return UsagePlanMembership{}, err
	}
	row, ok := r.s.usageMemberships[ClientKey{Scope: plan.Scope, ID: clientKeyID}][plan]
	if !ok {
		return UsagePlanMembership{}, ErrNotFound
	}
	return row, nil
}

func (r memoryReader) UsagePlanKeys(plan PlanKey) ([]ClientKeyRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]ClientKeyRecord, 0)
	for key, memberships := range r.s.usageMemberships {
		if _, ok := memberships[plan]; ok {
			rows = append(rows, cloneClientKey(r.s.clientKeys[key]))
		}
	}
	slices.SortFunc(rows, func(a, b ClientKeyRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return rows, nil
}

func (r memoryReader) UsageCount(plan PlanKey, clientKeyID string, start, end time.Time) (int64, error) {
	if err := r.tx.Check(false); err != nil {
		return 0, err
	}
	days := r.s.usageDays[ClientKey{Scope: plan.Scope, ID: clientKeyID}][plan]
	var used int64
	for day := start; day.Before(end); day = day.AddDate(0, 0, 1) {
		used += days[day]
	}
	return used, nil
}

func (w memoryWriter) PutUsagePlan(row UsagePlanRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.usagePlans[row.Key] = cloneUsagePlan(row)
	return nil
}

func (w memoryWriter) DeleteUsagePlan(plan PlanKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.usagePlans, plan)
	for key, memberships := range w.s.usageMemberships {
		if _, ok := memberships[plan]; ok {
			memberships = maps.Clone(memberships)
			delete(memberships, plan)
			if len(memberships) == 0 {
				delete(w.s.usageMemberships, key)
			} else {
				w.s.usageMemberships[key] = memberships
			}
		}
	}
	for key, plans := range w.s.usageDays {
		if _, ok := plans[plan]; ok {
			plans = maps.Clone(plans)
			delete(plans, plan)
			if len(plans) == 0 {
				delete(w.s.usageDays, key)
			} else {
				w.s.usageDays[key] = plans
			}
		}
	}
	return nil
}

func (w memoryWriter) PutUsagePlanMembership(row UsagePlanMembership) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	key := ClientKey{Scope: row.Plan.Scope, ID: row.ClientKeyID}
	memberships := maps.Clone(w.s.usageMemberships[key])
	if memberships == nil {
		memberships = make(map[PlanKey]UsagePlanMembership)
	}
	memberships[row.Plan] = row
	w.s.usageMemberships[key] = memberships
	return nil
}

func (w memoryWriter) DeleteUsagePlanMembership(plan PlanKey, clientKeyID string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	key := ClientKey{Scope: plan.Scope, ID: clientKeyID}
	memberships := maps.Clone(w.s.usageMemberships[key])
	delete(memberships, plan)
	if len(memberships) == 0 {
		delete(w.s.usageMemberships, key)
	} else {
		w.s.usageMemberships[key] = memberships
	}
	return nil
}

func (w memoryWriter) IncrementUsage(plan PlanKey, clientKeyID string, day time.Time) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	key := ClientKey{Scope: plan.Scope, ID: clientKeyID}
	plans := maps.Clone(w.s.usageDays[key])
	if plans == nil {
		plans = make(map[PlanKey]map[time.Time]int64)
	}
	days := maps.Clone(plans[plan])
	if days == nil {
		days = make(map[time.Time]int64)
	}
	days[day]++
	plans[plan] = days
	w.s.usageDays[key] = plans
	return nil
}

func (w memoryWriter) deleteUsageStages(matches func(StageKey) bool) {
	for key, client := range w.s.clientKeys {
		if !slices.ContainsFunc(client.StageKeys, matches) {
			continue
		}
		client.StageKeys = slices.DeleteFunc(slices.Clone(client.StageKeys), matches)
		w.s.clientKeys[key] = client
	}
	for key, plan := range w.s.usagePlans {
		if !slices.ContainsFunc(plan.Stages, func(stage UsagePlanStage) bool { return matches(stage.Key) }) {
			continue
		}
		plan.Stages = slices.DeleteFunc(slices.Clone(plan.Stages), func(stage UsagePlanStage) bool { return matches(stage.Key) })
		w.s.usagePlans[key] = plan
	}
}
