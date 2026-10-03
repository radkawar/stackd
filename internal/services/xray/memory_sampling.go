package xray

import (
	"cmp"
	"maps"
	"slices"
	"time"
)

func cloneSamplingRule(v SamplingRuleRecord) SamplingRuleRecord {
	v.Attributes = maps.Clone(v.Attributes)
	v.Tags = maps.Clone(v.Tags)
	if v.RateBoost != nil {
		boost := *v.RateBoost
		if boost.CooldownWindowMinutes != nil {
			boost.CooldownWindowMinutes = new(*boost.CooldownWindowMinutes)
		}
		if boost.MaxRate != nil {
			boost.MaxRate = new(*boost.MaxRate)
		}
		v.RateBoost = &boost
	}
	return v
}

func (r memoryReader) SamplingRule(key SamplingRuleKey) (SamplingRuleRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return SamplingRuleRecord{}, err
	}
	row, ok := r.s.samplingRules[key]
	if !ok {
		return SamplingRuleRecord{}, ErrNotFound
	}
	return cloneSamplingRule(row), nil
}

func (r memoryReader) SamplingRules(scope Scope) ([]SamplingRuleRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]SamplingRuleRecord, 0)
	for key, row := range r.s.samplingRules {
		if key.Scope == scope {
			rows = append(rows, cloneSamplingRule(row))
		}
	}
	slices.SortFunc(rows, func(a, b SamplingRuleRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return rows, nil
}

func (r memoryReader) SamplingClients(key SamplingRuleKey) ([]SamplingClientRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]SamplingClientRecord, 0)
	for k, row := range r.s.samplingClients {
		if k.Rule == key {
			rows = append(rows, row)
		}
	}
	slices.SortFunc(rows, func(a, b SamplingClientRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return rows, nil
}

func (r memoryReader) SamplingStatistics(key SamplingRuleKey) ([]SamplingStatisticRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]SamplingStatisticRecord, 0)
	for k, row := range r.s.samplingStatistics {
		if k.Rule == key {
			rows = append(rows, row)
		}
	}
	slices.SortFunc(rows, func(a, b SamplingStatisticRecord) int {
		if order := a.Key.Window.Compare(b.Key.Window); order != 0 {
			return order
		}
		return cmp.Compare(a.Key.ClientID, b.Key.ClientID)
	})
	return rows, nil
}

func (r memoryReader) SamplingModified(scope Scope) (time.Time, error) {
	if err := r.tx.Check(false); err != nil {
		return time.Time{}, err
	}
	if when, ok := r.s.samplingModified[scope]; ok {
		return when, nil
	}
	return time.Unix(0, 0).UTC(), nil
}

func (r memoryReader) EarliestSamplingReceipt() (time.Time, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return time.Time{}, false, err
	}
	var earliest time.Time
	found := false
	include := func(at time.Time) {
		if !found || at.Before(earliest) {
			earliest, found = at, true
		}
	}
	for _, row := range r.s.samplingStatistics {
		include(row.Received)
	}
	for _, row := range r.s.samplingClients {
		include(row.LastSeen)
	}
	for _, row := range r.s.samplingBoostStatistics {
		include(row.Received)
	}
	return earliest, found, nil
}

func (w memoryWriter) PutSamplingRule(row SamplingRuleRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.samplingRules[row.Key] = cloneSamplingRule(row)
	return nil
}

func (w memoryWriter) DeleteSamplingRule(key SamplingRuleKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.samplingRules, key)
	delete(w.s.samplingBoosts, key)
	for k := range w.s.samplingClients {
		if k.Rule == key {
			delete(w.s.samplingClients, k)
		}
	}
	for k := range w.s.samplingStatistics {
		if k.Rule == key {
			delete(w.s.samplingStatistics, k)
		}
	}
	for k := range w.s.samplingBoostStatistics {
		if k.Rule == key {
			delete(w.s.samplingBoostStatistics, k)
		}
	}
	return nil
}

func (w memoryWriter) PutSamplingClient(row SamplingClientRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.samplingClients[row.Key] = row
	return nil
}

func (w memoryWriter) PutSamplingStatistic(row SamplingStatisticRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.samplingStatistics[row.Key] = row
	return nil
}

func (w memoryWriter) SetSamplingModified(scope Scope, when time.Time) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.samplingModified[scope] = when
	return nil
}

func (w memoryWriter) DeleteExpiredSamplingState(cutoff time.Time) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for key, row := range w.s.samplingStatistics {
		if !row.Received.After(cutoff) {
			delete(w.s.samplingStatistics, key)
		}
	}
	for key, row := range w.s.samplingClients {
		if !row.LastSeen.After(cutoff) {
			delete(w.s.samplingClients, key)
		}
	}
	for key, row := range w.s.samplingBoostStatistics {
		if !row.Received.After(cutoff) {
			delete(w.s.samplingBoostStatistics, key)
		}
	}
	return nil
}

func (r memoryReader) SamplingBoostStatistics(key SamplingRuleKey) ([]SamplingBoostStatisticRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]SamplingBoostStatisticRecord, 0)
	for k, row := range r.s.samplingBoostStatistics {
		if k.Rule == key {
			rows = append(rows, row)
		}
	}
	slices.SortFunc(rows, func(a, b SamplingBoostStatisticRecord) int {
		if order := a.Key.Window.Compare(b.Key.Window); order != 0 {
			return order
		}
		return cmp.Compare(a.Key.ServiceName, b.Key.ServiceName)
	})
	return rows, nil
}

func (r memoryReader) SamplingBoost(key SamplingRuleKey) (SamplingBoostRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return SamplingBoostRecord{}, err
	}
	row, ok := r.s.samplingBoosts[key]
	if !ok {
		return SamplingBoostRecord{}, ErrNotFound
	}
	return row, nil
}

func (w memoryWriter) PutSamplingBoostStatistic(row SamplingBoostStatisticRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.samplingBoostStatistics[row.Key] = row
	return nil
}

func (w memoryWriter) PutSamplingBoost(row SamplingBoostRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.samplingBoosts[row.Key] = row
	return nil
}
