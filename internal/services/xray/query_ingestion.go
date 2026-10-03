package xray

import (
	"slices"
	"time"
)

type traceUpdate struct {
	Key      TraceKey
	Revision int64
}

// indexTraces runs after all changed documents in a command have been stored.
// Both the trace revision and each group's first membership share that command's
// transaction; replacing an in-progress document does not leave an old receipt.
func (s *Service) indexTraces(tx Transaction, updates []traceUpdate) error {
	if len(updates) == 0 {
		return nil
	}
	scope := scopeFor(tx.Context())
	groups, err := tx.Groups(scope)
	if err != nil {
		return err
	}
	foundDefault := false
	for _, group := range groups {
		foundDefault = foundDefault || group.Key.Name == "Default"
	}
	if !foundDefault {
		group := defaultGroup(scope)
		if err := tx.PutGroup(group); err != nil {
			return err
		}
		groups = append(groups, group)
	}
	expressions := groupExpressions(groups)
	filters := make([]*traceFilter, len(groups))
	for i, group := range groups {
		if group.Key.Name == "Default" {
			continue
		}
		filters[i], err = compileTraceFilter(group.FilterExpression, expressions)
		if err != nil {
			return err
		}
	}
	now := s.clock.Now()
	updated := now.UTC().Truncate(time.Second)
	for _, update := range updates {
		key := update.Key
		rows, err := tx.TraceSegments(key)
		if err != nil {
			return err
		}
		rows = liveTraceSegments(rows, now)
		if len(rows) == 0 {
			continue
		}
		view, err := projectTrace(key, rows)
		if err != nil {
			return err
		}
		if err := tx.PutTrace(TraceRecord{Key: key, Start: view.start, End: max(view.start, view.end), Updated: updated, Revision: update.Revision}); err != nil {
			return err
		}
		for i, group := range groups {
			if filters[i] != nil && !filters[i].match(view, nil, nil) {
				continue
			}
			inserted, err := tx.AddGroupTrace(group.Key, key, GroupMembership{Version: group.Version, Admitted: now, AdmittedRevision: update.Revision})
			if err != nil {
				return err
			}
			if inserted {
				if err := s.recordGroupMatch(tx, group); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func liveTraceSegments(rows []SegmentRecord, now time.Time) []SegmentRecord {
	return slices.DeleteFunc(rows, func(row SegmentRecord) bool {
		return !now.Before(row.Received.Add(traceRetention))
	})
}
