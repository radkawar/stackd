package iam

import (
	"cmp"
	"slices"
)

type principalActivityKey struct {
	principalID string
	service     string
	action      string
	region      string
}

func (t *memoryTx) PrincipalActivities(scope Scope) ([]PrincipalActivity, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	rows := make([]PrincipalActivity, 0, len(t.state.principalActivities[scope]))
	for _, row := range t.state.principalActivities[scope] {
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a, b PrincipalActivity) int {
		return cmp.Or(cmp.Compare(a.PrincipalID, b.PrincipalID),
			cmp.Compare(a.ServiceNamespace, b.ServiceNamespace),
			cmp.Compare(a.ActionName, b.ActionName), cmp.Compare(a.Region, b.Region))
	})
	return rows, nil
}

// PutPrincipalActivity retains the newest attempt, including when concurrent
// requests complete in a different order from their authentication times.
func (t *memoryTx) PutPrincipalActivity(scope Scope, activity PrincipalActivity) error {
	if err := t.check(true); err != nil {
		return err
	}
	key := principalActivityKey{activity.PrincipalID, activity.ServiceNamespace, activity.ActionName, activity.Region}
	rows := t.state.principalActivities[scope]
	if previous, ok := rows[key]; ok && previous.LastAuthenticated.After(activity.LastAuthenticated) {
		return nil
	}
	if rows == nil {
		rows = make(map[principalActivityKey]PrincipalActivity)
		t.state.principalActivities[scope] = rows
	}
	rows[key] = activity
	return nil
}
