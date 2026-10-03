package resourcegroups

import (
	"errors"
	"maps"
	"slices"
	"strings"
)

func cloneTask(t TagSyncTask) TagSyncTask {
	q := cloneStoredGroup(Group{Query: &t.Query}).Query
	t.Query = *q
	return t
}
func cloneSnapshot(s LifecycleSnapshot) LifecycleSnapshot {
	s.Group = cloneStoredGroup(s.Group)
	s.Members = slices.Clone(s.Members)
	return s
}
func (r memoryReader) TagSyncTasks() ([]TagSyncTask, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := make([]TagSyncTask, 0, len(r.state.tasks))
	for _, t := range r.state.tasks {
		out = append(out, cloneTask(t))
	}
	slices.SortFunc(out, func(a, b TagSyncTask) int { return strings.Compare(a.ARN, b.ARN) })
	return out, nil
}
func (w memoryWriter) PutTagSyncTask(t TagSyncTask) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if g, ok := w.state.groups[t.GroupARN]; !ok || g.Scope != t.Scope {
		return errors.New("tag-sync application group does not exist")
	}
	w.state.tasks[t.ARN] = cloneTask(t)
	return nil
}
func (w memoryWriter) DeleteTagSyncTask(arn string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.state.tasks, arn)
	delete(w.state.applied, arn)
	return nil
}
func (r memoryReader) AppliedMemberships(arn string) ([]AppliedMembership, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := slices.Collect(maps.Values(r.state.applied[arn]))
	slices.SortFunc(rows, func(a, b AppliedMembership) int { return strings.Compare(a.ResourceARN, b.ResourceARN) })
	return rows, nil
}
func (w memoryWriter) PutAppliedMembership(m AppliedMembership) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, ok := w.state.tasks[m.TaskARN]; !ok {
		return errors.New("tag-sync task does not exist")
	}
	rows := maps.Clone(w.state.applied[m.TaskARN])
	if rows == nil {
		rows = map[string]AppliedMembership{}
	}
	rows[m.ResourceARN] = m
	w.state.applied[m.TaskARN] = rows
	return nil
}
func (w memoryWriter) DeleteAppliedMembership(task, arn string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	rows := maps.Clone(w.state.applied[task])
	delete(rows, arn)
	w.state.applied[task] = rows
	return nil
}
func (r memoryReader) LifecycleAccounts() ([]LifecycleAccount, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := slices.Collect(maps.Values(r.state.accounts))
	slices.SortFunc(rows, func(a, b LifecycleAccount) int {
		return strings.Compare(lifecycleJobKey(a.Scope), lifecycleJobKey(b.Scope))
	})
	return rows, nil
}
func (w memoryWriter) PutLifecycleAccount(a LifecycleAccount) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.state.accounts[a.Scope] = a
	return nil
}
func (r memoryReader) LifecycleSnapshots(scope Scope) ([]LifecycleSnapshot, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []LifecycleSnapshot{}
	for _, s := range r.state.snapshots {
		if s.Group.Scope == scope {
			out = append(out, cloneSnapshot(s))
		}
	}
	slices.SortFunc(out, func(a, b LifecycleSnapshot) int { return strings.Compare(a.Group.ARN, b.Group.ARN) })
	return out, nil
}
func (w memoryWriter) PutLifecycleSnapshot(s LifecycleSnapshot) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.state.snapshots[s.Group.ARN] = cloneSnapshot(s)
	return nil
}
func (w memoryWriter) DeleteLifecycleSnapshot(arn string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.state.snapshots, arn)
	return nil
}
