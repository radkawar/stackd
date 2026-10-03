package glue

import (
	"cmp"
	"maps"
	"slices"
	api "stackd/internal/awsapi/glue"
)

type workflowRunKey struct {
	ResourceKey
	ID string
}
type workflowsMemory struct {
	workflows              map[ResourceKey]WorkflowRecord
	triggers               map[ResourceKey]TriggerRecord
	securityConfigurations map[ResourceKey]SecurityConfigurationRecord
	workflowRuns           map[workflowRunKey]WorkflowRunRecord
}

func initWorkflowsMemory() workflowsMemory {
	return workflowsMemory{map[ResourceKey]WorkflowRecord{}, map[ResourceKey]TriggerRecord{}, map[ResourceKey]SecurityConfigurationRecord{}, map[workflowRunKey]WorkflowRunRecord{}}
}
func cloneWorkflowsMemory(v workflowsMemory) workflowsMemory {
	v.workflows = maps.Clone(v.workflows)
	v.triggers = maps.Clone(v.triggers)
	v.securityConfigurations = maps.Clone(v.securityConfigurations)
	v.workflowRuns = maps.Clone(v.workflowRuns)
	return v
}
func cloneWorkflowRecord(v WorkflowRecord) WorkflowRecord {
	v.Workflow = api.CloneWorkflow(v.Workflow)
	v.Tags = maps.Clone(v.Tags)
	return v
}
func cloneTriggerRecord(v TriggerRecord) TriggerRecord {
	v.Trigger = api.CloneTrigger(v.Trigger)
	v.Tags = maps.Clone(v.Tags)
	if v.NextFire != nil {
		t := *v.NextFire
		v.NextFire = &t
	}
	return v
}
func cloneSecurityConfigurationRecord(v SecurityConfigurationRecord) SecurityConfigurationRecord {
	v.Configuration = api.CloneSecurityConfiguration(v.Configuration)
	return v
}
func cloneWorkflowRunRecord(v WorkflowRunRecord) WorkflowRunRecord {
	v.Properties = maps.Clone(v.Properties)
	v.Nodes = slices.Clone(v.Nodes)
	for i := range v.Nodes {
		v.Nodes[i].Action = api.CloneAction(v.Nodes[i].Action)
		v.Nodes[i].Conditions = slices.Clone(v.Nodes[i].Conditions)
		for j := range v.Nodes[i].Conditions {
			v.Nodes[i].Conditions[j] = api.CloneCondition(v.Nodes[i].Conditions[j])
		}
	}
	if v.Completed != nil {
		t := *v.Completed
		v.Completed = &t
	}
	if v.NextPoll != nil {
		t := *v.NextPoll
		v.NextPoll = &t
	}
	return v
}

func (r memoryReader) Workflow(k ResourceKey) (WorkflowRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return WorkflowRecord{}, err
	}
	v, ok := r.s.workflows[k]
	if !ok {
		return WorkflowRecord{}, ErrNotFound
	}
	return cloneWorkflowRecord(v), nil
}
func (r memoryReader) Workflows(scope Scope) ([]WorkflowRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []WorkflowRecord{}
	for k, v := range r.s.workflows {
		if k.Scope == scope {
			out = append(out, cloneWorkflowRecord(v))
		}
	}
	slices.SortFunc(out, func(a, b WorkflowRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (w memoryWriter) PutWorkflow(v WorkflowRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.workflows[v.Key] = cloneWorkflowRecord(v)
	return nil
}
func (w memoryWriter) DeleteWorkflow(k ResourceKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.workflows, k)
	return nil
}

func (r memoryReader) Trigger(k ResourceKey) (TriggerRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return TriggerRecord{}, err
	}
	v, ok := r.s.triggers[k]
	if !ok {
		return TriggerRecord{}, ErrNotFound
	}
	return cloneTriggerRecord(v), nil
}
func (r memoryReader) Triggers(scope Scope) ([]TriggerRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []TriggerRecord{}
	for k, v := range r.s.triggers {
		if k.Scope == scope {
			out = append(out, cloneTriggerRecord(v))
		}
	}
	slices.SortFunc(out, func(a, b TriggerRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (w memoryWriter) PutTrigger(v TriggerRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.triggers[v.Key] = cloneTriggerRecord(v)
	return nil
}
func (w memoryWriter) DeleteTrigger(k ResourceKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.triggers, k)
	return nil
}

func (r memoryReader) SecurityConfiguration(k ResourceKey) (SecurityConfigurationRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return SecurityConfigurationRecord{}, err
	}
	v, ok := r.s.securityConfigurations[k]
	if !ok {
		return SecurityConfigurationRecord{}, ErrNotFound
	}
	return cloneSecurityConfigurationRecord(v), nil
}
func (r memoryReader) SecurityConfigurations(scope Scope) ([]SecurityConfigurationRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []SecurityConfigurationRecord{}
	for k, v := range r.s.securityConfigurations {
		if k.Scope == scope {
			out = append(out, cloneSecurityConfigurationRecord(v))
		}
	}
	slices.SortFunc(out, func(a, b SecurityConfigurationRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (w memoryWriter) PutSecurityConfiguration(v SecurityConfigurationRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.securityConfigurations[v.Key] = cloneSecurityConfigurationRecord(v)
	return nil
}
func (w memoryWriter) DeleteSecurityConfiguration(k ResourceKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.securityConfigurations, k)
	return nil
}
func (r memoryReader) WorkflowRun(k ResourceKey, id string) (WorkflowRunRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return WorkflowRunRecord{}, err
	}
	v, ok := r.s.workflowRuns[workflowRunKey{k, id}]
	if !ok {
		return WorkflowRunRecord{}, ErrNotFound
	}
	return cloneWorkflowRunRecord(v), nil
}
func (r memoryReader) WorkflowRuns(k ResourceKey) ([]WorkflowRunRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []WorkflowRunRecord{}
	for key, v := range r.s.workflowRuns {
		if key.ResourceKey == k {
			out = append(out, cloneWorkflowRunRecord(v))
		}
	}
	slices.SortFunc(out, func(a, b WorkflowRunRecord) int { return cmp.Or(b.Started.Compare(a.Started), cmp.Compare(a.ID, b.ID)) })
	return out, nil
}
func (w memoryWriter) PutWorkflowRun(v WorkflowRunRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.workflowRuns[workflowRunKey{v.Key, v.ID}] = cloneWorkflowRunRecord(v)
	return nil
}
func (r memoryReader) NextWorkflowRun() (WorkflowRunRecord, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return WorkflowRunRecord{}, false, err
	}
	var out WorkflowRunRecord
	found := false
	for _, v := range r.s.workflowRuns {
		if v.NextPoll != nil && (!found || v.NextPoll.Before(*out.NextPoll) || v.NextPoll.Equal(*out.NextPoll) && v.ID < out.ID) {
			out = v
			found = true
		}
	}
	return cloneWorkflowRunRecord(out), found, nil
}
func (r memoryReader) NextTrigger() (TriggerRecord, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return TriggerRecord{}, false, err
	}
	var out TriggerRecord
	found := false
	for _, v := range r.s.triggers {
		if v.NextFire != nil && (!found || v.NextFire.Before(*out.NextFire) || v.NextFire.Equal(*out.NextFire) && v.Key.ARN("trigger") < out.Key.ARN("trigger")) {
			out = v
			found = true
		}
	}
	return cloneTriggerRecord(out), found, nil
}
