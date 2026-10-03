package glue

import (
	"database/sql"
	api "stackd/internal/awsapi/glue"
	domain "stackd/internal/services/glue"
	"stackd/storage/sqlite/glue/internal/sqlcgen"
	"time"
)

func (r reader) WorkflowRun(k domain.ResourceKey, id string) (domain.WorkflowRunRecord, error) {
	row, err := r.q.WFWorkflowRunGet(r.ctx, sqlcgen.WFWorkflowRunGetParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, RunID: id})
	if err != nil {
		return domain.WorkflowRunRecord{}, wfMissing(err)
	}
	return r.wfRun(row)
}
func (r reader) WorkflowRuns(k domain.ResourceKey) ([]domain.WorkflowRunRecord, error) {
	rows, err := r.q.WFWorkflowRunList(r.ctx, sqlcgen.WFWorkflowRunListParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.WorkflowRunRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.wfRun(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) NextWorkflowRun() (domain.WorkflowRunRecord, bool, error) {
	row, err := r.q.WFNextRun(r.ctx)
	if err == sql.ErrNoRows {
		return domain.WorkflowRunRecord{}, false, nil
	}
	if err != nil {
		return domain.WorkflowRunRecord{}, false, err
	}
	v, err := r.wfRun(row)
	return v, err == nil, err
}
func (r reader) wfRun(row sqlcgen.GlueWorkflowRun) (domain.WorkflowRunRecord, error) {
	k := wfKey(row.Partition, row.AccountID, row.Region, row.Name)
	id := row.RunID
	v := domain.WorkflowRunRecord{Key: k, ID: id, PreviousRunID: row.PreviousRunID, RootTrigger: row.RootTrigger, Status: row.Status, Error: row.Error, Started: time.Unix(0, row.Started).UTC(), Completed: wfTimePtr(row.Completed), NextPoll: wfTimePtr(row.NextPoll), Properties: api.WorkflowRunProperties{}, Nodes: []domain.WorkflowNodeRun{}}
	props, err := r.q.WFWorkflowRunPropertyList(r.ctx, sqlcgen.WFWorkflowRunPropertyListParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, RunID: id})
	if err != nil {
		return v, err
	}
	for _, p := range props {
		v.Properties[api.IdString(p.ItemKey)] = api.GenericString(p.ItemValue)
	}
	nodes, err := r.q.WFWorkflowNodeList(r.ctx, sqlcgen.WFWorkflowNodeListParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, RunID: id})
	if err != nil {
		return v, err
	}
	for _, n := range nodes {
		node := domain.WorkflowNodeRun{ID: n.NodeID, Kind: n.Kind, Name: n.NodeName, TriggerName: n.TriggerName, TriggerType: n.TriggerType, TriggerState: n.TriggerState, TriggerDescription: n.TriggerDescription, TriggerSchedule: n.TriggerSchedule, RunID: n.ChildRunID, State: n.State, Error: n.Error, Logical: n.Logical, Activated: n.Activated, Action: wfAction(n.JobName, n.CrawlerName, n.SecurityConfiguration, n.Timeout, n.NotificationDelay)}
		args, err := r.q.WFWorkflowNodeArgumentList(r.ctx, sqlcgen.WFWorkflowNodeArgumentListParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, RunID: id, NodeID: n.NodeID})
		if err != nil {
			return v, err
		}
		if len(args) > 0 {
			node.Action.Arguments = api.GenericMap{}
			for _, a := range args {
				node.Action.Arguments[api.GenericString(a.ItemKey)] = api.GenericString(a.ItemValue)
			}
		}
		conditions, err := r.q.WFWorkflowNodeConditionList(r.ctx, sqlcgen.WFWorkflowNodeConditionListParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, RunID: id, NodeID: n.NodeID})
		if err != nil {
			return v, err
		}
		for _, c := range conditions {
			node.Conditions = append(node.Conditions, wfCondition(c.JobName, c.CrawlerName, c.State, c.CrawlState, c.LogicalOperator))
		}
		v.Nodes = append(v.Nodes, node)
	}
	return v, nil
}
func (w writer) PutWorkflowRun(v domain.WorkflowRunRecord) error {
	k := v.Key
	id := v.ID
	if err := w.q.WFWorkflowRunPut(w.ctx, sqlcgen.WFWorkflowRunPutParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, RunID: id, PreviousRunID: v.PreviousRunID, RootTrigger: v.RootTrigger, Status: v.Status, Error: v.Error, Started: v.Started.UnixNano(), Completed: wfTime(v.Completed), NextPoll: wfTime(v.NextPoll)}); err != nil {
		return err
	}
	if err := w.q.WFWorkflowRunPropertyDelete(w.ctx, sqlcgen.WFWorkflowRunPropertyDeleteParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, RunID: id}); err != nil {
		return err
	}
	for key, val := range v.Properties {
		if err := w.q.WFWorkflowRunPropertyPut(w.ctx, sqlcgen.WFWorkflowRunPropertyPutParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, RunID: id, ItemKey: string(key), ItemValue: string(val)}); err != nil {
			return err
		}
	}
	if err := w.q.WFWorkflowNodeDelete(w.ctx, sqlcgen.WFWorkflowNodeDeleteParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, RunID: id}); err != nil {
		return err
	}
	for i, n := range v.Nodes {
		a := n.Action
		if err := w.q.WFWorkflowNodePut(w.ctx, sqlcgen.WFWorkflowNodePutParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, RunID: id, NodeID: n.ID, Ordinal: int64(i), Kind: n.Kind, NodeName: n.Name, TriggerName: n.TriggerName, TriggerType: n.TriggerType, TriggerState: n.TriggerState, TriggerDescription: n.TriggerDescription, TriggerSchedule: n.TriggerSchedule, ChildRunID: n.RunID, State: n.State, Error: n.Error, Logical: n.Logical, Activated: n.Activated, JobName: wfString(a.JobName), CrawlerName: wfString(a.CrawlerName), SecurityConfiguration: wfString(a.SecurityConfiguration), Timeout: wfInt(a.Timeout), NotificationDelay: wfDelay(a)}); err != nil {
			return err
		}
		for key, val := range a.Arguments {
			if err := w.q.WFWorkflowNodeArgumentPut(w.ctx, sqlcgen.WFWorkflowNodeArgumentPutParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, RunID: id, NodeID: n.ID, ItemKey: string(key), ItemValue: string(val)}); err != nil {
				return err
			}
		}
		for j, c := range n.Conditions {
			if err := w.q.WFWorkflowNodeConditionPut(w.ctx, sqlcgen.WFWorkflowNodeConditionPutParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, RunID: id, NodeID: n.ID, Ordinal: int64(j), JobName: wfString(c.JobName), CrawlerName: wfString(c.CrawlerName), State: wfString(c.State), CrawlState: wfString(c.CrawlState), LogicalOperator: wfString(c.LogicalOperator)}); err != nil {
				return err
			}
		}
	}
	return nil
}
