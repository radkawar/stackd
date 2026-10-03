package glue

import (
	"context"
	"maps"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awsctx"
	"stackd/internal/awsschedule"
	"stackd/internal/scheduler"
)

func workflowNodes(triggers []TriggerRecord, workflow, root string) []WorkflowNodeRun {
	nodes := []WorkflowNodeRun{}
	for _, v := range triggers {
		t := v.Trigger
		if value(t.WorkflowName) != workflow || root != "" && value(t.Type) != "CONDITIONAL" && v.Key.Name != root {
			continue
		}
		n := WorkflowNodeRun{ID: "trigger:" + v.Key.Name, Kind: "TRIGGER", Name: v.Key.Name, State: "WAITING",
			TriggerType: value(t.Type), TriggerState: value(t.State), TriggerDescription: value(t.Description), TriggerSchedule: value(t.Schedule),
			Activated: value(t.State) == "ACTIVATED" || v.Key.Name == root}
		if t.Predicate != nil {
			n.Conditions = t.Predicate.Conditions
			n.Logical = value(t.Predicate.Logical)
		}
		nodes = append(nodes, n)
		for i, a := range t.Actions {
			kind, name := "JOB", value(a.JobName)
			if name == "" {
				kind, name = "CRAWLER", value(a.CrawlerName)
			}
			nodes = append(nodes, WorkflowNodeRun{ID: strings.ToLower(kind) + ":" + name + ":" + v.Key.Name + ":" + strconv.Itoa(i), Kind: kind, Name: name, TriggerName: v.Key.Name, State: "WAITING", Action: a})
		}
	}
	return nodes
}
func workflowGraph(nodes []WorkflowNodeRun) *api.WorkflowGraph {
	out := &api.WorkflowGraph{Nodes: api.NodeList{}, Edges: api.EdgeList{}}
	for _, n := range nodes {
		node := api.Node{Name: new(api.NameString(n.Name)), UniqueId: new(api.NameString(n.ID)), Type: new(api.NodeType(n.Kind))}
		if n.Kind == "TRIGGER" {
			t := api.Trigger{Name: node.Name, State: new(api.TriggerState(n.TriggerState)), Type: new(api.TriggerType(n.TriggerType))}
			if n.TriggerDescription != "" {
				t.Description = new(api.DescriptionString(n.TriggerDescription))
			}
			if n.TriggerSchedule != "" {
				t.Schedule = new(api.GenericString(n.TriggerSchedule))
			}
			if len(n.Conditions) > 0 {
				t.Predicate = &api.Predicate{Conditions: n.Conditions}
				if n.Logical != "" {
					t.Predicate.Logical = new(api.Logical(n.Logical))
				}
			}
			for _, a := range nodes {
				if a.TriggerName == n.Name {
					t.Actions = append(t.Actions, a.Action)
				}
			}
			node.TriggerDetails = &api.TriggerNodeDetails{Trigger: &t}
			for _, c := range n.Conditions {
				for _, source := range nodes {
					if source.Kind == "JOB" && source.Name == value(c.JobName) || source.Kind == "CRAWLER" && source.Name == value(c.CrawlerName) {
						out.Edges = append(out.Edges, api.Edge{SourceId: new(api.NameString(source.ID)), DestinationId: node.UniqueId})
					}
				}
			}
		} else {
			out.Edges = append(out.Edges, api.Edge{SourceId: new(api.NameString("trigger:" + n.TriggerName)), DestinationId: node.UniqueId})
			if n.RunID != "" {
				if n.Kind == "JOB" {
					node.JobDetails = &api.JobNodeDetails{JobRuns: api.JobRunList{{Id: new(api.IdString(n.RunID)), JobName: node.Name, JobRunState: new(api.JobRunState(n.State))}}}
				} else {
					node.CrawlerDetails = &api.CrawlerNodeDetails{Crawls: api.CrawlList{{State: new(api.CrawlState(n.State))}}}
				}
			}
		}
		out.Nodes = append(out.Nodes, node)
	}
	return out
}
func workflowRunView(v WorkflowRunRecord, graph bool) api.WorkflowRun {
	out := api.WorkflowRun{Name: new(api.NameString(v.Key.Name)), WorkflowRunId: new(api.IdString(v.ID)), StartedOn: workflowTime(v.Started), Status: new(api.WorkflowRunStatus(v.Status)), WorkflowRunProperties: v.Properties}
	if v.Completed != nil {
		out.CompletedOn = workflowTime(*v.Completed)
	}
	if v.PreviousRunID != "" {
		out.PreviousRunId = new(api.IdString(v.PreviousRunID))
	}
	if v.Error != "" {
		out.ErrorMessage = new(api.ErrorString(v.Error))
	}
	var total, waiting, running, succeeded, failed, stopped, timedout, errored api.IntegerValue
	for _, n := range v.Nodes {
		if n.Kind == "TRIGGER" {
			continue
		}
		total++
		switch n.State {
		case "WAITING", "PENDING", "SKIPPED":
			waiting++
		case "SUCCEEDED":
			succeeded++
		case "FAILED":
			failed++
		case "ERROR":
			errored++
		case "STOPPED", "CANCELLED":
			stopped++
		case "TIMEOUT":
			timedout++
		default:
			running++
		}
	}
	out.Statistics = &api.WorkflowRunStatistics{TotalActions: &total, WaitingActions: &waiting, RunningActions: &running, SucceededActions: &succeeded, FailedActions: &failed, StoppedActions: &stopped, TimeoutActions: &timedout, ErroredActions: &errored}
	if graph {
		out.Graph = workflowGraph(v.Nodes)
	}
	return out
}
func (s *Service) admitTriggerRun(tx Transaction, trigger TriggerRecord, properties api.WorkflowRunProperties) (WorkflowRunRecord, error) {
	key := ResourceKey{trigger.Key.Scope, value(trigger.Trigger.WorkflowName)}
	props := api.WorkflowRunProperties{}
	if key.Name != "" {
		w, err := tx.Workflow(key)
		if err != nil {
			return WorkflowRunRecord{}, err
		}
		runs, err := tx.WorkflowRuns(key)
		if err != nil {
			return WorkflowRunRecord{}, err
		}
		active := 0
		for _, v := range runs {
			if v.Status == "RUNNING" || v.Status == "STOPPING" {
				active++
			}
		}
		if w.Workflow.MaxConcurrentRuns != nil && active >= int(*w.Workflow.MaxConcurrentRuns) {
			return WorkflowRunRecord{}, failure("ConcurrentRunsExceededException", "Workflow concurrent run limit exceeded.")
		}
		maps.Copy(props, w.Workflow.DefaultRunProperties)
	}
	maps.Copy(props, properties)
	triggers, err := tx.Triggers(key.Scope)
	if err != nil {
		return WorkflowRunRecord{}, err
	}
	now := s.clock.Now()
	v := WorkflowRunRecord{Key: key, ID: "wr_" + strings.ReplaceAll(uuid.NewString(), "-", ""), RootTrigger: trigger.Key.Name, Status: "RUNNING", Started: now, NextPoll: &now, Properties: props, Nodes: workflowNodes(triggers, key.Name, trigger.Key.Name)}
	return v, tx.PutWorkflowRun(v)
}
func (s *Service) startWorkflowRun(ctx context.Context, tx Transaction, in *api.StartWorkflowRunInput) (*api.StartWorkflowRunOutput, error) {
	key := ResourceKey{scopeFor(ctx), value(in.Name)}
	if _, err := s.workflowAccess(ctx, tx, "StartWorkflowRun", key); err != nil {
		return nil, err
	}
	triggers, err := tx.Triggers(key.Scope)
	if err != nil {
		return nil, err
	}
	var root *TriggerRecord
	for i := range triggers {
		v := &triggers[i]
		if value(v.Trigger.WorkflowName) == key.Name && value(v.Trigger.Type) == "ON_DEMAND" {
			if root != nil {
				return nil, failure("InvalidInputException", "Workflow has multiple on-demand start triggers.")
			}
			root = v
		}
	}
	if root == nil {
		return nil, failure("InvalidInputException", "Workflow requires an on-demand start trigger.")
	}
	run, err := s.admitTriggerRun(tx, *root, in.RunProperties)
	if err != nil {
		return nil, err
	}
	return &api.StartWorkflowRunOutput{RunId: new(api.IdString(run.ID))}, nil
}
func (s *Service) stopWorkflowRun(ctx context.Context, tx Transaction, in *api.StopWorkflowRunInput) (*api.StopWorkflowRunOutput, error) {
	key := ResourceKey{scopeFor(ctx), value(in.Name)}
	if _, err := s.workflowAccess(ctx, tx, "StopWorkflowRun", key); err != nil {
		return nil, err
	}
	v, err := tx.WorkflowRun(key, value(in.RunId))
	if err != nil {
		return nil, err
	}
	if v.Status == "RUNNING" {
		v.Status = "STOPPING"
		now := s.clock.Now()
		v.NextPoll = &now
		if err = tx.PutWorkflowRun(v); err != nil {
			return nil, err
		}
	}
	return &api.StopWorkflowRunOutput{}, nil
}
func (s *Service) resumeWorkflowRun(ctx context.Context, tx Transaction, in *api.ResumeWorkflowRunInput) (*api.ResumeWorkflowRunOutput, error) {
	key := ResourceKey{scopeFor(ctx), value(in.Name)}
	if _, err := s.workflowAccess(ctx, tx, "ResumeWorkflowRun", key); err != nil {
		return nil, err
	}
	old, err := tx.WorkflowRun(key, value(in.RunId))
	if err != nil {
		return nil, err
	}
	if old.Status != "COMPLETED" {
		return nil, failure("IllegalWorkflowStateException", "Only a completed workflow run can be resumed.")
	}
	if len(in.NodeIds) == 0 {
		return nil, failure("InvalidInputException", "At least one node must be selected.")
	}
	if old.PreviousRunID != "" {
		runs, err := tx.WorkflowRuns(key)
		if err != nil {
			return nil, err
		}
		for _, run := range runs {
			if run.PreviousRunID == old.ID {
				return nil, failure("IllegalWorkflowStateException", "A resumed run can only be resumed once.")
			}
		}
	}
	selected := map[string]bool{}
	for _, id := range in.NodeIds {
		found := false
		for _, n := range old.Nodes {
			if n.ID == string(id) && n.Kind != "TRIGGER" && n.State != "WAITING" && n.State != "SKIPPED" {
				found = true
				selected[n.ID] = true
			}
		}
		if !found {
			return nil, failure("InvalidInputException", "Selected node was not attempted in this workflow run.")
		}
	}
	roots := maps.Clone(selected)
	for id := range selected {
		for descendant := range workflowDownstream(old.Nodes, map[string]bool{id: true}) {
			if descendant != id {
				delete(roots, descendant)
			}
		}
	}
	if len(roots) == 0 {
		return nil, failure("InvalidInputException", "Selected nodes contain a dependency cycle.")
	}
	affected := workflowDownstream(old.Nodes, roots)
	root := TriggerRecord{Key: ResourceKey{key.Scope, old.RootTrigger}, Trigger: api.Trigger{WorkflowName: new(api.NameString(key.Name))}}
	v, err := s.admitTriggerRun(tx, root, old.Properties)
	if err != nil {
		return nil, err
	}
	v.PreviousRunID = old.ID
	v.Nodes = old.Nodes
	starts := api.NodeIdList{}
	for i := range v.Nodes {
		n := &v.Nodes[i]
		if !affected[n.ID] {
			continue
		}
		n.State = "WAITING"
		n.RunID = ""
		n.Error = ""
		if roots[n.ID] {
			n.State = "PENDING"
			starts = append(starts, api.NameString(n.ID))
		}
	}
	if err = tx.PutWorkflowRun(v); err != nil {
		return nil, err
	}
	return &api.ResumeWorkflowRunOutput{RunId: new(api.IdString(v.ID)), NodeIds: starts}, nil
}
func workflowDownstream(nodes []WorkflowNodeRun, roots map[string]bool) map[string]bool {
	affected := maps.Clone(roots)
	changed := true
	for changed {
		changed = false
		for _, n := range nodes {
			if affected[n.ID] || n.Kind != "TRIGGER" {
				continue
			}
			match := false
			for _, c := range n.Conditions {
				for _, p := range nodes {
					if affected[p.ID] && (p.Kind == "JOB" && p.Name == value(c.JobName) || p.Kind == "CRAWLER" && p.Name == value(c.CrawlerName)) {
						match = true
					}
				}
			}
			if !match {
				continue
			}
			affected[n.ID] = true
			changed = true
			for _, child := range nodes {
				if child.TriggerName == n.Name {
					affected[child.ID] = true
				}
			}
		}
	}
	return affected
}

// workflowJobs only admits child commands in the shared transaction. Job and
// crawler native effects run in their independent scheduler sources after commit.
type workflowJobs struct{ s *Service }

func (j workflowJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var out scheduler.Job
	found := false
	err := j.s.repository.View(ctx, func(tx Reader) error {
		r, ok, err := tx.NextWorkflowRun()
		if err != nil {
			return err
		}
		if ok {
			out = scheduler.Job{Key: "run/" + r.ID, Due: *r.NextPoll}
			found = true
		}
		t, ok, err := tx.NextTrigger()
		if err != nil {
			return err
		}
		if ok && (!found || t.NextFire.Before(out.Due)) {
			out = scheduler.Job{Key: "trigger/" + t.Key.ARN("trigger"), Due: *t.NextFire}
			found = true
		}
		return nil
	})
	return out, found, err
}
func (j workflowJobs) Run(ctx context.Context, job scheduler.Job) error {
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		if strings.HasPrefix(job.Key, "trigger/") {
			t, ok, err := tx.NextTrigger()
			if err != nil || !ok {
				return err
			}
			if job.Key != "trigger/"+t.Key.ARN("trigger") || !job.Due.Equal(*t.NextFire) {
				return nil
			}
			schedule, err := awsschedule.ParseEventBridge(value(t.Trigger.Schedule))
			if err != nil {
				return err
			}
			t.NextFire = nil
			if next, ok := schedule.Next(job.Due); ok {
				t.NextFire = &next
			}
			if err = tx.PutTrigger(t); err != nil {
				return err
			}
			_, err = j.s.admitTriggerRun(tx, t, nil)
			if err != nil {
				if e := wireError(err); e.Code == "ConcurrentRunsExceededException" || e.Code == "EntityNotFoundException" {
					return nil
				}
			}
			return err
		}
		v, ok, err := tx.NextWorkflowRun()
		if err != nil || !ok {
			return err
		}
		if job.Key != "run/"+v.ID || !job.Due.Equal(*v.NextPoll) {
			return nil
		}
		return j.s.advanceWorkflow(tx, v)
	})
}
func workflowTerminal(state string) bool {
	switch state {
	case "SUCCEEDED", "FAILED", "ERROR", "STOPPED", "CANCELLED", "TIMEOUT", "EXPIRED":
		return true
	}
	return false
}
func workflowPredicate(nodes []WorkflowNodeRun, n WorkflowNodeRun) bool {
	if len(n.Conditions) == 0 {
		return false
	}
	all := true
	for _, c := range n.Conditions {
		matched := false
		for _, parent := range nodes {
			if parent.RunID == "" {
				continue
			}
			if parent.Kind == "JOB" && parent.Name == value(c.JobName) && parent.State == value(c.State) || parent.Kind == "CRAWLER" && parent.Name == value(c.CrawlerName) && parent.State == value(c.CrawlState) {
				matched = true
				break
			}
		}
		if n.Logical == "ANY" && matched {
			return true
		}
		all = all && matched
	}
	return all
}
func (s *Service) advanceWorkflow(tx Transaction, v WorkflowRunRecord) error {
	scope := v.Key.Scope
	ctx := awsctx.WithMetadata(tx.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, ServicePrincipal: awsctx.ServicePrincipal{Name: "glue.amazonaws.com", SourceARN: ResourceKey{scope, v.RootTrigger}.ARN("trigger")}})
	active := false
	for i := range v.Nodes {
		n := &v.Nodes[i]
		if n.RunID == "" || workflowTerminal(n.State) {
			continue
		}
		if n.Kind == "JOB" {
			child, err := tx.GetJobRun(ResourceKey{scope, n.Name}, n.RunID)
			if err != nil {
				n.State = "ERROR"
				n.Error = wireError(err).Message
				continue
			}
			n.State = child.State
			n.Error = child.Error
		} else {
			child, err := tx.Crawl(n.RunID)
			if err != nil {
				n.State = "ERROR"
				n.Error = wireError(err).Message
				continue
			}
			n.State = child.State
			n.Error = child.ErrorMessage
		}
		if !workflowTerminal(n.State) {
			active = true
			if v.Status == "STOPPING" {
				var err error
				if n.Kind == "JOB" {
					err = s.StopTriggeredJob(ctx, scope, n.Name, n.RunID)
				} else {
					err = s.StopTriggeredCrawler(ctx, scope, n.Name, n.RunID)
				}
				if err != nil {
					return err
				}
			}
		}
	}
	if v.Status != "STOPPING" {
		// Glue snapshots triggers at workflow admission. Changes to downstream
		// jobs/crawlers still take effect through their authoritative commands.
		for i := range v.Nodes {
			n := &v.Nodes[i]
			if n.Kind != "TRIGGER" || n.State != "WAITING" || !n.Activated {
				continue
			}
			if n.Name != v.RootTrigger && !workflowPredicate(v.Nodes, *n) {
				continue
			}
			n.State = "FIRED"
			for k := range v.Nodes {
				if v.Nodes[k].TriggerName == n.Name && v.Nodes[k].State == "WAITING" {
					v.Nodes[k].State = "PENDING"
				}
			}
		}
		for i := range v.Nodes {
			n := &v.Nodes[i]
			if n.State != "PENDING" {
				continue
			}
			var id string
			var err error
			if n.Kind == "JOB" {
				args := map[string]string{}
				for k, val := range n.Action.Arguments {
					args[string(k)] = string(val)
				}
				if v.Key.Name != "" {
					args["--WORKFLOW_NAME"] = v.Key.Name
					args["--WORKFLOW_RUN_ID"] = v.ID
				}
				var timeout int32
				if n.Action.Timeout != nil {
					timeout = int32(*n.Action.Timeout)
				}
				// A child rejection must roll back only its command, not the
				// retained workflow transition recording the failed action.
				err = s.repository.Attempt(ctx, func(child Transaction) error {
					var rejected error
					id, rejected = s.StartTriggeredJob(child.Context(), scope, n.Name, n.TriggerName, v.Key.Name, v.ID, args, value(n.Action.SecurityConfiguration), timeout)
					return rejected
				})
			} else {
				err = s.repository.Attempt(ctx, func(child Transaction) error {
					var rejected error
					id, rejected = s.StartTriggeredCrawler(child.Context(), scope, n.Name, n.TriggerName, v.Key.Name, v.ID)
					return rejected
				})
			}
			if err != nil {
				rejected := wireError(err)
				if rejected.StatusCode >= 500 {
					return err
				}
				n.State = "ERROR"
				n.Error = rejected.Message
			} else {
				n.RunID = id
				n.State = "RUNNING"
				active = true
			}
		}
	}
	now := s.clock.Now()
	if active {
		next := now.Add(time.Second)
		v.NextPoll = &next
	} else {
		v.NextPoll = nil
		v.Completed = &now
		if v.Status == "STOPPING" {
			v.Status = "STOPPED"
		} else {
			v.Status = "COMPLETED"
		}
		for i := range v.Nodes {
			n := &v.Nodes[i]
			if n.State == "WAITING" || n.State == "PENDING" {
				n.State = "SKIPPED"
			}
		}
	}
	return tx.PutWorkflowRun(v)
}
