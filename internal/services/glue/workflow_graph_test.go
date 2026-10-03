package glue

import (
	api "stackd/internal/awsapi/glue"
	"testing"
)

// Dependency chains must share a trigger-origin run; matching terminal state
// without an admitted child run must not release a dependent action.
// https://docs.aws.amazon.com/glue/latest/dg/about-triggers.html
func TestWorkflowPredicateRequiresActualChildRuns(t *testing.T) {
	parent := WorkflowNodeRun{ID: "job:first", Kind: "JOB", Name: "first", State: "SUCCEEDED"}
	condition := api.Condition{JobName: new(api.NameString("first")), State: new(api.JobRunStateSUCCEEDED), LogicalOperator: new(api.LogicalOperatorEQUALS)}
	trigger := WorkflowNodeRun{Conditions: api.ConditionList{condition}, Logical: "AND"}
	if workflowPredicate([]WorkflowNodeRun{parent}, trigger) {
		t.Fatal("unadmitted terminal metadata released a trigger")
	}
	parent.RunID = "jr_actual"
	if !workflowPredicate([]WorkflowNodeRun{parent}, trigger) {
		t.Fatal("actual successful child did not release its condition")
	}
	trigger.Conditions = append(trigger.Conditions, api.Condition{CrawlerName: new(api.NameString("scan")), CrawlState: new(api.CrawlStateSUCCEEDED), LogicalOperator: new(api.LogicalOperatorEQUALS)})
	if workflowPredicate([]WorkflowNodeRun{parent}, trigger) {
		t.Fatal("AND released before the crawler completed")
	}
	trigger.Logical = "ANY"
	if !workflowPredicate([]WorkflowNodeRun{parent}, trigger) {
		t.Fatal("ANY failed to release on the completed child")
	}
}

// Resume selects an upstream frontier, not independent reruns of downstream
// selections. Unrelated branches and successful predecessors remain untouched.
// https://docs.aws.amazon.com/glue/latest/dg/resuming-workflow.html
func TestWorkflowResumeDependencyClosure(t *testing.T) {
	nodes := []WorkflowNodeRun{
		{ID: "a", Kind: "JOB", Name: "a"},
		{ID: "after-a", Kind: "TRIGGER", Name: "after-a", Conditions: api.ConditionList{{JobName: new(api.NameString("a"))}}},
		{ID: "b", Kind: "CRAWLER", Name: "b", TriggerName: "after-a"},
		{ID: "after-b", Kind: "TRIGGER", Name: "after-b", Conditions: api.ConditionList{{CrawlerName: new(api.NameString("b"))}}},
		{ID: "c", Kind: "JOB", Name: "c", TriggerName: "after-b"},
		{ID: "unrelated", Kind: "JOB", Name: "other"},
	}
	got := workflowDownstream(nodes, map[string]bool{"a": true})
	for _, id := range []string{"a", "after-a", "b", "after-b", "c"} {
		if !got[id] {
			t.Fatalf("resume omitted downstream node %s", id)
		}
	}
	if got["unrelated"] {
		t.Fatal("resume restarted an unrelated branch")
	}
	branch := workflowDownstream(nodes, map[string]bool{"b": true})
	if branch["a"] || branch["after-a"] || !branch["c"] {
		t.Fatalf("crawler resume changed its predecessors: %v", branch)
	}
}
