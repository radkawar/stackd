package glue

import (
	"errors"
	api "stackd/internal/awsapi/glue"
)

// Workflow graph metadata comes from the admitted graph, while child execution
// details are read from their authoritative retained job/crawler run records.
func (s *Service) workflowRunGraph(tx Reader, run WorkflowRunRecord, out *api.WorkflowRun) error {
	if out.Graph == nil {
		return nil
	}
	for i := range out.Graph.Nodes {
		node := &out.Graph.Nodes[i]
		if node.TriggerDetails != nil && node.TriggerDetails.Trigger != nil && run.Key.Name != "" {
			node.TriggerDetails.Trigger.WorkflowName = new(api.NameString(run.Key.Name))
		}
		for _, n := range run.Nodes {
			if n.ID != value(node.UniqueId) || n.RunID == "" {
				continue
			}
			if n.Kind == "JOB" {
				child, err := tx.GetJobRun(ResourceKey{run.Key.Scope, n.Name}, n.RunID)
				if errors.Is(err, ErrNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				node.JobDetails = &api.JobNodeDetails{JobRuns: api.JobRunList{jobRunWire(child, s.clock.Now())}}
			} else if n.Kind == "CRAWLER" {
				child, err := tx.Crawl(n.RunID)
				if errors.Is(err, ErrNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				crawl := api.Crawl{State: new(api.CrawlState(child.State)), StartedOn: workflowTime(child.Started)}
				if child.Completed != nil {
					crawl.CompletedOn = workflowTime(*child.Completed)
				}
				if child.ErrorMessage != "" {
					crawl.ErrorMessage = new(api.DescriptionString(child.ErrorMessage))
				}
				node.CrawlerDetails = &api.CrawlerNodeDetails{Crawls: api.CrawlList{crawl}}
			}
		}
	}
	return nil
}
