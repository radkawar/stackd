package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/cloudformation"
)

func cfnGlueCrawlerUpdateInput(r cloudformation.ResourceRequest) map[string]any {
	input := cfnComputeCopy(r.Properties, "Role", "Targets", "DatabaseName", "Classifiers", "Description", "SchemaChangePolicy", "Configuration", "RecrawlPolicy", "CrawlerSecurityConfiguration", "LakeFormationConfiguration", "TablePrefix")
	input["Name"] = r.PhysicalID
	for _, key := range []string{"DatabaseName", "Description", "Configuration", "CrawlerSecurityConfiguration", "TablePrefix"} {
		if input[key] == nil {
			input[key] = ""
		}
	}
	if input["Classifiers"] == nil {
		input["Classifiers"] = []string{}
	}
	if input["SchemaChangePolicy"] == nil {
		input["SchemaChangePolicy"] = map[string]any{"UpdateBehavior": "UPDATE_IN_DATABASE", "DeleteBehavior": "DEPRECATE_IN_DATABASE"}
	}
	if input["RecrawlPolicy"] == nil {
		input["RecrawlPolicy"] = map[string]any{"RecrawlBehavior": "CRAWL_EVERYTHING"}
	}
	if input["LakeFormationConfiguration"] == nil {
		input["LakeFormationConfiguration"] = map[string]any{"UseLakeFormationCredentials": false}
	}
	input["Schedule"] = ""
	if schedule, ok := cfnComputeObject(r.Properties["Schedule"]); ok {
		input["Schedule"] = cfnComputeDefault(schedule, "ScheduleExpression", "")
	}
	return input
}
func cfnGlueWorkflowUpdateInput(r cloudformation.ResourceRequest) map[string]any {
	input := cfnComputeCopy(r.Properties, "MaxConcurrentRuns")
	input["Name"] = r.PhysicalID
	input["Description"] = cfnComputeDefault(r.Properties, "Description", "")
	input["DefaultRunProperties"] = cfnComputeDefault(r.Properties, "DefaultRunProperties", map[string]any{})
	return input
}
func (h cfnGlueCrawler) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnGlueClaim(ctx, r, "crawler", r.PhysicalID)
	out, err := cfnComputeCall[api.GetCrawlerOutput](ctx, h.commands, "glue", "GetCrawler", map[string]any{"Name": r.PhysicalID})
	if err != nil {
		return false, err
	}
	if out.Crawler == nil {
		return false, fmt.Errorf("glue returned no crawler")
	}
	return cfnComputeValue(out.Crawler.State) == "READY", nil
}
func (h cfnGlueCrawler) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnGlueClaim(ctx, r, "crawler", r.PhysicalID)
	out, err := cfnComputeCall[api.GetCrawlerOutput](ctx, h.commands, "glue", "GetCrawler", map[string]any{"Name": r.PhysicalID})
	if cfnAnalyticsGone(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if out.Crawler == nil {
		return false, fmt.Errorf("glue returned no crawler")
	}
	if cfnComputeValue(out.Crawler.State) != "READY" {
		return false, nil
	}
	err = cfnComputeRun(ctx, h.commands, "glue", "DeleteCrawler", map[string]any{"Name": r.PhysicalID})
	return err == nil || cfnAnalyticsMissing(err), cfnAnalyticsAbsent(err)
}
func cfnGlueTriggerActivation(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest) error {
	if !cfnComputeChanged(r.Previous, r.Properties, "StartOnCreation") {
		return nil
	}
	active, _ := r.Properties["StartOnCreation"].(bool)
	if cfnComputeString(r.Properties, "Type") == "ON_DEMAND" {
		if active {
			return fmt.Errorf("StartOnCreation cannot activate an ON_DEMAND trigger")
		}
		return nil
	}
	operation := "StopTrigger"
	if active {
		operation = "StartTrigger"
	}
	return cfnComputeRun(ctx, c, "glue", operation, map[string]any{"Name": r.PhysicalID})
}
