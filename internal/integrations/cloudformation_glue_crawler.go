package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-crawler.html
type cfnGlueCrawler struct{ commands StepFunctionsCommands }

func (h cfnGlueCrawler) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Classifiers", "Description", "SchemaChangePolicy", "Configuration", "RecrawlPolicy", "DatabaseName", "Targets", "CrawlerSecurityConfiguration", "Name", "Role", "LakeFormationConfiguration", "Schedule", "TablePrefix", "Tags"); err != nil {
		return err
	}
	if err := cloudformation.ValidateResourceProperties("AWS::Glue::Crawler", p); err != nil {
		return err
	}
	_, err := cfnAnalyticsTags(p)
	return err
}
func (h cfnGlueCrawler) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name"), h.Validate(b)
}
func (h cfnGlueCrawler) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "Name", 255)
	r.PhysicalID = name
	ctx = cfnGlueClaim(ctx, r, "crawler", name)
	_, err := h.Read(ctx, r)
	if err == nil {
		return cfnAnalyticsResult(name, name, nil), nil
	}
	if !cfnAnalyticsMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	if err = cfnAnalyticsNotAdmitted(ctx); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnComputeCopy(r.Properties, "Classifiers", "Description", "SchemaChangePolicy", "Configuration", "RecrawlPolicy", "DatabaseName", "Targets", "CrawlerSecurityConfiguration", "Name", "Role", "LakeFormationConfiguration", "Schedule", "TablePrefix")
	input["Name"] = name
	input["Tags"] = cfnAnalyticsCustomerTags(r)
	if schedule, ok := cfnComputeObject(input["Schedule"]); ok {
		input["Schedule"] = schedule["ScheduleExpression"]
	}
	if err = cfnComputeRun(ctx, h.commands, "glue", "CreateCrawler", input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(name, name, nil), nil
}
func (h cfnGlueCrawler) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnAnalyticsRequireIdentity(h, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := r.PhysicalID
	ctx = cfnGlueClaim(ctx, r, "crawler", name)
	if err := cfnComputeRun(ctx, h.commands, "glue", "UpdateCrawler", cfnGlueCrawlerUpdateInput(r)); err != nil {
		return cfnAnalyticsResult(name, name, nil), err
	}
	return cfnAnalyticsResult(name, name, nil), cfnGlueUpdateTags(ctx, h.commands, r, cfnGlueARN(r, "crawler", name))
}
func (h cfnGlueCrawler) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnComputeName(r, "Name", 255)
	ctx = cfnGlueClaim(ctx, r, "crawler", name)
	out, err := cfnComputeCall[api.GetCrawlerOutput](ctx, h.commands, "glue", "GetCrawler", map[string]any{"Name": name})
	if err != nil {
		return cfnAnalyticsAbsent(err)
	}
	if out.Crawler == nil {
		return fmt.Errorf("glue returned no crawler")
	}
	switch cfnComputeValue(out.Crawler.State) {
	case "STOPPING":
		return nil
	case "READY":
		return cfnAnalyticsAbsent(cfnComputeRun(ctx, h.commands, "glue", "DeleteCrawler", map[string]any{"Name": name}))
	default:
		return cfnComputeRun(ctx, h.commands, "glue", "StopCrawler", map[string]any{"Name": name})
	}
}
func (h cfnGlueCrawler) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	name := r.PhysicalID
	ctx = cfnGlueClaim(ctx, r, "crawler", name)
	out, err := cfnComputeCall[api.GetCrawlerOutput](ctx, h.commands, "glue", "GetCrawler", map[string]any{"Name": name})
	if err != nil {
		return nil, err
	}
	p, err := cfnAnalyticsProject(out.Crawler, "Classifiers", "Description", "SchemaChangePolicy", "Configuration", "RecrawlPolicy", "DatabaseName", "Targets", "CrawlerSecurityConfiguration", "Name", "Role", "LakeFormationConfiguration", "Schedule", "TablePrefix")
	if err != nil {
		return nil, err
	}
	if v, ok := cfnComputeObject(p["Schedule"]); ok {
		p["Schedule"] = cfnComputeCopy(v, "ScheduleExpression")
	}
	tags, err := cfnGlueTags(ctx, h.commands, cfnGlueARN(r, "crawler", name))
	if err != nil {
		return nil, err
	}
	p["Tags"] = tags
	return p, nil
}
func (h cfnGlueCrawler) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.GetCrawlersOutput](ctx, h.commands, "glue", "GetCrawlers", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.Crawlers {
			r.PhysicalID = cfnComputeValue(v.Name)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.NextToken) == "" {
			break
		}
		input["NextToken"] = out.NextToken
	}
	return cfnAnalyticsSort(rows), nil
}
