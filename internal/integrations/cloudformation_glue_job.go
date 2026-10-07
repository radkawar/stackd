package integrations

import (
	"context"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-job.html
type cfnGlueJob struct{ commands StepFunctionsCommands }

func (h cfnGlueJob) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Connections", "MaxRetries", "Description", "Timeout", "AllocatedCapacity", "Name", "Role", "DefaultArguments", "NotificationProperty", "WorkerType", "ExecutionClass", "LogUri", "Command", "GlueVersion", "ExecutionProperty", "SecurityConfiguration", "NumberOfWorkers", "Tags", "MaxCapacity", "NonOverridableArguments", "MaintenanceWindow", "JobMode", "JobRunQueuingEnabled"); err != nil {
		return err
	}
	if err := cloudformation.ValidateResourceProperties("AWS::Glue::Job", p); err != nil {
		return err
	}
	_, err := cfnAnalyticsTags(p)
	return err
}
func (h cfnGlueJob) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name"), h.Validate(b)
}
func (h cfnGlueJob) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "Name", 255)
	r.PhysicalID = name
	ctx = cfnGlueClaim(ctx, r, "job", name)
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
	input := cfnComputeCopy(r.Properties, "Connections", "MaxRetries", "Description", "Timeout", "AllocatedCapacity", "Name", "Role", "DefaultArguments", "NotificationProperty", "WorkerType", "ExecutionClass", "LogUri", "Command", "GlueVersion", "ExecutionProperty", "SecurityConfiguration", "NumberOfWorkers", "MaxCapacity", "NonOverridableArguments", "MaintenanceWindow", "JobMode", "JobRunQueuingEnabled")
	input["Name"] = name
	input["Tags"] = cfnAnalyticsCustomerTags(r)
	if err = cfnComputeRun(ctx, h.commands, "glue", "CreateJob", input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(name, name, nil), nil
}
func (h cfnGlueJob) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnAnalyticsRequireIdentity(h, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := r.PhysicalID
	ctx = cfnGlueClaim(ctx, r, "job", name)
	if _, err := h.Read(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input := map[string]any{"JobName": name, "JobUpdate": cfnComputeCopy(r.Properties, "Connections", "MaxRetries", "Description", "Timeout", "AllocatedCapacity", "Role", "DefaultArguments", "NotificationProperty", "WorkerType", "ExecutionClass", "LogUri", "Command", "GlueVersion", "ExecutionProperty", "SecurityConfiguration", "NumberOfWorkers", "MaxCapacity", "NonOverridableArguments", "MaintenanceWindow", "JobMode", "JobRunQueuingEnabled")}
	if err := cfnComputeRun(ctx, h.commands, "glue", "UpdateJob", input); err != nil {
		return cfnAnalyticsResult(name, name, nil), err
	}
	return cfnAnalyticsResult(name, name, nil), cfnGlueUpdateTags(ctx, h.commands, r, cfnGlueARN(r, "job", name))
}
func (h cfnGlueJob) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnComputeName(r, "Name", 255)
	r.PhysicalID = name
	ctx = cfnGlueClaim(ctx, r, "job", name)
	if _, err := h.Read(ctx, r); err != nil {
		return cfnAnalyticsAbsent(err)
	}
	return cfnAnalyticsAbsent(cfnComputeRun(ctx, h.commands, "glue", "DeleteJob", map[string]any{"JobName": name}))
}
func (h cfnGlueJob) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	name := r.PhysicalID
	ctx = cfnGlueClaim(ctx, r, "job", name)
	out, err := cfnComputeCall[api.GetJobOutput](ctx, h.commands, "glue", "GetJob", map[string]any{"JobName": name})
	if err != nil {
		return nil, err
	}
	p, err := cfnAnalyticsProject(out.Job, "Connections", "MaxRetries", "Description", "Timeout", "AllocatedCapacity", "Name", "Role", "DefaultArguments", "NotificationProperty", "WorkerType", "ExecutionClass", "LogUri", "Command", "GlueVersion", "ExecutionProperty", "SecurityConfiguration", "NumberOfWorkers", "MaxCapacity", "NonOverridableArguments", "MaintenanceWindow", "JobMode", "JobRunQueuingEnabled")
	if err != nil {
		return nil, err
	}
	tags, err := cfnGlueTags(ctx, h.commands, cfnGlueARN(r, "job", name))
	if err != nil {
		return nil, err
	}
	p["Tags"] = tags
	return p, nil
}
func (h cfnGlueJob) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.GetJobsOutput](ctx, h.commands, "glue", "GetJobs", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.Jobs {
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
