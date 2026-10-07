package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/codebuild"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/codebuild"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codebuild-project.html
// Omitted optional values retain their owner value, as specified by the CFN resource.
var cfnCodeBuildProjectProperties = []string{"Name", "Description", "Source", "SourceVersion", "SecondarySources", "SecondarySourceVersions", "Artifacts", "SecondaryArtifacts", "Environment", "ServiceRole", "EncryptionKey", "Cache", "LogsConfig", "TimeoutInMinutes", "QueuedTimeoutInMinutes", "ConcurrentBuildLimit", "BadgeEnabled", "AutoRetryLimit", "BuildBatchConfig", "FileSystemLocations", "VpcConfig", "Tags"}

type cfnCodeBuildProject struct{ commands StepFunctionsCommands }

func (h cfnCodeBuildProject) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, cfnCodeBuildProjectProperties...); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Source", "Artifacts", "Environment", "ServiceRole"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnCodeBuildProject) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name"), h.Validate(b)
}
func (h cfnCodeBuildProject) get(ctx context.Context, id string) (*api.Project, error) {
	out, err := cfnComputeCall[api.BatchGetProjectsOutput](ctx, h.commands, "codebuild", "BatchGetProjects", map[string]any{"names": []string{id}})
	if err != nil {
		return nil, err
	}
	if len(out.Projects) != 1 {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "Project not found", StatusCode: 400}
	}
	return &out.Projects[0], nil
}
func cfnCodeBuildTags(tags api.TagList) map[string]string {
	out := map[string]string{}
	for _, t := range tags {
		out[cfnComputeValue(t.Key)] = cfnComputeValue(t.Value)
	}
	return out
}
func cfnCodeBuildProjectResult(p *api.Project) cloudformation.ResourceResult {
	id := cfnComputeValue(p.Name)
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Id": id, "Arn": cfnComputeValue(p.Arn)}}
}
func (h cfnCodeBuildProject) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id := cfnComputeName(r, "Name", 150)
	rows := map[string]string{}
	ctx = codebuild.WithCloudFormationResourceOwnership(ctx, "Project", cfnDeveloperClaim(r), id, true, rows)
	p, err := h.get(ctx, id)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if rows[id] != cfnDeveloperClaim(r) {
		return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, fmt.Errorf("project belongs to another CloudFormation incarnation"))
	}
	return cfnCodeBuildProjectResult(p), nil
}
func (h cfnCodeBuildProject) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result, err := h.RecoverCreation(ctx, r)
	if err == nil {
		return result, nil
	}
	if !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	id := cfnComputeName(r, "Name", 150)
	ctx = codebuild.WithCloudFormationResourceOwnership(ctx, "Project", cfnDeveloperClaim(r), id, false, nil)
	in := cfnDeveloperInput(r.Properties, cfnCodeBuildProjectProperties...)
	in["name"] = id
	in["tags"] = cfnECRTags(cfnResourceTags(r))
	out, err := cfnComputeCall[api.CreateProjectOutput](ctx, h.commands, "codebuild", "CreateProject", in)
	if err != nil {
		recovered, recoveryErr := h.RecoverCreation(ctx, r)
		if recoveryErr == nil {
			return recovered, err
		}
		return cloudformation.ResourceResult{}, err
	}
	return cfnCodeBuildProjectResult(out.Project), nil
}
func (h cfnCodeBuildProject) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnDeveloperCodeBuildContext(ctx, r, "Project")
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	p, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	in := cfnDeveloperInput(r.Properties, cfnCodeBuildProjectProperties...)
	in["name"] = r.PhysicalID
	in["tags"] = cfnECRTags(cfnResourceTags(r))
	out, err := cfnComputeCall[api.UpdateProjectOutput](ctx, h.commands, "codebuild", "UpdateProject", in)
	if err != nil {
		return cfnCodeBuildProjectResult(p), err
	}
	return cfnCodeBuildProjectResult(out.Project), nil
}
func (h cfnCodeBuildProject) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnDeveloperCodeBuildContext(ctx, r, "Project")
	_, err := h.get(ctx, r.PhysicalID)
	if cfnComputeMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return cfnComputeRun(ctx, h.commands, "codebuild", "DeleteProject", map[string]any{"name": r.PhysicalID})
}
func (h cfnCodeBuildProject) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	p, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	out, err := cfnDeveloperModel(p, cfnCodeBuildProjectProperties...)
	if err != nil {
		return nil, err
	}
	out["Tags"] = cfnComputeTagList(cfnCodeBuildTags(p.Tags))
	out["Id"] = cfnComputeValue(p.Name)
	out["Arn"] = cfnComputeValue(p.Arn)
	return out, nil
}
func (h cfnCodeBuildProject) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	token := ""
	for {
		out, err := cfnComputeCall[api.ListProjectsOutput](ctx, h.commands, "codebuild", "ListProjects", cfnDeveloperPageInput(token, map[string]any{}))
		if err != nil {
			return nil, err
		}
		for _, id := range out.Projects {
			r.PhysicalID = string(id)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		next := cfnComputeValue(out.NextToken)
		if next == "" {
			return rows, nil
		}
		if next == token {
			return nil, fmt.Errorf("CodeBuild pagination did not advance")
		}
		token = next
	}
}
