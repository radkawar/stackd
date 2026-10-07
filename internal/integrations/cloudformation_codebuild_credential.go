package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	api "stackd/internal/awsapi/codebuild"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/codebuild"
	"strings"
)

func cfnDeveloperClaim(r cloudformation.ResourceRequest) string {
	b, _ := json.Marshal([]string{r.StackID, r.LogicalID, r.Token})
	return string(b)
}

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codebuild-sourcecredential.html
// ImportSourceCredentials owns KMS ciphertext; CFN never creates a token store.
type cfnCodeBuildCredential struct{ commands StepFunctionsCommands }

func (h cfnCodeBuildCredential) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "ServerType", "AuthType", "Token", "Username"); err != nil {
		return err
	}
	return cfnComputeRequired(p, "ServerType", "AuthType", "Token")
}
func (h cfnCodeBuildCredential) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ServerType", "AuthType"), h.Validate(b)
}
func cfnCodeBuildCredentialID(r cloudformation.ResourceRequest) string {
	if r.PhysicalID != "" {
		return r.PhysicalID
	}
	return "arn:" + r.Scope.Partition + ":codebuild:" + r.Scope.Region + ":" + r.Scope.Account + ":token/" + strings.ToLower(cfnComputeString(r.Properties, "ServerType")) + "/" + strings.ToLower(cfnComputeString(r.Properties, "AuthType"))
}
func (h cfnCodeBuildCredential) get(ctx context.Context, id string) (*api.SourceCredentialsInfo, error) {
	out, err := cfnComputeCall[api.ListSourceCredentialsOutput](ctx, h.commands, "codebuild", "ListSourceCredentials", map[string]any{})
	if err != nil {
		return nil, err
	}
	for i := range out.SourceCredentialsInfos {
		if cfnComputeValue(out.SourceCredentialsInfos[i].Arn) == id {
			return &out.SourceCredentialsInfos[i], nil
		}
	}
	return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "Source credential not found", StatusCode: 400}
}
func (h cfnCodeBuildCredential) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := cfnCodeBuildCredentialID(r)
	rows := map[string]string{}
	ctx = codebuild.WithCloudFormationOwnership(ctx, cfnDeveloperClaim(r), id, false, rows)
	_, err := h.get(ctx, id)
	if err == nil {
		if rows[id] != cfnDeveloperClaim(r) {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, fmt.Errorf("source credential belongs to another incarnation"))
		}
		return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Arn": id}}, nil
	}
	if !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	ctx = codebuild.WithCloudFormationOwnership(ctx, cfnDeveloperClaim(r), id, true, nil)
	in := cfnDeveloperInput(r.Properties, "ServerType", "AuthType", "Token", "Username")
	in["shouldOverwrite"] = false
	out, err := cfnComputeCall[api.ImportSourceCredentialsOutput](ctx, h.commands, "codebuild", "ImportSourceCredentials", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id = cfnComputeValue(out.Arn)
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Arn": id}}, nil
}
func (h cfnCodeBuildCredential) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if !r.CloudControl {
		ctx = codebuild.WithCloudFormationOwnership(ctx, cfnDeveloperClaim(r), r.PhysicalID, true, nil)
	}
	if _, err := h.get(ctx, r.PhysicalID); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	in := cfnDeveloperInput(r.Properties, "ServerType", "AuthType", "Token", "Username")
	in["shouldOverwrite"] = true
	out, err := cfnComputeCall[api.ImportSourceCredentialsOutput](ctx, h.commands, "codebuild", "ImportSourceCredentials", in)
	if err != nil {
		return cloudformation.ResourceResult{PhysicalID: r.PhysicalID}, err
	}
	id := cfnComputeValue(out.Arn)
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Arn": id}}, nil
}
func (h cfnCodeBuildCredential) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if !r.CloudControl {
		ctx = codebuild.WithCloudFormationOwnership(ctx, cfnDeveloperClaim(r), r.PhysicalID, true, nil)
	}
	if _, err := h.get(ctx, r.PhysicalID); err != nil {
		return cfnComputeAbsent(err)
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "codebuild", "DeleteSourceCredentials", map[string]any{"arn": r.PhysicalID}))
}
func (h cfnCodeBuildCredential) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	p, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	return cloudformation.Properties{"Arn": cfnComputeValue(p.Arn), "ServerType": cfnComputeValue(p.ServerType), "AuthType": cfnComputeValue(p.AuthType)}, nil
}
func (h cfnCodeBuildCredential) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	out, err := cfnComputeCall[api.ListSourceCredentialsOutput](ctx, h.commands, "codebuild", "ListSourceCredentials", map[string]any{})
	if err != nil {
		return nil, err
	}
	rows := make([]cloudformation.ResourceDescription, 0, len(out.SourceCredentialsInfos))
	for _, p := range out.SourceCredentialsInfos {
		id := cfnComputeValue(p.Arn)
		rows = append(rows, cloudformation.ResourceDescription{Identifier: id, Properties: cloudformation.Properties{"Arn": id, "ServerType": cfnComputeValue(p.ServerType), "AuthType": cfnComputeValue(p.AuthType)}})
	}
	return rows, nil
}
