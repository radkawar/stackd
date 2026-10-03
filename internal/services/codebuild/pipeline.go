package codebuild

import (
	"context"
	"slices"
	"strings"

	api "stackd/internal/awsapi/codebuild"
)

type pipelineActionKey struct{}

// WithPipelineAction binds an internal action invocation to its immutable
// execution identity. It is not a public StartBuild field or an environment
// variable and cannot be supplied by an SDK request.
func WithPipelineAction(ctx context.Context, actionExecutionID string) context.Context {
	return context.WithValue(ctx, pipelineActionKey{}, actionExecutionID)
}

// Pipeline source versions and artifact names come from the admitted action,
// not the masked environmentVariablesOverride in native StartBuild audit records.
// https://docs.aws.amazon.com/codepipeline/latest/userguide/action-reference-CodeBuild.html
func (s *Service) pipelineBuild(ctx context.Context, key ProjectKey, p *api.Project) (PipelineBuild, error) {
	if value(p.Source.Type) != "CODEPIPELINE" {
		return PipelineBuild{}, nil
	}
	sourceARN := value(p.SourceVersion)
	if _, _, err := pipelineObjectLocation(key.Partition, sourceARN); err != nil {
		return PipelineBuild{}, err
	}
	actionID, _ := ctx.Value(pipelineActionKey{}).(string)
	if actionID == "" {
		// A public/manual request can run this real S3 source, but does not
		// supply an original revision or authorize pipeline output publication.
		return PipelineBuild{Inputs: []PipelineInput{{Location: sourceARN}}}, nil
	}
	if s.pipelineArtifacts == nil {
		return PipelineBuild{}, unsupported("CodePipeline artifact authority is not configured.")
	}
	outputARN := ""
	if value(p.Artifacts.Type) == "CODEPIPELINE" {
		outputARN = value(p.Artifacts.Location)
	}
	binding, err := s.pipelineArtifacts.ResolveBuild(ctx, actionID, key.ARN(), sourceARN, outputARN)
	if err != nil {
		return PipelineBuild{}, err
	}
	if binding.PipelineName == "" || len(binding.Inputs) < 1 || len(binding.Inputs) > 5 || len(binding.Outputs) > 5 || binding.Inputs[0].Location != sourceARN {
		return PipelineBuild{}, failure("InvalidInputException", "Invalid CodePipeline build artifact binding.")
	}
	if len(binding.Outputs) == 0 {
		if outputARN != "" {
			return PipelineBuild{}, failure("InvalidInputException", "CodePipeline action has no output artifact.")
		}
	} else if value(p.Artifacts.Type) != "CODEPIPELINE" || binding.Outputs[0].Location != outputARN {
		return PipelineBuild{}, failure("InvalidInputException", "CodePipeline output artifact does not match the action.")
	}
	seen := make(map[string]bool, len(binding.Inputs))
	for _, input := range binding.Inputs {
		if !pipelineArtifactName(input.Name) || seen[input.Name] {
			return PipelineBuild{}, failure("InvalidInputException", "Invalid CodePipeline input artifact.")
		}
		seen[input.Name] = true
		if _, _, err := pipelineObjectLocation(key.Partition, input.Location); err != nil {
			return PipelineBuild{}, err
		}
	}
	clear(seen)
	for _, output := range binding.Outputs {
		if !pipelineArtifactName(output.Name) || seen[output.Name] || output.EncryptionKey == "" {
			return PipelineBuild{}, failure("InvalidInputException", "Invalid CodePipeline output artifact.")
		}
		seen[output.Name] = true
		if _, _, err := pipelineObjectLocation(key.Partition, output.Location); err != nil {
			return PipelineBuild{}, err
		}
	}
	binding.Inputs = slices.Clone(binding.Inputs)
	binding.Outputs = slices.Clone(binding.Outputs)
	return binding, nil
}

func pipelineArtifactName(name string) bool {
	if name == "" || len(name) > 100 {
		return false
	}
	for _, c := range name {
		if c != '_' && c != '-' && (c < '0' || c > '9') && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

func pipelineObjectLocation(partition, location string) (string, string, error) {
	prefix := "arn:" + partition + ":s3:::"
	if !strings.HasPrefix(location, prefix) {
		return "", "", failure("InvalidInputException", "CodePipeline artifacts require an S3 object ARN in the build partition.")
	}
	return objectLocation(strings.TrimPrefix(location, prefix))
}
