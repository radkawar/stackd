package codebuild

import (
	"regexp"
	api "stackd/internal/awsapi/codebuild"
	"strings"
)

// ProjectSource documents alphanumerics/underscores and fewer than 128 characters.
var sourceIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,127}$`)

func validateSecondaries(p *api.Project) error {
	if len(p.SecondarySources) > 12 || len(p.SecondaryArtifacts) > 12 || len(p.SecondarySourceVersions) > 12 {
		return failure("InvalidInputException", "At most 12 secondary sources, versions and artifacts are supported.")
	}
	sources := make(map[string]bool, len(p.SecondarySources))
	gitLocations := make(map[string]bool)
	for _, source := range p.SecondarySources {
		id := value(source.SourceIdentifier)
		if !sourceIdentifierPattern.MatchString(id) || sources[id] || id == value(p.Source.SourceIdentifier) {
			return failure("InvalidInputException", "Secondary sources require unique source identifiers containing only alphanumerics and underscores, fewer than 128 characters.")
		}
		sources[id] = true
		switch value(source.Type) {
		case "S3":
			if _, _, err := sourceLocation(value(source.Location)); err != nil {
				return err
			}
			if source.Auth != nil || source.GitCloneDepth != nil || source.GitSubmodulesConfig != nil {
				return unsupported("Git authentication and checkout options are not supported for S3 secondary sources.")
			}
		case "GITHUB", "GITHUB_ENTERPRISE", "BITBUCKET", "GITLAB", "GITLAB_SELF_MANAGED":
			if err := validateGitSource(&source); err != nil {
				return err
			}
			location := value(source.Location)
			if gitLocations[location] {
				return failure("InvalidInputException", "Invalid input: conflicting source locations")
			}
			gitLocations[location] = true
		default:
			return unsupported("Unsupported secondary source type: " + value(source.Type))
		}
		if err := validateSourceOptions(&source); err != nil {
			return err
		}
		// The primary source owns the buildspec, including when a secondary
		// source carries a buildspec declaration in its modeled configuration.
	}
	versions := make(map[string]bool, len(p.SecondarySourceVersions))
	for _, version := range p.SecondarySourceVersions {
		id := value(version.SourceIdentifier)
		if !sources[id] || versions[id] || version.SourceVersion == nil {
			return failure("InvalidInputException", "Secondary source versions require a unique matching secondary source identifier and a version.")
		}
		for _, source := range p.SecondarySources {
			if value(source.Type) == "S3" && value(source.SourceIdentifier) == id && strings.HasSuffix(value(source.Location), "/") && value(version.SourceVersion) != "" {
				return failure("InvalidInputException", "Source version should be empty for S3 folder source location")
			}
		}
		versions[id] = true
	}
	artifacts := make(map[string]bool, len(p.SecondaryArtifacts))
	for _, artifact := range p.SecondaryArtifacts {
		id := value(artifact.ArtifactIdentifier)
		if id == "" || artifacts[id] || id == value(p.Artifacts.ArtifactIdentifier) {
			return failure("InvalidInputException", "Secondary artifacts require unique artifact identifiers.")
		}
		artifacts[id] = true
		if value(artifact.Type) != "S3" {
			return unsupported("Only S3 secondary artifacts are supported.")
		}
		if value(artifact.Location) == "" || strings.Contains(value(artifact.Location), "/") {
			return failure("InvalidInputException", "S3 artifacts require a bucket name location.")
		}
		if artifact.BucketOwnerAccess != nil && value(artifact.BucketOwnerAccess) != "NONE" {
			return unsupported("Artifact bucket-owner grants are not supported.")
		}
	}
	return nil
}
