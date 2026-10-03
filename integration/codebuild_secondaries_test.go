package stackd_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	buildtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"stackd"
)

func TestCodeBuildSecondaryProjectContracts(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			c, reopen := retainedCloud(t, backend, stackd.Config{})
			if _, err := s3NativeClient(c, "test", "test").CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: aws.String("source-bucket")}); err != nil {
				t.Fatal(err)
			}
			role, err := c.iam("test", "test", "").CreateRole(t.Context(), &iam.CreateRoleInput{
				RoleName: aws.String("secondary-build"), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"codebuild.amazonaws.com"},"Action":"sts:AssumeRole"}]}`),
			})
			if err != nil {
				t.Fatal(err)
			}
			client := fleetTaggingClient(c, "us-east-1", "test", "test")
			input := codebuild.CreateProjectInput{
				Name: aws.String("secondary-project"), ServiceRole: role.Role.Arn,
				Source:                  &buildtypes.ProjectSource{Type: buildtypes.SourceTypeS3, Location: aws.String("source-bucket/primary.zip")},
				Artifacts:               &buildtypes.ProjectArtifacts{Type: buildtypes.ArtifactsTypeNoArtifacts},
				Environment:             &buildtypes.ProjectEnvironment{Type: buildtypes.EnvironmentTypeLinuxContainer, ComputeType: buildtypes.ComputeTypeBuildGeneral1Small, Image: aws.String("busybox:1.38.0")},
				SecondarySources:        []buildtypes.ProjectSource{{Type: buildtypes.SourceTypeS3, SourceIdentifier: aws.String("Aux_1"), Location: aws.String("source-bucket/aux.zip")}},
				SecondarySourceVersions: []buildtypes.ProjectSourceVersion{{SourceIdentifier: aws.String("Aux_1"), SourceVersion: aws.String("old-version")}},
				SecondaryArtifacts:      []buildtypes.ProjectArtifacts{{Type: buildtypes.ArtifactsTypeS3, ArtifactIdentifier: aws.String("Output"), Location: aws.String("output-bucket"), Packaging: buildtypes.ArtifactPackagingZip, Name: aws.String("result.zip")}},
			}
			if _, err := client.CreateProject(t.Context(), &input); err != nil {
				t.Fatal(err)
			}
			read := func() buildtypes.Project {
				t.Helper()
				out, err := client.BatchGetProjects(t.Context(), &codebuild.BatchGetProjectsInput{Names: []string{*input.Name}})
				if err != nil || len(out.Projects) != 1 {
					t.Fatalf("read project: %+v %v", out, err)
				}
				return out.Projects[0]
			}
			assertConfig := func() {
				t.Helper()
				got := read()
				if !reflect.DeepEqual(got.SecondarySources, input.SecondarySources) || !reflect.DeepEqual(got.SecondaryArtifacts, input.SecondaryArtifacts) || !reflect.DeepEqual(got.SecondarySourceVersions, input.SecondarySourceVersions) {
					t.Fatalf("secondary configuration lost: %+v", got)
				}
			}
			assertConfig()
			cases := []struct {
				name   string
				update codebuild.UpdateProjectInput
			}{
				{"duplicate sources", codebuild.UpdateProjectInput{SecondarySources: append(append([]buildtypes.ProjectSource{}, input.SecondarySources...), input.SecondarySources[0])}},
				{"missing source identifier", codebuild.UpdateProjectInput{SecondarySources: []buildtypes.ProjectSource{{Type: buildtypes.SourceTypeS3, Location: aws.String("source-bucket/aux.zip")}}}},
				{"identifier punctuation", codebuild.UpdateProjectInput{SecondarySources: []buildtypes.ProjectSource{{Type: buildtypes.SourceTypeS3, SourceIdentifier: aws.String("bad-id"), Location: aws.String("source-bucket/aux.zip")}}}},
				{"identifier boundary", codebuild.UpdateProjectInput{SecondarySources: []buildtypes.ProjectSource{{Type: buildtypes.SourceTypeS3, SourceIdentifier: aws.String(strings.Repeat("a", 128)), Location: aws.String("source-bucket/aux.zip")}}}},
				{"unknown version source", codebuild.UpdateProjectInput{SecondarySourceVersions: []buildtypes.ProjectSourceVersion{{SourceIdentifier: aws.String("Missing"), SourceVersion: aws.String("v")}}}},
				{"duplicate versions", codebuild.UpdateProjectInput{SecondarySourceVersions: append(append([]buildtypes.ProjectSourceVersion{}, input.SecondarySourceVersions...), input.SecondarySourceVersions[0])}},
				{"duplicate artifacts", codebuild.UpdateProjectInput{SecondaryArtifacts: append(append([]buildtypes.ProjectArtifacts{}, input.SecondaryArtifacts...), input.SecondaryArtifacts[0])}},
				{"missing artifact identifier", codebuild.UpdateProjectInput{SecondaryArtifacts: []buildtypes.ProjectArtifacts{{Type: buildtypes.ArtifactsTypeS3, Location: aws.String("output-bucket")}}}},
				{"unsupported provider", codebuild.UpdateProjectInput{SecondarySources: []buildtypes.ProjectSource{{Type: buildtypes.SourceTypeCodecommit, SourceIdentifier: aws.String("Aux_1"), Location: aws.String("https://git-codecommit.us-east-1.amazonaws.com/v1/repos/repository")}}}},
				{"unsupported pipeline artifact", codebuild.UpdateProjectInput{SecondaryArtifacts: []buildtypes.ProjectArtifacts{{Type: buildtypes.ArtifactsTypeCodepipeline, ArtifactIdentifier: aws.String("Output")}}}},
			}
			for _, test := range cases {
				t.Run(test.name, func(t *testing.T) {
					test.update.Name = input.Name
					_, err := client.UpdateProject(t.Context(), &test.update)
					assertAPIError(t, err, "InvalidInputException")
					assertConfig()
				})
			}
			input.SecondarySources[0].SourceIdentifier = aws.String(strings.Repeat("a", 127))
			input.SecondarySourceVersions[0].SourceIdentifier = input.SecondarySources[0].SourceIdentifier
			input.SecondarySourceVersions[0].SourceVersion = aws.String("new-version")
			input.SecondaryArtifacts[0].Name = aws.String("new.zip")
			_, err = client.UpdateProject(t.Context(), &codebuild.UpdateProjectInput{Name: input.Name, SecondarySources: input.SecondarySources, SecondarySourceVersions: input.SecondarySourceVersions, SecondaryArtifacts: input.SecondaryArtifacts})
			if err != nil {
				t.Fatal(err)
			}
			assertConfig()
			c = reopen()
			client = fleetTaggingClient(c, "us-east-1", "test", "test")
			assertConfig()
		})
	}
}
