package stackd_test

import (
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	buildtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"stackd"
)

// Native captures stackd-cb-folder-{1ca8154a9b13,admit-7e57b53393cf}
// distinguish a folder's current contents from a versioned ZIP source.
func TestCodeBuildFolderProjectContracts(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			c, reopen := retainedCloud(t, backend, stackd.Config{})
			if _, err := s3NativeClient(c, "test", "test").CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: aws.String("folder-source")}); err != nil {
				t.Fatal(err)
			}
			role, err := c.iam("test", "test", "").CreateRole(t.Context(), &iam.CreateRoleInput{
				RoleName: aws.String("folder-build"), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"codebuild.amazonaws.com"},"Action":"sts:AssumeRole"}]}`),
			})
			if err != nil {
				t.Fatal(err)
			}
			client := fleetTaggingClient(c, "us-east-1", "test", "test")
			sources := []buildtypes.ProjectSource{{Type: buildtypes.SourceTypeS3, SourceIdentifier: aws.String("Aux"), Location: aws.String("folder-source/aux/")}}
			input := codebuild.CreateProjectInput{
				Name: aws.String("folder-project"), ServiceRole: role.Role.Arn,
				Source:           &buildtypes.ProjectSource{Type: buildtypes.SourceTypeS3, Location: aws.String("folder-source/primary/")},
				SecondarySources: sources,
				Artifacts:        &buildtypes.ProjectArtifacts{Type: buildtypes.ArtifactsTypeNoArtifacts},
				Environment:      &buildtypes.ProjectEnvironment{Type: buildtypes.EnvironmentTypeLinuxContainer, ComputeType: buildtypes.ComputeTypeBuildGeneral1Small, Image: aws.String("busybox:1.38.0")},
			}
			if _, err := client.CreateProject(t.Context(), &input); err != nil {
				t.Fatal(err)
			}
			assertConfig := func(primary string) {
				t.Helper()
				out, err := client.BatchGetProjects(t.Context(), &codebuild.BatchGetProjectsInput{Names: []string{*input.Name}})
				if err != nil || len(out.Projects) != 1 {
					t.Fatalf("read folder project: %+v %v", out, err)
				}
				p := out.Projects[0]
				if aws.ToString(p.Source.Location) != primary || !reflect.DeepEqual(p.SecondarySources, sources) || aws.ToString(p.SourceVersion) != "" || len(p.SecondarySourceVersions) != 0 {
					t.Fatalf("folder acceptance snapshot changed: %+v", p)
				}
			}
			for _, update := range []codebuild.UpdateProjectInput{
				{Name: input.Name, SourceVersion: aws.String("object-version")},
				{Name: input.Name, SecondarySourceVersions: []buildtypes.ProjectSourceVersion{{SourceIdentifier: aws.String("Aux"), SourceVersion: aws.String("object-version")}}},
			} {
				_, err := client.UpdateProject(t.Context(), &update)
				assertAPIError(t, err, "InvalidInputException")
				assertConfig("folder-source/primary/")
			}
			_, err = client.UpdateProject(t.Context(), &codebuild.UpdateProjectInput{Name: input.Name, Source: &buildtypes.ProjectSource{Type: buildtypes.SourceTypeS3, Location: aws.String("folder-source/")}})
			if err != nil {
				t.Fatal(err)
			}
			c = reopen()
			client = fleetTaggingClient(c, "us-east-1", "test", "test")
			assertConfig("folder-source/")
		})
	}
}
