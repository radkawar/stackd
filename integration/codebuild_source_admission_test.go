package stackd_test

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	buildtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"stackd"
)

// Native source captures 15baed3a31e5491f, 51143e720af345e9 and
// 104ba4096e17466c distinguish bucket existence from S3 authorization and
// establish that even description-only updates revalidate retained sources.
func TestCodeBuildSourceBucketAdmission(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			c, reopen := retainedCloud(t, backend, stackd.Config{})
			ctx := t.Context()
			identity := c.iam("test", "test", "")
			role, err := identity.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String("source-admission"), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"codebuild.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = identity.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: aws.String("deny-s3"), PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`)})
			if err != nil {
				t.Fatal(err)
			}
			client := fleetTaggingClient(c, "us-east-1", "test", "test")
			input := codebuild.CreateProjectInput{
				Name: aws.String("source-admission"), ServiceRole: role.Role.Arn,
				Source:      &buildtypes.ProjectSource{Type: buildtypes.SourceTypeS3},
				Artifacts:   &buildtypes.ProjectArtifacts{Type: buildtypes.ArtifactsTypeNoArtifacts},
				Environment: &buildtypes.ProjectEnvironment{Type: buildtypes.EnvironmentTypeLinuxContainer, ComputeType: buildtypes.ComputeTypeBuildGeneral1Small, Image: aws.String("busybox:1.38.0")},
			}
			for _, location := range []string{"missing-source/file.zip", "missing-source/folder/", "missing-source/"} {
				input.Source.Location = aws.String(location)
				_, err = client.CreateProject(ctx, &input)
				assertAPIError(t, err, "InvalidInputException")
			}
			absent, err := client.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{Names: []string{*input.Name}})
			if err != nil || len(absent.Projects) != 0 || len(absent.ProjectsNotFound) != 1 {
				t.Fatalf("rejected creation retained a project: %+v %v", absent, err)
			}
			objects := s3NativeClient(c, "test", "test")
			_, err = objects.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("admission-source")})
			if err != nil {
				t.Fatal(err)
			}
			input.Source.Location = aws.String("admission-source/missing.zip")
			created, err := client.CreateProject(ctx, &input)
			if err != nil {
				t.Fatal(err)
			}
			for _, location := range []string{"admission-source/empty/", "admission-source/"} {
				_, err = client.UpdateProject(ctx, &codebuild.UpdateProjectInput{Name: input.Name, Source: &buildtypes.ProjectSource{Type: buildtypes.SourceTypeS3, Location: aws.String(location)}})
				if err != nil {
					t.Fatal(err)
				}
			}
			noSource := &buildtypes.ProjectSource{Type: buildtypes.SourceTypeNoSource, Buildspec: aws.String("version: 0.2\nphases:\n  build:\n    commands: [true]\n")}
			secondary := []buildtypes.ProjectSource{{Type: buildtypes.SourceTypeS3, SourceIdentifier: aws.String("Aux"), Location: aws.String("missing-source/aux/")}}
			_, err = client.UpdateProject(ctx, &codebuild.UpdateProjectInput{Name: input.Name, Source: noSource, SecondarySources: secondary})
			assertAPIError(t, err, "InvalidInputException")
			retained, err := client.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{Names: []string{*input.Name}})
			if err != nil || len(retained.Projects) != 1 {
				t.Fatalf("retained project: %+v %v", retained, err)
			}
			if aws.ToString(retained.Projects[0].Source.Location) != "admission-source/" || len(retained.Projects[0].SecondarySources) != 0 {
				t.Fatalf("failed secondary update changed primary: %+v", retained.Projects[0])
			}
			secondary[0].Location = aws.String("admission-source/aux/")
			_, err = client.UpdateProject(ctx, &codebuild.UpdateProjectInput{Name: input.Name, Source: noSource, SecondarySources: secondary})
			if err != nil {
				t.Fatal(err)
			}
			user, err := identity.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String("source-admission-caller")})
			if err != nil {
				t.Fatal(err)
			}
			policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["codebuild:UpdateProject","codebuild:BatchGetProjects"],"Resource":%q},{"Effect":"Allow","Action":"iam:PassRole","Resource":%q},{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`, *created.Project.Arn, *role.Role.Arn)
			_, err = identity.PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: user.User.UserName, PolicyName: aws.String("admission"), PolicyDocument: &policy})
			if err != nil {
				t.Fatal(err)
			}
			key, err := identity.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: user.User.UserName})
			if err != nil {
				t.Fatal(err)
			}
			_, err = s3NativeClient(c, *key.AccessKey.AccessKeyId, *key.AccessKey.SecretAccessKey).HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String("admission-source")})
			if err == nil {
				t.Fatal("caller S3 denial control unexpectedly succeeded")
			}
			caller := fleetTaggingClient(c, "us-east-1", *key.AccessKey.AccessKeyId, *key.AccessKey.SecretAccessKey)
			_, err = caller.UpdateProject(ctx, &codebuild.UpdateProjectInput{Name: input.Name, ServiceRole: role.Role.Arn, Description: aws.String("accepted without S3 authority")})
			if err != nil {
				t.Fatal(err)
			}
			c = reopen()
			client = fleetTaggingClient(c, "us-east-1", "test", "test")
			objects = s3NativeClient(c, "test", "test")
			_, err = objects.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String("admission-source")})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.UpdateProject(ctx, &codebuild.UpdateProjectInput{Name: input.Name, Description: aws.String("must not commit")})
			assertAPIError(t, err, "InvalidInputException")
			retained, err = client.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{Names: []string{*input.Name}})
			if err != nil || len(retained.Projects) != 1 {
				t.Fatalf("retained after deletion: %+v %v", retained, err)
			}
			if aws.ToString(retained.Projects[0].Description) != "accepted without S3 authority" {
				t.Fatalf("failed update committed: %+v", retained.Projects[0])
			}
		})
	}
}
