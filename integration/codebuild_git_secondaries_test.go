package stackd_test

import (
	"os"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	buildtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd"
	buildruntime "stackd/compute/codebuild"
	"stackd/compute/docker"
)

func gitSecondaryProject(t *testing.T, c cloudClients) codebuild.CreateProjectInput {
	t.Helper()
	role, err := c.iam("test", "test", "").CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("git-secondary"), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"codebuild.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	sources := []buildtypes.ProjectSource{}
	for _, row := range []struct {
		id       string
		provider buildtypes.SourceType
		location string
	}{
		{"GitHub", buildtypes.SourceTypeGithub, "https://github.com/owner/repo.git"},
		{"Enterprise", buildtypes.SourceTypeGithubEnterprise, "https://enterprise.example.invalid/owner/repo.git"},
		{"Bitbucket", buildtypes.SourceTypeBitbucket, "https://bitbucket.org/owner/repo.git"},
		{"GitLab", buildtypes.SourceTypeGitlab, "https://gitlab.com/owner/repo.git/"},
		{"SelfManaged", buildtypes.SourceTypeGitlabSelfManaged, "https://gitlab.example.invalid/owner/repo.git/"},
	} {
		source := buildtypes.ProjectSource{Type: row.provider, Location: aws.String(row.location), SourceIdentifier: aws.String(row.id), GitCloneDepth: aws.Int32(2), Auth: &buildtypes.SourceAuth{Type: buildtypes.SourceAuthTypeSecretsManager, Resource: aws.String("missing-git-secret")}, Buildspec: aws.String("secondary-must-not-own-buildspec.yml")}
		if row.provider != buildtypes.SourceTypeGitlab && row.provider != buildtypes.SourceTypeGitlabSelfManaged {
			source.GitSubmodulesConfig = &buildtypes.GitSubmodulesConfig{FetchSubmodules: aws.Bool(true)}
		}
		sources = append(sources, source)
	}
	return codebuild.CreateProjectInput{Name: aws.String("git-secondary"), ServiceRole: role.Role.Arn, Source: &buildtypes.ProjectSource{Type: buildtypes.SourceTypeNoSource, Buildspec: aws.String("version: 0.2\nphases:\n  build:\n    commands: [true]\n")}, Artifacts: &buildtypes.ProjectArtifacts{Type: buildtypes.ArtifactsTypeNoArtifacts}, Environment: &buildtypes.ProjectEnvironment{Type: buildtypes.EnvironmentTypeLinuxContainer, ComputeType: buildtypes.ComputeTypeBuildGeneral1Small, Image: aws.String("busybox:1.38.0")}, SecondarySources: sources, SecondarySourceVersions: []buildtypes.ProjectSourceVersion{{SourceIdentifier: aws.String("Enterprise"), SourceVersion: aws.String("refs/heads/old")}, {SourceIdentifier: aws.String("SelfManaged"), SourceVersion: aws.String("refs/tags/keep")}}}
}

func TestCodeBuildGitSecondaryProjectContracts(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			c, reopen := retainedCloud(t, backend, stackd.Config{})
			input := gitSecondaryProject(t, c)
			client := fleetTaggingClient(c, "us-east-1", "test", "test")
			if _, err := client.CreateProject(t.Context(), &input); err != nil {
				t.Fatal(err)
			}
			assertProject := func() {
				t.Helper()
				out, err := client.BatchGetProjects(t.Context(), &codebuild.BatchGetProjectsInput{Names: []string{*input.Name}})
				if err != nil || len(out.Projects) != 1 {
					t.Fatalf("project: %+v %v", out, err)
				}
				p := out.Projects[0]
				if !reflect.DeepEqual(p.SecondarySources, input.SecondarySources) || !reflect.DeepEqual(p.SecondarySourceVersions, input.SecondarySourceVersions) || !reflect.DeepEqual(p.Source, input.Source) {
					t.Fatalf("retained Git configuration changed: %+v", p)
				}
			}
			for _, invalid := range []buildtypes.ProjectSource{
				{Type: buildtypes.SourceTypeGithub, Location: aws.String("https://foreign.example.invalid/repo.git")},
				{Type: buildtypes.SourceTypeCodecommit, Location: aws.String("https://git-codecommit.us-east-1.amazonaws.com/v1/repos/repo")},
				{Type: buildtypes.SourceTypeGithubEnterprise, Location: aws.String("https://enterprise.example.invalid/repo.git"), Auth: &buildtypes.SourceAuth{Type: buildtypes.SourceAuthTypeCodeconnections, Resource: aws.String("unowned-connection")}},
				{Type: buildtypes.SourceTypeGithubEnterprise, Location: aws.String("https://enterprise.example.invalid/repo.git"), ReportBuildStatus: aws.Bool(true)},
				{Type: buildtypes.SourceTypeGithubEnterprise, Location: aws.String("https://enterprise.example.invalid/repo.git"), InsecureSsl: aws.Bool(true)},
				{Type: buildtypes.SourceTypeGithub, Location: aws.String("https://github.com/owner/repo.git/")},
				{Type: buildtypes.SourceTypeGithubEnterprise, Location: aws.String("https://enterprise.example.invalid/repo.git/")},
				{Type: buildtypes.SourceTypeBitbucket, Location: aws.String("https://bitbucket.org/owner/repo.git/")},
				{Type: buildtypes.SourceTypeGitlab, Location: aws.String("https://gitlab.com/owner/repo.git"), GitSubmodulesConfig: &buildtypes.GitSubmodulesConfig{FetchSubmodules: aws.Bool(true)}},
				{Type: buildtypes.SourceTypeGitlabSelfManaged, Location: aws.String("https://gitlab.example.invalid/owner/repo.git"), GitSubmodulesConfig: &buildtypes.GitSubmodulesConfig{FetchSubmodules: aws.Bool(true)}},
			} {
				invalid.SourceIdentifier = aws.String("Enterprise")
				_, err := client.UpdateProject(t.Context(), &codebuild.UpdateProjectInput{Name: input.Name, SecondarySources: []buildtypes.ProjectSource{invalid}, SecondarySourceVersions: []buildtypes.ProjectSourceVersion{input.SecondarySourceVersions[0]}})
				assertAPIError(t, err, "InvalidInputException")
				assertProject()
			}
			duplicate := append([]buildtypes.ProjectSource{}, input.SecondarySources...)
			duplicate[1].Type, duplicate[1].Location = duplicate[0].Type, duplicate[0].Location
			_, err := client.UpdateProject(t.Context(), &codebuild.UpdateProjectInput{Name: input.Name, SecondarySources: duplicate})
			assertAPIError(t, err, "InvalidInputException")
			assertProject()
			c = reopen()
			client = fleetTaggingClient(c, "us-east-1", "test", "test")
			assertProject()
		})
	}
}

// The actual Docker owner is configured, not an executor mock. The deliberately
// absent secret prevents external Git access while admission and durable build
// snapshots are exercised; executable smoke proves successful native checkout.
func TestCodeBuildGitSecondaryBuildOverrides(t *testing.T) {
	if os.Getenv("STACKD_CODEBUILD_FLEET_TEST_IMAGE") == "" {
		t.Skip("set STACKD_CODEBUILD_FLEET_TEST_IMAGE to enable the real Docker owner")
	}
	engine, err := docker.New(t.Context(), docker.Config{Host: os.Getenv("STACKD_CODEBUILD_FLEET_TEST_DOCKER_HOST")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	executor, err := buildruntime.NewDockerExecutor(engine, buildruntime.DockerConfig{Namespace: "git-secondary-contract"})
	if err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			c, reopen := retainedCloud(t, backend, stackd.Config{CodeBuildExecutor: executor, ComputeEndpoint: "http://127.0.0.1:1"})
			input := gitSecondaryProject(t, c)
			client := fleetTaggingClient(c, "us-east-1", "test", "test")
			if _, err := client.CreateProject(t.Context(), &input); err != nil {
				t.Fatal(err)
			}
			sources := []buildtypes.ProjectSource{input.SecondarySources[1], input.SecondarySources[4]}
			sources[0].GitCloneDepth = aws.Int32(1)
			versions := []buildtypes.ProjectSourceVersion{{SourceIdentifier: aws.String("Enterprise"), SourceVersion: aws.String("refs/heads/new")}}
			started, err := client.StartBuild(t.Context(), &codebuild.StartBuildInput{ProjectName: input.Name, SecondarySourcesOverride: sources, SecondarySourcesVersionOverride: versions})
			if err != nil {
				t.Fatal(err)
			}
			expected := versions
			if !reflect.DeepEqual(started.Build.SecondarySources, sources) || !reflect.DeepEqual(started.Build.SecondarySourceVersions, expected) {
				t.Fatalf("accepted override lost independence: %+v", started.Build)
			}
			for _, invalid := range [][]buildtypes.ProjectSourceVersion{
				{{SourceIdentifier: aws.String("Missing"), SourceVersion: aws.String("new")}},
				{versions[0], versions[0]},
			} {
				_, err := client.StartBuild(t.Context(), &codebuild.StartBuildInput{ProjectName: input.Name, SecondarySourcesVersionOverride: invalid})
				assertAPIError(t, err, "InvalidInputException")
			}
			_, err = client.UpdateProject(t.Context(), &codebuild.UpdateProjectInput{Name: input.Name, SecondarySourceVersions: []buildtypes.ProjectSourceVersion{{SourceIdentifier: aws.String("Enterprise"), SourceVersion: aws.String("future")}}})
			if err != nil {
				t.Fatal(err)
			}
			c = reopen()
			client = fleetTaggingClient(c, "us-east-1", "test", "test")
			out, err := client.BatchGetBuilds(t.Context(), &codebuild.BatchGetBuildsInput{Ids: []string{*started.Build.Id}})
			if err != nil || len(out.Builds) != 1 {
				t.Fatalf("build after restart: %+v %v", out, err)
			}
			if !reflect.DeepEqual(out.Builds[0].SecondarySources, sources) || !reflect.DeepEqual(out.Builds[0].SecondarySourceVersions, expected) {
				t.Fatalf("restart reinterpreted accepted overrides: %+v", out.Builds[0])
			}
		})
	}
}
