package codebuild

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/codebuild"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
)

type projectShareSource struct {
	identity SharedProject
	policies []authorization.BoundPolicy
}

func (g *projectShareSource) ResourcePolicies(_ context.Context, resource string) ([]authorization.BoundPolicy, error) {
	if resource != g.identity.ARN {
		return nil, nil
	}
	return g.policies, nil
}
func (g *projectShareSource) SharedProjects(context.Context, Scope) ([]SharedProject, error) {
	if len(g.policies) == 0 {
		return nil, nil
	}
	return []SharedProject{g.identity}, nil
}
func (g *projectShareSource) HasResourceShares(_ context.Context, resource string) (bool, error) {
	return resource == g.identity.ARN && len(g.policies) != 0, nil
}
func (g *projectShareSource) ResourceDeleted(_ context.Context, resource string) error {
	if resource == g.identity.ARN {
		g.policies = nil
	}
	return nil
}

type sharingIdentity struct{ set authorization.PolicySet }

func (s *sharingIdentity) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	return s.set, nil
}

func sharingContext(account string) context.Context {
	return awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", AccountID: account, Region: "us-east-1", PrincipalARN: "arn:aws:iam::" + account + ":root", PrincipalID: account})
}

func seedSharedProject(t *testing.T, authorizer authorization.Authorizer) (*Service, *projectShareSource, ProjectRecord, BuildRecord) {
	t.Helper()
	owner := scopeFor(controlContext())
	key := ProjectKey{Scope: owner, Name: "shared-build"}
	project := ProjectRecord{Key: key, Data: api.Project{Arn: new(api.String(key.ARN())), Name: new(api.ProjectName(key.Name)), Description: new(api.ProjectDescription("owner metadata"))}}
	buildKey := BuildKey{Scope: owner, ID: key.Name + ":00000000-0000-4000-8000-000000000001"}
	build := BuildRecord{Key: buildKey, Data: api.Build{
		Arn: new(api.NonEmptyString(buildKey.ARN())), Id: new(api.NonEmptyString(buildKey.ID)), ProjectName: new(api.NonEmptyString(key.Name)), BuildComplete: new(api.Boolean(true)), BuildStatus: new(api.StatusType("SUCCEEDED")),
		Logs:      &api.LogsLocation{GroupName: new(api.String("/aws/codebuild/shared-build")), StreamName: new(api.String("original-owner-stream"))},
		Artifacts: &api.BuildArtifacts{Location: new(api.String("arn:aws:s3:::owner-artifacts/build.zip"))},
	}}
	grants := &projectShareSource{identity: SharedProject{Scope: owner, ARN: key.ARN()}, policies: []authorization.BoundPolicy{{Document: fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"444455556666"},"Action":["codebuild:BatchGetProjects","codebuild:BatchGetBuilds","codebuild:ListBuildsForProject"],"Resource":%q}]}`, key.ARN())}}}
	s := New(Config{Authorizer: authorizer, ResourceShares: grants})
	t.Cleanup(func() { s.Close() })
	if err := s.repository.Update(controlContext(), func(tx Transaction) error {
		if err := tx.PutProject(project); err != nil {
			return err
		}
		return tx.PutBuild(build)
	}); err != nil {
		t.Fatal(err)
	}
	return s, grants, project, build
}

func assertSharingDenied(t *testing.T, err error) {
	t.Helper()
	if rejected := wireError(err); rejected == nil || rejected.Code != "AccessDeniedException" {
		t.Fatalf("want current permission denial, got %v", err)
	}
}

func TestSharedProjectReadsRetainOwnerAndRevoke(t *testing.T) {
	s, grants, project, build := seedSharedProject(t, nil)
	consumer := sharingContext("444455556666")
	readProject := func() error {
		return s.repository.Update(consumer, func(tx Transaction) error {
			out, err := s.batchGetProjects(tx.Context(), tx, &api.BatchGetProjectsInput{Names: api.ProjectNames{api.NonEmptyString(project.Key.ARN())}})
			if err == nil && (len(out.Projects) != 1 || value(out.Projects[0].Arn) != project.Key.ARN() || value(out.Projects[0].Description) != value(project.Data.Description)) {
				t.Fatalf("shared project was copied or re-owned: %+v", out)
			}
			return err
		})
	}
	readBuild := func() error {
		return s.repository.Update(consumer, func(tx Transaction) error {
			out, err := s.batchGetBuilds(tx.Context(), tx, &api.BatchGetBuildsInput{Ids: api.BuildIds{api.NonEmptyString(build.Key.ARN())}})
			if err == nil && (len(out.Builds) != 1 || value(out.Builds[0].Arn) != build.Key.ARN() || out.Builds[0].Logs == nil || value(out.Builds[0].Logs.StreamName) != "original-owner-stream" || out.Builds[0].Artifacts == nil || value(out.Builds[0].Artifacts.Location) != "arn:aws:s3:::owner-artifacts/build.zip") {
				t.Fatalf("shared build lost actual owner outputs: %+v", out)
			}
			return err
		})
	}
	if err := readProject(); err != nil {
		t.Fatal(err)
	}
	if err := readBuild(); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.Update(consumer, func(tx Transaction) error {
		listed, err := s.listSharedProjects(tx.Context(), tx, &api.ListSharedProjectsInput{})
		if err != nil {
			return err
		}
		if len(listed.Projects) != 1 || string(listed.Projects[0]) != project.Key.ARN() {
			t.Fatalf("shared project discovery = %+v", listed)
		}
		history, err := s.listBuildsForProject(tx.Context(), tx, &api.ListBuildsForProjectInput{ProjectName: new(api.NonEmptyString(project.Key.ARN()))})
		if err != nil {
			return err
		}
		if len(history.Ids) != 1 || string(history.Ids[0]) != build.Key.ARN() {
			t.Fatalf("shared history lost owner scope: %+v", history)
		}
		_, err = s.startBuild(tx.Context(), tx, &api.StartBuildInput{ProjectName: new(api.NonEmptyString(project.Key.ARN()))})
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("shared project reached execution admission: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	project.Data.Description = new(api.ProjectDescription("updated by owner"))
	if err := s.repository.Update(controlContext(), func(tx Transaction) error { return tx.PutProject(project) }); err != nil {
		t.Fatal(err)
	}
	if err := readProject(); err != nil {
		t.Fatal(err)
	}
	policies := grants.policies
	grants.policies = nil
	assertSharingDenied(t, readProject())
	assertSharingDenied(t, readBuild())
	if err := s.repository.Update(consumer, func(tx Transaction) error {
		out, err := s.listSharedProjects(tx.Context(), tx, &api.ListSharedProjectsInput{})
		if err == nil && len(out.Projects) != 0 {
			t.Fatalf("revoked project remained discoverable: %+v", out)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.Update(controlContext(), func(tx Transaction) error {
		_, err := s.deleteProject(tx.Context(), tx, &api.DeleteProjectInput{Name: new(api.NonEmptyString(project.Key.Name))})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveSharedProject(consumer, project.Key.ARN()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted project remained shareable: %v", err)
	}
	assertSharingDenied(t, readBuild())
	if err := s.repository.Update(controlContext(), func(tx Transaction) error { return tx.PutProject(project) }); err != nil {
		t.Fatal(err)
	}
	assertSharingDenied(t, readProject())
	assertSharingDenied(t, readBuild())
	grants.policies = policies
	if err := readProject(); err != nil {
		t.Fatal(err)
	}
	if err := readBuild(); err != nil {
		t.Fatal(err)
	}
	// An owner still inspects retained history under the original project ARN.
	if err := s.repository.Update(controlContext(), func(tx Transaction) error { return s.authorizeBuildRead(tx.Context(), tx, build) }); err != nil {
		t.Fatal(err)
	}
}

func TestSharedProjectBoundPrincipalAndIAMDenials(t *testing.T) {
	identity := &sharingIdentity{set: authorization.PolicySet{Identity: []policy.Policy{{Document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"codebuild:*","Resource":"*"}]}`}}}}
	s, grants, project, build := seedSharedProject(t, authorization.New(identity, nil))
	userARN := "arn:aws:iam::444455556666:user/reader"
	grants.policies = []authorization.BoundPolicy{{Document: fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":%q},"Action":["codebuild:BatchGetProjects","codebuild:BatchGetBuilds"],"Resource":%q}]}`, userARN, project.Key.ARN()), PrincipalIDs: map[string]string{userARN: "AIDAORIGINALREADER1234"}}}
	m := awsctx.FromContext(sharingContext("444455556666"))
	m.PrincipalARN, m.PrincipalID = userARN, "AIDAORIGINALREADER1234"
	read := func() error {
		return s.repository.Update(awsctx.WithMetadata(context.Background(), m), func(tx Transaction) error {
			return s.authorizeBuildRead(tx.Context(), tx, build)
		})
	}
	if err := read(); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.Update(awsctx.WithMetadata(context.Background(), m), func(tx Transaction) error {
		_, err := s.listBuildsForProject(tx.Context(), tx, &api.ListBuildsForProjectInput{ProjectName: new(api.NonEmptyString(project.Key.ARN()))})
		assertSharingDenied(t, err)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	m.PrincipalID = "AIDAREPLACEDREADER1234"
	assertSharingDenied(t, read())
	m.PrincipalID = "AIDAORIGINALREADER1234"
	identity.set.Identity = append(identity.set.Identity, policy.Policy{Document: fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"codebuild:BatchGetBuilds","Resource":%q}]}`, project.Key.ARN())})
	assertSharingDenied(t, read())
	identity.set.Identity = identity.set.Identity[:1]
	identity.set.HasBoundary = true
	assertSharingDenied(t, read())
	identity.set.HasBoundary = false
	m.HasSessionPolicy = true
	assertSharingDenied(t, read())
}

func TestSharedProjectTypedCommandsAndIsolation(t *testing.T) {
	s, _, project, build := seedSharedProject(t, nil)
	model, ok := awscatalog.LookupService("codebuild")
	if !ok {
		t.Fatal("CodeBuild model is missing")
	}
	call := func(ctx context.Context, action string, input any) (any, error) {
		t.Helper()
		operation, ok := model.Operation(action)
		if !ok {
			t.Fatalf("missing modeled operation %s", action)
		}
		out, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Input: input})
		if rejected != nil {
			return nil, rejected
		}
		return out, nil
	}
	consumer := sharingContext("444455556666")
	listed, err := call(consumer, "ListSharedProjects", &api.ListSharedProjectsInput{})
	if err != nil {
		t.Fatal(err)
	}
	if out := listed.(*api.ListSharedProjectsOutput); len(out.Projects) != 1 || string(out.Projects[0]) != project.Key.ARN() {
		t.Fatalf("typed shared discovery = %+v", out)
	}
	result, err := call(consumer, "BatchGetBuilds", &api.BatchGetBuildsInput{Ids: api.BuildIds{api.NonEmptyString(build.Key.ARN())}})
	if err != nil {
		t.Fatal(err)
	}
	if out := result.(*api.BatchGetBuildsOutput); len(out.Builds) != 1 || value(out.Builds[0].BuildStatus) != "SUCCEEDED" || value(out.Builds[0].Arn) != build.Key.ARN() {
		t.Fatalf("typed build inspection = %+v", out)
	}
	_, err = call(sharingContext("777788889999"), "BatchGetProjects", &api.BatchGetProjectsInput{Names: api.ProjectNames{api.NonEmptyString(project.Key.ARN())}})
	assertSharingDenied(t, err)
	m := awsctx.FromContext(consumer)
	m.Region = "us-west-2"
	result, err = call(awsctx.WithMetadata(context.Background(), m), "BatchGetProjects", &api.BatchGetProjectsInput{Names: api.ProjectNames{api.NonEmptyString(project.Key.ARN())}})
	if err != nil {
		t.Fatal(err)
	}
	if out := result.(*api.BatchGetProjectsOutput); len(out.Projects) != 0 || len(out.ProjectsNotFound) != 1 {
		t.Fatalf("shared lookup crossed endpoint region: %+v", out)
	}
	if _, err := s.ResolveSharedProject(consumer, "arn:aws:codebuild:us-east-1:111122223333:report-group/shared-build"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unimplemented report-group owner accepted: %v", err)
	}
	if err := s.AuthorizeResourceSharing(consumer, project.Key.ARN()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("consumer could reshare another owner's project: %v", err)
	}
}

func TestSharedProjectWithBuildsRequiresUnsharingBeforeDeletion(t *testing.T) {
	s, grants, project, build := seedSharedProject(t, nil)
	err := s.repository.Update(controlContext(), func(tx Transaction) error {
		_, err := s.deleteProject(tx.Context(), tx, &api.DeleteProjectInput{Name: new(api.NonEmptyString(project.Key.Name))})
		return err
	})
	if rejected := wireError(err); rejected == nil || rejected.Code != "InvalidInputException" {
		t.Fatalf("shared project with builds was deletable: %v", err)
	}
	grants.policies = nil
	if err := s.repository.Update(controlContext(), func(tx Transaction) error {
		if _, err := s.deleteProject(tx.Context(), tx, &api.DeleteProjectInput{Name: new(api.NonEmptyString(project.Key.Name))}); err != nil {
			return err
		}
		retained, err := tx.Build(build.Key)
		if err != nil {
			return err
		}
		return s.authorizeBuildRead(tx.Context(), tx, retained)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDeletedSharedProjectDoesNotRestoreOldAssociation(t *testing.T) {
	s, grants, project, build := seedSharedProject(t, nil)
	policies := grants.policies
	if err := s.repository.Update(controlContext(), func(tx Transaction) error {
		if err := tx.DeleteBuild(build.Key); err != nil {
			return err
		}
		_, err := s.deleteProject(tx.Context(), tx, &api.DeleteProjectInput{Name: new(api.NonEmptyString(project.Key.Name))})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.Update(controlContext(), func(tx Transaction) error { return tx.PutProject(project) }); err != nil {
		t.Fatal(err)
	}
	consumer := sharingContext("444455556666")
	read := func() error {
		return s.repository.Update(consumer, func(tx Transaction) error {
			_, err := s.batchGetProjects(tx.Context(), tx, &api.BatchGetProjectsInput{Names: api.ProjectNames{api.NonEmptyString(project.Key.ARN())}})
			return err
		})
	}
	assertSharingDenied(t, read())
	if err := s.repository.Update(consumer, func(tx Transaction) error {
		out, err := s.listSharedProjects(tx.Context(), tx, &api.ListSharedProjectsInput{})
		if err == nil && len(out.Projects) != 0 {
			t.Fatalf("deleted resource association reappeared: %+v", out)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	grants.policies = policies
	if err := read(); err != nil {
		t.Fatal(err)
	}
}
