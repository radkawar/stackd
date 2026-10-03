package codebuild

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/codebuild"
)

// SharedProject identifies one current project, not a copy of its metadata.
type SharedProject struct {
	Scope
	ARN string
}

// ResourceShares supplies current resource policies inside the CodeBuild
// transaction. The shared IAM evaluator, not this source, decides permission.
type ResourceShares interface {
	ResourcePolicies(context.Context, string) ([]authorization.BoundPolicy, error)
	SharedProjects(context.Context, Scope) ([]SharedProject, error)
	HasResourceShares(context.Context, string) (bool, error)
	ResourceDeleted(context.Context, string) error
}

// SetResourceShares connects RAM after resource owners have been constructed.
// It must be called before serving requests or starting the service.
func (s *Service) SetResourceShares(shares ResourceShares) {
	s.resourceShares = shares
}

// ResolveSharedProject is the RAM owner boundary. Only existing projects are
// shareable; reports and report groups have no implemented resource owner.
func (s *Service) ResolveSharedProject(ctx context.Context, resource string) (SharedProject, error) {
	key, err := sharedProjectKey(scopeFor(ctx), resource)
	if err != nil || !strings.HasPrefix(resource, "arn:") {
		return SharedProject{}, ErrNotFound
	}
	var out SharedProject
	err = s.repository.View(ctx, func(tx Reader) error {
		project, err := tx.Project(key)
		if err != nil {
			return err
		}
		if value(project.Data.Arn) != key.ARN() {
			return ErrNotFound
		}
		out = SharedProject{Scope: key.Scope, ARN: key.ARN()}
		return nil
	})
	return out, err
}

// AuthorizeResourceSharing checks the current owner permission required for RAM
// to manage a CodeBuild project resource policy. It cannot reshare a recipient's
// project or turn a read grant into owner control.
func (s *Service) AuthorizeResourceSharing(ctx context.Context, resource string) error {
	key, err := projectKey(scopeFor(ctx), resource)
	if err != nil {
		return err
	}
	return s.repository.View(ctx, func(tx Reader) error {
		project, err := tx.Project(key)
		if err != nil {
			return err
		}
		return s.authorize(tx.Context(), "PutResourcePolicy", key.ARN(), tagConditions(project.Data.Tags))
	})
}

// Foreign reads require a full ARN in the endpoint's partition and region.
// Mutation paths deliberately retain the owner-only projectKey/buildKey helpers.
func sharedProjectKey(scope Scope, resource string) (ProjectKey, error) {
	if !strings.HasPrefix(resource, "arn:") {
		return projectKey(scope, resource)
	}
	owner, name, err := sharedResourceKey(scope, resource, "project/")
	if err != nil || !projectNamePattern.MatchString(name) {
		return ProjectKey{}, ErrNotFound
	}
	return ProjectKey{Scope: owner, Name: name}, nil
}

func sharedBuildKey(scope Scope, resource string) (BuildKey, error) {
	if !strings.HasPrefix(resource, "arn:") {
		return buildKey(scope, resource)
	}
	owner, id, err := sharedResourceKey(scope, resource, "build/")
	if err != nil {
		return BuildKey{}, err
	}
	return BuildKey{Scope: owner, ID: id}, nil
}

func sharedResourceKey(scope Scope, resource, prefix string) (Scope, string, error) {
	parsed, err := arn.Parse(resource)
	if err != nil || parsed.Service != "codebuild" || parsed.Partition != scope.Partition || parsed.Region != scope.Region || len(parsed.AccountID) != 12 || strings.Trim(parsed.AccountID, "0123456789") != "" || !strings.HasPrefix(parsed.Resource, prefix) {
		return Scope{}, "", ErrNotFound
	}
	name := strings.TrimPrefix(parsed.Resource, prefix)
	if name == "" || strings.Contains(name, "/") {
		return Scope{}, "", ErrNotFound
	}
	return Scope{Partition: parsed.Partition, AccountID: parsed.AccountID, Region: parsed.Region}, name, nil
}

func (s *Service) authorizeProject(ctx context.Context, action string, project ProjectRecord) error {
	var policies []authorization.BoundPolicy
	if s.resourceShares != nil && value(project.Data.Arn) == project.Key.ARN() {
		var err error
		policies, err = s.resourceShares.ResourcePolicies(ctx, project.Key.ARN())
		if err != nil {
			return err
		}
	}
	now := s.clock.Now()
	return errorOrNil(s.authorizer.Authorize(ctx, authorization.Request{
		Action: "codebuild:" + action, ResourceARN: project.Key.ARN(), ResourceAccountID: project.Key.AccountID,
		ResourcePolicies: policies, Context: tagConditions(project.Data.Tags), EvaluationTime: &now,
	}))
}

func (s *Service) authorizeBuildRead(ctx context.Context, tx Reader, build BuildRecord) error {
	key := ProjectKey{Scope: build.Key.Scope, Name: value(build.Data.ProjectName)}
	if !projectNamePattern.MatchString(key.Name) {
		return ErrNotFound
	}
	project, err := tx.Project(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if errors.Is(err, ErrNotFound) {
		// Retained owner history uses the recorded project ARN. A deleted
		// project's RAM associations are revoked by its deletion transaction.
		project = ProjectRecord{Key: key}
	}
	return s.authorizeProject(ctx, "BatchGetBuilds", project)
}

func (s *Service) listSharedProjects(ctx context.Context, tx Transaction, in *api.ListSharedProjectsInput) (*api.ListSharedProjectsOutput, error) {
	if err := s.authorize(ctx, "ListSharedProjects", "*", nil); err != nil {
		return nil, err
	}
	limit := 100
	if in.MaxResults != nil {
		limit = int(*in.MaxResults)
	}
	order, sortBy := value(in.SortOrder), value(in.SortBy)
	if limit < 1 || limit > 100 || order != "" && order != "ASCENDING" && order != "DESCENDING" || sortBy != "" && sortBy != "ARN" && sortBy != "MODIFIED_TIME" {
		return nil, failure("InvalidInputException", "Invalid shared project listing parameters.")
	}
	scope := scopeFor(ctx)
	var projects []ProjectRecord
	if s.resourceShares != nil {
		shared, err := s.resourceShares.SharedProjects(ctx, scope)
		if err != nil {
			return nil, err
		}
		seen := make(map[ProjectKey]bool, len(shared))
		for _, identity := range shared {
			key, err := sharedProjectKey(scope, identity.ARN)
			if err != nil || seen[key] {
				continue
			}
			project, err := tx.Project(key)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if err = s.authorizeProject(ctx, "BatchGetProjects", project); err != nil {
				if rejected := wireError(err); rejected.Code == "AccessDeniedException" {
					continue
				}
				return nil, err
			}
			seen[key] = true
			projects = append(projects, project)
		}
	}
	slices.SortFunc(projects, func(a, b ProjectRecord) int {
		n := 0
		if sortBy == "MODIFIED_TIME" {
			n = timestamp(a.Data.LastModified).Compare(timestamp(b.Data.LastModified))
		}
		n = cmp.Or(n, cmp.Compare(a.Key.Partition, b.Key.Partition), cmp.Compare(a.Key.Region, b.Key.Region), cmp.Compare(a.Key.AccountID, b.Key.AccountID), cmp.Compare(a.Key.Name, b.Key.Name))
		if order == "DESCENDING" {
			return -n
		}
		return n
	})
	projects, next, err := page(scope, "shared-projects/"+sortBy+"/"+order, value(in.NextToken), projects, limit)
	if err != nil {
		return nil, err
	}
	out := &api.ListSharedProjectsOutput{NextToken: next}
	for _, project := range projects {
		out.Projects = append(out.Projects, api.NonEmptyString(project.Key.ARN()))
	}
	return out, nil
}
