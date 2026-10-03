package iam

import (
	"context"
	"strings"
	"time"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// InstanceProfile is an account-global EC2 role container. RoleId is empty or
// references one immutable IAM role ID; role documents are read from live state.
type InstanceProfile struct {
	Path                string
	InstanceProfileName string
	InstanceProfileId   string
	Arn                 string
	CreateDate          time.Time
	RoleId              string
	Tags                []Tag
}

func (s *Service) instanceProfileHandlers() map[string]handler {
	return map[string]handler{
		"CreateInstanceProfile":         s.createInstanceProfile,
		"GetInstanceProfile":            s.getInstanceProfile,
		"ListInstanceProfiles":          s.listInstanceProfiles,
		"DeleteInstanceProfile":         deleteInstanceProfile,
		"AddRoleToInstanceProfile":      addRoleToInstanceProfile,
		"RemoveRoleFromInstanceProfile": removeRoleFromInstanceProfile,
		"ListInstanceProfilesForRole":   s.listInstanceProfilesForRole,
		"TagInstanceProfile":            tagInstanceProfile,
		"UntagInstanceProfile":          untagInstanceProfile,
		"ListInstanceProfileTags":       listInstanceProfileTags,
	}
}

func findInstanceProfile(a *account, name string) (*InstanceProfile, *awswire.Error) {
	if len(name) < 1 || len(name) > 128 || !namePattern.MatchString(name) {
		return nil, invalid("InstanceProfileName must contain 1-128 alphanumeric or _+=,.@- characters.")
	}
	profile := a.instanceProfiles[strings.ToLower(name)]
	if profile == nil {
		return nil, missing("instance profile", name)
	}
	return profile, nil
}

func (s *Service) createInstanceProfile(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	input, err := generatedIAMInput[iamapi.CreateInstanceProfileInput](ctx)
	if err != nil {
		return nil, err
	}
	name := inputString(input.InstanceProfileName)
	path, err := validPath(inputString(input.Path))
	if err != nil {
		return nil, err
	}
	tags, err := inputTags(input.Tags, "InstanceProfile")
	if err != nil {
		return nil, err
	}
	key := strings.ToLower(name)
	if a.instanceProfiles[key] != nil {
		return nil, duplicate("Instance profile", name)
	}
	if len(a.instanceProfiles) >= maxInstanceProfiles {
		return nil, limit("IAM instance profile quota exceeded.")
	}
	profile := &InstanceProfile{Path: path, InstanceProfileName: name, InstanceProfileId: newID("AIPA"), Arn: resourceARN(m, "instance-profile", path, name), CreateDate: a.currentTime, Tags: tags}
	a.instanceProfiles[key] = profile
	wire, err := s.wireInstanceProfile(ctx, a, m, profile, true)
	return &iamapi.CreateInstanceProfileOutput{InstanceProfile: wire}, err
}

func (s *Service) getInstanceProfile(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	input, err := generatedIAMInput[iamapi.GetInstanceProfileInput](ctx)
	if err != nil {
		return nil, err
	}
	profile, err := findInstanceProfile(a, inputString(input.InstanceProfileName))
	if err != nil {
		return nil, err
	}
	wire, err := s.wireInstanceProfile(ctx, a, m, profile, true)
	return &iamapi.GetInstanceProfileOutput{InstanceProfile: wire}, err
}

func deleteInstanceProfile(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	input, err := generatedIAMInput[iamapi.DeleteInstanceProfileInput](ctx)
	if err != nil {
		return nil, err
	}
	profile, err := findInstanceProfile(a, inputString(input.InstanceProfileName))
	if err != nil {
		return nil, err
	}
	if profile.RoleId != "" {
		return nil, conflict("Cannot delete instance profile with an associated role.")
	}
	delete(a.instanceProfiles, strings.ToLower(profile.InstanceProfileName))
	return &iamapi.DeleteInstanceProfileOutput{}, nil
}

func addRoleToInstanceProfile(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	input, err := generatedIAMInput[iamapi.AddRoleToInstanceProfileInput](ctx)
	if err != nil {
		return nil, err
	}
	profile, err := findInstanceProfile(a, inputString(input.InstanceProfileName))
	if err != nil {
		return nil, err
	}
	r, err := findRole(a, inputString(input.RoleName))
	if err != nil {
		return nil, err
	}
	if profile.RoleId != "" {
		return nil, limit("An instance profile can contain only one role.")
	}
	profile.RoleId = r.RoleId
	return &iamapi.AddRoleToInstanceProfileOutput{}, nil
}

func removeRoleFromInstanceProfile(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	input, err := generatedIAMInput[iamapi.RemoveRoleFromInstanceProfileInput](ctx)
	if err != nil {
		return nil, err
	}
	profile, err := findInstanceProfile(a, inputString(input.InstanceProfileName))
	if err != nil {
		return nil, err
	}
	r, err := findRole(a, inputString(input.RoleName))
	if err != nil {
		return nil, err
	}
	if profile.RoleId != r.RoleId {
		return nil, missing("instance profile role association", r.RoleName)
	}
	profile.RoleId = ""
	return &iamapi.RemoveRoleFromInstanceProfileOutput{}, nil
}
