package eks

import (
	"context"
	"errors"
	"maps"
	"strings"

	"github.com/google/uuid"
	native "stackd/compute/eks"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/eks"
	"stackd/internal/awsctx"
)

func registerFargate(s *Service) {
	register(s, "CreateFargateProfile", s.createFargateProfile)
	register(s, "DescribeFargateProfile", s.describeFargateProfile)
	register(s, "ListFargateProfiles", s.listFargateProfiles)
	register(s, "DeleteFargateProfile", s.deleteFargateProfile)
}
func (s *Service) createFargateProfile(ctx context.Context, tx Transaction, in *api.CreateFargateProfileRequest) (*api.CreateFargateProfileResponse, error) {
	c, err := s.load(ctx, tx, value(in.ClusterName), "CreateFargateProfile")
	if err != nil {
		return nil, err
	}
	name := value(in.FargateProfileName)
	if !clusterName.MatchString(name) || strings.HasPrefix(strings.ToLower(name), "eks") {
		return nil, invalid("Invalid Fargate profile name.")
	}
	hash, err := requestHash(in)
	if err != nil {
		return nil, err
	}
	if old, e := tx.FargateProfile(c.Key, name); e == nil {
		if value(in.ClientRequestToken) != "" && old.ClientToken == value(in.ClientRequestToken) {
			if old.RequestHash != hash {
				return nil, invalid("ClientRequestToken was previously used with different parameters.")
			}
			return &api.CreateFargateProfileResponse{FargateProfile: fargateAPI(old)}, nil
		}
		return nil, failure("ResourceInUseException", "Fargate profile already exists.", 409)
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	profiles, err := tx.FargateProfiles(c.Key)
	if err != nil {
		return nil, err
	}
	for _, p := range profiles {
		if p.Status == "DELETING" {
			return nil, failure("ResourceInUseException", "A Fargate profile is being deleted.", 409)
		}
	}
	// TODO: Comeback apply approved Service Quotas increases to profile and selector limits.
	if len(profiles) >= 10 {
		return nil, failure("ResourceLimitExceededException", "The cluster has reached its Fargate profile limit.", 400)
	}
	if _, ok := s.runtime.(native.FargateRuntime); !ok || s.workloadRoles == nil {
		return nil, unsupported("A Fargate-capable Kubernetes runtime and IAM execution-role owner are required.")
	}
	if len(in.Selectors) > 5 {
		return nil, invalid("Specify no more than five Fargate selectors.")
	}
	p := FargateProfile{Key: c.Key, Name: name, ID: uuid.NewString(), RoleARN: value(in.PodExecutionRoleArn), Status: "CREATING", Operation: "create", ClientToken: value(in.ClientRequestToken), RequestHash: hash, Tags: tagsFromAPI(in.Tags), Subnets: stringsFromAPI(in.Subnets), Created: s.clock.Now(), Due: s.clock.Now(), Generation: 1}
	for _, sel := range in.Selectors {
		if len(sel.Labels) > 5 {
			return nil, invalid("Specify no more than five label pairs per Fargate selector.")
		}
		selector := native.FargateSelector{Namespace: value(sel.Namespace), Labels: map[string]string{}}
		for k, v := range sel.Labels {
			selector.Labels[string(k)] = string(v)
		}
		if err = native.ValidateFargateSelector(selector); err != nil {
			return nil, invalid(err.Error())
		}
		p.Selectors = append(p.Selectors, selector)
	}
	if len(p.Subnets) == 0 {
		p.Subnets = append([]string(nil), c.Subnets...)
	}
	if err = validateTags(p.Tags); err != nil {
		return nil, err
	}
	if err = s.authorize(ctx, c, "CreateFargateProfile", tagConditions(p.Tags)); err != nil {
		return nil, err
	}
	prefix := "arn:" + c.Key.Partition + ":iam::" + c.Key.AccountID + ":role/"
	if !strings.HasPrefix(p.RoleARN, prefix) || len(p.RoleARN) == len(prefix) {
		return nil, invalid("podExecutionRoleArn must name an IAM role in this account.")
	}
	if rejected := s.authorizer.Authorize(ctx, authorization.Request{Action: "iam:PassRole", ResourceARN: p.RoleARN, Context: map[string][]string{"iam:PassedToService": {"eks-fargate-pods.amazonaws.com"}}}); rejected != nil {
		return nil, rejected
	}
	if p.RoleID, err = s.workloadRoles.ValidateFargateExecutionRole(ctx, p.RoleARN, p.ARN()); err != nil {
		return nil, err
	}
	if err = s.workloadRoles.ValidateFargateSubnets(ctx, p.Key, c.VPCID, p.Subnets); err != nil {
		return nil, err
	}
	if err = queueComponents(s, tx, c); err != nil {
		return nil, err
	}
	if err = tx.PutFargateProfile(p); err != nil {
		return nil, err
	}
	return &api.CreateFargateProfileResponse{FargateProfile: fargateAPI(p)}, nil
}
func (s *Service) describeFargateProfile(ctx context.Context, tx Transaction, in *api.DescribeFargateProfileRequest) (*api.DescribeFargateProfileResponse, error) {
	_, p, err := s.loadFargate(ctx, tx, value(in.ClusterName), value(in.FargateProfileName), "DescribeFargateProfile")
	if err != nil {
		return nil, err
	}
	return &api.DescribeFargateProfileResponse{FargateProfile: fargateAPI(p)}, nil
}
func (s *Service) listFargateProfiles(ctx context.Context, tx Transaction, in *api.ListFargateProfilesRequest) (*api.ListFargateProfilesResponse, error) {
	c, err := s.load(ctx, tx, value(in.ClusterName), "ListFargateProfiles")
	if err != nil {
		return nil, err
	}
	profiles, err := tx.FargateProfiles(c.Key)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(profiles))
	for _, p := range profiles {
		names = append(names, p.Name)
	}
	page, next, err := pageStrings(names, value(in.NextToken), pageLimit(in.MaxResults), c.Key.ARN()+"/fargateprofiles")
	if err != nil {
		return nil, err
	}
	return &api.ListFargateProfilesResponse{FargateProfileNames: stringsToAPI(page), NextToken: next}, nil
}
func (s *Service) deleteFargateProfile(ctx context.Context, tx Transaction, in *api.DeleteFargateProfileRequest) (*api.DeleteFargateProfileResponse, error) {
	c, p, err := s.loadFargate(ctx, tx, value(in.ClusterName), value(in.FargateProfileName), "DeleteFargateProfile")
	if err != nil {
		return nil, err
	}
	if p.Status == "CREATING" {
		return nil, failure("ResourceInUseException", "Fargate profile is being created.", 409)
	}
	if p.Status != "DELETING" {
		p.Status = "DELETING"
		p.Operation = "delete"
		p.Generation++
		p.Due = s.clock.Now()
		if err = queueComponents(s, tx, c); err != nil {
			return nil, err
		}
		if err = tx.PutFargateProfile(p); err != nil {
			return nil, err
		}
	}
	return &api.DeleteFargateProfileResponse{FargateProfile: fargateAPI(p)}, nil
}
func fargateAPI(p FargateProfile) *api.FargateProfile {
	out := &api.FargateProfile{ClusterName: new(api.String(p.Key.Name)), FargateProfileName: new(api.String(p.Name)), FargateProfileArn: new(api.String(p.ARN())), PodExecutionRoleArn: new(api.String(p.RoleARN)), Status: new(api.FargateProfileStatus(p.Status)), CreatedAt: new(p.Created), Tags: tagsToAPI(p.Tags), Subnets: stringsToAPI(p.Subnets), Health: &api.FargateProfileHealth{Issues: api.FargateProfileIssueList{}}}
	for _, sel := range p.Selectors {
		labels := api.FargateProfileLabel{}
		for k, v := range sel.Labels {
			labels[api.String(k)] = api.String(v)
		}
		out.Selectors = append(out.Selectors, api.FargateProfileSelector{Namespace: new(api.String(sel.Namespace)), Labels: labels})
	}
	if p.Error != "" {
		out.Health.Issues = append(out.Health.Issues, api.FargateProfileIssue{Code: new(api.FargateProfileIssueCode("InternalFailure")), Message: new(api.String(p.Error))})
	}
	return out
}
func fargateSpec(c Cluster, p FargateProfile) native.FargateSpecification {
	return native.FargateSpecification{ClusterID: c.ID, ID: p.ID, Name: p.Name, RoleARN: p.RoleARN, RoleID: p.RoleID, Selectors: cloneFargateSelectors(p.Selectors), Delete: p.Operation == "delete"}
}
func cloneFargateSelectors(v []native.FargateSelector) []native.FargateSelector {
	out := make([]native.FargateSelector, len(v))
	for i, s := range v {
		out[i] = native.FargateSelector{Namespace: s.Namespace, Labels: maps.Clone(s.Labels)}
	}
	return out
}
func (s *Service) loadFargate(ctx context.Context, tx Reader, cluster, name, action string) (Cluster, FargateProfile, error) {
	k := Key{Scope: scopeFor(ctx), Name: cluster}
	p, err := tx.FargateProfile(k, name)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Cluster{}, p, err
	}
	if errors.Is(err, ErrNotFound) {
		p = FargateProfile{Key: k, Name: name, ID: "*"}
	}
	if denied := s.authorizeResource(ctx, p.ARN(), p.Tags, action, nil); denied != nil {
		return Cluster{}, p, denied
	}
	if err != nil {
		return Cluster{}, p, err
	}
	c, err := tx.Cluster(k)
	return c, p, err
}
func (s *Service) runtimeFargateProfiles(ctx context.Context, key Key) ([]native.FargateSpecification, error) {
	var out []native.FargateSpecification
	err := s.repository.View(ctx, func(tx Reader) error {
		cluster, err := tx.Cluster(key)
		if err != nil {
			return err
		}
		profiles, err := tx.FargateProfiles(key)
		if err != nil {
			return err
		}
		out = make([]native.FargateSpecification, len(profiles))
		for i, profile := range profiles {
			out[i] = native.FargateSpecification{
				ClusterID: cluster.ID, ID: profile.ID, Name: profile.Name,
				RoleARN: profile.RoleARN, RoleID: profile.RoleID, Selectors: profile.Selectors,
				Delete: profile.Operation == "delete", AdmissionDenied: profile.Status != "ACTIVE",
			}
		}
		return nil
	})
	return out, err
}

func (s *Service) authorizeFargatePod(ctx context.Context, k Key, profileID string) error {
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
	return s.repository.Update(ctx, func(tx Transaction) error {
		profiles, err := tx.FargateProfiles(k)
		if err != nil {
			return err
		}
		for _, p := range profiles {
			if p.ID != profileID {
				continue
			}
			if p.Status != "ACTIVE" || p.Operation == "delete" {
				return errors.New("fargate profile is not active")
			}
			if s.workloadRoles == nil {
				return errors.New("fargate execution-role owner unavailable")
			}
			id, err := s.workloadRoles.ValidateFargateExecutionRole(tx.Context(), p.RoleARN, p.ARN())
			if err != nil {
				return err
			}
			if id != p.RoleID {
				return errors.New("fargate execution role identity changed")
			}
			return nil
		}
		return ErrNotFound
	})
}
