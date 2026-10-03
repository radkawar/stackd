package ecr

import (
	"encoding/json"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ecr"
)

func (s *Service) bindPolicy(tx Transaction, text string) (authorization.BoundPolicy, error) {
	if !json.Valid([]byte(text)) {
		return authorization.BoundPolicy{}, failure("InvalidParameterException", "Invalid policy JSON.")
	}
	if s.binder == nil {
		return authorization.BoundPolicy{}, failure("ServerException", "Resource policy binding requires the IAM policy binder.")
	}
	bound, err := s.binder.BindResourcePolicy(tx.Context(), text, authorization.ResourcePolicyOptions{})
	if err != nil {
		return authorization.BoundPolicy{}, failure("InvalidParameterException", err.Error())
	}
	return bound, nil
}
func (s *Service) renderPolicy(tx Reader, p authorization.BoundPolicy) (string, error) {
	if s.binder == nil {
		return p.Document, nil
	}
	return s.binder.RenderResourcePolicy(tx.Context(), p)
}
func (s *Service) setRepositoryPolicy(tx Transaction, in *api.SetRepositoryPolicyInput) (*api.SetRepositoryPolicyOutput, error) {
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "SetRepositoryPolicy")
	if err != nil {
		return nil, err
	}
	bound, err := s.bindRepositoryPolicy(tx, value(in.PolicyText))
	if err != nil {
		return nil, err
	}
	repo.Policy = bound
	if in.Force == nil || !bool(*in.Force) {
		if err = s.authorize(tx, "SetRepositoryPolicy", repo, nil); err != nil {
			return nil, failure("InvalidParameterException", "The policy would prevent future policy changes; use force to confirm.")
		}
	}
	if err = tx.PutRepository(repo); err != nil {
		return nil, err
	}
	text, err := s.renderRepositoryPolicy(tx, bound)
	if err != nil {
		return nil, err
	}
	return &api.SetRepositoryPolicyOutput{RegistryId: new(api.RegistryId(repo.Key.AccountID)), RepositoryName: in.RepositoryName, PolicyText: new(api.RepositoryPolicyText(text))}, nil
}
func (s *Service) getRepositoryPolicy(tx Transaction, in *api.GetRepositoryPolicyInput) (*api.GetRepositoryPolicyOutput, error) {
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "GetRepositoryPolicy")
	if err != nil {
		return nil, err
	}
	if repo.Policy.Document == "" {
		return nil, failure("RepositoryPolicyNotFoundException", "No repository policy is configured.")
	}
	text, err := s.renderRepositoryPolicy(tx, repo.Policy)
	if err != nil {
		return nil, err
	}
	return &api.GetRepositoryPolicyOutput{RegistryId: new(api.RegistryId(repo.Key.AccountID)), RepositoryName: in.RepositoryName, PolicyText: new(api.RepositoryPolicyText(text))}, nil
}
func (s *Service) deleteRepositoryPolicy(tx Transaction, in *api.DeleteRepositoryPolicyInput) (*api.DeleteRepositoryPolicyOutput, error) {
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "DeleteRepositoryPolicy")
	if err != nil {
		return nil, err
	}
	if repo.Policy.Document == "" {
		return nil, failure("RepositoryPolicyNotFoundException", "No repository policy is configured.")
	}
	text, err := s.renderRepositoryPolicy(tx, repo.Policy)
	if err != nil {
		return nil, err
	}
	repo.Policy = authorization.BoundPolicy{}
	if err = tx.PutRepository(repo); err != nil {
		return nil, err
	}
	return &api.DeleteRepositoryPolicyOutput{RegistryId: new(api.RegistryId(repo.Key.AccountID)), RepositoryName: in.RepositoryName, PolicyText: new(api.RepositoryPolicyText(text))}, nil
}
func (s *Service) putRegistryPolicy(tx Transaction, in *api.PutRegistryPolicyInput) (*api.PutRegistryPolicyOutput, error) {
	scope := scopeFor(tx.Context())
	if err := s.authorize(tx, "PutRegistryPolicy", RepositoryRecord{Key: RepositoryKey{Scope: scope}}, nil); err != nil {
		return nil, err
	}
	r, err := s.registry(tx, scope)
	if err != nil {
		return nil, err
	}
	r.Policy, err = s.bindPolicy(tx, value(in.PolicyText))
	if err != nil {
		return nil, err
	}
	if err = tx.PutRegistry(r); err != nil {
		return nil, err
	}
	text, err := s.renderPolicy(tx, r.Policy)
	if err != nil {
		return nil, err
	}
	return &api.PutRegistryPolicyOutput{RegistryId: new(api.RegistryId(scope.AccountID)), PolicyText: new(api.RegistryPolicyText(text))}, nil
}
func (s *Service) getRegistryPolicy(tx Transaction, _ *api.GetRegistryPolicyInput) (*api.GetRegistryPolicyOutput, error) {
	scope := scopeFor(tx.Context())
	if err := s.authorize(tx, "GetRegistryPolicy", RepositoryRecord{Key: RepositoryKey{Scope: scope}}, nil); err != nil {
		return nil, err
	}
	r, err := s.registry(tx, scope)
	if err != nil {
		return nil, err
	}
	if r.Policy.Document == "" {
		return nil, failure("RegistryPolicyNotFoundException", "No registry policy is configured.")
	}
	text, err := s.renderPolicy(tx, r.Policy)
	if err != nil {
		return nil, err
	}
	return &api.GetRegistryPolicyOutput{RegistryId: new(api.RegistryId(scope.AccountID)), PolicyText: new(api.RegistryPolicyText(text))}, nil
}
func (s *Service) deleteRegistryPolicy(tx Transaction, _ *api.DeleteRegistryPolicyInput) (*api.DeleteRegistryPolicyOutput, error) {
	scope := scopeFor(tx.Context())
	if err := s.authorize(tx, "DeleteRegistryPolicy", RepositoryRecord{Key: RepositoryKey{Scope: scope}}, nil); err != nil {
		return nil, err
	}
	r, err := s.registry(tx, scope)
	if err != nil {
		return nil, err
	}
	if r.Policy.Document == "" {
		return nil, failure("RegistryPolicyNotFoundException", "No registry policy is configured.")
	}
	text, err := s.renderPolicy(tx, r.Policy)
	if err != nil {
		return nil, err
	}
	r.Policy = authorization.BoundPolicy{}
	if err = tx.PutRegistry(r); err != nil {
		return nil, err
	}
	return &api.DeleteRegistryPolicyOutput{RegistryId: new(api.RegistryId(scope.AccountID)), PolicyText: new(api.RegistryPolicyText(text))}, nil
}
