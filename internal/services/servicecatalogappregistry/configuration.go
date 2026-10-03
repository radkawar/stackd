package servicecatalogappregistry

import (
	api "stackd/internal/awsapi/servicecatalogappregistry"
)

func (s *Service) getConfiguration(tx Transaction, _ *api.Unit) (*api.GetConfigurationResponse, error) {
	if err := s.authorize(tx.Context(), "GetConfiguration", "*", nil, nil, nil); err != nil {
		return nil, err
	}
	c, err := tx.Configuration(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	q := &api.TagQueryConfiguration{}
	if c.TagKey != "" {
		q.TagKey = new(api.TagKeyConfig(c.TagKey))
	}
	return &api.GetConfigurationResponse{Configuration: &api.AppRegistryConfiguration{TagQueryConfiguration: q}}, nil
}
func (s *Service) putConfiguration(tx Transaction, in *api.PutConfigurationRequest) (*api.Unit, error) {
	if err := s.authorize(tx.Context(), "PutConfiguration", "*", nil, nil, nil); err != nil {
		return nil, err
	}
	key := ""
	if in.Configuration != nil && in.Configuration.TagQueryConfiguration != nil {
		key = value(in.Configuration.TagQueryConfiguration.TagKey)
	}
	if err := tx.PutConfiguration(Configuration{Scope: scopeFor(tx.Context()), TagKey: key}); err != nil {
		return nil, err
	}
	return &api.Unit{}, nil
}
