package appconfig

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	api "stackd/internal/awsapi/appconfig"
	"stackd/internal/awswire"
)

const predefinedStrategyPrefix = "AppConfig."

func registerStrategies(s *Service) {
	register(s, "CreateDeploymentStrategy", s.createStrategy)
	register(s, "GetDeploymentStrategy", s.getStrategy)
	register(s, "UpdateDeploymentStrategy", s.updateStrategy)
	register(s, "DeleteDeploymentStrategy", s.deleteStrategy)
	register(s, "ListDeploymentStrategies", s.listStrategies)
}

// builtinStrategies returns the AWS predefined strategies in native list
// order, as returned by ListDeploymentStrategies in us-east-1 on 2026-09-28.
func builtinStrategies(sc Scope) []Strategy {
	return []Strategy{
		{Scope: sc, ID: "AppConfig.AllAtOnce", Name: "AppConfig.AllAtOnce", Description: "Quick", GrowthType: "LINEAR", ReplicateTo: "NONE", DurationMinutes: 0, FinalBakeMinutes: 10, GrowthFactor: 100},
		{Scope: sc, ID: "AppConfig.Linear50PercentEvery30Seconds", Name: "AppConfig.Linear50PercentEvery30Seconds", Description: "Test/Demo", GrowthType: "LINEAR", ReplicateTo: "NONE", DurationMinutes: 1, FinalBakeMinutes: 1, GrowthFactor: 50},
		{Scope: sc, ID: "AppConfig.Canary10Percent20Minutes", Name: "AppConfig.Canary10Percent20Minutes", Description: "AWS Recommended", GrowthType: "EXPONENTIAL", ReplicateTo: "NONE", DurationMinutes: 20, FinalBakeMinutes: 10, GrowthFactor: 10},
		{Scope: sc, ID: "AppConfig.Linear20PercentEvery6Minutes", Name: "AppConfig.Linear20PercentEvery6Minutes", Description: "AWS Recommended", GrowthType: "LINEAR", ReplicateTo: "NONE", DurationMinutes: 30, FinalBakeMinutes: 30, GrowthFactor: 20},
	}
}

func strategyOutput(v Strategy) api.DeploymentStrategy {
	return api.DeploymentStrategy{
		Id:                          textOf[api.Id](v.ID),
		Name:                        textOf[api.Name](v.Name),
		Description:                 textOf[api.Description](v.Description),
		DeploymentDurationInMinutes: new(api.MinutesBetween0And24Hours(v.DurationMinutes)),
		FinalBakeTimeInMinutes:      new(api.MinutesBetween0And24Hours(v.FinalBakeMinutes)),
		GrowthType:                  textOf[api.GrowthType](v.GrowthType),
		GrowthFactor:                new(api.Percentage(v.GrowthFactor)),
		ReplicateTo:                 textOf[api.ReplicateTo](v.ReplicateTo),
	}
}

// controlStrategy resolves custom or predefined strategies by ID and
// authorizes the deploymentstrategy resource element.
func (s *Service) controlStrategy(r Reader, action, id string) (Strategy, error) {
	sc := scopeFor(r.Context())
	v, err := findStrategy(r, sc, id)
	if notFound(err) {
		if denied := s.authorize(r.Context(), action, strategyARN(sc, id), nil); denied != nil {
			return Strategy{}, denied
		}
		return Strategy{}, failure("ResourceNotFoundException", fmt.Sprintf("DeploymentStrategy with Id %s could not be found.", id))
	}
	if err != nil {
		return Strategy{}, err
	}
	return v, s.authorizeResource(r, sc, action, strategyARN(sc, v.ID), v.Ownership)
}

func replicated(v Strategy) bool { return v.ReplicateTo == string(api.ReplicateToSSM_DOCUMENT) }

// strategyDocument applies a Systems Manager DeploymentStrategy document
// transition inside the strategy transaction, so the strategy, its document
// and the API event commit or roll back together. AppConfig reports owner
// rejections as a BadRequestException carrying the SSM error code. A document
// already deleted outside AppConfig does not block strategy deletion.
func (s *Service) strategyDocument(tx Transaction, v Strategy, apply func(StrategyDocuments, context.Context, Strategy) error, deleting bool) error {
	if s.strategyDocuments == nil {
		return failure("BadRequestException", "Deployment strategy SSM document replication is not configured.")
	}
	err := apply(s.strategyDocuments, tx.Context(), v)
	var e *awswire.Error
	if !errors.As(err, &e) || e.Code == "AccessDenied" || e.Code == "AccessDeniedException" {
		return err
	}
	if deleting && e.Code == "InvalidDocument" {
		return nil
	}
	wrapped := failure("BadRequestException", fmt.Sprintf("%s (Service: AWSSimpleSystemsManagement; Status Code: %d; Error Code: %s)", e.Message, e.StatusCode, e.Code))
	wrapped.Cause = e
	return wrapped
}

func (s *Service) createStrategy(tx Transaction, in *api.CreateDeploymentStrategyInput) (*api.DeploymentStrategy, error) {
	sc := scopeFor(tx.Context())
	if err := s.authorize(tx.Context(), "CreateDeploymentStrategy", "*", nil); err != nil {
		return nil, err
	}
	tags, err := createTags(in.Tags)
	if err != nil {
		return nil, err
	}
	v := Strategy{Scope: sc, Name: value(in.Name), Description: value(in.Description), GrowthType: value(in.GrowthType), ReplicateTo: value(in.ReplicateTo), DurationMinutes: number(in.DeploymentDurationInMinutes), FinalBakeMinutes: number(in.FinalBakeTimeInMinutes), Ownership: cloudFormationClaim(tx.Context(), "deploymentstrategy")}
	if in.GrowthFactor != nil {
		v.GrowthFactor = float64(*in.GrowthFactor)
	}
	if v.GrowthType == "" {
		v.GrowthType = string(api.GrowthTypeLINEAR)
	}
	if v.ReplicateTo == "" {
		v.ReplicateTo = string(api.ReplicateToNONE)
	}
	rows, err := tx.Strategies(sc)
	if err != nil {
		return nil, err
	}
	// Strategy names are not unique natively.
	v.ID = uniqueID(func(id string) bool {
		return slices.ContainsFunc(rows, func(s Strategy) bool { return s.ID == id })
	})
	if err := s.authorizeTagsOnCreate(tx.Context(), strategyARN(sc, v.ID), tags); err != nil {
		return nil, err
	}
	if err := tx.PutStrategy(v); err != nil {
		return nil, err
	}
	if replicated(v) {
		if err := s.strategyDocument(tx, v, StrategyDocuments.CreateStrategyDocument, false); err != nil {
			return nil, err
		}
	}
	if err := tx.PutTags(sc, strategyARN(sc, v.ID), tags); err != nil {
		return nil, err
	}
	out := strategyOutput(v)
	out.Description = in.Description
	return &out, nil
}

func (s *Service) getStrategy(tx Transaction, in *api.GetDeploymentStrategyInput) (*api.DeploymentStrategy, error) {
	v, err := s.controlStrategy(tx, "GetDeploymentStrategy", value(in.DeploymentStrategyId))
	if err != nil {
		return nil, err
	}
	out := strategyOutput(v)
	return &out, nil
}

// updateStrategy changes future deployments only; started deployments retain
// their copied strategy parameters.
func (s *Service) updateStrategy(tx Transaction, in *api.UpdateDeploymentStrategyInput) (*api.DeploymentStrategy, error) {
	v, err := s.controlStrategy(tx, "UpdateDeploymentStrategy", value(in.DeploymentStrategyId))
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(v.ID, predefinedStrategyPrefix) {
		return nil, failure("BadRequestException", "Cannot update predefined Deployment Strategy "+v.ID)
	}
	previous := v
	if in.Description != nil {
		v.Description = value(in.Description)
	}
	if in.DeploymentDurationInMinutes != nil {
		v.DurationMinutes = number(in.DeploymentDurationInMinutes)
	}
	if in.FinalBakeTimeInMinutes != nil {
		v.FinalBakeMinutes = number(in.FinalBakeTimeInMinutes)
	}
	if in.GrowthFactor != nil {
		v.GrowthFactor = float64(*in.GrowthFactor)
	}
	if in.GrowthType != nil {
		v.GrowthType = value(in.GrowthType)
	}
	if err := tx.PutStrategy(v); err != nil {
		return nil, err
	}
	// Native replication adds a document version only when content changes.
	if replicated(v) && v != previous {
		if err := s.strategyDocument(tx, v, StrategyDocuments.UpdateStrategyDocument, false); err != nil {
			return nil, err
		}
	}
	out := strategyOutput(v)
	if in.Description != nil {
		out.Description = in.Description
	}
	return &out, nil
}

// deleteStrategy leaves deployments intact because each deployment copies
// the strategy parameters it started with.
func (s *Service) deleteStrategy(tx Transaction, in *api.DeleteDeploymentStrategyInput) (*api.Unit, error) {
	v, err := s.controlStrategy(tx, "DeleteDeploymentStrategy", value(in.DeploymentStrategyId))
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(v.ID, predefinedStrategyPrefix) {
		return nil, failure("BadRequestException", "Cannot delete predefined Deployment Strategy "+v.ID+".")
	}
	if err := tx.DeleteStrategy(v.Scope, v.ID); err != nil {
		return nil, err
	}
	if replicated(v) {
		if err := s.strategyDocument(tx, v, StrategyDocuments.DeleteStrategyDocument, true); err != nil {
			return nil, err
		}
	}
	if err := tx.PutTags(v.Scope, strategyARN(v.Scope, v.ID), nil); err != nil {
		return nil, err
	}
	return &api.Unit{}, nil
}

// listStrategies lists custom strategies before the predefined strategies,
// as AWS does.
func (s *Service) listStrategies(tx Transaction, in *api.ListDeploymentStrategiesInput) (*api.DeploymentStrategies, error) {
	sc := scopeFor(tx.Context())
	if err := s.authorize(tx.Context(), "ListDeploymentStrategies", "*", nil); err != nil {
		return nil, err
	}
	rows, err := tx.Strategies(sc)
	if err != nil {
		return nil, err
	}
	customCount := len(rows)
	rows = append(rows, builtinStrategies(sc)...)
	rows, next, err := page(rows, in.NextToken, in.MaxResults, pageBinding(sc, "ListDeploymentStrategies"), func(i int) pageKey {
		if i < customCount {
			return pageKey{ID: rows[i].ID}
		}
		return pageKey{Number: int64(i-customCount) + 1, ID: rows[i].ID}
	})
	if err != nil {
		return nil, err
	}
	out := &api.DeploymentStrategies{Items: make(api.DeploymentStrategyList, 0, len(rows)), NextToken: next}
	for _, v := range rows {
		out.Items = append(out.Items, strategyOutput(v))
	}
	return out, nil
}
