package iam

import (
	"strings"

	policyeval "stackd/iam/policy"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awswire"
)

type simulationMatch struct {
	sourceID, sourceType string
	match                policyeval.StatementMatch
}

type simulationDecision struct {
	decision      policyeval.Decision
	matches       []simulationMatch
	missing       []string
	boundary      *bool
	organizations *bool
	details       map[string]policyeval.Decision
}

func (s *compiledSimulation) resource(action, resource string) (simulationDecision, *awswire.Error) {
	request := policyeval.Request{Action: action, Resource: resource, Context: s.context, ContextTypes: s.contextTypes}
	result := simulationDecision{decision: policyeval.Allow}
	if len(s.controls) != 0 {
		control := policyeval.Allow
		for _, level := range s.controls {
			evaluation, err := policyeval.EvaluateSimulationDetailed(level, request)
			if err != nil {
				return result, simulationError(err)
			}
			control = restrictiveDecision(control, evaluation.Decision)
		}
		result.organizations = wirePointer(control == policyeval.Allow)
		if control != policyeval.Allow {
			result.decision = control
			return result, nil
		}
	}
	compatible, apiErr := simulationResourceCompatible(action, resource)
	if apiErr != nil {
		return result, apiErr
	}
	identity, err := policyeval.EvaluateSimulationDetailed(s.documents, request)
	if err != nil {
		return result, simulationError(err)
	}
	if !compatible {
		identity = policyeval.Evaluation{Decision: policyeval.ImplicitDeny, MissingContextValues: identity.MissingContextValues}
	}
	boundary := policyeval.Evaluation{Decision: policyeval.Allow}
	if s.boundaryDocument != nil {
		boundary, err = policyeval.EvaluateSimulationDetailed([]*policyeval.Document{s.boundaryDocument}, request)
		if err != nil {
			return result, simulationError(err)
		}
		if !compatible {
			boundary = policyeval.Evaluation{Decision: policyeval.ImplicitDeny, MissingContextValues: boundary.MissingContextValues}
		}
		result.boundary = wirePointer(boundary.Decision == policyeval.Allow)
	}
	resourcePolicy := policyeval.ResourceEvaluation{ResourceDecision: policyeval.ResourceDecision{Decision: policyeval.ImplicitDeny}}
	if s.resourceDocument != nil {
		resourcePolicy, err = policyeval.EvaluateResourceSimulationDetailed(s.resourceDocument, request, s.principal)
		if err != nil {
			return result, simulationError(err)
		}
		if !compatible {
			resourcePolicy = policyeval.ResourceEvaluation{ResourceDecision: policyeval.ResourceDecision{Decision: policyeval.ImplicitDeny}, MissingContextValues: resourcePolicy.MissingContextValues}
		}
	}
	owner := s.ownerAccount
	if owner == "" {
		if parts := strings.SplitN(resource, ":", 6); len(parts) == 6 {
			owner = parts[4]
		}
	}
	crossAccount := s.resourceDocument != nil && owner != "" && owner != s.principal.AccountID
	if crossAccount {
		result.details = map[string]policyeval.Decision{"IAM Policy": identity.Decision, "Resource Policy": resourcePolicy.Decision}
		if s.boundary != nil {
			result.details["Permissions Boundary Policy"] = boundary.Decision
		}
		result.decision = restrictiveDecision(identity.Decision, resourcePolicy.Decision)
	} else {
		result.decision = identity.Decision
		if resourcePolicy.Decision == policyeval.Allow {
			result.decision = policyeval.Allow
		}
	}
	// Explicit denies apply regardless of which layer grants permission. The
	// simulator grants same-account resource permission past an implicit boundary
	// denial, including account-root delegation; explicit boundary denies remain.
	if identity.Decision == policyeval.ExplicitDeny || resourcePolicy.Decision == policyeval.ExplicitDeny {
		result.decision = policyeval.ExplicitDeny
	}
	if crossAccount || resourcePolicy.Decision != policyeval.Allow || boundary.Decision == policyeval.ExplicitDeny {
		result.decision = restrictiveDecision(result.decision, boundary.Decision)
	}
	if result.decision == policyeval.ImplicitDeny {
		documents := append([]*policyeval.Document(nil), s.documents...)
		if s.boundaryDocument != nil {
			documents = append(documents, s.boundaryDocument)
		}
		if s.resourceDocument != nil {
			documents = append(documents, s.resourceDocument)
		}
		result.missing = policyeval.MissingSimulationContextValues(documents, s.explicitContext)
		return result, nil
	}
	for _, match := range identity.MatchedStatements {
		if match.Effect == result.decision {
			source := s.policies[match.DocumentIndex]
			result.matches = append(result.matches, simulationMatch{sourceID: source.sourceID, sourceType: "IAM Policy", match: match})
		}
	}
	for _, match := range resourcePolicy.MatchedStatements {
		if match.Effect == result.decision {
			result.matches = append(result.matches, simulationMatch{sourceID: "ResourcePolicy", sourceType: "Resource Policy", match: match})
		}
	}
	if result.decision == policyeval.ExplicitDeny && s.boundary != nil {
		for _, match := range boundary.MatchedStatements {
			if match.Effect == policyeval.ExplicitDeny {
				result.matches = append(result.matches, simulationMatch{sourceID: s.boundary.sourceID, sourceType: "Permissions Boundary Policy", match: match})
			}
		}
	}
	return result, nil
}

func restrictiveDecision(a, b policyeval.Decision) policyeval.Decision {
	if a == policyeval.ExplicitDeny || b == policyeval.ExplicitDeny {
		return policyeval.ExplicitDeny
	}
	if a == policyeval.ImplicitDeny || b == policyeval.ImplicitDeny {
		return policyeval.ImplicitDeny
	}
	return policyeval.Allow
}

func (s *compiledSimulation) evaluate(action string) (iamapi.EvaluationResult, *awswire.Error) {
	result := iamapi.EvaluationResult{
		EvalActionName:    wirePointer(iamapi.ActionNameType(action)),
		MatchedStatements: iamapi.StatementListType{}, MissingContextValues: iamapi.ContextKeyNamesResultListType{},
	}
	if name := s.aggregateResource(action); name != nil {
		result.EvalResourceName = wirePointer(iamapi.ResourceNameType(*name))
	}
	aggregate := simulationDecision{decision: policyeval.Allow}
	explicitResources := len(s.resources) != 1 || s.resources[0] != "*"
	for _, resource := range s.resources {
		decision, apiErr := s.resource(action, resource)
		if apiErr != nil {
			return result, apiErr
		}
		aggregate.decision = restrictiveDecision(aggregate.decision, decision.decision)
		aggregate.matches = append(aggregate.matches, decision.matches...)
		aggregate.missing = append(aggregate.missing, decision.missing...)
		aggregate.boundary = simulationAll(aggregate.boundary, decision.boundary)
		aggregate.organizations = simulationAll(aggregate.organizations, decision.organizations)
		if decision.details != nil {
			if aggregate.details == nil {
				aggregate.details = make(map[string]policyeval.Decision)
			}
			for kind, value := range decision.details {
				if previous, exists := aggregate.details[kind]; exists {
					value = restrictiveDecision(previous, value)
				}
				aggregate.details[kind] = value
			}
		}
		if explicitResources {
			specific := iamapi.ResourceSpecificResult{
				EvalResourceName: wirePointer(iamapi.ResourceNameType(resource)), EvalResourceDecision: wirePointer(iamapi.PolicyEvaluationDecisionType(decision.decision)),
				MatchedStatements: simulationStatements(decision.matches, decision.decision), MissingContextValues: simulationMissing(decision.missing),
				PermissionsBoundaryDecisionDetail: simulationBoundaryDetail(decision.boundary), EvalDecisionDetails: simulationDetails(decision.details),
			}
			if len(specific.MatchedStatements) == 0 {
				specific.MatchedStatements = nil
			}
			if len(specific.MissingContextValues) == 0 {
				specific.MissingContextValues = nil
			}
			result.ResourceSpecificResults = append(result.ResourceSpecificResults, specific)
		}
	}
	result.EvalDecision = wirePointer(iamapi.PolicyEvaluationDecisionType(aggregate.decision))
	result.MatchedStatements = simulationStatements(aggregate.matches, aggregate.decision)
	result.MissingContextValues = simulationMissing(aggregate.missing)
	result.PermissionsBoundaryDecisionDetail = simulationBoundaryDetail(aggregate.boundary)
	if aggregate.organizations != nil {
		result.OrganizationsDecisionDetail = &iamapi.OrganizationsDecisionDetail{AllowedByOrganizations: wirePointer(iamapi.BooleanType(*aggregate.organizations))}
	}
	result.EvalDecisionDetails = simulationDetails(aggregate.details)
	if explicitResources && result.EvalDecisionDetails == nil {
		result.EvalDecisionDetails = iamapi.EvalDecisionDetailsType{}
	}
	return result, nil
}
