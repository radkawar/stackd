package iam

import (
	"errors"
	"maps"
	"strings"

	policyeval "stackd/iam/policy"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type compiledSimulation struct {
	accountID        string
	partition        string
	resources        []string
	context          map[string][]string
	explicitContext  map[string][]string
	contextTypes     map[string]string
	policies         []simulationPolicy
	documents        []*policyeval.Document
	boundary         *simulationPolicy
	boundaryDocument *policyeval.Document
	resourceDocument *policyeval.Document
	principal        policyeval.Principal
	ownerAccount     string
	controls         [][]*policyeval.Document
}

func compileSimulation(input iamapi.SimulateCustomPolicyRequest, m awsctx.Metadata, principal simulationPrincipal, controls [][]string) (*compiledSimulation, *awswire.Error) {
	result := &compiledSimulation{accountID: m.AccountID, partition: m.Partition, resources: simulationStrings(input.ResourceArns), policies: principal.policies, boundary: principal.boundary}
	if len(result.resources) == 0 {
		result.resources = []string{"*"}
	}
	if err := validateSimulationResources(result.resources, inputString(input.ResourceHandlingOption)); err != nil {
		return nil, err
	}
	if err := validateSimulationActions(simulationStrings(input.ActionNames), result.resources); err != nil {
		return nil, err
	}
	if err := validateSimulationHandling(simulationStrings(input.ActionNames), result.resources, inputString(input.ResourceHandlingOption)); err != nil {
		return nil, err
	}
	var apiErr *awswire.Error
	result.context, result.contextTypes, apiErr = simulationContextEntries(input.ContextEntries)
	if apiErr != nil {
		return nil, apiErr
	}
	result.explicitContext = maps.Clone(result.context)
	for _, source := range result.policies {
		document, err := policyeval.ParseSimulation([]byte(source.document))
		if err != nil {
			return nil, simulationError(err)
		}
		result.documents = append(result.documents, document)
	}
	if result.boundary != nil {
		document, err := policyeval.ParseSimulation([]byte(result.boundary.document))
		if err != nil {
			return nil, simulationError(err)
		}
		result.boundaryDocument = document
	}
	for _, level := range controls {
		var documents []*policyeval.Document
		for _, input := range level {
			document, err := policyeval.ParseSimulation([]byte(input))
			if err != nil {
				return nil, simulationError(err)
			}
			documents = append(documents, document)
		}
		result.controls = append(result.controls, documents)
	}
	result.principal = policyeval.Principal{AccountID: m.AccountID, Partition: m.Partition, HasBoundary: result.boundary != nil}
	if input.CallerArn != nil {
		caller := string(*input.CallerArn)
		kind, name, apiErr := contextKeySourceARN(caller)
		if apiErr != nil {
			return nil, invalidInput("Invalid caller - Caller must be an IAM user, role or group in this context.")
		}
		parts := strings.SplitN(caller, ":", 6)
		result.principal.ARN, result.principal.AccountID, result.principal.Partition = caller, parts[4], parts[1]
		result.defaultContext("aws:principalarn", caller)
		result.defaultContext("aws:principalaccount", parts[4])
		result.defaultContext("aws:userid", caller)
		if kind == "user" {
			result.defaultContext("aws:username", name)
		}
		if caller == principal.arn {
			result.principal.ID = principal.id
		}
	}
	if input.CallerArn == nil {
		result.defaultContext("aws:principalaccount", m.AccountID)
		// AWS synthesizes this literal value; it does not use the authenticated
		// caller's IAM ID. See testdata/aws/iam/simulation_defaults.json.
		result.defaultContext("aws:userid", "STUB_PRINCIPAL_FOR_POLICY_SIMULATOR")
	}
	if input.ResourceOwner != nil {
		owner := string(*input.ResourceOwner)
		parts := strings.SplitN(owner, ":", 6)
		if len(parts) != 6 || parts[0] != "arn" || parts[1] == "" || parts[2] != "iam" || parts[3] != "" || len(parts[4]) != 12 || strings.Trim(parts[4], "0123456789") != "" || parts[5] == "" {
			return nil, invalidInput("Invalid Resource Owner.")
		}
		result.ownerAccount = parts[4]
	}
	if input.ResourcePolicy != nil {
		if result.principal.ARN == "" {
			return nil, invalidInput("Invalid caller - Caller cannot be null or empty.")
		}
		for _, resource := range result.resources {
			if resource == "*" {
				return nil, invalidInput("Invalid Entity Arn: * does not clearly define entity type and name.")
			}
		}
		document, err := policyeval.ParseResourceSimulation([]byte(*input.ResourcePolicy))
		if err != nil {
			return nil, simulationError(err)
		}
		for _, resource := range document.ResourcePatterns() {
			if resource == "*" {
				return nil, invalidInput("ResourceNames are not in a valid ARN format: *.")
			}
		}
		result.resourceDocument = document
	}
	return result, nil
}

// Caller-derived simulation context is only a default; explicit hypothetical
// ContextEntries override it. It never supplies the authenticated API context.
func (s *compiledSimulation) defaultContext(key, value string) {
	if _, supplied := s.context[key]; supplied {
		return
	}
	if s.context == nil {
		s.context = make(map[string][]string)
	}
	if s.contextTypes == nil {
		s.contextTypes = make(map[string]string)
	}
	s.context[key] = []string{value}
	s.contextTypes[key] = "string"
}

func simulationError(err error) *awswire.Error {
	if errors.Is(err, policyeval.ErrUnsupported) {
		return &awswire.Error{Code: "NotImplemented", Message: err.Error(), StatusCode: 501}
	}
	if errors.Is(err, policyeval.ErrInvalidRequest) || errors.Is(err, policyeval.ErrInvalidPolicy) {
		return invalidInput(err.Error())
	}
	return &awswire.Error{Code: "PolicyEvaluation", Message: err.Error(), StatusCode: 500}
}
