package organizations

import (
	"net/http"
	"strings"

	api "stackd/internal/awsapi/organizations"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/identitystore"
)

func (s *Service) registerOrganizationOperations() {
	register(s, "CreateOrganization", (*operationState).createOrganization)
	register(s, "DescribeOrganization", func(s *operationState, r *http.Request, _ *api.DescribeOrganizationInput) (*api.DescribeOrganizationOutput, *awswire.Error) {
		o, err := s.organizationFor(r, false)
		if err != nil {
			return nil, err
		}
		if identitystore.CheckCloudFormationOwner(r.Context(), o.organization.CloudFormationOwner) != nil {
			return nil, failure("AccessDeniedException", "Organization is not owned by this CloudFormation incarnation.")
		}
		return &api.DescribeOrganizationOutput{Organization: new(o.organization.api())}, nil
	})
	register(s, "DeleteOrganization", func(s *operationState, r *http.Request, _ *api.DeleteOrganizationInput) (*api.DeleteOrganizationOutput, *awswire.Error) {
		o, err := s.organizationFor(r, true)
		if err != nil {
			return nil, err
		}
		if identitystore.CheckCloudFormationOwner(r.Context(), o.organization.CloudFormationOwner) != nil {
			return nil, failure("AccessDeniedException", "Organization is not owned by this CloudFormation incarnation.")
		}
		for _, job := range o.creations {
			if job.State == "IN_PROGRESS" {
				return nil, failure("ConcurrentModificationException", "Account creation is in progress.")
			}
		}
		if len(o.accounts) != 1 {
			return nil, failure("OrganizationNotEmptyException", "Remove all member accounts before deleting the organization.")
		}
		delete(s.memberships, o.organization.MasterAccountID)
		s.removeEffectivePolicies(o, "", awsctx.FromContext(r.Context()))
		delete(s.orgs, o.organization.ID)
		return &api.DeleteOrganizationOutput{}, nil
	})
	register(s, "ListRoots", func(s *operationState, r *http.Request, in *api.ListRootsInput) (*api.ListRootsOutput, *awswire.Error) {
		o, err := s.organizationFor(r, true)
		if err != nil {
			return nil, err
		}
		items, next, err := paginate(s, []api.Root{o.root.api()}, in, o.organization.ID+"/roots", func(v api.Root) string { return inputString(v.Id) })
		return &api.ListRootsOutput{Roots: items, NextToken: nextToken(next)}, err
	})
}

func (s *operationState) createOrganization(r *http.Request, in *api.CreateOrganizationInput) (*api.CreateOrganizationOutput, *awswire.Error) {
	meta := awsctx.FromContext(r.Context())
	if existingID, exists := s.memberships[meta.AccountID]; exists {
		existing := s.orgs[existingID]
		if owner := identitystore.CloudFormationOwner(r.Context()); owner != "" && existing != nil && existing.organization.CloudFormationOwner == owner {
			return &api.CreateOrganizationOutput{Organization: new(existing.organization.api())}, nil
		}
		return nil, failure("AlreadyInOrganizationException", "This account already belongs to an organization.")
	}
	featureSet := "ALL"
	if in.FeatureSet != nil {
		featureSet = string(*in.FeatureSet)
	}
	if meta.Partition == "aws-us-gov" && featureSet == "CONSOLIDATED_BILLING" {
		return nil, failure("ConstraintViolationException", "CREATE_ORGANIZATION_IN_BILLING_MODE_UNSUPPORTED_REGION")
	}
	id := identifier("o-", 6)
	initial := bootstrapAccount(meta.AccountID)
	if existing, ok := s.knownAccounts[meta.AccountID]; ok {
		if existing.State != "ACTIVE" {
			return nil, failure("ConstraintViolationException", "ACCOUNT_CREATION_NOT_COMPLETE: The management account must be active.")
		}
		initial = existing
	}
	email, name := initial.Email, initial.Name
	o := &orgState{
		organization: organization{ID: id, ARN: "arn:" + meta.Partition + ":organizations::" + meta.AccountID + ":organization/" + id, FeatureSet: featureSet, MasterAccountID: meta.AccountID, MasterAccountEmail: email, AvailablePolicyTypes: []policyType{}},
		accounts:     make(map[string]account), units: make(map[string]organizationalUnit), parents: make(map[string]string), creations: make(map[string]AccountCreationRecord), policies: make(map[string]policy), attachments: make(map[string][]string), tags: make(map[string]map[string]string), services: make(map[string]float64), delegates: make(map[string]map[string]float64),
	}
	o.organization.CloudFormationOwner = identitystore.CloudFormationOwner(r.Context())
	o.organization.MasterAccountARN = o.arn(meta.Partition, "account", meta.AccountID)
	o.root = root{ID: identifier("r-", 2), Name: "Root", PolicyTypes: []policyType{}}
	o.root.ARN = o.arn(meta.Partition, "root", o.root.ID)
	o.accounts[meta.AccountID] = account{ID: meta.AccountID, ARN: o.organization.MasterAccountARN, Name: name, Email: email, State: "ACTIVE", Status: "ACTIVE", JoinedMethod: "INVITED", JoinedTimestamp: s.timestamp()}
	o.parents[meta.AccountID] = o.root.ID
	if featureSet == "ALL" {
		o.root.PolicyTypes = []policyType{{Type: "SERVICE_CONTROL_POLICY", Status: "ENABLED"}}
		o.organization.AvailablePolicyTypes = []policyType{{Type: "SERVICE_CONTROL_POLICY", Status: "ENABLED"}}
		o.installFullAccessPolicy("SERVICE_CONTROL_POLICY")
		o.attachDefaults(o.root.ID)
		o.attachDefaults(meta.AccountID)
	}
	s.orgs[id] = o
	s.memberships[meta.AccountID] = id
	s.knownEmails[strings.ToLower(email)] = meta.AccountID
	s.knownAccounts[meta.AccountID] = o.accounts[meta.AccountID]
	s.accountProvisioning = &AccountProvisioning{Partition: meta.Partition, AccountID: meta.AccountID, ManagementAccountID: meta.AccountID, CreatedAt: s.instant}
	return &api.CreateOrganizationOutput{Organization: new(o.organization.api())}, nil
}
