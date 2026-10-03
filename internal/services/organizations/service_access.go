package organizations

import (
	"net/http"
	"regexp"

	api "stackd/internal/awsapi/organizations"
	"stackd/internal/awswire"
)

var servicePrincipalPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*\.amazonaws\.com(\.cn)?$`)

func (s *Service) registerServiceAccessOperations() {
	register(s, "EnableAWSServiceAccess", func(s *operationState, r *http.Request, in *api.EnableAWSServiceAccessInput) (*api.EnableAWSServiceAccessOutput, *awswire.Error) {
		return &api.EnableAWSServiceAccessOutput{}, s.changeServiceAccess(r, inputString(in.ServicePrincipal), true)
	})
	register(s, "DisableAWSServiceAccess", func(s *operationState, r *http.Request, in *api.DisableAWSServiceAccessInput) (*api.DisableAWSServiceAccessOutput, *awswire.Error) {
		return &api.DisableAWSServiceAccessOutput{}, s.changeServiceAccess(r, inputString(in.ServicePrincipal), false)
	})
	register(s, "ListAWSServiceAccessForOrganization", (*operationState).listServiceAccess)
	register(s, "RegisterDelegatedAdministrator", func(s *operationState, r *http.Request, in *api.RegisterDelegatedAdministratorInput) (*api.RegisterDelegatedAdministratorOutput, *awswire.Error) {
		return &api.RegisterDelegatedAdministratorOutput{}, s.changeDelegate(r, inputString(in.AccountId), inputString(in.ServicePrincipal), true)
	})
	register(s, "DeregisterDelegatedAdministrator", func(s *operationState, r *http.Request, in *api.DeregisterDelegatedAdministratorInput) (*api.DeregisterDelegatedAdministratorOutput, *awswire.Error) {
		return &api.DeregisterDelegatedAdministratorOutput{}, s.changeDelegate(r, inputString(in.AccountId), inputString(in.ServicePrincipal), false)
	})
	register(s, "ListDelegatedAdministrators", (*operationState).listDelegates)
	register(s, "ListDelegatedServicesForAccount", (*operationState).listDelegatedServices)
}

func (s *operationState) changeServiceAccess(r *http.Request, principal string, enable bool) *awswire.Error {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return err
	}
	if o.organization.FeatureSet != "ALL" {
		return failure("ConstraintViolationException", "ORGANIZATION_NOT_IN_ALL_FEATURES_MODE: Trusted service access requires all features.")
	}
	if !servicePrincipalPattern.MatchString(principal) {
		return failure("InvalidInputException", "Invalid service principal.")
	}
	// TODO: Comeback connect trusted access and delegated administrators to each service's account permissions and service-linked roles.
	if enable {
		if _, exists := o.services[principal]; !exists {
			o.services[principal] = s.timestamp()
		}
	} else {
		for _, delegated := range o.delegates {
			if _, exists := delegated[principal]; exists {
				return &awswire.Error{Code: "ConstraintViolationException", Reason: "DELEGATED_ADMINISTRATOR_EXISTS_FOR_THIS_SERVICE", Message: "You have delegated administrator/s for this service. De-register them in order to disable service access.", StatusCode: http.StatusBadRequest}
			}
		}
		delete(o.services, principal)
	}
	return nil
}

func (s *operationState) listServiceAccess(r *http.Request, in *api.ListAWSServiceAccessForOrganizationInput) (*api.ListAWSServiceAccessForOrganizationOutput, *awswire.Error) {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return nil, err
	}
	items := make(api.EnabledServicePrincipals, 0, len(o.services))
	for principal, enabled := range o.services {
		items = append(items, api.EnabledServicePrincipal{ServicePrincipal: new(api.ServicePrincipal(principal)), DateEnabled: timestamp(enabled)})
	}
	items, next, err := paginate(s, items, in, o.organization.ID+"/services", func(v api.EnabledServicePrincipal) string { return inputString(v.ServicePrincipal) })
	return &api.ListAWSServiceAccessForOrganizationOutput{EnabledServicePrincipals: items, NextToken: nextToken(next)}, err
}

func (s *operationState) changeDelegate(r *http.Request, accountID, principal string, register bool) *awswire.Error {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return err
	}
	a, ok := o.accounts[accountID]
	if !ok {
		return failure("AccountNotFoundException", "The account does not exist in this organization.")
	}
	if !servicePrincipalPattern.MatchString(principal) {
		return failure("InvalidInputException", "Invalid service principal.")
	}
	if accountID == o.organization.MasterAccountID {
		return failure("ConstraintViolationException", "CANNOT_REGISTER_MASTER_AS_DELEGATED_ADMINISTRATOR")
	}
	if o.organization.FeatureSet != "ALL" {
		return failure("ConstraintViolationException", "ORGANIZATION_NOT_IN_ALL_FEATURES_MODE")
	}
	delegations := o.delegates[accountID]
	_, exists := delegations[principal]
	if register {
		if a.State != "ACTIVE" {
			return failure("ConstraintViolationException", "CANNOT_REGISTER_SUSPENDED_ACCOUNT_AS_DELEGATED_ADMINISTRATOR")
		}
		if _, enabled := o.services[principal]; !enabled {
			return failure("ConstraintViolationException", "SERVICE_ACCESS_NOT_ENABLED")
		}
		if exists {
			return failure("AccountAlreadyRegisteredException", "The account is already registered for this service.")
		}
		if delegations == nil {
			delegations = make(map[string]float64)
			o.delegates[accountID] = delegations
		}
		delegations[principal] = s.timestamp()
	} else {
		if !exists {
			return failure("AccountNotRegisteredException", "The account is not registered for this service.")
		}
		delete(delegations, principal)
	}
	return nil
}

func (s *operationState) listDelegates(r *http.Request, in *api.ListDelegatedAdministratorsInput) (*api.ListDelegatedAdministratorsOutput, *awswire.Error) {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return nil, err
	}
	if inputString(in.ServicePrincipal) != "" && !servicePrincipalPattern.MatchString(inputString(in.ServicePrincipal)) {
		return nil, failure("InvalidInputException", "Invalid service principal.")
	}
	items := make(api.DelegatedAdministrators, 0)
	for id, services := range o.delegates {
		enabled := float64(0)
		found := false
		for principal, when := range services {
			if (inputString(in.ServicePrincipal) == "" || inputString(in.ServicePrincipal) == principal) && (!found || when < enabled) {
				enabled = when
				found = true
			}
		}
		if found {
			a := o.accountAPI(o.accounts[id])
			items = append(items, api.DelegatedAdministrator{Id: a.Id, Arn: a.Arn, Name: a.Name,
				Email: a.Email, State: a.State, Status: a.Status, JoinedMethod: a.JoinedMethod,
				JoinedTimestamp: a.JoinedTimestamp, DelegationEnabledDate: timestamp(enabled)})
		}
	}
	items, next, err := paginate(s, items, in, o.organization.ID+"/delegates/"+inputString(in.ServicePrincipal), func(v api.DelegatedAdministrator) string { return inputString(v.Id) })
	return &api.ListDelegatedAdministratorsOutput{DelegatedAdministrators: items, NextToken: nextToken(next)}, err
}

func (s *operationState) listDelegatedServices(r *http.Request, in *api.ListDelegatedServicesForAccountInput) (*api.ListDelegatedServicesForAccountOutput, *awswire.Error) {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return nil, err
	}
	if _, exists := o.accounts[inputString(in.AccountId)]; !exists {
		return nil, failure("AccountNotFoundException", "The account does not exist in this organization.")
	}
	items := make(api.DelegatedServices, 0)
	for principal, enabled := range o.delegates[inputString(in.AccountId)] {
		items = append(items, api.DelegatedService{ServicePrincipal: new(api.ServicePrincipal(principal)), DelegationEnabledDate: timestamp(enabled)})
	}
	items, next, err := paginate(s, items, in, o.organization.ID+"/delegated-services/"+inputString(in.AccountId), func(v api.DelegatedService) string { return inputString(v.ServicePrincipal) })
	return &api.ListDelegatedServicesForAccountOutput{DelegatedServices: items, NextToken: nextToken(next)}, err
}
