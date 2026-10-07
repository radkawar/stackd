package iam

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/scheduler"
)

const namespace = "https://iam.amazonaws.com/doc/2010-05-08/"

type handler func(context.Context, *account, awsctx.Metadata) (any, *awswire.Error)

// Service owns account-scoped IAM state. IAM resources are global across regions.
type Service struct {
	mu                     sync.Mutex
	repository             Repository
	authorizer             authorization.Authorizer
	handlers               map[string]handler
	credentials            CredentialStore
	accountIdentity        AccountIdentitySource
	oidcDiscovery          OIDCDiscovery
	serviceLinked          *serviceLinkedRuntime
	clock                  clock.Clock
	jobs                   *scheduler.Driver
	simulationControls     authorization.ControlSource
	organizationReports    OrganizationAccessSource
	rootAccess             RootAccessSource
	publicEndpoint         string
	credentialEvents       CredentialEvents
	apiCallEvents          apievents.Recorder
	serverCertificateUsage ServerCertificateUsage
}

// Config supplies IAM's typed state, credential lifecycle and service clock.
// Omitted dependencies select isolated memory state and wall-clock service time.
type Config struct {
	Credentials CredentialStore
	Repository  Repository
	Clock       clock.Clock
	// CredentialEvents appends session issuance and access-key API mutations in the IAM transaction.
	// Nil omits diagnostic events for standalone service consumers.
	CredentialEvents CredentialEvents
	// APICallEvents records authenticated IAM command outcomes.
	// Successful outcomes join IAM's resource transaction; nil omits capture.
	APICallEvents apievents.Recorder
	// SimulationControls supplies the simulated account's current SCP hierarchy.
	// It is separate from the authorizer protecting the simulation API request.
	SimulationControls authorization.ControlSource
	// OrganizationReports supplies management-account eligibility and the SCP
	// hierarchy through IAM's borrowed transaction context.
	OrganizationReports OrganizationAccessSource
	// RootAccess owns Organizations feature eligibility and mutations. These
	// operations join IAM's authority through its borrowed transaction context.
	RootAccess RootAccessSource
	// PublicEndpoint is the trusted, validated absolute origin used to publish
	// outbound identity discovery. Empty disables initial issuer provisioning.
	PublicEndpoint string
}

// New returns an empty IAM service.
func New() *Service {
	return NewWithRepository(nil, NewMemoryRepository(nil))
}

// NewWithRepository uses a pluggable typed IAM backend and shared credential
// lifecycle. A nil backend or credential store selects an isolated memory implementation.
func NewWithRepository(store CredentialStore, repository Repository) *Service {
	return NewWithConfig(Config{Credentials: store, Repository: repository})
}

// NewWithConfig constructs IAM with explicit time and storage dependencies.
func NewWithConfig(config Config) *Service {
	repository, store, source := config.Repository, config.Credentials, config.Clock
	if source == nil {
		source = clock.Real{}
	}
	if repository == nil {
		repository = NewMemoryRepository(nil)
	}
	if store == nil {
		store = identity.NewWithConfig(identity.Config{Repository: NewCredentialRepository(repository, config.CredentialEvents), Clock: source})
	}
	s := &Service{repository: repository, credentials: store, clock: source, simulationControls: config.SimulationControls, organizationReports: config.OrganizationReports, rootAccess: config.RootAccess, publicEndpoint: config.PublicEndpoint, credentialEvents: config.CredentialEvents, apiCallEvents: config.APICallEvents}
	s.initServiceLinkedRoles()
	s.jobs = scheduler.New(source, credentialReportJobs{s}, accessReportJobs{s}, serviceLinkedDeletionJobs{s})
	s.authorizer = authorization.NewWithClock(s, nil, source)
	s.handlers = map[string]handler{
		"GetAccountProperties":                      getAccountProperties,
		"PutAccountProperties":                      s.putAccountProperties,
		"GetRoleTemplateVersion":                    getRoleTemplateVersion,
		"AcquireRole":                               s.acquireRole,
		"SetSecurityTokenServicePreferences":        setSecurityTokenServicePreferences,
		"EnableOutboundWebIdentityFederation":       s.enableOutboundWebIdentityFederation,
		"DisableOutboundWebIdentityFederation":      disableOutboundWebIdentityFederation,
		"GetOutboundWebIdentityFederationInfo":      getOutboundWebIdentityFederationInfo,
		"GenerateOrganizationsAccessReport":         s.generateOrganizationsAccessReport,
		"GetOrganizationsAccessReport":              s.getOrganizationsAccessReport,
		"GenerateServiceLastAccessedDetails":        s.generateServiceLastAccessedDetails,
		"GetServiceLastAccessedDetails":             s.getServiceLastAccessedDetails,
		"GetServiceLastAccessedDetailsWithEntities": s.getServiceLastAccessedDetailsWithEntities,
		"ListPoliciesGrantingServiceAccess":         listPoliciesGrantingServiceAccess,
		"GenerateCredentialReport":                  s.generateCredentialReport,
		"GetCredentialReport":                       s.getCredentialReport,
		"GetAccountAuthorizationDetails":            s.getAccountAuthorizationDetails,
		"GetAccountSummary":                         s.getAccountSummary,
		"CreateUser":                                createUser, "GetUser": getUser, "ListUsers": listUsers, "UpdateUser": s.updateUser, "DeleteUser": s.deleteUser,
		"CreateAccessKey": s.createAccessKey, "ListAccessKeys": s.listAccessKeys, "UpdateAccessKey": s.updateAccessKey, "DeleteAccessKey": s.deleteAccessKey, "GetAccessKeyLastUsed": s.getAccessKeyLastUsed,
		"CreateGroup": createGroup, "GetGroup": getGroup, "ListGroups": listGroups, "UpdateGroup": updateGroup, "DeleteGroup": deleteGroup,
		"AddUserToGroup": addUserToGroup, "RemoveUserFromGroup": removeUserFromGroup, "ListGroupsForUser": listGroupsForUser,
		"CreateRole": s.createRole, "GetRole": s.getRole, "ListRoles": s.listRoles, "UpdateRole": updateRole, "UpdateRoleDescription": s.updateRoleDescription, "UpdateAssumeRolePolicy": s.updateAssumeRolePolicy, "DeleteRole": deleteRole,
		"CreatePolicy": createPolicy, "GetPolicy": getPolicy, "ListPolicies": listPolicies, "DeletePolicy": deletePolicy,
		"CreatePolicyVersion": createPolicyVersion, "GetPolicyVersion": getPolicyVersion, "ListPolicyVersions": listPolicyVersions, "SetDefaultPolicyVersion": setDefaultPolicyVersion, "DeletePolicyVersion": deletePolicyVersion,
		"ListEntitiesForPolicy":         listEntitiesForPolicy,
		"SimulateCustomPolicy":          simulateCustomPolicy,
		"SimulatePrincipalPolicy":       s.simulatePrincipalPolicy,
		"GetContextKeysForCustomPolicy": getContextKeysForCustomPolicy, "GetContextKeysForPrincipalPolicy": getContextKeysForPrincipalPolicy,
		"CreateVirtualMFADevice": createVirtualMFADevice, "DeleteVirtualMFADevice": deleteVirtualMFADevice,
		"EnableMFADevice": enableMFADevice, "DeactivateMFADevice": deactivateMFADevice, "ResyncMFADevice": resyncMFADevice,
		"ListMFADevices": listMFADevices, "ListVirtualMFADevices": listVirtualMFADevices,
		"CreateLoginProfile": createLoginProfile, "GetLoginProfile": getLoginProfile, "UpdateLoginProfile": updateLoginProfile, "DeleteLoginProfile": deleteLoginProfile,
		"ChangePassword":           changePassword,
		"GetAccountPasswordPolicy": getAccountPasswordPolicy, "UpdateAccountPasswordPolicy": updateAccountPasswordPolicy, "DeleteAccountPasswordPolicy": deleteAccountPasswordPolicy,
		"CreateAccountAlias": s.createAccountAlias, "ListAccountAliases": listAccountAliases, "DeleteAccountAlias": deleteAccountAlias,
		"CreateServiceSpecificCredential": createServiceSpecificCredential, "ListServiceSpecificCredentials": listServiceSpecificCredentials,
		"UpdateServiceSpecificCredential": updateServiceSpecificCredential, "ResetServiceSpecificCredential": resetServiceSpecificCredential, "DeleteServiceSpecificCredential": deleteServiceSpecificCredential,
	}
	for action, handler := range s.certificateHandlers() {
		s.handlers[action] = handler
	}
	for action, handler := range s.instanceProfileHandlers() {
		s.handlers[action] = handler
	}
	for action, handler := range s.federationHandlers() {
		s.handlers[action] = handler
	}
	for action, handler := range s.serviceLinkedHandlers() {
		s.handlers[action] = handler
	}
	for _, kind := range []string{"User", "Group", "Role"} {
		s.handlers["Put"+kind+"Policy"] = putInlinePolicy
		s.handlers["Get"+kind+"Policy"] = getInlinePolicy
		s.handlers["Delete"+kind+"Policy"] = deleteInlinePolicy
		s.handlers["List"+kind+"Policies"] = listInlinePolicies
		s.handlers["Attach"+kind+"Policy"] = attachPolicy
		s.handlers["Detach"+kind+"Policy"] = detachPolicy
		s.handlers["ListAttached"+kind+"Policies"] = listAttachedPolicies
	}
	for _, kind := range []string{"User", "Role", "Policy", "MFADevice"} {
		s.handlers["Tag"+kind] = tagResource
		s.handlers["Untag"+kind] = untagResource
		s.handlers["List"+kind+"Tags"] = listResourceTags
	}
	for _, kind := range []string{"User", "Role"} {
		s.handlers["Put"+kind+"PermissionsBoundary"] = putBoundary
		s.handlers["Delete"+kind+"PermissionsBoundary"] = deleteBoundary
	}
	return s
}

// SetAuthorizer connects Organizations controls and shared policy evaluation.
// Configure this boundary during instance assembly, before serving requests.
func (s *Service) SetAuthorizer(authorizer authorization.Authorizer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if authorizer == nil {
		authorizer = authorization.NewWithClock(s, nil, s.clock)
	}
	s.authorizer = authorizer
}

// Operations returns the supported Query operation names in lexical order.
func (s *Service) Operations() []string {
	names := make([]string, 0, len(s.handlers))
	for name := range s.handlers {
		names = append(names, name)
	}
	for name := range rootAccessActions {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	decoded, bound := awsapi.FromContext(r.Context())
	action := string(decoded.Operation.Name)
	var request awsapi.Request
	if !bound {
		q, err := awswire.ParseQuery(r, awscatalog.AWSQuery)
		if err != nil {
			awswire.QueryError(w, r, namespace, invalid("Invalid Query request: "+err.Error()))
			return
		}
		action, request.Query = q.Get("Action"), q
	}
	_, rootAccess := rootAccessActions[action]
	_, implemented := s.handlers[action]
	if !implemented && !rootAccess {
		if !bound {
			model, _ := awscatalog.LookupService("iam")
			decoded.Operation, _ = model.Operation(action)
		}
		_, apiErr := s.dispatch(awsapi.WithDecodedRequest(r.Context(), decoded), action, nil)
		awswire.QueryError(w, r, namespace, apiErr)
		return
	}
	// The gateway normally supplies this binding. Standalone use has the same
	// generated validation boundary, before authorization or state changes.
	if !bound {
		input, err := iamapi.DecodeRequest(action, request)
		if err != nil {
			apiErr := s.RequestError(action, err)
			if err := s.RecordRequestError(r.Context(), input, apiErr); err != nil {
				apiErr = &awswire.Error{Code: "ServiceFailure", Message: "Unable to record IAM API outcome.", StatusCode: 500}
			}
			awswire.QueryError(w, r, namespace, apiErr)
			return
		}
		r = r.WithContext(awsapi.WithDecodedRequest(r.Context(), input))
	}
	buffer := awswire.NewBuffer()
	_, apiErr := s.dispatch(r.Context(), action, func(result any) error {
		fields, err := iamapi.EncodeResponse(action, result)
		if err != nil {
			return err
		}
		awswire.WriteQueryBytes(buffer, r, namespace, action, fields)
		return nil
	})
	if apiErr != nil {
		awswire.QueryError(w, r, namespace, apiErr)
		return
	}
	buffer.Send(w)
}

// ExecuteCommand runs an admitted generated request through IAM's authority.
func (s *Service) ExecuteCommand(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	return s.dispatch(awsapi.WithDecodedRequest(ctx, decoded), string(decoded.Operation.Name), nil)
}

func (s *Service) dispatch(ctx context.Context, action string, prepareResponse func(any) error) (any, *awswire.Error) {
	command, rootAccess := rootAccessActions[action]
	h, implemented := s.handlers[action]
	if !implemented && !rootAccess {
		// TODO: Comeback complete IAM hardware/FIDO MFA, account/delegation features, noncommercial template resource-account and full partition/version conformance and full simulation; audit all IAM semantics, including nonempty root key/certificate/MFA responses, against AWS before service completion.
		apiErr := &awswire.Error{Code: "NotImplemented", Message: "IAM operation is not implemented: " + action, StatusCode: http.StatusNotImplemented}
		decoded, _ := awsapi.FromContext(ctx)
		if err := s.RecordRequestError(ctx, decoded, apiErr); err != nil {
			apiErr = &awswire.Error{Code: "ServiceFailure", Message: "Unable to record IAM API outcome.", StatusCode: 500}
		}
		return nil, apiErr
	}
	if rootAccess {
		return s.executeRootAccess(ctx, action, command, prepareResponse)
	}
	m := awsctx.FromContext(ctx)
	var output any
	s.mu.Lock()
	authorizer := s.authorizer
	s.mu.Unlock()
	requestContext := ctx
	var err error
	if federationNeedsPreparation(ctx) {
		err = s.repository.View(requestContext, func(tx ReadTx) error {
			now := s.clock.Now().UTC()
			a, err := loadAccount(tx, Scope{Partition: m.Partition, AccountID: m.AccountID})
			if err != nil {
				return err
			}
			a.currentTime = now
			ctx := context.WithValue(tx.Context(), transactionKey{}, serviceTransaction{service: s, tx: tx, currentTime: now})
			if apiErr := s.authorizeOperation(ctx, authorizer, a, m); apiErr != nil {
				return apiErr
			}
			return nil
		})
		if err == nil {
			var apiErr *awswire.Error
			requestContext, apiErr = s.prepareFederationRequest(requestContext)
			if apiErr != nil {
				err = apiErr
			}
		}
	}
	if err == nil {
		err = s.repository.Update(requestContext, func(tx WriteTx) error {
			now := s.clock.Now().UTC()
			scope := Scope{Partition: m.Partition, AccountID: m.AccountID}
			before, err := loadAccount(tx, scope)
			if err != nil {
				return err
			}
			a, err := loadAccount(tx, scope)
			if err != nil {
				return err
			}
			a.currentTime = now
			ctx := context.WithValue(tx.Context(), transactionKey{}, serviceTransaction{service: s, tx: tx, currentTime: now})
			if err := s.authorizeOperation(ctx, authorizer, a, m); err != nil {
				return err
			}
			if err := s.prepareAccountIdentity(ctx, a, m); err != nil {
				return err
			}
			result, apiErr := s.cloudFormationCommand(ctx, a, m, action, h)
			if apiErr != nil {
				return apiErr
			}
			if err := saveAccount(tx, scope, before, a); err != nil {
				return err
			}
			if prepareResponse != nil {
				if err := prepareResponse(result); err != nil {
					return err
				}
			}
			output = result
			return s.appendAPICall(ctx, now, result, nil)
		})
	}
	if err != nil {
		var apiErr *awswire.Error
		if !errors.As(err, &apiErr) {
			apiErr = &awswire.Error{Code: "ServiceFailure", Message: "IAM transaction failed.", StatusCode: 500}
		}
		if err := s.appendAPICall(ctx, s.clock.Now(), nil, apiErr); err != nil {
			apiErr = &awswire.Error{Code: "ServiceFailure", Message: "Unable to record IAM API outcome.", StatusCode: 500}
		}
		return nil, apiErr
	}
	if action == "DeleteServiceLinkedRole" || action == "GenerateCredentialReport" || action == "GenerateServiceLastAccessedDetails" || action == "GenerateOrganizationsAccessReport" {
		s.wakeJobs()
	}
	return output, nil
}
