package organizations

import (
	"context"
	"net/http"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// RootAccessFeature identifies one independently configurable organization-wide
// IAM root access feature.
type RootAccessFeature string

const (
	RootCredentialsManagement RootAccessFeature = "RootCredentialsManagement"
	RootSessions              RootAccessFeature = "RootSessions"
)

// RootAccessFeatures is Organizations-owned state. Disabling IAM trusted access
// makes these settings inaccessible without deleting them or changing any root
// credentials. Root credential records remain owned by IAM.
type RootAccessFeatures struct {
	CredentialsManagement bool
	Sessions              bool
}

// RootAccessFeatures authorizes IAM's ListOrganizationsFeatures operation and
// returns the organization's current root access settings. Organizations API
// permissions are not an additional requirement for this IAM operation.
func (s *Service) RootAccessFeatures(ctx context.Context) (string, RootAccessFeatures, error) {
	state, _, err := s.authorizedRootAccessState(ctx, "iam:ListOrganizationsFeatures")
	if err != nil {
		return "", RootAccessFeatures{}, err
	}
	o, apiErr := state.rootAccessOrganization(false)
	if apiErr != nil {
		return "", RootAccessFeatures{}, apiErr
	}
	return o.organization.ID, o.rootAccess, nil
}

// SetRootAccessFeature authorizes and commits one IAM root feature transition in
// Organizations storage. IAM's API calls it inside the shared authority
// transaction, so permission reads and feature writes commit together. A
// standalone call uses optimistic revision checks and repeats authorization
// after a conflicting Organizations commit.
func (s *Service) SetRootAccessFeature(ctx context.Context, feature RootAccessFeature, enabled bool) (string, RootAccessFeatures, error) {
	if feature != RootCredentialsManagement && feature != RootSessions {
		return "", RootAccessFeatures{}, rootFeatureError("InvalidInput", "Unknown organization root access feature.")
	}
	action := "iam:DisableOrganizations" + string(feature)
	if enabled {
		action = "iam:EnableOrganizations" + string(feature)
	}
	for attempt := 0; attempt < 16; attempt++ {
		state, revision, err := s.authorizedRootAccessState(ctx, action)
		if err != nil {
			return "", RootAccessFeatures{}, err
		}
		o, apiErr := state.rootAccessOrganization(enabled)
		if apiErr != nil {
			return "", RootAccessFeatures{}, apiErr
		}
		previous := o.rootAccess
		switch feature {
		case RootCredentialsManagement:
			o.rootAccess.CredentialsManagement = enabled
		case RootSessions:
			o.rootAccess.Sessions = enabled
		}
		if previous == o.rootAccess {
			return o.organization.ID, o.rootAccess, nil
		}
		committed, err := s.storage.CompareAndSwap(ctx, state.partition, revision, state.record(), nil)
		if err != nil {
			return "", RootAccessFeatures{}, rootFeatureStorageError(ctx)
		}
		if committed {
			return o.organization.ID, o.rootAccess, nil
		}
	}
	return "", RootAccessFeatures{}, &awswire.Error{Code: "ConcurrentModification", Message: "Organization state changed while updating root access; retry the operation.", StatusCode: http.StatusConflict}
}

func (s *Service) authorizedRootAccessState(ctx context.Context, action string) (*operationState, uint64, error) {
	state, revision, err := s.rootAccessState(ctx)
	if err != nil {
		return nil, 0, err
	}
	s.mu.RLock()
	authorizer := s.authorizer
	s.mu.RUnlock()
	snapshot := context.WithValue(ctx, policySnapshotKey{}, state.callerPolicySnapshot(s))
	permission := authorization.Request{Action: action, ResourceARN: "*", EvaluationTime: &state.instant}
	if err := authorizer.Authorize(snapshot, permission); err != nil {
		return nil, 0, err
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	return state, revision, nil
}

func (s *Service) rootAccessState(ctx context.Context) (*operationState, uint64, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	m := awsctx.FromContext(ctx)
	if m.AccountID == "" || m.Partition == "" {
		return nil, 0, &awswire.Error{Code: "AccessDenied", Message: "An authenticated account and partition are required.", StatusCode: http.StatusForbidden}
	}
	record, revision, err := s.storage.Load(ctx, m.Partition)
	if err != nil {
		return nil, 0, rootFeatureStorageError(ctx)
	}
	state := &operationState{serviceState: decodeState(record, m.Partition, m.AccountID), instant: s.clock.Now().UTC()}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	return state, revision, nil
}

func (s *operationState) rootAccessOrganization(managementOnly bool) (*orgState, *awswire.Error) {
	o := s.orgs[s.memberships[s.caller]]
	if o == nil {
		return nil, rootFeatureError("OrganizationNotFoundException", "No organization is associated with your account.")
	}
	if o.organization.FeatureSet != "ALL" {
		return nil, rootFeatureError("OrganizationNotInAllFeaturesModeException", "Your organization must have all features enabled.")
	}
	if _, trusted := o.services["iam.amazonaws.com"]; !trusted {
		return nil, rootFeatureError("ServiceAccessNotEnabledException", "Trusted access is not enabled for IAM in AWS Organizations.")
	}
	_, delegated := o.delegates[s.caller]["iam.amazonaws.com"]
	management := o.organization.MasterAccountID == s.caller
	if o.accounts[s.caller].State != "ACTIVE" || !management && !delegated {
		return nil, rootFeatureError("AccountNotManagementOrDelegatedAdministratorException", "The account must be the management account or an IAM delegated administrator.")
	}
	// AWS permits IAM delegates to list and disable these features, but only
	// the management account can enable them. See root_sessions.json.
	if managementOnly && !management {
		return nil, rootFeatureError("CallerIsNotManagementAccountException", "Only the management account can enable organization root access features.")
	}
	return o, nil
}

// CheckRootSession checks Organizations eligibility for an STS root task.
// STS separately validates the caller principal kind, requested task policy,
// endpoint, duration, and sts:AssumeRoot permission. A borrowed IAM transaction
// keeps this Organizations read atomic with subsequent credential publication.
func (s *Service) CheckRootSession(ctx context.Context, targetAccountID, taskPolicyARN string) error {
	// TODO: Comeback model transient STS root-eligibility views after IAM delegation and trusted-access changes; AWS regional STS can lag current IAM metadata and alternate between allow and deny before convergence.
	state, _, err := s.rootAccessState(ctx)
	if err != nil {
		return err
	}
	o, apiErr := state.rootAccessOrganization(false)
	if apiErr != nil {
		return &awswire.Error{Code: "AccessDenied", Message: apiErr.Message, StatusCode: http.StatusForbidden}
	}
	target, exists := o.accounts[targetAccountID]
	// AWS gates the three IAM credential tasks with CredentialsManagement and
	// the S3/SQS recovery tasks with Sessions. Neither flag implies the other.
	// See the captured task matrix in testdata/aws/iam/root_sessions.json.
	taskPrefix := "arn:" + state.partition + ":iam::aws:policy/root-task/"
	enabled := false
	switch taskPolicyARN {
	case taskPrefix + "IAMAuditRootUserCredentials", taskPrefix + "IAMDeleteRootUserCredentials", taskPrefix + "IAMCreateRootUserPassword":
		enabled = o.rootAccess.CredentialsManagement
	case taskPrefix + "S3UnlockBucketPolicy", taskPrefix + "SQSUnlockQueuePolicy":
		enabled = o.rootAccess.Sessions
	}
	if !enabled || !exists || target.State != "ACTIVE" || targetAccountID == o.organization.MasterAccountID {
		return &awswire.Error{Code: "AccessDenied", Message: "The root task requires an active member account and its organization root access feature.", StatusCode: http.StatusForbidden}
	}
	return nil
}

func rootFeatureError(code, message string) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: http.StatusBadRequest}
}

func rootFeatureStorageError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return &awswire.Error{Code: "ServiceFailure", Message: "Organizations storage failed while accessing root features.", StatusCode: http.StatusInternalServerError}
}
