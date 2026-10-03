package organizations

import (
	"net/http"
	"slices"
	"strings"
	"time"

	api "stackd/internal/awsapi/organizations"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// This modeled delay gives every accepted request a pending lifecycle in service
// time. AWS does not promise a fixed completion deadline.
const accountCreationDelay = time.Second
const concurrentAccountCreations = 5

func (s *operationState) createAccount(r *http.Request, in *api.CreateAccountInput) (*api.CreateAccountOutput, *awswire.Error) {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return nil, err
	}
	if !validEmail(string(*in.Email)) {
		return nil, failure("InvalidInputException", "Email must be a valid account email address.")
	}
	roleName := "OrganizationAccountAccessRole"
	if in.RoleName != nil {
		roleName = string(*in.RoleName)
	}
	if strings.HasPrefix(roleName, "AWSServiceRoleFor") {
		return nil, failure("InvalidInputException", "RoleName uses a reserved service-linked role prefix.")
	}
	tags, err := mergeTags(nil, in.Tags)
	if err != nil {
		return nil, err
	}
	if s.accountQuotaReached(o, s.accountQuota, "") {
		return nil, failure("ConstraintViolationException", "ACCOUNT_NUMBER_LIMIT_EXCEEDED: The organization has reached its account quota.")
	}
	pending := 0
	for _, job := range o.creations {
		if job.State != "IN_PROGRESS" {
			continue
		}
		if strings.EqualFold(job.Email, string(*in.Email)) {
			return nil, failure("ConcurrentModificationException", "Another account creation request is using this email address.")
		}
		pending++
	}
	if pending >= concurrentAccountCreations {
		return nil, failure("ConstraintViolationException", "ACCOUNT_CREATION_RATE_LIMIT_EXCEEDED: At most five account creations can be in progress.")
	}
	id, sequence := s.nextAccountID()
	s.nextAccount = sequence
	job := AccountCreationRecord{ID: identifier("car-", 12), AccountID: id, AccountName: string(*in.AccountName), Email: string(*in.Email), RoleName: roleName, State: "IN_PROGRESS", RequestedAt: s.instant, Due: s.instant.Add(accountCreationDelay), Tags: tags}
	origin := awsctx.FromContext(r.Context())
	job.RequestID, job.RequestRegion, job.ActorARN = origin.RequestID, origin.Region, origin.PrincipalARN
	// TODO: Comeback implement account billing access, post-success initialization, Service Quotas API integration, request throttling and remaining AWS failure/timestamp conformance; current jobs publish membership, IAM roles and copied primary contact together.
	o.creations[job.ID] = job
	s.recordAccountCreation(o, job)
	return &api.CreateAccountOutput{CreateAccountStatus: accountStatus(job)}, nil
}

func (s *operationState) describeAccountStatus(r *http.Request, in *api.DescribeCreateAccountStatusInput) (*api.DescribeCreateAccountStatusOutput, *awswire.Error) {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return nil, err
	}
	job, ok := o.creations[string(*in.CreateAccountRequestId)]
	if !ok {
		return nil, failure("CreateAccountStatusNotFoundException", "The account creation request does not exist.")
	}
	return &api.DescribeCreateAccountStatusOutput{CreateAccountStatus: accountStatus(job)}, nil
}

func (s *operationState) listAccountStatus(r *http.Request, in *api.ListCreateAccountStatusInput) (*api.ListCreateAccountStatusOutput, *awswire.Error) {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return nil, err
	}
	states := make([]string, len(in.States))
	for i, state := range in.States {
		states[i] = string(state)
	}
	slices.Sort(states)
	states = slices.Compact(states)
	items := make([]AccountCreationRecord, 0)
	for _, job := range o.creations {
		if len(states) == 0 || slices.Contains(states, job.State) {
			items = append(items, job)
		}
	}
	items, next, err := paginate(s, items, in, o.organization.ID+"/creations/"+strings.Join(states, ","), func(v AccountCreationRecord) string { return v.ID })
	if err != nil {
		return nil, err
	}
	out := &api.ListCreateAccountStatusOutput{CreateAccountStatuses: make(api.CreateAccountStatuses, len(items))}
	for i, job := range items {
		out.CreateAccountStatuses[i] = *accountStatus(job)
	}
	out.NextToken = nextToken(next)
	return out, nil
}

func accountStatus(job AccountCreationRecord) *api.CreateAccountStatus {
	id, name, state := api.CreateAccountRequestId(job.ID), api.CreateAccountName(job.AccountName), api.CreateAccountState(job.State)
	out := &api.CreateAccountStatus{Id: &id, AccountName: &name, State: &state, RequestedTimestamp: &job.RequestedAt}
	if job.State != "IN_PROGRESS" {
		out.CompletedTimestamp = &job.CompletedAt
	}
	if job.State == "SUCCEEDED" {
		id := api.AccountId(job.AccountID)
		out.AccountId = &id
	}
	if job.State == "FAILED" {
		reason := api.CreateAccountFailureReason(job.FailureReason)
		out.FailureReason = &reason
	}
	return out
}
