package organizations

import (
	"fmt"
	"net/http"
	"strings"

	api "stackd/internal/awsapi/organizations"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) registerAccountOperations() {
	register(s, "CreateAccount", (*operationState).createAccount)
	register(s, "DescribeAccount", func(s *operationState, r *http.Request, in *api.DescribeAccountInput) (*api.DescribeAccountOutput, *awswire.Error) {
		o, err := s.organizationFor(r, true)
		if err != nil {
			return nil, err
		}
		a, ok := o.accounts[inputString(in.AccountId)]
		if !ok {
			return nil, failure("AccountNotFoundException", "The account does not exist in this organization.")
		}
		return &api.DescribeAccountOutput{Account: new(o.accountAPI(a))}, nil
	})
	register(s, "DescribeCreateAccountStatus", (*operationState).describeAccountStatus)
	register(s, "ListCreateAccountStatus", (*operationState).listAccountStatus)
	register(s, "ListAccounts", func(s *operationState, r *http.Request, in *api.ListAccountsInput) (*api.ListAccountsOutput, *awswire.Error) {
		items, next, err := s.listAccounts(r, in, "")
		return &api.ListAccountsOutput{Accounts: items, NextToken: nextToken(next)}, err
	})
	register(s, "ListAccountsForParent", func(s *operationState, r *http.Request, in *api.ListAccountsForParentInput) (*api.ListAccountsForParentOutput, *awswire.Error) {
		items, next, err := s.listAccounts(r, in, inputString(in.ParentId))
		return &api.ListAccountsForParentOutput{Accounts: items, NextToken: nextToken(next)}, err
	})
	register(s, "MoveAccount", (*operationState).moveAccount)
	register(s, "RemoveAccountFromOrganization", func(s *operationState, r *http.Request, in *api.RemoveAccountFromOrganizationInput) (*api.RemoveAccountFromOrganizationOutput, *awswire.Error) {
		o, err := s.organizationFor(r, true)
		if err != nil {
			return nil, err
		}
		return &api.RemoveAccountFromOrganizationOutput{}, s.removeAccount(r, o, inputString(in.AccountId))
	})
	register(s, "LeaveOrganization", func(s *operationState, r *http.Request, _ *api.LeaveOrganizationInput) (*api.LeaveOrganizationOutput, *awswire.Error) {
		o, err := s.organizationFor(r, false)
		if err != nil {
			return nil, err
		}
		return &api.LeaveOrganizationOutput{}, s.removeAccount(r, o, awsctx.FromContext(r.Context()).AccountID)
	})
	register(s, "CloseAccount", func(s *operationState, r *http.Request, in *api.CloseAccountInput) (*api.CloseAccountOutput, *awswire.Error) {
		o, err := s.organizationFor(r, true)
		if err != nil {
			return nil, err
		}
		a, ok := o.accounts[inputString(in.AccountId)]
		if !ok {
			return nil, failure("AccountNotFoundException", "The account does not exist in this organization.")
		}
		if inputString(in.AccountId) == o.organization.MasterAccountID {
			return nil, failure("ConstraintViolationException", "CANNOT_CLOSE_MANAGEMENT_ACCOUNT")
		}
		if a.State == "CLOSED" {
			return nil, failure("AccountAlreadyClosedException", "The account has already been closed.")
		}
		// TODO: Comeback coordinate account suspension/closure with the shared account registry and downstream resources.
		a.State, a.Status = "CLOSED", "SUSPENDED"
		o.accounts[inputString(in.AccountId)] = a
		s.knownAccounts[inputString(in.AccountId)] = a
		return &api.CloseAccountOutput{}, nil
	})
}

// nextAccountID is shared by tag authorization and the account transition so
// both refer to the same candidate in this operation's partition snapshot.
func (s *operationState) nextAccountID() (string, uint64) {
	for next := s.nextAccount + 1; ; next++ {
		id := fmt.Sprintf("%012d", next)
		if _, exists := s.knownAccounts[id]; !exists {
			return id, next
		}
	}
}

// validEmail follows the Organizations CreateAccount email contract, which is
// stricter than an RFC 5322 mailbox and permits neither display names nor quotes.
func validEmail(email string) bool {
	if len(email) < 6 || len(email) > 64 || strings.Count(email, "@") != 1 {
		return false
	}
	local, domain, _ := strings.Cut(email, "@")
	if local == "" || strings.HasPrefix(local, ".") || domain == "" || !strings.Contains(domain, ".") || strings.ContainsAny(domain[:1]+domain[len(domain)-1:], "-.") {
		return false
	}
	for _, r := range local {
		if r <= ' ' || r >= 127 || strings.ContainsRune(`"'()<>[]:;,\|%&`, r) {
			return false
		}
	}
	for _, r := range domain {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' && r != '.' {
			return false
		}
	}
	return true
}

func (s *operationState) listAccounts(r *http.Request, in paginationInput, parent string) (api.Accounts, string, *awswire.Error) {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return nil, "", err
	}
	if parent != "" && !o.parentExists(parent) {
		return nil, "", failure("ParentNotFoundException", "The parent does not exist.")
	}
	items := make(api.Accounts, 0)
	for id, a := range o.accounts {
		if parent == "" || o.parents[id] == parent {
			items = append(items, o.accountAPI(a))
		}
	}
	return paginate(s, items, in, o.organization.ID+"/accounts/"+parent, func(a api.Account) string { return inputString(a.Id) })
}

func (s *operationState) moveAccount(r *http.Request, in *api.MoveAccountInput) (*api.MoveAccountOutput, *awswire.Error) {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return nil, err
	}
	if _, ok := o.accounts[inputString(in.AccountId)]; !ok {
		return nil, failure("AccountNotFoundException", "The account does not exist in this organization.")
	}
	if !o.parentExists(inputString(in.SourceParentId)) {
		return nil, failure("SourceParentNotFoundException", "The source parent does not exist.")
	}
	if !o.parentExists(inputString(in.DestinationParentId)) {
		return nil, failure("DestinationParentNotFoundException", "The destination parent does not exist.")
	}
	if o.parents[inputString(in.AccountId)] == inputString(in.DestinationParentId) {
		return nil, failure("DuplicateAccountException", "The account is already in the destination.")
	}
	if o.parents[inputString(in.AccountId)] != inputString(in.SourceParentId) {
		return nil, failure("AccountNotFoundException", "The source parent does not contain the account.")
	}
	o.parents[inputString(in.AccountId)] = inputString(in.DestinationParentId)
	s.scheduleEffectivePolicies(o, []string{inputString(in.AccountId)}, "", awsctx.FromContext(r.Context()))
	return &api.MoveAccountOutput{}, nil
}

func (s *operationState) removeAccount(r *http.Request, o *orgState, id string) *awswire.Error {
	if _, ok := o.accounts[id]; !ok {
		return failure("AccountNotFoundException", "The account does not exist in this organization.")
	}
	if id == o.organization.MasterAccountID {
		return failure("ConstraintViolationException", "ACCOUNT_CANNOT_LEAVE_ORGANIZATION: Delete the organization to remove its management account.")
	}
	if len(o.delegates[id]) > 0 {
		return failure("ConstraintViolationException", "CANNOT_REMOVE_DELEGATED_ADMINISTRATOR_FROM_ORG")
	}
	delete(o.accounts, id)
	s.removeEffectivePolicies(o, id, awsctx.FromContext(r.Context()))
	delete(o.parents, id)
	delete(o.attachments, id)
	delete(o.tags, id)
	delete(s.memberships, id)
	s.removeFeatureAccount(r, o, id)
	return nil
}
