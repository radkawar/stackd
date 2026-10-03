package identitycenter

import (
	"github.com/google/uuid"
	api "stackd/internal/awsapi/ssoadmin"
)

func (s *Service) registerAssignments() {
	register(s, "ssoadmin", "CreateAccountAssignment", s.createAssignment)
	register(s, "ssoadmin", "DeleteAccountAssignment", s.deleteAssignment)
	register(s, "ssoadmin", "ProvisionPermissionSet", s.provisionPermissionSet)
	register(s, "ssoadmin", "DescribeAccountAssignmentCreationStatus", func(tx Transaction, in *api.DescribeAccountAssignmentCreationStatusInput) (*api.DescribeAccountAssignmentCreationStatusOutput, error) {
		v, e := s.operation(tx, value(in.InstanceArn), value(in.AccountAssignmentCreationRequestId), "CREATE_ASSIGNMENT", "DescribeAccountAssignmentCreationStatus")
		if e != nil {
			return nil, e
		}
		return &api.DescribeAccountAssignmentCreationStatusOutput{AccountAssignmentCreationStatus: wireAssignmentStatus(v)}, nil
	})
	register(s, "ssoadmin", "DescribeAccountAssignmentDeletionStatus", func(tx Transaction, in *api.DescribeAccountAssignmentDeletionStatusInput) (*api.DescribeAccountAssignmentDeletionStatusOutput, error) {
		v, e := s.operation(tx, value(in.InstanceArn), value(in.AccountAssignmentDeletionRequestId), "DELETE_ASSIGNMENT", "DescribeAccountAssignmentDeletionStatus")
		if e != nil {
			return nil, e
		}
		return &api.DescribeAccountAssignmentDeletionStatusOutput{AccountAssignmentDeletionStatus: wireAssignmentStatus(v)}, nil
	})
	register(s, "ssoadmin", "DescribePermissionSetProvisioningStatus", func(tx Transaction, in *api.DescribePermissionSetProvisioningStatusInput) (*api.DescribePermissionSetProvisioningStatusOutput, error) {
		v, e := s.operation(tx, value(in.InstanceArn), value(in.ProvisionPermissionSetRequestId), "PROVISION", "DescribePermissionSetProvisioningStatus")
		if e != nil {
			return nil, e
		}
		return &api.DescribePermissionSetProvisioningStatusOutput{PermissionSetProvisioningStatus: wireProvisionStatus(v)}, nil
	})
	s.registerAssignmentLists()
}
func (s *Service) target(tx Transaction, i Instance, accountID, action string) error {
	if e := s.authorize(tx.Context(), action, "arn:"+i.Partition+":sso:::account/"+accountID); e != nil {
		return e
	}
	return s.targetEligible(tx, i, accountID)
}

// Eligibility is separate from IAM account-resource authorization: operations
// such as DeletePermissionSet support only instance/permission-set resources,
// while every cross-account IAM effect still requires current Organizations authority.
func (s *Service) targetEligible(tx Transaction, i Instance, accountID string) error {
	allowed := accountID == i.AccountID
	var e error
	if s.accounts != nil {
		allowed, e = s.accounts.Allowed(tx.Context(), i.Scope, accountID)
		if e != nil {
			return e
		}
	}
	if !allowed {
		return failure("AccessDeniedException", "The target account is not managed by this Identity Center instance.", 400)
	}
	return nil
}
func (s *Service) createAssignment(tx Transaction, in *api.CreateAccountAssignmentInput) (*api.CreateAccountAssignmentOutput, error) {
	i, p, e := s.permission(tx, value(in.InstanceArn), value(in.PermissionSetArn), "CreateAccountAssignment")
	if e != nil {
		return nil, e
	}
	if value(in.TargetType) != "AWS_ACCOUNT" {
		return nil, bad("TargetType must be AWS_ACCOUNT.")
	}
	if e = s.target(tx, i, value(in.TargetId), "CreateAccountAssignment"); e != nil {
		return nil, e
	}
	a := Assignment{InstanceARN: i.ARN, PermissionSetARN: p.ARN, AccountID: value(in.TargetId), PrincipalType: value(in.PrincipalType), PrincipalID: value(in.PrincipalId)}
	if s.directory == nil {
		return nil, failure("InternalServerException", "Identity Store is not configured.", 500)
	}
	switch a.PrincipalType {
	case "USER":
		_, e = s.directory.FindUser(tx.Context(), directoryScope(i), i.StoreID, a.PrincipalID)
	case "GROUP":
		var exists bool
		exists, e = s.directory.GroupExists(tx.Context(), directoryScope(i), i.StoreID, a.PrincipalID)
		if e == nil && !exists {
			e = ErrNotFound
		}
	default:
		return nil, bad("PrincipalType must be USER or GROUP.")
	}
	if e != nil {
		return nil, e
	}
	provisions, e := tx.Provisionings(i.ARN)
	if e != nil {
		return nil, e
	}
	found := false
	for _, v := range provisions {
		if v.PermissionSetARN == p.ARN && v.AccountID == a.AccountID {
			found = true
			break
		}
	}
	if !found {
		if e = s.provision(tx, i, p, a.AccountID); e != nil {
			return nil, e
		}
	}
	if e = tx.PutAssignment(a); e != nil {
		return nil, e
	}
	status := Operation{InstanceARN: i.ARN, ID: uuid.NewString(), Kind: "CREATE_ASSIGNMENT", PermissionSetARN: p.ARN, AccountID: a.AccountID, PrincipalType: a.PrincipalType, PrincipalID: a.PrincipalID, Created: s.clock.Now()}
	if e = tx.PutOperation(status); e != nil {
		return nil, e
	}
	return &api.CreateAccountAssignmentOutput{AccountAssignmentCreationStatus: wireAssignmentStatus(status)}, nil
}
func (s *Service) deleteAssignment(tx Transaction, in *api.DeleteAccountAssignmentInput) (*api.DeleteAccountAssignmentOutput, error) {
	i, p, e := s.permission(tx, value(in.InstanceArn), value(in.PermissionSetArn), "DeleteAccountAssignment")
	if e != nil {
		return nil, e
	}
	if value(in.TargetType) != "AWS_ACCOUNT" {
		return nil, bad("TargetType must be AWS_ACCOUNT.")
	}
	if e = s.target(tx, i, value(in.TargetId), "DeleteAccountAssignment"); e != nil {
		return nil, e
	}
	a := Assignment{InstanceARN: i.ARN, PermissionSetARN: p.ARN, AccountID: value(in.TargetId), PrincipalType: value(in.PrincipalType), PrincipalID: value(in.PrincipalId)}
	rows, e := tx.Assignments(i.ARN)
	if e != nil {
		return nil, e
	}
	found, others := false, false
	for _, v := range rows {
		if v == a {
			found = true
		} else if v.PermissionSetARN == p.ARN && v.AccountID == a.AccountID {
			others = true
		}
	}
	if !found {
		return nil, ErrNotFound
	}
	if e = tx.DeleteAssignment(a); e != nil {
		return nil, e
	}
	if !others {
		provisions, e := tx.Provisionings(i.ARN)
		if e != nil {
			return nil, e
		}
		for _, v := range provisions {
			if v.PermissionSetARN == p.ARN && v.AccountID == a.AccountID {
				if s.roles == nil {
					return nil, failure("InternalServerException", "IAM provisioning is not configured.", 500)
				}
				if e = s.roles.Remove(tx.Context(), v); e != nil {
					return nil, e
				}
				if e = tx.DeleteProvisioning(v); e != nil {
					return nil, e
				}
			}
		}
	}
	status := Operation{InstanceARN: i.ARN, ID: uuid.NewString(), Kind: "DELETE_ASSIGNMENT", PermissionSetARN: p.ARN, AccountID: a.AccountID, PrincipalType: a.PrincipalType, PrincipalID: a.PrincipalID, Created: s.clock.Now()}
	if e = tx.PutOperation(status); e != nil {
		return nil, e
	}
	return &api.DeleteAccountAssignmentOutput{AccountAssignmentDeletionStatus: wireAssignmentStatus(status)}, nil
}
func (s *Service) provision(tx Transaction, i Instance, p PermissionSet, account string) error {
	if s.roles == nil {
		return failure("InternalServerException", "IAM provisioning is not configured.", 500)
	}
	v, e := s.roles.Provision(tx.Context(), RoleSpec{Instance: i, PermissionSet: p, AccountID: account})
	if e != nil {
		return e
	}
	return tx.PutProvisioning(v)
}
func (s *Service) provisionPermissionSet(tx Transaction, in *api.ProvisionPermissionSetInput) (*api.ProvisionPermissionSetOutput, error) {
	i, p, e := s.permission(tx, value(in.InstanceArn), value(in.PermissionSetArn), "ProvisionPermissionSet")
	if e != nil {
		return nil, e
	}
	targets := []string{}
	switch value(in.TargetType) {
	case "AWS_ACCOUNT":
		if value(in.TargetId) == "" {
			return nil, bad("TargetId is required for AWS_ACCOUNT.")
		}
		targets = append(targets, value(in.TargetId))
	case "ALL_PROVISIONED_ACCOUNTS":
		if in.TargetId != nil {
			return nil, bad("TargetId cannot be used with ALL_PROVISIONED_ACCOUNTS.")
		}
		rows, e := tx.Provisionings(i.ARN)
		if e != nil {
			return nil, e
		}
		for _, v := range rows {
			if v.PermissionSetARN == p.ARN {
				targets = append(targets, v.AccountID)
			}
		}
	default:
		return nil, bad("Unsupported provision target type.")
	}
	for _, target := range targets {
		if e = s.target(tx, i, target, "ProvisionPermissionSet"); e != nil {
			return nil, e
		}
		if e = s.provision(tx, i, p, target); e != nil {
			return nil, e
		}
	}
	status := Operation{InstanceARN: i.ARN, ID: uuid.NewString(), Kind: "PROVISION", PermissionSetARN: p.ARN, AccountID: value(in.TargetId), Created: s.clock.Now()}
	if e = tx.PutOperation(status); e != nil {
		return nil, e
	}
	return &api.ProvisionPermissionSetOutput{PermissionSetProvisioningStatus: wireProvisionStatus(status)}, nil
}
func (s *Service) operation(tx Transaction, instance, id, kind, action string) (Operation, error) {
	if _, e := s.instance(tx, instance, action); e != nil {
		return Operation{}, e
	}
	v, e := tx.Operation(id)
	if e != nil {
		return v, e
	}
	if v.InstanceARN != instance || v.Kind != kind {
		return Operation{}, ErrNotFound
	}
	return v, nil
}
func wireAssignmentStatus(v Operation) *api.AccountAssignmentOperationStatus {
	return &api.AccountAssignmentOperationStatus{RequestId: new(api.UUId(v.ID)), Status: new(api.StatusValuesSUCCEEDED), CreatedDate: new(api.Date(v.Created)), PermissionSetArn: new(api.PermissionSetArn(v.PermissionSetARN)), PrincipalId: new(api.PrincipalId(v.PrincipalID)), PrincipalType: new(api.PrincipalType(v.PrincipalType)), TargetId: new(api.TargetId(v.AccountID)), TargetType: new(api.TargetTypeAWS_ACCOUNT)}
}
func wireProvisionStatus(v Operation) *api.PermissionSetProvisioningStatus {
	out := &api.PermissionSetProvisioningStatus{RequestId: new(api.UUId(v.ID)), Status: new(api.StatusValuesSUCCEEDED), CreatedDate: new(api.Date(v.Created)), PermissionSetArn: new(api.PermissionSetArn(v.PermissionSetARN))}
	if v.AccountID != "" {
		out.AccountId = new(api.AccountId(v.AccountID))
	}
	return out
}
