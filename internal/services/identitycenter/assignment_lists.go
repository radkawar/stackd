package identitycenter

import (
	"slices"
	api "stackd/internal/awsapi/ssoadmin"
)

func (s *Service) registerAssignmentLists() {
	register(s, "ssoadmin", "ListAccountAssignments", func(tx Transaction, in *api.ListAccountAssignmentsInput) (*api.ListAccountAssignmentsOutput, error) {
		i, p, e := s.permission(tx, value(in.InstanceArn), value(in.PermissionSetArn), "ListAccountAssignments")
		if e != nil {
			return nil, e
		}
		if e = s.target(tx, i, value(in.AccountId), "ListAccountAssignments"); e != nil {
			return nil, e
		}
		rows, e := tx.Assignments(i.ARN)
		if e != nil {
			return nil, e
		}
		rows = slices.DeleteFunc(rows, func(v Assignment) bool { return v.PermissionSetARN != p.ARN || v.AccountID != value(in.AccountId) })
		rows, next, e := pageSlice(rows, value(in.NextToken), "ListAccountAssignments/"+p.ARN+"/"+value(in.AccountId), intValue(in.MaxResults), assignmentKey)
		if e != nil {
			return nil, e
		}
		out := &api.ListAccountAssignmentsOutput{AccountAssignments: api.AccountAssignmentList{}}
		for _, v := range rows {
			out.AccountAssignments = append(out.AccountAssignments, api.AccountAssignment{AccountId: new(api.AccountId(v.AccountID)), PermissionSetArn: new(api.PermissionSetArn(v.PermissionSetARN)), PrincipalType: new(api.PrincipalType(v.PrincipalType)), PrincipalId: new(api.PrincipalId(v.PrincipalID))})
		}
		if next != "" {
			out.NextToken = new(api.Token(next))
		}
		return out, nil
	})
	register(s, "ssoadmin", "ListAccountAssignmentsForPrincipal", func(tx Transaction, in *api.ListAccountAssignmentsForPrincipalInput) (*api.ListAccountAssignmentsForPrincipalOutput, error) {
		i, e := s.instance(tx, value(in.InstanceArn), "ListAccountAssignmentsForPrincipal")
		if e != nil {
			return nil, e
		}
		account := ""
		if in.Filter != nil {
			account = value(in.Filter.AccountId)
		}
		rows, e := tx.Assignments(i.ARN)
		if e != nil {
			return nil, e
		}
		rows = slices.DeleteFunc(rows, func(v Assignment) bool {
			return v.PrincipalType != value(in.PrincipalType) || v.PrincipalID != value(in.PrincipalId) || (account != "" && v.AccountID != account)
		})
		rows, next, e := pageSlice(rows, value(in.NextToken), "ListAccountAssignmentsForPrincipal/"+i.ARN+"/"+value(in.PrincipalType)+"/"+value(in.PrincipalId)+"/"+account, intValue(in.MaxResults), assignmentKey)
		if e != nil {
			return nil, e
		}
		out := &api.ListAccountAssignmentsForPrincipalOutput{AccountAssignments: api.AccountAssignmentListForPrincipal{}}
		for _, v := range rows {
			out.AccountAssignments = append(out.AccountAssignments, api.AccountAssignmentForPrincipal{AccountId: new(api.AccountId(v.AccountID)), PermissionSetArn: new(api.PermissionSetArn(v.PermissionSetARN)), PrincipalType: new(api.PrincipalType(v.PrincipalType)), PrincipalId: new(api.PrincipalId(v.PrincipalID))})
		}
		if next != "" {
			out.NextToken = new(api.Token(next))
		}
		return out, nil
	})
	register(s, "ssoadmin", "ListPermissionSetsProvisionedToAccount", func(tx Transaction, in *api.ListPermissionSetsProvisionedToAccountInput) (*api.ListPermissionSetsProvisionedToAccountOutput, error) {
		i, e := s.instance(tx, value(in.InstanceArn), "ListPermissionSetsProvisionedToAccount")
		if e != nil {
			return nil, e
		}
		if in.ProvisioningStatus != nil {
			return nil, unsupportedProvisionFilter()
		}
		if e = s.target(tx, i, value(in.AccountId), "ListPermissionSetsProvisionedToAccount"); e != nil {
			return nil, e
		}
		rows, e := tx.Provisionings(i.ARN)
		if e != nil {
			return nil, e
		}
		rows = slices.DeleteFunc(rows, func(v Provisioning) bool { return v.AccountID != value(in.AccountId) })
		rows, next, e := pageSlice(rows, value(in.NextToken), "ListPermissionSetsProvisionedToAccount/"+i.ARN+"/"+value(in.AccountId), intValue(in.MaxResults), provisioningKey)
		if e != nil {
			return nil, e
		}
		out := &api.ListPermissionSetsProvisionedToAccountOutput{PermissionSets: api.PermissionSetList{}}
		for _, v := range rows {
			out.PermissionSets = append(out.PermissionSets, api.PermissionSetArn(v.PermissionSetARN))
		}
		if next != "" {
			out.NextToken = new(api.Token(next))
		}
		return out, nil
	})
	register(s, "ssoadmin", "ListAccountsForProvisionedPermissionSet", func(tx Transaction, in *api.ListAccountsForProvisionedPermissionSetInput) (*api.ListAccountsForProvisionedPermissionSetOutput, error) {
		i, p, e := s.permission(tx, value(in.InstanceArn), value(in.PermissionSetArn), "ListAccountsForProvisionedPermissionSet")
		if e != nil {
			return nil, e
		}
		if in.ProvisioningStatus != nil {
			return nil, unsupportedProvisionFilter()
		}
		rows, e := tx.Provisionings(i.ARN)
		if e != nil {
			return nil, e
		}
		rows = slices.DeleteFunc(rows, func(v Provisioning) bool { return v.PermissionSetARN != p.ARN })
		rows, next, e := pageSlice(rows, value(in.NextToken), "ListAccountsForProvisionedPermissionSet/"+p.ARN, intValue(in.MaxResults), provisioningKey)
		if e != nil {
			return nil, e
		}
		out := &api.ListAccountsForProvisionedPermissionSetOutput{AccountIds: api.AccountList{}}
		for _, v := range rows {
			out.AccountIds = append(out.AccountIds, api.AccountId(v.AccountID))
		}
		if next != "" {
			out.NextToken = new(api.Token(next))
		}
		return out, nil
	})
	register(s, "ssoadmin", "ListAccountAssignmentCreationStatus", func(tx Transaction, in *api.ListAccountAssignmentCreationStatusInput) (*api.ListAccountAssignmentCreationStatusOutput, error) {
		rows, next, e := s.operationList(tx, value(in.InstanceArn), "CREATE_ASSIGNMENT", "ListAccountAssignmentCreationStatus", in.Filter, value(in.NextToken), intValue(in.MaxResults))
		if e != nil {
			return nil, e
		}
		out := &api.ListAccountAssignmentCreationStatusOutput{AccountAssignmentsCreationStatus: wireOperationList(rows)}
		if next != "" {
			out.NextToken = new(api.Token(next))
		}
		return out, nil
	})
	register(s, "ssoadmin", "ListAccountAssignmentDeletionStatus", func(tx Transaction, in *api.ListAccountAssignmentDeletionStatusInput) (*api.ListAccountAssignmentDeletionStatusOutput, error) {
		rows, next, e := s.operationList(tx, value(in.InstanceArn), "DELETE_ASSIGNMENT", "ListAccountAssignmentDeletionStatus", in.Filter, value(in.NextToken), intValue(in.MaxResults))
		if e != nil {
			return nil, e
		}
		out := &api.ListAccountAssignmentDeletionStatusOutput{AccountAssignmentsDeletionStatus: wireOperationList(rows)}
		if next != "" {
			out.NextToken = new(api.Token(next))
		}
		return out, nil
	})
	register(s, "ssoadmin", "ListPermissionSetProvisioningStatus", func(tx Transaction, in *api.ListPermissionSetProvisioningStatusInput) (*api.ListPermissionSetProvisioningStatusOutput, error) {
		rows, next, e := s.operationList(tx, value(in.InstanceArn), "PROVISION", "ListPermissionSetProvisioningStatus", in.Filter, value(in.NextToken), intValue(in.MaxResults))
		if e != nil {
			return nil, e
		}
		out := &api.ListPermissionSetProvisioningStatusOutput{PermissionSetsProvisioningStatus: api.PermissionSetProvisioningStatusList{}}
		for _, v := range rows {
			out.PermissionSetsProvisioningStatus = append(out.PermissionSetsProvisioningStatus, api.PermissionSetProvisioningStatusMetadata{RequestId: new(api.UUId(v.ID)), CreatedDate: new(api.Date(v.Created)), Status: new(api.StatusValuesSUCCEEDED)})
		}
		if next != "" {
			out.NextToken = new(api.Token(next))
		}
		return out, nil
	})
}
func (s *Service) operationList(tx Transaction, instance, kind, action string, filter *api.OperationStatusFilter, token string, limit int) ([]Operation, string, error) {
	if _, e := s.instance(tx, instance, action); e != nil {
		return nil, "", e
	}
	rows, e := tx.Operations(instance)
	if e != nil {
		return nil, "", e
	}
	status := ""
	if filter != nil {
		status = value(filter.Status)
	}
	rows = slices.DeleteFunc(rows, func(v Operation) bool { return v.Kind != kind || (status != "" && status != "SUCCEEDED") })
	return pageSlice(rows, token, action+"/"+instance+"/"+status, limit, func(v Operation) string { return v.ID })
}
func wireOperationList(rows []Operation) api.AccountAssignmentOperationStatusList {
	out := api.AccountAssignmentOperationStatusList{}
	for _, v := range rows {
		out = append(out, api.AccountAssignmentOperationStatusMetadata{RequestId: new(api.UUId(v.ID)), CreatedDate: new(api.Date(v.Created)), Status: new(api.StatusValuesSUCCEEDED)})
	}
	return out
}
func unsupportedProvisionFilter() error {
	// TODO: Comeback — retain applied permission-set revisions for latest-provisioned status filters; ordinary discovery reports actual provisioned roles.
	return bad("ProvisioningStatus filters are not implemented.")
}
