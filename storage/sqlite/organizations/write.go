package organizations

import (
	domain "stackd/storage/organizations"
	"stackd/storage/sqlite/organizations/internal/sqlcgen"
)

func (w writer) partition(partition string, record domain.PartitionRecord) error {
	for i, a := range record.Accounts {
		if err := w.q.PutRegistry(w.ctx, sqlcgen.PutRegistryParams{Partition: partition, Position: int64(i), ID: a.ID, Arn: a.ARN, Name: a.Name, Email: a.Email, Status: a.Status, State: a.State, JoinedMethod: a.JoinedMethod, JoinedTimestamp: a.JoinedTimestamp, CloudformationOwner: a.CloudFormationOwner, CloudformationRegion: a.CloudFormationRegion}); err != nil {
			return err
		}
	}
	for i, o := range record.Organizations {
		if err := w.q.PutOrganizations(w.ctx, sqlcgen.PutOrganizationsParams{Partition: partition, Position: int64(i), OrgID: o.Organization.ID, Arn: o.Organization.ARN, FeatureSet: o.Organization.FeatureSet, MasterAccountID: o.Organization.MasterAccountID, MasterAccountArn: o.Organization.MasterAccountARN, MasterAccountEmail: o.Organization.MasterAccountEmail, RootID: o.Root.ID, RootArn: o.Root.ARN, RootName: o.Root.Name, CredentialsManagement: o.RootAccess.CredentialsManagement, RootSessions: o.RootAccess.Sessions, CloudformationOwner: o.Organization.CloudFormationOwner}); err != nil {
			return err
		}
		if err := w.organization(partition, o); err != nil {
			return err
		}
	}
	return w.handshakes(partition, record.Handshakes)
}

func (w writer) organization(partition string, o domain.OrganizationRecord) error {
	orgID := o.Organization.ID
	if policy := o.ResourcePolicy; policy.ID != "" {
		if err := w.q.PutResourcePolicy(w.ctx, sqlcgen.PutResourcePolicyParams{Partition: partition, OrgID: orgID, ID: policy.ID, Arn: policy.ARN, Content: policy.Content, CloudformationOwner: policy.CloudFormationOwner}); err != nil {
			return err
		}
	}
	for i, record := range o.Organization.AvailablePolicyTypes {
		if err := w.q.PutAvailablePolicyTypes(w.ctx, sqlcgen.PutAvailablePolicyTypesParams{Partition: partition, OrgID: orgID, Position: int64(i), Type: record.Type, Status: record.Status}); err != nil {
			return err
		}
	}
	for i, record := range o.Root.PolicyTypes {
		if err := w.q.PutRootPolicyTypes(w.ctx, sqlcgen.PutRootPolicyTypesParams{Partition: partition, OrgID: orgID, Position: int64(i), Type: record.Type, Status: record.Status}); err != nil {
			return err
		}
	}
	for i, record := range o.Accounts {
		if err := w.q.PutMembers(w.ctx, sqlcgen.PutMembersParams{Partition: partition, OrgID: orgID, Position: int64(i), ID: record.ID, Arn: record.ARN, Name: record.Name, Email: record.Email, Status: record.Status, State: record.State, JoinedMethod: record.JoinedMethod, JoinedTimestamp: record.JoinedTimestamp, CloudformationOwner: record.CloudFormationOwner, CloudformationRegion: record.CloudFormationRegion}); err != nil {
			return err
		}
	}
	for i, record := range o.Units {
		if err := w.q.PutUnits(w.ctx, sqlcgen.PutUnitsParams{Partition: partition, OrgID: orgID, Position: int64(i), ID: record.ID, Arn: record.ARN, Name: record.Name, CloudformationOwner: record.CloudFormationOwner}); err != nil {
			return err
		}
	}
	for i, record := range o.Parents {
		if err := w.q.PutParents(w.ctx, sqlcgen.PutParentsParams{Partition: partition, OrgID: orgID, Position: int64(i), ChildID: record.ChildID, ParentID: record.ParentID}); err != nil {
			return err
		}
	}
	for i, record := range o.Attachments {
		if err := w.q.PutAttachments(w.ctx, sqlcgen.PutAttachmentsParams{Partition: partition, OrgID: orgID, Position: int64(i), TargetID: record.TargetID, PolicyID: record.PolicyID}); err != nil {
			return err
		}
	}
	for _, record := range o.EffectivePolicies {
		if err := w.q.PutEffectivePolicy(w.ctx, sqlcgen.PutEffectivePolicyParams{Partition: partition, OrgID: orgID, AccountID: record.AccountID, PolicyType: record.PolicyType, Content: record.Content, UpdatedAt: record.UpdatedAt, Due: record.Due, RequestID: record.RequestID, RequestRegion: record.RequestRegion, ActorArn: record.ActorARN, ValidationPath: record.ValidationPath}); err != nil {
			return err
		}
		for position, e := range record.ValidationErrors {
			if err := w.q.PutEffectivePolicyError(w.ctx, sqlcgen.PutEffectivePolicyErrorParams{Partition: partition, OrgID: orgID, AccountID: record.AccountID, PolicyType: record.PolicyType, Position: int64(position), Code: e.Code, Message: e.Message, Path: e.Path}); err != nil {
				return err
			}
			for index, id := range e.ContributingPolicies {
				if err := w.q.PutEffectivePolicyErrorSource(w.ctx, sqlcgen.PutEffectivePolicyErrorSourceParams{Partition: partition, OrgID: orgID, AccountID: record.AccountID, PolicyType: record.PolicyType, ErrorPosition: int64(position), Position: int64(index), PolicyID: id}); err != nil {
					return err
				}
			}
		}
	}
	for i, record := range o.Tags {
		if err := w.q.PutTags(w.ctx, sqlcgen.PutTagsParams{Partition: partition, OrgID: orgID, Position: int64(i), ResourceID: record.ResourceID, Key: record.Key, Value: record.Value}); err != nil {
			return err
		}
	}
	for i, record := range o.Services {
		if err := w.q.PutServices(w.ctx, sqlcgen.PutServicesParams{Partition: partition, OrgID: orgID, Position: int64(i), Principal: record.Principal, Enabled: record.Enabled}); err != nil {
			return err
		}
	}
	for i, record := range o.Delegations {
		if err := w.q.PutDelegations(w.ctx, sqlcgen.PutDelegationsParams{Partition: partition, OrgID: orgID, Position: int64(i), AccountID: record.AccountID, Principal: record.Principal, Enabled: record.Enabled}); err != nil {
			return err
		}
	}
	for i, record := range o.Policies {
		p := record.PolicySummary
		if err := w.q.PutPolicies(w.ctx, sqlcgen.PutPoliciesParams{Partition: partition, OrgID: orgID, Position: int64(i), ID: p.ID, Arn: p.ARN, Name: p.Name, Description: p.Description, Type: p.Type, Content: record.Content, AwsManaged: p.AWSManaged, CloudformationOwner: record.CloudFormationOwner}); err != nil {
			return err
		}
	}
	for i, record := range o.Creations {
		if err := w.q.PutCreations(w.ctx, sqlcgen.PutCreationsParams{Partition: partition, OrgID: orgID, Position: int64(i), ID: record.ID, AccountID: record.AccountID, AccountName: record.AccountName, Email: record.Email, RoleName: record.RoleName, State: record.State, FailureReason: record.FailureReason, RequestedAt: record.RequestedAt, Due: record.Due, CompletedAt: record.CompletedAt, RequestID: record.RequestID, RequestRegion: record.RequestRegion, ActorArn: record.ActorARN, CloudformationOwner: record.CloudFormationOwner}); err != nil {
			return err
		}
		for key, value := range record.Tags {
			if err := w.q.PutCreationTags(w.ctx, sqlcgen.PutCreationTagsParams{Partition: partition, OrgID: orgID, CreationPosition: int64(i), Key: key, Value: value}); err != nil {
				return err
			}
		}
	}
	return nil
}
