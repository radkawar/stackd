package organizations

import (
	"database/sql"
	"errors"
	domain "stackd/storage/organizations"
	"stackd/storage/sqlite/organizations/internal/sqlcgen"
)

func (r reader) partition(partition string, sequence uint64) (domain.PartitionRecord, error) {
	record := domain.PartitionRecord{AccountSequence: sequence}
	registry, err := r.q.Registry(r.ctx, partition)
	if err != nil {
		return record, err
	}
	for _, row := range registry {
		record.Accounts = append(record.Accounts, domain.AccountRecord{ID: row.ID, ARN: row.Arn, Name: row.Name, Email: row.Email, Status: row.Status, State: row.State, JoinedMethod: row.JoinedMethod, JoinedTimestamp: row.JoinedTimestamp})
	}
	organizations, err := r.q.Organizations(r.ctx, partition)
	if err != nil {
		return record, err
	}
	for _, row := range organizations {
		o, err := r.organization(row)
		if err != nil {
			return record, err
		}
		record.Organizations = append(record.Organizations, o)
	}
	if err := r.handshakes(partition, &record); err != nil {
		return record, err
	}
	return record, nil
}

func (r reader) organization(row sqlcgen.OrgOrganization) (domain.OrganizationRecord, error) {
	o := domain.OrganizationRecord{
		Organization: domain.OrganizationDetails{ID: row.OrgID, ARN: row.Arn, FeatureSet: row.FeatureSet, MasterAccountID: row.MasterAccountID, MasterAccountARN: row.MasterAccountArn, MasterAccountEmail: row.MasterAccountEmail},
		Root:         domain.RootRecord{ID: row.RootID, ARN: row.RootArn, Name: row.RootName},
		RootAccess:   domain.RootAccessFeatures{CredentialsManagement: row.CredentialsManagement, Sessions: row.RootSessions},
	}
	resourcePolicy, err := r.q.ResourcePolicy(r.ctx, sqlcgen.ResourcePolicyParams{Partition: row.Partition, OrgID: row.OrgID})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return o, err
	}
	o.ResourcePolicy = domain.ResourcePolicyRecord{ID: resourcePolicy.ID, ARN: resourcePolicy.Arn, Content: resourcePolicy.Content}

	{
		rows, err := r.q.AvailablePolicyTypes(r.ctx, sqlcgen.AvailablePolicyTypesParams{Partition: row.Partition, OrgID: row.OrgID})
		if err != nil {
			return o, err
		}
		for _, row := range rows {
			o.Organization.AvailablePolicyTypes = append(o.Organization.AvailablePolicyTypes, domain.PolicyTypeRecord{Type: row.Type, Status: row.Status})
		}
	}
	{
		rows, err := r.q.RootPolicyTypes(r.ctx, sqlcgen.RootPolicyTypesParams{Partition: row.Partition, OrgID: row.OrgID})
		if err != nil {
			return o, err
		}
		for _, row := range rows {
			o.Root.PolicyTypes = append(o.Root.PolicyTypes, domain.PolicyTypeRecord{Type: row.Type, Status: row.Status})
		}
	}
	{
		rows, err := r.q.Members(r.ctx, sqlcgen.MembersParams{Partition: row.Partition, OrgID: row.OrgID})
		if err != nil {
			return o, err
		}
		for _, row := range rows {
			o.Accounts = append(o.Accounts, domain.AccountRecord{ID: row.ID, ARN: row.Arn, Name: row.Name, Email: row.Email, Status: row.Status, State: row.State, JoinedMethod: row.JoinedMethod, JoinedTimestamp: row.JoinedTimestamp})
		}
	}
	{
		rows, err := r.q.Units(r.ctx, sqlcgen.UnitsParams{Partition: row.Partition, OrgID: row.OrgID})
		if err != nil {
			return o, err
		}
		for _, row := range rows {
			o.Units = append(o.Units, domain.UnitRecord{ID: row.ID, ARN: row.Arn, Name: row.Name})
		}
	}
	{
		rows, err := r.q.Parents(r.ctx, sqlcgen.ParentsParams{Partition: row.Partition, OrgID: row.OrgID})
		if err != nil {
			return o, err
		}
		for _, row := range rows {
			o.Parents = append(o.Parents, domain.ParentRecord{ChildID: row.ChildID, ParentID: row.ParentID})
		}
	}
	{
		rows, err := r.q.Attachments(r.ctx, sqlcgen.AttachmentsParams{Partition: row.Partition, OrgID: row.OrgID})
		if err != nil {
			return o, err
		}
		for _, row := range rows {
			o.Attachments = append(o.Attachments, domain.PolicyAttachment{TargetID: row.TargetID, PolicyID: row.PolicyID})
		}
	}
	{
		rows, err := r.q.Tags(r.ctx, sqlcgen.TagsParams{Partition: row.Partition, OrgID: row.OrgID})
		if err != nil {
			return o, err
		}
		for _, row := range rows {
			o.Tags = append(o.Tags, domain.ResourceTagRecord{ResourceID: row.ResourceID, Key: row.Key, Value: row.Value})
		}
	}
	{
		rows, err := r.q.Services(r.ctx, sqlcgen.ServicesParams{Partition: row.Partition, OrgID: row.OrgID})
		if err != nil {
			return o, err
		}
		for _, row := range rows {
			o.Services = append(o.Services, domain.ServiceAccessRecord{Principal: row.Principal, Enabled: row.Enabled})
		}
	}
	{
		rows, err := r.q.Delegations(r.ctx, sqlcgen.DelegationsParams{Partition: row.Partition, OrgID: row.OrgID})
		if err != nil {
			return o, err
		}
		for _, row := range rows {
			o.Delegations = append(o.Delegations, domain.DelegationRecord{AccountID: row.AccountID, Principal: row.Principal, Enabled: row.Enabled})
		}
	}
	generations, err := r.q.EffectivePolicies(r.ctx, sqlcgen.EffectivePoliciesParams{Partition: row.Partition, OrgID: row.OrgID})
	if err != nil {
		return o, err
	}
	for _, generation := range generations {
		p := domain.EffectivePolicyRecord{AccountID: generation.AccountID, PolicyType: generation.PolicyType, Content: generation.Content, UpdatedAt: generation.UpdatedAt, Due: generation.Due, RequestID: generation.RequestID, RequestRegion: generation.RequestRegion, ActorARN: generation.ActorArn, ValidationPath: generation.ValidationPath}
		errors, err := r.q.EffectivePolicyErrors(r.ctx, sqlcgen.EffectivePolicyErrorsParams{Partition: row.Partition, OrgID: row.OrgID, AccountID: p.AccountID, PolicyType: p.PolicyType})
		if err != nil {
			return o, err
		}
		for _, e := range errors {
			ids, err := r.q.EffectivePolicyErrorSources(r.ctx, sqlcgen.EffectivePolicyErrorSourcesParams{Partition: row.Partition, OrgID: row.OrgID, AccountID: p.AccountID, PolicyType: p.PolicyType, ErrorPosition: e.Position})
			if err != nil {
				return o, err
			}
			p.ValidationErrors = append(p.ValidationErrors, domain.EffectivePolicyError{Code: e.Code, Message: e.Message, Path: e.Path, ContributingPolicies: ids})
		}
		o.EffectivePolicies = append(o.EffectivePolicies, p)
	}
	policies, err := r.q.Policies(r.ctx, sqlcgen.PoliciesParams{Partition: row.Partition, OrgID: row.OrgID})
	if err != nil {
		return o, err
	}
	for _, row := range policies {
		o.Policies = append(o.Policies, domain.PolicyRecord{Content: row.Content, PolicySummary: domain.PolicySummaryRecord{ID: row.ID, ARN: row.Arn, Name: row.Name, Description: row.Description, Type: row.Type, AWSManaged: row.AwsManaged}})
	}
	creations, err := r.q.Creations(r.ctx, sqlcgen.CreationsParams{Partition: row.Partition, OrgID: row.OrgID})
	if err != nil {
		return o, err
	}
	for _, row := range creations {
		tags, err := r.q.CreationTags(r.ctx, sqlcgen.CreationTagsParams{Partition: row.Partition, OrgID: row.OrgID, CreationPosition: row.Position})
		if err != nil {
			return o, err
		}
		creation := domain.AccountCreationRecord{ID: row.ID, AccountID: row.AccountID, AccountName: row.AccountName, Email: row.Email, RoleName: row.RoleName, State: row.State, FailureReason: row.FailureReason, RequestedAt: row.RequestedAt, Due: row.Due, CompletedAt: row.CompletedAt, RequestID: row.RequestID, RequestRegion: row.RequestRegion, ActorARN: row.ActorArn, Tags: make(map[string]string, len(tags))}
		for _, tag := range tags {
			creation.Tags[tag.Key] = tag.Value
		}
		o.Creations = append(o.Creations, creation)
	}
	return o, nil
}
