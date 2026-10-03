package organizations

import (
	"math"
	"time"

	api "stackd/internal/awsapi/organizations"
)

func (v organization) api() api.Organization {
	return api.Organization{Id: new(api.OrganizationId(v.ID)), Arn: new(api.OrganizationArn(v.ARN)),
		FeatureSet:      new(api.OrganizationFeatureSet(v.FeatureSet)),
		MasterAccountId: new(api.AccountId(v.MasterAccountID)), MasterAccountArn: new(api.AccountArn(v.MasterAccountARN)),
		MasterAccountEmail: new(api.Email(v.MasterAccountEmail)), AvailablePolicyTypes: policyTypes(v.AvailablePolicyTypes)}
}

func policyTypes(values []policyType) api.PolicyTypes {
	out := make(api.PolicyTypes, len(values))
	for i, v := range values {
		out[i] = api.PolicyTypeSummary{Type: new(api.PolicyType(v.Type)), Status: new(api.PolicyTypeStatus(v.Status))}
	}
	return out
}

func (v root) api() api.Root {
	return api.Root{Id: new(api.RootId(v.ID)), Arn: new(api.RootArn(v.ARN)), Name: new(api.RootName(v.Name)), PolicyTypes: policyTypes(v.PolicyTypes)}
}

func (o *orgState) unitAPI(v organizationalUnit) api.OrganizationalUnit {
	return api.OrganizationalUnit{Id: new(api.OrganizationalUnitId(v.ID)), Arn: new(api.OrganizationalUnitArn(v.ARN)), Name: new(api.OrganizationalUnitName(v.Name)), Path: new(api.Path(o.entityPath(v.ID)))}
}

func (o *orgState) accountAPI(v account) api.Account {
	return api.Account{Id: new(api.AccountId(v.ID)), Arn: new(api.AccountArn(v.ARN)), Name: new(api.AccountName(v.Name)),
		Email: new(api.Email(v.Email)), State: new(api.AccountState(v.State)), Status: new(api.AccountStatus(v.Status)),
		JoinedMethod: new(api.AccountJoinedMethod(v.JoinedMethod)), JoinedTimestamp: timestamp(v.JoinedTimestamp), Paths: api.Paths{api.Path(o.entityPath(v.ID))}}
}

func (v policySummary) api() api.PolicySummary {
	return api.PolicySummary{Id: new(api.PolicyId(v.ID)), Arn: new(api.PolicyArn(v.ARN)), Name: new(api.PolicyName(v.Name)),
		Description: new(api.PolicyDescription(v.Description)), Type: new(api.PolicyType(v.Type)), AwsManaged: new(api.AwsManagedPolicy(v.AWSManaged))}
}

func (v policy) api() api.Policy {
	return api.Policy{Content: new(api.PolicyContent(v.Content)), PolicySummary: new(v.PolicySummary.api())}
}

// Stored Organizations timestamps have millisecond precision in epoch seconds.
// The generated encoder owns their wire representation.
func timestamp(seconds float64) *api.Timestamp {
	return new(time.UnixMilli(int64(math.Round(seconds * 1000))))
}
