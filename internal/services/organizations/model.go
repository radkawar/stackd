// Package organizations implements the AWS Organizations JSON API.
package organizations

type organization struct {
	ID                   string
	CloudFormationOwner  string
	ARN                  string
	FeatureSet           string
	MasterAccountID      string
	MasterAccountARN     string
	MasterAccountEmail   string
	AvailablePolicyTypes []policyType
}

type policyType struct{ Type, Status string }

type root struct {
	ID          string
	ARN         string
	Name        string
	PolicyTypes []policyType
}

// CloudFormationOwner is trusted private incarnation metadata. Public tags
// and API projections never carry it.
type organizationalUnit struct {
	ID                  string
	ARN                 string
	Name                string
	CloudFormationOwner string
}

type account struct {
	ID                   string
	ARN                  string
	Name                 string
	Email                string
	Status               string
	State                string
	JoinedMethod         string
	JoinedTimestamp      float64
	CloudFormationOwner  string
	CloudFormationRegion string
}

type policySummary struct {
	ID          string
	ARN         string
	Name        string
	Description string
	Type        string
	AWSManaged  bool
}

type policy struct {
	Content       string
	PolicySummary policySummary
	// CloudFormationOwner is trusted private incarnation metadata.
	CloudFormationOwner string
}

type orgState struct {
	organization      organization
	resourcePolicy    ResourcePolicyRecord
	root              root
	rootAccess        RootAccessFeatures
	accounts          map[string]account
	units             map[string]organizationalUnit
	parents           map[string]string
	creations         map[string]AccountCreationRecord
	policies          map[string]policy
	attachments       map[string][]string
	effectivePolicies map[effectivePolicyKey]EffectivePolicyRecord
	tags              map[string]map[string]string
	services          map[string]float64
	delegates         map[string]map[string]float64
}

func (o *orgState) arn(partition, resource, id string) string {
	return "arn:" + partition + ":organizations::" + o.organization.MasterAccountID + ":" + resource + "/" + o.organization.ID + "/" + id
}

func (o *orgState) targetExists(id string) bool {
	_, isAccount := o.accounts[id]
	_, isUnit := o.units[id]
	return id == o.root.ID || isAccount || isUnit
}

func (o *orgState) parentExists(id string) bool {
	_, isUnit := o.units[id]
	return id == o.root.ID || isUnit
}

func (o *orgState) policyEnabled(kind string) bool {
	for _, p := range o.root.PolicyTypes {
		if p.Type == kind && p.Status == "ENABLED" {
			return true
		}
	}
	return false
}
