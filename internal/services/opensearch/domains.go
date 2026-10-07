package opensearch

import (
	"context"
	"errors"
	"maps"
	"strings"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/opensearch"
)

func (s *Service) createDomain(ctx context.Context, tx Transaction, in *api.CreateDomainRequest) (*api.CreateDomainResponse, error) {
	if err := validateCreate(in); err != nil {
		return nil, err
	}
	tags, err := requestTags(in.TagList)
	if err != nil {
		return nil, err
	}
	k := Key{scopeFor(ctx), value(in.DomainName)}
	if err = s.authorize(ctx, "CreateDomain", k.ARN(), nil, tagConditions(tags), nil); err != nil {
		return nil, err
	}
	if _, err = tx.Domain(k); err == nil {
		return nil, failure("ResourceAlreadyExistsException", "Domain already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if s.runtime == nil || s.endpoint == "" {
		return nil, failure("ValidationException", "A native OpenSearch runtime and public endpoint must be explicitly configured.")
	}
	options, err := advancedOptions(in.AdvancedOptions)
	if err != nil {
		return nil, err
	}
	bound, err := s.bindPolicy(ctx, value(in.AccessPolicies))
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	v := Domain{Key: k, Incarnation: uuid.NewString(), EngineVersion: EngineVersion, Status: "creating", AccessPolicy: bound.Document, PolicyPrincipals: bound.PrincipalIDs, InstanceCount: 1, AdvancedOptions: options, Tags: tags, Created: now, Updated: now, Due: now, Version: 1, ConfigVersion: 1, Ownership: cloudFormationOwner(ctx)}
	if err = tx.PutDomain(v); err != nil {
		return nil, err
	}
	out, err := s.domainStatus(ctx, v)
	return &api.CreateDomainResponse{DomainStatus: out}, err
}
func (s *Service) describeDomain(ctx context.Context, tx Transaction, in *api.DescribeDomainRequest) (*api.DescribeDomainResponse, error) {
	v, err := s.load(ctx, tx, value(in.DomainName), "DescribeDomain")
	if err != nil {
		return nil, err
	}
	out, err := s.domainStatus(ctx, v)
	return &api.DescribeDomainResponse{DomainStatus: out}, err
}
func (s *Service) describeDomains(ctx context.Context, tx Transaction, in *api.DescribeDomainsRequest) (*api.DescribeDomainsResponse, error) {
	out := &api.DescribeDomainsResponse{DomainStatusList: api.DomainStatusList{}}
	for _, name := range in.DomainNames {
		v, err := s.load(ctx, tx, string(name), "DescribeDomains")
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		status, err := s.domainStatus(ctx, v)
		if err != nil {
			return nil, err
		}
		out.DomainStatusList = append(out.DomainStatusList, *status)
	}
	return out, nil
}
func (s *Service) describeConfig(ctx context.Context, tx Transaction, in *api.DescribeDomainConfigRequest) (*api.DescribeDomainConfigResponse, error) {
	v, err := s.load(ctx, tx, value(in.DomainName), "DescribeDomainConfig")
	if err != nil {
		return nil, err
	}
	out, err := s.domainConfig(ctx, v)
	return &api.DescribeDomainConfigResponse{DomainConfig: out}, err
}
func (s *Service) updateConfig(ctx context.Context, tx Transaction, in *api.UpdateDomainConfigRequest) (*api.UpdateDomainConfigResponse, error) {
	v, err := s.load(ctx, tx, value(in.DomainName), "UpdateDomainConfig")
	if err != nil {
		return nil, err
	}
	if v.Status == "deleting" {
		return nil, failure("ValidationException", "Domain is being deleted.")
	}
	if err = validateUpdate(in); err != nil {
		return nil, err
	}
	if in.AccessPolicies != nil {
		bound, e := s.bindPolicy(ctx, string(*in.AccessPolicies))
		if e != nil {
			return nil, e
		}
		v.AccessPolicy, v.PolicyPrincipals = bound.Document, bound.PrincipalIDs
	}
	if in.AdvancedOptions != nil {
		options, e := advancedOptions(in.AdvancedOptions)
		if e != nil {
			return nil, e
		}
		if v.AdvancedOptions == nil {
			v.AdvancedOptions = map[string]string{}
		}
		maps.Copy(v.AdvancedOptions, options)
	}
	v.Status = "updating"
	v.Version++
	v.ConfigVersion++
	v.Updated = s.clock.Now()
	v.Due = v.Updated
	if err = tx.PutDomain(v); err != nil {
		return nil, err
	}
	out, err := s.domainConfig(ctx, v)
	return &api.UpdateDomainConfigResponse{DomainConfig: out}, err
}
func (s *Service) deleteDomain(ctx context.Context, tx Transaction, in *api.DeleteDomainRequest) (*api.DeleteDomainResponse, error) {
	v, err := s.load(ctx, tx, value(in.DomainName), "DeleteDomain")
	if err != nil {
		return nil, err
	}
	v.Status = "deleting"
	v.Version++
	v.Due = s.clock.Now()
	if err = tx.PutDomain(v); err != nil {
		return nil, err
	}
	out, err := s.domainStatus(ctx, v)
	return &api.DeleteDomainResponse{DomainStatus: out}, err
}
func (s *Service) listDomains(ctx context.Context, tx Transaction, in *api.ListDomainNamesRequest) (*api.ListDomainNamesResponse, error) {
	if err := s.authorize(ctx, "ListDomainNames", "*", nil, nil, nil); err != nil {
		return nil, err
	}
	out := &api.ListDomainNamesResponse{DomainNames: api.DomainInfoList{}}
	if value(in.EngineType) == "Elasticsearch" {
		return out, nil
	}
	domains, err := tx.Domains(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	for _, v := range domains {
		out.DomainNames = append(out.DomainNames, api.DomainInfo{DomainName: new(api.DomainName(v.Key.Name)), EngineType: new(api.EngineType("OpenSearch"))})
	}
	return out, nil
}
func (s *Service) listVersions(ctx context.Context, _ Transaction, in *api.ListVersionsRequest) (*api.ListVersionsResponse, error) {
	if err := s.authorize(ctx, "ListVersions", "*", nil, nil, nil); err != nil {
		return nil, err
	}
	if in.NextToken != nil {
		return nil, failure("ValidationException", "Invalid pagination token.")
	}
	return &api.ListVersionsResponse{Versions: api.VersionList{api.VersionString(EngineVersion)}}, nil
}

func (s *Service) renderedPolicy(ctx context.Context, v Domain) (string, error) {
	if v.AccessPolicy == "" || s.binder == nil {
		return v.AccessPolicy, nil
	}
	return s.binder.RenderResourcePolicy(ctx, boundPolicy(v))
}
func (s *Service) domainStatus(ctx context.Context, v Domain) (*api.DomainStatus, error) {
	policy, err := s.renderedPolicy(ctx, v)
	if err != nil {
		return nil, err
	}
	processing := v.Status != "active"
	state := api.DomainProcessingStatusType("Active")
	switch v.Status {
	case "creating":
		state = "Creating"
	case "updating":
		state = "Modifying"
	case "deleting":
		state = "Deleting"
	case "failed":
		state = "Isolated"
	}
	out := &api.DomainStatus{ARN: new(api.ARN(v.Key.ARN())), DomainId: new(api.DomainId(v.Key.AccountID + "/" + v.Key.Name)), DomainName: new(api.DomainName(v.Key.Name)), EngineVersion: new(api.VersionString(v.EngineVersion)), Created: new(api.Boolean(v.NativeEndpoint != "")), Deleted: new(api.Boolean(v.Status == "deleting")), Processing: new(api.Boolean(processing)), UpgradeProcessing: new(api.Boolean(false)), DomainProcessingStatus: &state, AccessPolicies: new(api.PolicyDocument(policy)), ClusterConfig: clusterConfig(v), AdvancedOptions: api.AdvancedOptions{}, EBSOptions: &api.EBSOptions{EBSEnabled: new(api.Boolean(false))}, EncryptionAtRestOptions: &api.EncryptionAtRestOptions{Enabled: new(api.Boolean(false))}, NodeToNodeEncryptionOptions: &api.NodeToNodeEncryptionOptions{Enabled: new(api.Boolean(false))}, AdvancedSecurityOptions: &api.AdvancedSecurityOptions{Enabled: new(api.Boolean(false)), InternalUserDatabaseEnabled: new(api.Boolean(false))}, DomainEndpointOptions: &api.DomainEndpointOptions{EnforceHTTPS: new(api.Boolean(false)), CustomEndpointEnabled: new(api.Boolean(false))}}
	for k, v := range v.AdvancedOptions {
		out.AdvancedOptions[api.String(k)] = api.String(v)
	}
	if v.NativeEndpoint != "" && v.Status != "deleting" {
		out.Endpoint = new(api.ServiceUrl(strings.TrimPrefix(strings.TrimPrefix(s.endpoint, "http://"), "https://") + domainPath(v)))
	}
	return out, nil
}
func clusterConfig(v Domain) *api.ClusterConfig {
	return &api.ClusterConfig{InstanceCount: new(api.IntegerClass(v.InstanceCount)), DedicatedMasterEnabled: new(api.Boolean(false)), ZoneAwarenessEnabled: new(api.Boolean(false)), WarmEnabled: new(api.Boolean(false)), MultiAZWithStandbyEnabled: new(api.Boolean(false))}
}
func (s *Service) domainConfig(ctx context.Context, v Domain) (*api.DomainConfig, error) {
	d, err := s.domainStatus(ctx, v)
	if err != nil {
		return nil, err
	}
	state := api.OptionState("Active")
	if v.Status != "active" {
		state = "Processing"
	}
	status := &api.OptionStatus{CreationDate: new(api.UpdateTimestamp(v.Created)), UpdateDate: new(api.UpdateTimestamp(v.Updated)), UpdateVersion: new(api.UIntValue(v.ConfigVersion)), State: &state, PendingDeletion: new(api.Boolean(v.Status == "deleting"))}
	return &api.DomainConfig{AccessPolicies: &api.AccessPoliciesStatus{Options: d.AccessPolicies, Status: status}, AdvancedOptions: &api.AdvancedOptionsStatus{Options: d.AdvancedOptions, Status: status}, ClusterConfig: &api.ClusterConfigStatus{Options: d.ClusterConfig, Status: status}, EngineVersion: &api.VersionStatus{Options: d.EngineVersion, Status: status}, EBSOptions: &api.EBSOptionsStatus{Options: d.EBSOptions, Status: status}, EncryptionAtRestOptions: &api.EncryptionAtRestOptionsStatus{Options: d.EncryptionAtRestOptions, Status: status}, NodeToNodeEncryptionOptions: &api.NodeToNodeEncryptionOptionsStatus{Options: d.NodeToNodeEncryptionOptions, Status: status}, AdvancedSecurityOptions: &api.AdvancedSecurityOptionsStatus{Options: d.AdvancedSecurityOptions, Status: status}, DomainEndpointOptions: &api.DomainEndpointOptionsStatus{Options: d.DomainEndpointOptions, Status: status}}, nil
}
