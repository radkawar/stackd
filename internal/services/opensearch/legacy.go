package opensearch

import (
	"context"
	"net/http"
	"slices"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	es "stackd/internal/awsapi/es"
	api "stackd/internal/awsapi/opensearch"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
)

// Legacy serves the 2015-01-01 Elasticsearch configuration API against its
// Service's existing domain repository, authorization and native runtime.
type Legacy struct {
	service    *Service
	operations map[string]func(context.Context) (any, *awswire.Error)
}

// Legacy returns an independently routable frontend, not another domain owner.
func (s *Service) Legacy() *Legacy {
	l := &Legacy{service: s, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	registerLegacy(l, "ListDomainNames", l.listDomains)
	registerLegacy(l, "ListElasticsearchVersions", l.listVersions)
	registerLegacy(l, "DescribeElasticsearchDomain", l.describeDomain)
	registerLegacy(l, "DescribeElasticsearchDomains", l.describeDomains)
	registerLegacy(l, "DescribeElasticsearchDomainConfig", l.describeConfig)
	registerLegacy(l, "UpdateElasticsearchDomainConfig", l.updateConfig)
	registerLegacy(l, "DeleteElasticsearchDomain", l.deleteDomain)
	registerLegacy(l, "AddTags", l.addTags)
	registerLegacy(l, "RemoveTags", l.removeTags)
	registerLegacy(l, "ListTags", l.listTags)
	return l
}

func (l *Legacy) Operations() []string {
	out := make([]string, 0, len(l.operations))
	for action := range l.operations {
		out = append(out, action)
	}
	slices.Sort(out)
	return out
}

func (l *Legacy) ExecuteCommand(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, request)
	if fn := l.operations[string(request.Operation.Name)]; fn != nil {
		return fn(ctx)
	}
	rejected := failure("ValidationException", "The requested legacy Elasticsearch operation is not supported.")
	if request.Operation.Name == "CreateElasticsearchDomain" {
		rejected = failure("ValidationException", "Unsupported engine version: legacy Elasticsearch creation is not supported. Use CreateDomain with "+EngineVersion+" for the configured native runtime.")
	}
	if err := l.RecordRequestError(ctx, request, rejected); err != nil {
		return nil, wireError(err)
	}
	return nil, rejected
}

func (l *Legacy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	request, ok := awsapi.FromContext(r.Context())
	model, _ := awscatalog.LookupService("es")
	if !ok {
		awswire.RESTJSONError(w, r, &model, failure("InternalException", "Missing generated request binding."))
		return
	}
	out, rejected := l.ExecuteCommand(r.Context(), request)
	if rejected != nil {
		awswire.RESTJSONError(w, r, &model, rejected)
		return
	}
	body, err := awsapi.EncodeResponse(model, request.Operation, out)
	if err != nil {
		awswire.RESTJSONError(w, r, &model, wireError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}

func (l *Legacy) RequestError(action string, err error) *awswire.Error {
	return l.service.RequestError(action, err)
}

func (l *Legacy) RecordRequestError(ctx context.Context, request awsapi.DecodedRequest, rejected *awswire.Error) error {
	return l.service.recordCall(ctx, "es", string(request.Operation.Name), request.Input, nil, rejected)
}

func registerLegacy[I, O any](l *Legacy, action string, fn func(context.Context, Transaction, *I) (*O, error)) {
	l.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalException", "Missing generated request binding.")
		}
		ctx, err := apievents.Reserve(ctx)
		if err != nil {
			return nil, wireError(err)
		}
		var out *O
		err = l.service.repository.Attempt(ctx, func(tx Transaction) error {
			var err error
			out, err = fn(tx.Context(), tx, in)
			if err != nil {
				return err
			}
			return l.service.recordCall(tx.Context(), "es", action, in, out, nil)
		})
		if err != nil {
			rejected := wireError(err)
			completion, cancel := apievents.CompletionContext(ctx)
			defer cancel()
			if err := l.service.recordCall(completion, "es", action, in, nil, rejected); err != nil {
				return nil, wireError(err)
			}
			return nil, rejected
		}
		l.service.jobs.Wake()
		return out, nil
	}
}

func (l *Legacy) listDomains(ctx context.Context, tx Transaction, in *es.ListDomainNamesRequest) (*es.ListDomainNamesResponse, error) {
	out, err := l.service.listDomains(ctx, tx, &api.ListDomainNamesRequest{EngineType: (*api.EngineType)(in.EngineType)})
	if err != nil {
		return nil, err
	}
	result := &es.ListDomainNamesResponse{DomainNames: make(es.DomainInfoList, len(out.DomainNames))}
	for i, domain := range out.DomainNames {
		result.DomainNames[i] = es.DomainInfo{DomainName: (*es.DomainName)(domain.DomainName), EngineType: (*es.EngineType)(domain.EngineType)}
	}
	return result, nil
}

func (l *Legacy) listVersions(ctx context.Context, tx Transaction, in *es.ListElasticsearchVersionsRequest) (*es.ListElasticsearchVersionsResponse, error) {
	out, err := l.service.listVersions(ctx, tx, &api.ListVersionsRequest{MaxResults: (*api.MaxResults)(in.MaxResults), NextToken: (*api.NextToken)(in.NextToken)})
	if err != nil {
		return nil, err
	}
	result := &es.ListElasticsearchVersionsResponse{NextToken: (*es.NextToken)(out.NextToken), ElasticsearchVersions: make(es.ElasticsearchVersionList, len(out.Versions))}
	for i, version := range out.Versions {
		result.ElasticsearchVersions[i] = es.ElasticsearchVersionString(version)
	}
	return result, nil
}

func (l *Legacy) describeDomain(ctx context.Context, tx Transaction, in *es.DescribeElasticsearchDomainRequest) (*es.DescribeElasticsearchDomainResponse, error) {
	out, err := l.service.describeDomain(ctx, tx, &api.DescribeDomainRequest{DomainName: (*api.DomainName)(in.DomainName)})
	if err != nil {
		return nil, err
	}
	return &es.DescribeElasticsearchDomainResponse{DomainStatus: legacyDomainStatus(out.DomainStatus)}, nil
}

func (l *Legacy) describeDomains(ctx context.Context, tx Transaction, in *es.DescribeElasticsearchDomainsRequest) (*es.DescribeElasticsearchDomainsResponse, error) {
	names := make(api.DomainNameList, len(in.DomainNames))
	for i, name := range in.DomainNames {
		names[i] = api.DomainName(name)
	}
	out, err := l.service.describeDomains(ctx, tx, &api.DescribeDomainsRequest{DomainNames: names})
	if err != nil {
		return nil, err
	}
	result := &es.DescribeElasticsearchDomainsResponse{DomainStatusList: make(es.ElasticsearchDomainStatusList, len(out.DomainStatusList))}
	for i := range out.DomainStatusList {
		result.DomainStatusList[i] = *legacyDomainStatus(&out.DomainStatusList[i])
	}
	return result, nil
}

func (l *Legacy) describeConfig(ctx context.Context, tx Transaction, in *es.DescribeElasticsearchDomainConfigRequest) (*es.DescribeElasticsearchDomainConfigResponse, error) {
	out, err := l.service.describeConfig(ctx, tx, &api.DescribeDomainConfigRequest{DomainName: (*api.DomainName)(in.DomainName)})
	if err != nil {
		return nil, err
	}
	return &es.DescribeElasticsearchDomainConfigResponse{DomainConfig: legacyDomainConfig(out.DomainConfig)}, nil
}

func (l *Legacy) updateConfig(ctx context.Context, tx Transaction, in *es.UpdateElasticsearchDomainConfigRequest) (*es.UpdateElasticsearchDomainConfigResponse, error) {
	request, err := legacyUpdateRequest(in)
	if err != nil {
		return nil, err
	}
	out, err := l.service.updateConfig(ctx, tx, request)
	if err != nil {
		return nil, err
	}
	return &es.UpdateElasticsearchDomainConfigResponse{DomainConfig: legacyDomainConfig(out.DomainConfig)}, nil
}

func (l *Legacy) deleteDomain(ctx context.Context, tx Transaction, in *es.DeleteElasticsearchDomainRequest) (*es.DeleteElasticsearchDomainResponse, error) {
	out, err := l.service.deleteDomain(ctx, tx, &api.DeleteDomainRequest{DomainName: (*api.DomainName)(in.DomainName)})
	if err != nil {
		return nil, err
	}
	return &es.DeleteElasticsearchDomainResponse{DomainStatus: legacyDomainStatus(out.DomainStatus)}, nil
}

func (l *Legacy) addTags(ctx context.Context, tx Transaction, in *es.AddTagsRequest) (*es.Unit, error) {
	tags := make(api.TagList, len(in.TagList))
	for i, tag := range in.TagList {
		tags[i] = api.Tag{Key: (*api.TagKey)(tag.Key), Value: (*api.TagValue)(tag.Value)}
	}
	if _, err := l.service.addTags(ctx, tx, &api.AddTagsRequest{ARN: (*api.ARN)(in.ARN), TagList: tags}); err != nil {
		return nil, err
	}
	return &es.Unit{}, nil
}

func (l *Legacy) removeTags(ctx context.Context, tx Transaction, in *es.RemoveTagsRequest) (*es.Unit, error) {
	keys := make(api.StringList, len(in.TagKeys))
	for i, key := range in.TagKeys {
		keys[i] = api.String(key)
	}
	if _, err := l.service.removeTags(ctx, tx, &api.RemoveTagsRequest{ARN: (*api.ARN)(in.ARN), TagKeys: keys}); err != nil {
		return nil, err
	}
	return &es.Unit{}, nil
}

func (l *Legacy) listTags(ctx context.Context, tx Transaction, in *es.ListTagsRequest) (*es.ListTagsResponse, error) {
	out, err := l.service.listTags(ctx, tx, &api.ListTagsRequest{ARN: (*api.ARN)(in.ARN)})
	if err != nil {
		return nil, err
	}
	result := &es.ListTagsResponse{TagList: make(es.TagList, len(out.TagList))}
	for i, tag := range out.TagList {
		result.TagList[i] = es.Tag{Key: (*es.TagKey)(tag.Key), Value: (*es.TagValue)(tag.Value)}
	}
	return result, nil
}

// Validate the legacy shapes before translation, including nested structures.
// Otherwise a field absent from the modern request could silently disappear.
func legacyUpdateRequest(in *es.UpdateElasticsearchDomainConfigRequest) (*api.UpdateDomainConfigRequest, error) {
	if err := rejectOtherFields(in, "DomainName", "AccessPolicies", "AdvancedOptions", "ElasticsearchClusterConfig", "EBSOptions", "AdvancedSecurityOptions", "EncryptionAtRestOptions", "NodeToNodeEncryptionOptions", "DomainEndpointOptions"); err != nil {
		return nil, err
	}
	out := &api.UpdateDomainConfigRequest{DomainName: (*api.DomainName)(in.DomainName), AccessPolicies: (*api.PolicyDocument)(in.AccessPolicies)}
	if in.AdvancedOptions != nil {
		out.AdvancedOptions = make(api.AdvancedOptions, len(in.AdvancedOptions))
		for key, val := range in.AdvancedOptions {
			out.AdvancedOptions[api.String(key)] = api.String(val)
		}
	}
	if cluster := in.ElasticsearchClusterConfig; cluster != nil {
		if err := rejectOtherFields(cluster, "InstanceCount", "DedicatedMasterEnabled", "ZoneAwarenessEnabled", "WarmEnabled"); err != nil {
			return nil, err
		}
		out.ClusterConfig = &api.ClusterConfig{InstanceCount: (*api.IntegerClass)(cluster.InstanceCount), DedicatedMasterEnabled: (*api.Boolean)(cluster.DedicatedMasterEnabled), ZoneAwarenessEnabled: (*api.Boolean)(cluster.ZoneAwarenessEnabled), WarmEnabled: (*api.Boolean)(cluster.WarmEnabled)}
	}
	if ebs := in.EBSOptions; ebs != nil {
		if err := rejectOtherFields(ebs, "EBSEnabled"); err != nil {
			return nil, err
		}
		out.EBSOptions = &api.EBSOptions{EBSEnabled: (*api.Boolean)(ebs.EBSEnabled)}
	}
	if security := in.AdvancedSecurityOptions; security != nil {
		if err := rejectOtherFields(security, "Enabled", "InternalUserDatabaseEnabled", "AnonymousAuthEnabled"); err != nil {
			return nil, err
		}
		out.AdvancedSecurityOptions = &api.AdvancedSecurityOptionsInput{Enabled: (*api.Boolean)(security.Enabled), InternalUserDatabaseEnabled: (*api.Boolean)(security.InternalUserDatabaseEnabled), AnonymousAuthEnabled: (*api.Boolean)(security.AnonymousAuthEnabled)}
	}
	if rest := in.EncryptionAtRestOptions; rest != nil {
		if err := rejectOtherFields(rest, "Enabled"); err != nil {
			return nil, err
		}
		out.EncryptionAtRestOptions = &api.EncryptionAtRestOptions{Enabled: (*api.Boolean)(rest.Enabled)}
	}
	if node := in.NodeToNodeEncryptionOptions; node != nil {
		if err := rejectOtherFields(node, "Enabled"); err != nil {
			return nil, err
		}
		out.NodeToNodeEncryptionOptions = &api.NodeToNodeEncryptionOptions{Enabled: (*api.Boolean)(node.Enabled)}
	}
	if endpoint := in.DomainEndpointOptions; endpoint != nil {
		if err := rejectOtherFields(endpoint, "EnforceHTTPS", "CustomEndpointEnabled"); err != nil {
			return nil, err
		}
		out.DomainEndpointOptions = &api.DomainEndpointOptions{EnforceHTTPS: (*api.Boolean)(endpoint.EnforceHTTPS), CustomEndpointEnabled: (*api.Boolean)(endpoint.CustomEndpointEnabled)}
	}
	return out, nil
}

func legacyAdvancedOptions(in api.AdvancedOptions) es.AdvancedOptions {
	if in == nil {
		return nil
	}
	out := make(es.AdvancedOptions, len(in))
	for key, val := range in {
		out[es.String(key)] = es.String(val)
	}
	return out
}

func legacyClusterConfig(in *api.ClusterConfig) *es.ElasticsearchClusterConfig {
	if in == nil {
		return nil
	}
	return &es.ElasticsearchClusterConfig{InstanceCount: (*es.IntegerClass)(in.InstanceCount), DedicatedMasterEnabled: (*es.Boolean)(in.DedicatedMasterEnabled), ZoneAwarenessEnabled: (*es.Boolean)(in.ZoneAwarenessEnabled), WarmEnabled: (*es.Boolean)(in.WarmEnabled)}
}

func legacyEBSOptions(in *api.EBSOptions) *es.EBSOptions {
	if in == nil {
		return nil
	}
	return &es.EBSOptions{EBSEnabled: (*es.Boolean)(in.EBSEnabled)}
}

func legacySecurityOptions(in *api.AdvancedSecurityOptions) *es.AdvancedSecurityOptions {
	if in == nil {
		return nil
	}
	return &es.AdvancedSecurityOptions{Enabled: (*es.Boolean)(in.Enabled), InternalUserDatabaseEnabled: (*es.Boolean)(in.InternalUserDatabaseEnabled), AnonymousAuthEnabled: (*es.Boolean)(in.AnonymousAuthEnabled)}
}

func legacyEncryptionOptions(in *api.EncryptionAtRestOptions) *es.EncryptionAtRestOptions {
	if in == nil {
		return nil
	}
	return &es.EncryptionAtRestOptions{Enabled: (*es.Boolean)(in.Enabled)}
}

func legacyNodeEncryptionOptions(in *api.NodeToNodeEncryptionOptions) *es.NodeToNodeEncryptionOptions {
	if in == nil {
		return nil
	}
	return &es.NodeToNodeEncryptionOptions{Enabled: (*es.Boolean)(in.Enabled)}
}

func legacyEndpointOptions(in *api.DomainEndpointOptions) *es.DomainEndpointOptions {
	if in == nil {
		return nil
	}
	return &es.DomainEndpointOptions{EnforceHTTPS: (*es.Boolean)(in.EnforceHTTPS), CustomEndpointEnabled: (*es.Boolean)(in.CustomEndpointEnabled)}
}

func legacyDomainStatus(in *api.DomainStatus) *es.ElasticsearchDomainStatus {
	if in == nil {
		return nil
	}
	// Both API generations manage the same domains. Keep OpenSearch_X.Y intact:
	// the historical field name must not misrepresent the native engine as ES.
	// https://docs.aws.amazon.com/opensearch-service/latest/developerguide/rename.html
	// TODO: Comeback calibrate successful legacy domain/config version output
	// with an owned native domain; free native version-list evidence alone does
	// not establish every successful domain response field.
	return &es.ElasticsearchDomainStatus{
		ARN: (*es.ARN)(in.ARN), DomainId: (*es.DomainId)(in.DomainId), DomainName: (*es.DomainName)(in.DomainName),
		ElasticsearchVersion: (*es.ElasticsearchVersionString)(in.EngineVersion),
		Created:              (*es.Boolean)(in.Created), Deleted: (*es.Boolean)(in.Deleted), Processing: (*es.Boolean)(in.Processing), UpgradeProcessing: (*es.Boolean)(in.UpgradeProcessing),
		DomainProcessingStatus: (*es.DomainProcessingStatusType)(in.DomainProcessingStatus), Endpoint: (*es.ServiceUrl)(in.Endpoint),
		AccessPolicies: (*es.PolicyDocument)(in.AccessPolicies), AdvancedOptions: legacyAdvancedOptions(in.AdvancedOptions),
		ElasticsearchClusterConfig: legacyClusterConfig(in.ClusterConfig), EBSOptions: legacyEBSOptions(in.EBSOptions),
		AdvancedSecurityOptions: legacySecurityOptions(in.AdvancedSecurityOptions), EncryptionAtRestOptions: legacyEncryptionOptions(in.EncryptionAtRestOptions),
		NodeToNodeEncryptionOptions: legacyNodeEncryptionOptions(in.NodeToNodeEncryptionOptions), DomainEndpointOptions: legacyEndpointOptions(in.DomainEndpointOptions),
	}
}

func legacyOptionStatus(in *api.OptionStatus) *es.OptionStatus {
	if in == nil {
		return nil
	}
	return &es.OptionStatus{CreationDate: (*es.UpdateTimestamp)(in.CreationDate), UpdateDate: (*es.UpdateTimestamp)(in.UpdateDate), UpdateVersion: (*es.UIntValue)(in.UpdateVersion), State: (*es.OptionState)(in.State), PendingDeletion: (*es.Boolean)(in.PendingDeletion)}
}

func legacyDomainConfig(in *api.DomainConfig) *es.ElasticsearchDomainConfig {
	if in == nil {
		return nil
	}
	out := &es.ElasticsearchDomainConfig{}
	if v := in.AccessPolicies; v != nil {
		out.AccessPolicies = &es.AccessPoliciesStatus{Options: (*es.PolicyDocument)(v.Options), Status: legacyOptionStatus(v.Status)}
	}
	if v := in.AdvancedOptions; v != nil {
		out.AdvancedOptions = &es.AdvancedOptionsStatus{Options: legacyAdvancedOptions(v.Options), Status: legacyOptionStatus(v.Status)}
	}
	if v := in.EngineVersion; v != nil {
		out.ElasticsearchVersion = &es.ElasticsearchVersionStatus{Options: (*es.ElasticsearchVersionString)(v.Options), Status: legacyOptionStatus(v.Status)}
	}
	if v := in.ClusterConfig; v != nil {
		out.ElasticsearchClusterConfig = &es.ElasticsearchClusterConfigStatus{Options: legacyClusterConfig(v.Options), Status: legacyOptionStatus(v.Status)}
	}
	if v := in.EBSOptions; v != nil {
		out.EBSOptions = &es.EBSOptionsStatus{Options: legacyEBSOptions(v.Options), Status: legacyOptionStatus(v.Status)}
	}
	if v := in.AdvancedSecurityOptions; v != nil {
		out.AdvancedSecurityOptions = &es.AdvancedSecurityOptionsStatus{Options: legacySecurityOptions(v.Options), Status: legacyOptionStatus(v.Status)}
	}
	if v := in.EncryptionAtRestOptions; v != nil {
		out.EncryptionAtRestOptions = &es.EncryptionAtRestOptionsStatus{Options: legacyEncryptionOptions(v.Options), Status: legacyOptionStatus(v.Status)}
	}
	if v := in.NodeToNodeEncryptionOptions; v != nil {
		out.NodeToNodeEncryptionOptions = &es.NodeToNodeEncryptionOptionsStatus{Options: legacyNodeEncryptionOptions(v.Options), Status: legacyOptionStatus(v.Status)}
	}
	if v := in.DomainEndpointOptions; v != nil {
		out.DomainEndpointOptions = &es.DomainEndpointOptionsStatus{Options: legacyEndpointOptions(v.Options), Status: legacyOptionStatus(v.Status)}
	}
	return out
}
