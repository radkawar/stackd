package opensearch

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/opensearch"
)

const EngineVersion = "OpenSearch_2.19"

var domainName = regexp.MustCompile(`^[a-z][a-z0-9-]{2,27}$`)

// rejectOtherFields keeps newly generated controls unsupported until their
// effects have an owner. Presence is not silently reduced to inert metadata.
func rejectOtherFields(in any, allowed ...string) error {
	v := reflect.ValueOf(in).Elem()
	t := v.Type()
	for i := range v.NumField() {
		if v.Field(i).IsZero() {
			continue
		}
		name := t.Field(i).Name
		found := false
		for _, a := range allowed {
			if a == name {
				found = true
				break
			}
		}
		if !found {
			return failure("ValidationException", name+" is not supported by the configured native runtime.")
		}
	}
	return nil
}
func validateCommon(cluster *api.ClusterConfig, ebs *api.EBSOptions, security *api.AdvancedSecurityOptionsInput, rest *api.EncryptionAtRestOptions, node *api.NodeToNodeEncryptionOptions, endpoint *api.DomainEndpointOptions) error {
	if cluster != nil {
		if err := rejectOtherFields(cluster, "InstanceCount", "DedicatedMasterEnabled", "ZoneAwarenessEnabled", "WarmEnabled", "MultiAZWithStandbyEnabled"); err != nil {
			return err
		}
		if cluster.InstanceCount != nil && *cluster.InstanceCount != 1 {
			return failure("ValidationException", "Only one native data node is supported.")
		}
		if enabled(cluster.DedicatedMasterEnabled) || enabled(cluster.ZoneAwarenessEnabled) || enabled(cluster.WarmEnabled) || enabled(cluster.MultiAZWithStandbyEnabled) {
			return failure("ValidationException", "Distributed domain topology is not supported.")
		}
	}
	if ebs != nil {
		if err := rejectOtherFields(ebs, "EBSEnabled"); err != nil {
			return err
		}
		if enabled(ebs.EBSEnabled) {
			return failure("ValidationException", "Managed EBS is not supported; native domain data uses an owned durable local volume.")
		}
	}
	if security != nil {
		if err := rejectOtherFields(security, "Enabled", "InternalUserDatabaseEnabled", "AnonymousAuthEnabled"); err != nil {
			return err
		}
		if enabled(security.Enabled) || enabled(security.InternalUserDatabaseEnabled) || enabled(security.AnonymousAuthEnabled) {
			return failure("ValidationException", "Fine-grained/internal-user security is not supported. Use IAM and domain access policies.")
		}
	}
	if rest != nil {
		if err := rejectOtherFields(rest, "Enabled"); err != nil {
			return err
		}
		if enabled(rest.Enabled) {
			return failure("ValidationException", "Native domain encryption at rest is not supported.")
		}
	}
	if node != nil && enabled(node.Enabled) {
		return failure("ValidationException", "Native node-to-node TLS is not supported.")
	}
	if endpoint != nil {
		if err := rejectOtherFields(endpoint, "EnforceHTTPS", "CustomEndpointEnabled"); err != nil {
			return err
		}
		if enabled(endpoint.EnforceHTTPS) || enabled(endpoint.CustomEndpointEnabled) {
			return failure("ValidationException", "Managed HTTPS/custom endpoints are not supported.")
		}
	}
	return nil
}
func validateCreate(in *api.CreateDomainRequest) error {
	if !domainName.MatchString(value(in.DomainName)) {
		return failure("ValidationException", "DomainName must be 3–28 lowercase letters, digits or hyphens, beginning with a letter.")
	}
	if version := value(in.EngineVersion); version != "" && version != EngineVersion {
		return failure("ValidationException", "Unsupported engine version: "+version+". The installed runtime supports "+EngineVersion+" only.")
	}
	if err := rejectOtherFields(in, "DomainName", "EngineVersion", "AccessPolicies", "AdvancedOptions", "ClusterConfig", "EBSOptions", "AdvancedSecurityOptions", "EncryptionAtRestOptions", "NodeToNodeEncryptionOptions", "DomainEndpointOptions", "TagList"); err != nil {
		return err
	}
	return validateCommon(in.ClusterConfig, in.EBSOptions, in.AdvancedSecurityOptions, in.EncryptionAtRestOptions, in.NodeToNodeEncryptionOptions, in.DomainEndpointOptions)
}
func validateUpdate(in *api.UpdateDomainConfigRequest) error {
	if err := rejectOtherFields(in, "DomainName", "AccessPolicies", "AdvancedOptions", "ClusterConfig", "EBSOptions", "AdvancedSecurityOptions", "EncryptionAtRestOptions", "NodeToNodeEncryptionOptions", "DomainEndpointOptions"); err != nil {
		return err
	}
	return validateCommon(in.ClusterConfig, in.EBSOptions, in.AdvancedSecurityOptions, in.EncryptionAtRestOptions, in.NodeToNodeEncryptionOptions, in.DomainEndpointOptions)
}
func advancedOptions(in api.AdvancedOptions) (map[string]string, error) {
	out := make(map[string]string, len(in))
	for k, v := range in {
		switch k {
		case "indices.query.bool.max_clause_count":
			n, e := strconv.ParseInt(string(v), 10, 32)
			if e != nil || n < 1 {
				return nil, failure("ValidationException", "max_clause_count must be a positive 32-bit integer.")
			}
		case "rest.action.multi.allow_explicit_index":
			if v != "true" && v != "false" {
				return nil, failure("ValidationException", "allow_explicit_index must be true or false.")
			}
		default:
			return nil, failure("ValidationException", "Unsupported advanced option: "+string(k))
		}
		out[string(k)] = string(v)
	}
	return out, nil
}
func (s *Service) bindPolicy(ctx context.Context, document string) (authorization.BoundPolicy, error) {
	if document == "" {
		return authorization.BoundPolicy{}, nil
	}
	if s.binder == nil {
		return authorization.BoundPolicy{}, failure("InternalException", "Policy binding is unavailable.")
	}
	bound, err := s.binder.BindResourcePolicy(ctx, document, authorization.ResourcePolicyOptions{})
	if err != nil {
		return bound, failure("ValidationException", "Invalid domain access policy: "+err.Error())
	}
	return bound, nil
}
func (s *Service) authorize(ctx context.Context, action, arn string, tags map[string]string, conditions map[string][]string, resource *Domain) error {
	if legacy := legacyAction(action); legacy != "" {
		if decoded, ok := awsapi.FromContext(ctx); ok && string(decoded.Operation.Name) == legacy {
			action = legacy
		}
	}
	if conditions == nil {
		conditions = map[string][]string{}
	}
	for k, v := range tags {
		conditions["aws:ResourceTag/"+k] = []string{v}
	}
	now := s.clock.Now()
	request := authorization.Request{Action: "es:" + action, ResourceARN: arn, Context: conditions, ContextTypes: map[string]string{"aws:TagKeys": "stringList"}, EvaluationTime: &now}
	if alias := policyActionAlias(action); alias != "" {
		request.PolicyActionAliases = []string{"es:" + alias}
	}
	if resource != nil && resource.AccessPolicy != "" {
		request.ResourcePolicies = []authorization.BoundPolicy{{Document: resource.AccessPolicy, PrincipalIDs: resource.PolicyPrincipals}}
	}
	returnError := s.authorizer.Authorize(ctx, request)
	if returnError != nil {
		return returnError
	}
	return nil
}
func (s *Service) load(ctx context.Context, tx Reader, name, action string) (Domain, error) {
	k := Key{scopeFor(ctx), name}
	v, err := tx.Domain(k)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return v, err
	}
	if rejected := s.authorize(ctx, action, k.ARN(), v.Tags, nil, nil); rejected != nil {
		return v, rejected
	}
	return v, err
}
func requestTags(in api.TagList) (map[string]string, error) {
	out := map[string]string{}
	for _, tag := range in {
		k := value(tag.Key)
		if k == "" || len(k) > 128 || strings.HasPrefix(strings.ToLower(k), "aws:") || len(value(tag.Value)) > 256 {
			return nil, failure("ValidationException", "Invalid resource tag.")
		}
		out[k] = value(tag.Value)
	}
	if len(out) > 50 {
		return nil, failure("ValidationException", "A domain cannot have more than 50 tags.")
	}
	return out, nil
}
func tagConditions(tags map[string]string) map[string][]string {
	out := map[string][]string{}
	for k, v := range tags {
		out["aws:RequestTag/"+k] = []string{v}
		out["aws:TagKeys"] = append(out["aws:TagKeys"], k)
	}
	return out
}
