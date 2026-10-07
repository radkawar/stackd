package integrations

import (
	"context"
	"fmt"
	"strings"

	api "stackd/internal/awsapi/cognitoidentity"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/cognitoidentity"
)

type cfnCognitoIdentityPool struct{ commands StepFunctionsCommands }

// Cognito Sync (streams, push sync and sync events) has no owner.
var cfnCognitoSyncProperties = []string{"CognitoStreams", "PushSync", "CognitoEvents"}

func cfnCognitoIdentityPoolName(r cloudformation.ResourceRequest) string {
	if name, ok := r.Properties["IdentityPoolName"].(string); ok {
		return name
	}
	// Identity pool names admit only word characters and spaces.
	var b strings.Builder
	for _, ch := range r.StackName + "_" + r.LogicalID {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' {
			b.WriteRune(ch)
		}
	}
	prefix := b.String()
	if len(prefix) > 128-25 {
		prefix = prefix[:128-25]
	}
	return prefix + "_" + cfnComputeHash(r.StackID+"/"+r.LogicalID+"/"+r.Token)
}

func cfnCognitoIdentityPoolTags(r cloudformation.ResourceRequest) (map[string]string, error) {
	var tags []cfnMessagingTag
	if raw, ok := r.Properties["IdentityPoolTags"]; ok {
		decoded, err := cfnCognitoInput[struct {
			Tags []cfnMessagingTag `json:"Tags"`
		}](map[string]any{"Tags": raw})
		if err != nil {
			return nil, err
		}
		tags = decoded.Tags
	}
	return cfnCognitoTags(r, tags)
}

// input projects template properties onto the owner's identity pool shape.
func (h cfnCognitoIdentityPool) input(r cloudformation.ResourceRequest, id string) (*api.IdentityPool, map[string]string, error) {
	for _, key := range cfnCognitoSyncProperties {
		if _, ok := r.Properties[key]; ok {
			return nil, nil, fmt.Errorf("identity pool property %s is not supported: Amazon Cognito Sync is not implemented", key)
		}
	}
	tags, err := cfnCognitoIdentityPoolTags(r)
	if err != nil {
		return nil, nil, err
	}
	m := cfnCognitoWithout(r.Properties, "IdentityPoolTags", "Id", "Name")
	m["IdentityPoolName"] = cfnCognitoIdentityPoolName(r)
	if id != "" {
		m["IdentityPoolId"] = id
	}
	in, err := cfnCognitoInput[api.IdentityPool](m)
	if err != nil {
		return nil, nil, err
	}
	return in, tags, nil
}

func (h cfnCognitoIdentityPool) Validate(p cloudformation.Properties) error {
	if err := cfnComputeRequired(p, "AllowUnauthenticatedIdentities"); err != nil {
		return err
	}
	_, _, err := h.input(cloudformation.ResourceRequest{Properties: p, StackName: "stack", LogicalID: "Pool"}, "")
	return err
}

func (h cfnCognitoIdentityPool) Replacement(a, b cloudformation.Properties) (bool, error) {
	return false, h.Validate(b)
}

func cfnCognitoIdentityPoolResult(p *api.IdentityPool) cloudformation.ResourceResult {
	id := cfnComputeValue(p.IdentityPoolId)
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Id": id, "Name": cfnComputeValue(p.IdentityPoolName)}}
}

func (h cfnCognitoIdentityPool) describe(ctx context.Context, id string) (*api.IdentityPool, map[string]string, error) {
	out, err := cfnMessagingCall[api.DescribeIdentityPoolOutput](ctx, h.commands, "cognitoidentity", "DescribeIdentityPool", &api.DescribeIdentityPoolInput{IdentityPoolId: new(api.IdentityPoolId(id))})
	if err != nil {
		return nil, nil, err
	}
	tags := make(map[string]string, len(out.IdentityPoolTags))
	for key, value := range out.IdentityPoolTags {
		tags[string(key)] = string(value)
	}
	return out, tags, nil
}

func (h cfnCognitoIdentityPool) ids(ctx context.Context) ([]string, error) {
	var ids []string
	token := ""
	for {
		page := map[string]any{"MaxResults": 60}
		if token != "" {
			page["NextToken"] = token
		}
		in, err := cfnCognitoInput[api.ListIdentityPoolsInput](page)
		if err != nil {
			return nil, err
		}
		out, err := cfnMessagingCall[api.ListIdentityPoolsOutput](ctx, h.commands, "cognitoidentity", "ListIdentityPools", in)
		if err != nil {
			return nil, err
		}
		for _, pool := range out.IdentityPools {
			ids = append(ids, cfnComputeValue(pool.IdentityPoolId))
		}
		if token = cfnComputeValue(out.NextToken); token == "" {
			return ids, nil
		}
	}
}

func cfnCognitoIdentityTags(tags map[string]string) api.IdentityPoolTagsType {
	out := make(api.IdentityPoolTagsType, len(tags))
	for key, value := range tags {
		out[api.TagKeysType(key)] = api.TagValueType(value)
	}
	return out
}

// cfnCognitoIdentityContext binds stack mutations of an identity pool to the
// owner's private incarnation claim; Cloud Control mutates directly.
func cfnCognitoIdentityContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return cognitoidentity.WithResourceOwner(ctx, cfnCognitoIdentityOwner(r))
}

func cfnCognitoIdentityOwner(r cloudformation.ResourceRequest) cognitoidentity.ResourceOwner {
	return cognitoidentity.ResourceOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token}
}

// create admits this incarnation's pool, or with recover set only observes it.
// Identity pool IDs are generated; the owner commits the pool with its private
// claim, so a retried create replays it and foreign or tagged pools never match.
func (h cfnCognitoIdentityPool) create(ctx context.Context, r cloudformation.ResourceRequest, recover bool) (cloudformation.ResourceResult, error) {
	in, tags, err := h.input(r, "")
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	create := &api.CreateIdentityPoolInput{
		IdentityPoolName: in.IdentityPoolName, AllowUnauthenticatedIdentities: in.AllowUnauthenticatedIdentities, AllowClassicFlow: in.AllowClassicFlow,
		SupportedLoginProviders: in.SupportedLoginProviders, DeveloperProviderName: in.DeveloperProviderName, OpenIdConnectProviderARNs: in.OpenIdConnectProviderARNs,
		CognitoIdentityProviders: in.CognitoIdentityProviders, SamlProviderARNs: in.SamlProviderARNs, IdentityPoolTags: cfnCognitoIdentityTags(tags),
	}
	owner := cfnCognitoIdentityOwner(r)
	ctx = cognitoidentity.WithResourceOwner(ctx, owner)
	if recover {
		ctx = cognitoidentity.WithCreationRecovery(ctx, owner)
	}
	out, err := cfnMessagingCall[api.CreateIdentityPoolOutput](ctx, h.commands, "cognitoidentity", "CreateIdentityPool", create)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnCognitoIdentityPoolResult(out), nil
}

func (h cfnCognitoIdentityPool) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.create(ctx, r, false)
}

// RecoverCreation observes only the pool claimed by this exact incarnation.
func (h cfnCognitoIdentityPool) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.create(ctx, r, true)
}

func (h cfnCognitoIdentityPool) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	in, tags, err := h.input(r, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	in.IdentityPoolTags = cfnCognitoIdentityTags(tags)
	out, err := cfnMessagingCall[api.UpdateIdentityPoolOutput](cfnCognitoIdentityContext(ctx, r), h.commands, "cognitoidentity", "UpdateIdentityPool", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnCognitoIdentityPoolResult(out), nil
}

func (h cfnCognitoIdentityPool) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	return cfnCognitoAbsent(cfnMessagingExec(cfnCognitoIdentityContext(ctx, r), h.commands, "cognitoidentity", "DeleteIdentityPool", &api.DeleteIdentityPoolInput{IdentityPoolId: new(api.IdentityPoolId(r.PhysicalID))}))
}

func (h cfnCognitoIdentityPool) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	pool, tags, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p, err := cfnCognitoProject(pool, "IdentityPoolName", "AllowUnauthenticatedIdentities", "AllowClassicFlow", "CognitoIdentityProviders", "SupportedLoginProviders", "DeveloperProviderName", "OpenIdConnectProviderARNs", "SamlProviderARNs")
	if err != nil {
		return nil, err
	}
	p["Id"], p["Name"] = cfnComputeValue(pool.IdentityPoolId), cfnComputeValue(pool.IdentityPoolName)
	public := make([]any, 0, len(tags))
	for _, key := range cfnMessagingKeys(tags) {
		public = append(public, map[string]any{"Key": key, "Value": tags[key]})
	}
	p["IdentityPoolTags"] = public
	return p, nil
}

func (h cfnCognitoIdentityPool) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	ids, err := h.ids(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]cloudformation.ResourceDescription, 0, len(ids))
	for _, id := range ids {
		p, err := h.Read(ctx, cloudformation.ResourceRequest{PhysicalID: id, Scope: r.Scope, CloudControl: true})
		if cfnCognitoMissing(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, cloudformation.ResourceDescription{Identifier: id, Properties: p})
	}
	return out, nil
}

// IdentityPoolRoleAttachment sets the pool's single role configuration. Its
// identifier is the identity pool ID; deletion clears roles and mappings.
// Template role mappings use arbitrary keys whose values name their provider,
// unlike the API map keyed by provider.
type cfnCognitoIdentityPoolRoleAttachment struct{ commands StepFunctionsCommands }

func (h cfnCognitoIdentityPoolRoleAttachment) input(p map[string]any) (*api.SetIdentityPoolRolesInput, error) {
	if err := cfnComputeProperties(p, "IdentityPoolId", "Roles", "RoleMappings"); err != nil {
		return nil, err
	}
	in, err := cfnCognitoInput[api.SetIdentityPoolRolesInput](cfnCognitoWithout(p, "RoleMappings"))
	if err != nil {
		return nil, err
	}
	if in.Roles == nil {
		in.Roles = api.RolesMap{}
	}
	in.RoleMappings = api.RoleMappingMap{}
	raw, ok := p["RoleMappings"].(map[string]any)
	if _, present := p["RoleMappings"]; present && !ok {
		return nil, fmt.Errorf("RoleMappings must be an object")
	}
	for _, key := range cfnMessagingKeys(raw) {
		item, ok := raw[key].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("RoleMappings.%s must be an object", key)
		}
		mapping, err := cfnCognitoInput[api.RoleMapping](cfnCognitoWithout(item, "IdentityProvider"))
		if err != nil {
			return nil, fmt.Errorf("RoleMappings.%s: %w", key, err)
		}
		provider, _ := item["IdentityProvider"].(string)
		if provider == "" {
			return nil, fmt.Errorf("RoleMappings.%s.IdentityProvider is required", key)
		}
		if _, duplicate := in.RoleMappings[api.IdentityProviderName(provider)]; duplicate {
			return nil, fmt.Errorf("RoleMappings name provider %s more than once", provider)
		}
		in.RoleMappings[api.IdentityProviderName(provider)] = *mapping
	}
	return in, nil
}

func (h cfnCognitoIdentityPoolRoleAttachment) Validate(p cloudformation.Properties) error {
	if err := cfnComputeRequired(p, "IdentityPoolId"); err != nil {
		return err
	}
	_, err := h.input(p)
	return err
}

func (h cfnCognitoIdentityPoolRoleAttachment) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "IdentityPoolId"), h.Validate(b)
}

func (h cfnCognitoIdentityPoolRoleAttachment) set(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	m := cfnCognitoWithout(r.Properties, "Id")
	if r.PhysicalID != "" {
		m["IdentityPoolId"] = r.PhysicalID
	}
	in, err := h.input(m)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnMessagingExec(ctx, h.commands, "cognitoidentity", "SetIdentityPoolRoles", in); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := cfnComputeValue(in.IdentityPoolId)
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Id": id}}, nil
}

func (h cfnCognitoIdentityPoolRoleAttachment) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.set(ctx, r)
}

func (h cfnCognitoIdentityPoolRoleAttachment) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.set(ctx, r)
}

func (h cfnCognitoIdentityPoolRoleAttachment) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	return cfnCognitoAbsent(cfnMessagingExec(ctx, h.commands, "cognitoidentity", "SetIdentityPoolRoles", &api.SetIdentityPoolRolesInput{IdentityPoolId: new(api.IdentityPoolId(r.PhysicalID)), Roles: api.RolesMap{}}))
}

func (h cfnCognitoIdentityPoolRoleAttachment) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, err := cfnMessagingCall[api.GetIdentityPoolRolesOutput](ctx, h.commands, "cognitoidentity", "GetIdentityPoolRoles", &api.GetIdentityPoolRolesInput{IdentityPoolId: new(api.IdentityPoolId(r.PhysicalID))})
	if err != nil {
		return nil, err
	}
	if len(out.Roles) == 0 && len(out.RoleMappings) == 0 {
		return nil, cfnCognitoNotFound("role attachment for identity pool " + r.PhysicalID)
	}
	p, err := cfnCognitoProject(out, "Roles")
	if err != nil {
		return nil, err
	}
	if len(out.RoleMappings) > 0 {
		mappings := map[string]any{}
		for provider, mapping := range out.RoleMappings {
			projected, err := cfnCognitoProject(mapping, "Type", "AmbiguousRoleResolution", "RulesConfiguration")
			if err != nil {
				return nil, err
			}
			projected["IdentityProvider"] = string(provider)
			mappings[string(provider)] = map[string]any(projected)
		}
		p["RoleMappings"] = mappings
	}
	p["IdentityPoolId"], p["Id"] = r.PhysicalID, r.PhysicalID
	return p, nil
}

func (h cfnCognitoIdentityPoolRoleAttachment) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	ids, err := cfnCognitoIdentityPool(h).ids(ctx)
	if err != nil {
		return nil, err
	}
	var out []cloudformation.ResourceDescription
	for _, id := range ids {
		p, err := h.Read(ctx, cloudformation.ResourceRequest{PhysicalID: id, Scope: r.Scope, CloudControl: true})
		if cfnCognitoMissing(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, cloudformation.ResourceDescription{Identifier: id, Properties: p})
	}
	return out, nil
}

// IdentityPoolPrincipalTag maps one provider's token claims to session tags.
type cfnCognitoIdentityPoolPrincipalTag struct{ commands StepFunctionsCommands }

var cfnCognitoPrincipalTagKeys = []string{"IdentityPoolId", "IdentityProviderName"}

func (h cfnCognitoIdentityPoolPrincipalTag) Validate(p cloudformation.Properties) error {
	if err := cfnComputeRequired(p, cfnCognitoPrincipalTagKeys...); err != nil {
		return err
	}
	_, err := cfnCognitoInput[api.SetPrincipalTagAttributeMapInput](p)
	return err
}

func (h cfnCognitoIdentityPoolPrincipalTag) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, cfnCognitoPrincipalTagKeys...), h.Validate(b)
}

func (h cfnCognitoIdentityPoolPrincipalTag) set(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	m := cfnCognitoWithout(r.Properties)
	if r.PhysicalID != "" {
		ids, err := cfnCognitoIdentifier(r, cfnCognitoPrincipalTagKeys...)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		m["IdentityPoolId"], m["IdentityProviderName"] = ids[0], ids[1]
	}
	in, err := cfnCognitoInput[api.SetPrincipalTagAttributeMapInput](m)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if in.PrincipalTags == nil {
		in.PrincipalTags = api.PrincipalTags{}
	}
	if err := cfnMessagingExec(ctx, h.commands, "cognitoidentity", "SetPrincipalTagAttributeMap", in); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := cfnComputeValue(in.IdentityPoolId) + "|" + cfnComputeValue(in.IdentityProviderName)
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{}}, nil
}

func (h cfnCognitoIdentityPoolPrincipalTag) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.set(ctx, r)
}

func (h cfnCognitoIdentityPoolPrincipalTag) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.set(ctx, r)
}

func (h cfnCognitoIdentityPoolPrincipalTag) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ids, err := cfnCognitoIdentifier(r, cfnCognitoPrincipalTagKeys...)
	if err != nil {
		return err
	}
	in := &api.SetPrincipalTagAttributeMapInput{IdentityPoolId: new(api.IdentityPoolId(ids[0])), IdentityProviderName: new(api.IdentityProviderName(ids[1])), UseDefaults: new(api.UseDefaults(false)), PrincipalTags: api.PrincipalTags{}}
	err = cfnMessagingExec(ctx, h.commands, "cognitoidentity", "SetPrincipalTagAttributeMap", in)
	// A provider removed from its pool no longer has a mapping to clear.
	if cfnMessagingMissing(err, "InvalidParameterException") {
		return nil
	}
	return cfnCognitoAbsent(err)
}

func (h cfnCognitoIdentityPoolPrincipalTag) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	ids, err := cfnCognitoIdentifier(r, cfnCognitoPrincipalTagKeys...)
	if err != nil {
		return nil, err
	}
	out, err := cfnMessagingCall[api.GetPrincipalTagAttributeMapOutput](ctx, h.commands, "cognitoidentity", "GetPrincipalTagAttributeMap", &api.GetPrincipalTagAttributeMapInput{IdentityPoolId: new(api.IdentityPoolId(ids[0])), IdentityProviderName: new(api.IdentityProviderName(ids[1]))})
	if err != nil {
		return nil, err
	}
	return cfnCognitoProject(out, "IdentityPoolId", "IdentityProviderName", "UseDefaults", "PrincipalTags")
}

func (h cfnCognitoIdentityPoolPrincipalTag) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	pool, err := cfnCognitoParent(r, "IdentityPoolId")
	if err != nil {
		return nil, err
	}
	described, _, err := cfnCognitoIdentityPool(h).describe(ctx, pool)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []cloudformation.ResourceDescription
	for _, provider := range described.CognitoIdentityProviders {
		name := cfnComputeValue(provider.ProviderName)
		if seen[name] {
			continue
		}
		seen[name] = true
		id := pool + "|" + name
		p, err := h.Read(ctx, cloudformation.ResourceRequest{PhysicalID: id, Scope: r.Scope, CloudControl: true})
		if cfnCognitoMissing(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, cloudformation.ResourceDescription{Identifier: id, Properties: p})
	}
	return out, nil
}
