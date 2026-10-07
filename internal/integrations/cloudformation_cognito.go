package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/cognitoidp"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/cognitoidp"
)

// CloudFormationCognitoHandlers registers the Cognito user pool and identity
// pool resources whose behavior the cognitoidp/cognitoidentity owners
// implement. Every effect is an owner command under the caller's IAM scope.
// Hosted UI/OAuth, MFA, passwordless, Lambda triggers, risk configuration,
// resource servers, UI customization, branding, log delivery, replicas and
// Cognito Sync have no owner, so their resource types remain unregistered.
func CloudFormationCognitoHandlers(commands StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{
		"AWS::Cognito::UserPool":                      cfnCognitoUserPool{commands},
		"AWS::Cognito::UserPoolClient":                cfnCognitoUserPoolClient{commands},
		"AWS::Cognito::UserPoolDomain":                cfnCognitoUserPoolDomain{commands},
		"AWS::Cognito::UserPoolUser":                  cfnCognitoUserPoolUser{commands},
		"AWS::Cognito::UserPoolGroup":                 cfnCognitoUserPoolGroup{commands},
		"AWS::Cognito::UserPoolUserToGroupAttachment": cfnCognitoUserPoolUserToGroupAttachment{commands},
		"AWS::Cognito::UserPoolIdentityProvider":      cfnCognitoUserPoolIdentityProvider{commands},
		"AWS::Cognito::IdentityPool":                  cfnCognitoIdentityPool{commands},
		"AWS::Cognito::IdentityPoolRoleAttachment":    cfnCognitoIdentityPoolRoleAttachment{commands},
		"AWS::Cognito::IdentityPoolPrincipalTag":      cfnCognitoIdentityPoolPrincipalTag{commands},
	}
}

// cfnCognitoContext binds stack mutations of pools and pool children to the
// owner's persisted private incarnation claim. Cloud Control mutates existing
// resources directly under the caller's current IAM authority.
func cfnCognitoContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return cognitoidp.WithResourceOwner(ctx, cfnCognitoOwner(r))
}

// cfnCognitoClaimContext binds every create, including a Cloud Control create,
// so the new resource commits with its private claim and a retried create of
// the same incarnation replays it.
func cfnCognitoClaimContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	return cognitoidp.WithResourceOwner(ctx, cfnCognitoOwner(r))
}

func cfnCognitoOwner(r cloudformation.ResourceRequest) cognitoidp.ResourceOwner {
	return cognitoidp.ResourceOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token}
}

// cfnCognitoTags merges stack tags with a resource's tags. Tags are public,
// customer-mutable metadata; ownership is the owner's private claim.
func cfnCognitoTags(r cloudformation.ResourceRequest, tags []cfnMessagingTag) (map[string]string, error) {
	out := make(map[string]string, len(r.Tags)+len(tags))
	maps.Copy(out, r.Tags)
	seen := make(map[string]bool, len(tags))
	for _, tag := range tags {
		if seen[tag.Key] {
			return nil, fmt.Errorf("duplicate tag %q", tag.Key)
		}
		seen[tag.Key] = true
		out[tag.Key] = tag.Value
	}
	for k, v := range out {
		if k == "" || len(k) > 128 || len(v) > 256 || strings.HasPrefix(strings.ToLower(k), "aws:") {
			return nil, fmt.Errorf("invalid or reserved tag %q", k)
		}
	}
	return out, nil
}

// cfnCognitoInput decodes template properties into a generated owner input.
// CloudFormation names these properties after the API members. Unknown members
// fail rather than being ignored, and Ref-produced scalar strings are coerced
// to the member's boolean or numeric type.
func cfnCognitoInput[T any](p map[string]any) (*T, error) {
	out := new(T)
	if err := cfnCognitoAssign("", p, reflect.ValueOf(out).Elem()); err != nil {
		return nil, err
	}
	return out, nil
}

func cfnCognitoPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func cfnCognitoNumber(raw any) (string, bool) {
	switch x := raw.(type) {
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case json.Number:
		return string(x), true
	case int:
		return strconv.Itoa(x), true
	case int64:
		return strconv.FormatInt(x, 10), true
	case string:
		return x, true
	}
	return "", false
}

func cfnCognitoAssign(path string, raw any, v reflect.Value) error {
	if raw == nil {
		return fmt.Errorf("property %s must not be null; use AWS::NoValue to omit it", path)
	}
	switch v.Kind() {
	case reflect.Pointer:
		next := reflect.New(v.Type().Elem())
		if err := cfnCognitoAssign(path, raw, next.Elem()); err != nil {
			return err
		}
		v.Set(next)
	case reflect.Struct:
		object, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("property %s must be an object", path)
		}
		fields := make(map[string]int, v.NumField())
		for i := range v.NumField() {
			field := v.Type().Field(i)
			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if name == "" && field.IsExported() && !field.Anonymous {
				name = field.Name
			}
			if name != "" && name != "-" {
				fields[name] = i
			}
		}
		for _, key := range cfnMessagingKeys(object) {
			i, ok := fields[key]
			if !ok {
				return fmt.Errorf("unsupported CloudFormation property %s", cfnCognitoPath(path, key))
			}
			if err := cfnCognitoAssign(cfnCognitoPath(path, key), object[key], v.Field(i)); err != nil {
				return err
			}
		}
	case reflect.Slice:
		list, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("property %s must be a list", path)
		}
		out := reflect.MakeSlice(v.Type(), len(list), len(list))
		for i, item := range list {
			if err := cfnCognitoAssign(fmt.Sprintf("%s[%d]", path, i), item, out.Index(i)); err != nil {
				return err
			}
		}
		v.Set(out)
	case reflect.Map:
		object, ok := raw.(map[string]any)
		if !ok || v.Type().Key().Kind() != reflect.String {
			return fmt.Errorf("property %s must be an object", path)
		}
		out := reflect.MakeMapWithSize(v.Type(), len(object))
		for key, item := range object {
			value := reflect.New(v.Type().Elem()).Elem()
			if err := cfnCognitoAssign(cfnCognitoPath(path, key), item, value); err != nil {
				return err
			}
			name := reflect.New(v.Type().Key()).Elem()
			name.SetString(key)
			out.SetMapIndex(name, value)
		}
		v.Set(out)
	case reflect.String:
		switch x := raw.(type) {
		case string:
			v.SetString(x)
		case bool:
			v.SetString(strconv.FormatBool(x))
		default:
			text, ok := cfnCognitoNumber(raw)
			if !ok {
				return fmt.Errorf("property %s must be a string", path)
			}
			v.SetString(text)
		}
	case reflect.Bool:
		switch x := raw.(type) {
		case bool:
			v.SetBool(x)
		case string:
			if x != "true" && x != "false" {
				return fmt.Errorf("property %s must be a boolean", path)
			}
			v.SetBool(x == "true")
		default:
			return fmt.Errorf("property %s must be a boolean", path)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		text, ok := cfnCognitoNumber(raw)
		n, err := strconv.ParseInt(text, 10, 64)
		if !ok || err != nil || v.OverflowInt(n) {
			return fmt.Errorf("property %s must be an integer", path)
		}
		v.SetInt(n)
	case reflect.Float32, reflect.Float64:
		text, ok := cfnCognitoNumber(raw)
		n, err := strconv.ParseFloat(text, 64)
		if !ok || err != nil {
			return fmt.Errorf("property %s must be a number", path)
		}
		v.SetFloat(n)
	case reflect.Interface:
		v.Set(reflect.ValueOf(raw))
	default:
		return fmt.Errorf("property %s has an unsupported type", path)
	}
	return nil
}

// cfnCognitoProject reads named members of an owner output as properties.
func cfnCognitoProject(v any, keys ...string) (cloudformation.Properties, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	all := map[string]any{}
	if err := json.Unmarshal(body, &all); err != nil {
		return nil, err
	}
	return cloudformation.Properties(cfnComputeCopy(all, keys...)), nil
}

func cfnCognitoWithout(p map[string]any, keys ...string) map[string]any {
	out := make(map[string]any, len(p))
	for key, value := range p {
		out[key] = value
	}
	for _, key := range keys {
		delete(out, key)
	}
	return out
}

// cfnCognitoIdentifier parses Cloud Control compound identifiers: schema
// primaryIdentifier values joined by "|". Stack creates read the properties.
func cfnCognitoIdentifier(r cloudformation.ResourceRequest, keys ...string) ([]string, error) {
	ids := make([]string, len(keys))
	if r.PhysicalID == "" {
		for i, key := range keys {
			ids[i], _ = r.Properties[key].(string)
		}
	} else {
		parts := strings.Split(r.PhysicalID, "|")
		if len(parts) != len(keys) {
			return nil, fmt.Errorf("identifier must be %s", strings.Join(keys, "|"))
		}
		copy(ids, parts)
	}
	for i, id := range ids {
		if id == "" {
			return nil, fmt.Errorf("identifier requires %s", keys[i])
		}
	}
	return ids, nil
}

func cfnCognitoMissing(err error) bool {
	return cfnMessagingMissing(err, "ResourceNotFoundException", "UserNotFoundException")
}

// cfnCognitoNotFound reports a relationship absent from an owner read in the
// owner's own not-found shape.
func cfnCognitoNotFound(what string) error {
	return &awswire.Error{Code: "ResourceNotFoundException", Message: what + " does not exist", StatusCode: http.StatusBadRequest}
}

func cfnCognitoAbsent(err error) error {
	if cfnCognitoMissing(err) {
		return nil
	}
	return err
}

// cfnCognitoParent returns the required parent identifier for Cloud Control List.
func cfnCognitoParent(r cloudformation.ResourceRequest, key string) (string, error) {
	id, _ := r.Properties[key].(string)
	if id == "" {
		return "", fmt.Errorf("listing requires %s", key)
	}
	return id, nil
}

type cfnCognitoUserPool struct{ commands StepFunctionsCommands }

// User pool properties without an implemented owner (MFA factors, passwordless
// sign-in and WebAuthn) are rejected by name rather than stored.
var cfnCognitoUnsupportedPoolProperties = []string{"EnabledMfas", "EmailAuthenticationMessage", "EmailAuthenticationSubject", "WebAuthnRelyingPartyID", "WebAuthnUserVerification", "WebAuthnFactorConfiguration"}

// Usernames, aliases and case sensitivity are fixed at creation by the owner.
var cfnCognitoFixedPoolProperties = []string{"AliasAttributes", "UsernameAttributes", "UsernameConfiguration"}

func cfnCognitoPoolCommon(p map[string]any) (map[string]any, error) {
	for _, key := range cfnCognitoUnsupportedPoolProperties {
		if _, ok := p[key]; ok {
			if list, empty := p[key].([]any); empty && len(list) == 0 {
				continue
			}
			return nil, fmt.Errorf("user pool property %s is not supported: MFA factors and passwordless sign-in are not implemented", key)
		}
	}
	// Read-only attributes can arrive in a Cloud Control desired state.
	m := cfnCognitoWithout(p, append([]string{"UserPoolName", "UserPoolTags", "Arn", "ProviderName", "ProviderURL", "UserPoolId"}, cfnCognitoUnsupportedPoolProperties...)...)
	if name, ok := p["UserPoolName"]; ok {
		m["PoolName"] = name
	}
	return m, nil
}

func cfnCognitoPoolTags(r cloudformation.ResourceRequest) (map[string]string, error) {
	user := map[string]string{}
	if raw, ok := r.Properties["UserPoolTags"]; ok {
		object, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("UserPoolTags must be an object of strings")
		}
		for key, value := range object {
			text, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("UserPoolTags values must be strings")
			}
			user[key] = text
		}
	}
	tags := make([]cfnMessagingTag, 0, len(user))
	for _, key := range cfnMessagingKeys(user) {
		tags = append(tags, cfnMessagingTag{Key: key, Value: user[key]})
	}
	return cfnCognitoTags(r, tags)
}

func (h cfnCognitoUserPool) createInput(r cloudformation.ResourceRequest) (*api.CreateUserPoolInput, error) {
	m, err := cfnCognitoPoolCommon(r.Properties)
	if err != nil {
		return nil, err
	}
	if _, ok := m["PoolName"]; !ok {
		m["PoolName"] = cfnComputeName(r, "UserPoolName", 128)
	}
	return cfnCognitoInput[api.CreateUserPoolInput](m)
}

func (h cfnCognitoUserPool) Validate(p cloudformation.Properties) error {
	if _, err := h.createInput(cloudformation.ResourceRequest{Properties: p, StackName: "stack", LogicalID: "Pool"}); err != nil {
		return err
	}
	_, err := cfnCognitoPoolTags(cloudformation.ResourceRequest{Properties: p})
	return err
}

func (h cfnCognitoUserPool) Replacement(a, b cloudformation.Properties) (bool, error) {
	return false, h.Validate(b)
}

func (h cfnCognitoUserPool) result(pool *api.UserPoolType) cloudformation.ResourceResult {
	id, arn := cfnComputeValue(pool.Id), cfnComputeValue(pool.Arn)
	attributes := map[string]any{"UserPoolId": id, "Arn": arn}
	if parts := strings.SplitN(arn, ":", 6); len(parts) == 6 {
		name := cognitoidp.ProviderName(parts[1], parts[3], id)
		attributes["ProviderName"], attributes["ProviderURL"] = name, "https://"+name
	}
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: attributes}
}

func (h cfnCognitoUserPool) describe(ctx context.Context, id string) (*api.UserPoolType, map[string]string, error) {
	out, err := cfnMessagingCall[api.DescribeUserPoolOutput](ctx, h.commands, "cognitoidp", "DescribeUserPool", &api.DescribeUserPoolInput{UserPoolId: new(api.UserPoolIdType(id))})
	if err != nil {
		return nil, nil, err
	}
	tags := make(map[string]string, len(out.UserPool.UserPoolTags))
	for key, value := range out.UserPool.UserPoolTags {
		tags[string(key)] = string(value)
	}
	return out.UserPool, tags, nil
}

// ids lists the caller's pools in this Region in identifier order.
func (h cfnCognitoUserPool) ids(ctx context.Context) ([]string, error) {
	var ids []string
	token := ""
	for {
		page := map[string]any{"MaxResults": 60}
		if token != "" {
			page["NextToken"] = token
		}
		in, err := cfnCognitoInput[api.ListUserPoolsInput](page)
		if err != nil {
			return nil, err
		}
		out, err := cfnMessagingCall[api.ListUserPoolsOutput](ctx, h.commands, "cognitoidp", "ListUserPools", in)
		if err != nil {
			return nil, err
		}
		for _, summary := range out.UserPools {
			ids = append(ids, cfnComputeValue(summary.Id))
		}
		if token = cfnComputeValue(out.NextToken); token == "" {
			sort.Strings(ids)
			return ids, nil
		}
	}
}

// create admits this incarnation's pool, or with recover set only observes it.
// The owner commits the pool with its private claim, so a retried create of
// the same incarnation replays it and foreign or tagged pools never match.
func (h cfnCognitoUserPool) create(ctx context.Context, r cloudformation.ResourceRequest, recover bool) (cloudformation.ResourceResult, error) {
	in, err := h.createInput(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	tags, err := cfnCognitoPoolTags(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	in.UserPoolTags = api.UserPoolTagsType{}
	for key, value := range tags {
		in.UserPoolTags[api.TagKeysType(key)] = api.TagValueType(value)
	}
	ctx = cfnCognitoClaimContext(ctx, r)
	if recover {
		ctx = cognitoidp.WithCreationRecovery(ctx, cfnCognitoOwner(r))
	}
	out, err := cfnMessagingCall[api.CreateUserPoolOutput](ctx, h.commands, "cognitoidp", "CreateUserPool", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(out.UserPool), nil
}

func (h cfnCognitoUserPool) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.create(ctx, r, false)
}

// RecoverCreation observes only the pool claimed by this exact incarnation.
func (h cfnCognitoUserPool) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.create(ctx, r, true)
}

func cfnCognitoSchema(p map[string]any) (api.SchemaAttributesListType, error) {
	raw, ok := p["Schema"]
	if !ok {
		return nil, nil
	}
	in, err := cfnCognitoInput[api.CreateUserPoolInput](map[string]any{"Schema": raw})
	if err != nil {
		return nil, err
	}
	return in.Schema, nil
}

func cfnCognitoSchemaName(a api.SchemaAttributeType) string {
	return strings.TrimPrefix(strings.TrimPrefix(cfnComputeValue(a.Name), "custom:"), "dev:")
}

// cfnCognitoSchemaAdditions returns custom attributes added by an update. The
// owner cannot modify or remove existing attributes, so those fail.
func cfnCognitoSchemaAdditions(before, after map[string]any) (api.SchemaAttributesListType, error) {
	old, err := cfnCognitoSchema(before)
	if err != nil {
		return nil, err
	}
	next, err := cfnCognitoSchema(after)
	if err != nil {
		return nil, err
	}
	previous := make(map[string]api.SchemaAttributeType, len(old))
	for _, a := range old {
		previous[cfnCognitoSchemaName(a)] = a
	}
	var added api.SchemaAttributesListType
	seen := map[string]bool{}
	for _, a := range next {
		name := cfnCognitoSchemaName(a)
		seen[name] = true
		prior, existed := previous[name]
		switch {
		case !existed:
			added = append(added, a)
		case !reflect.DeepEqual(prior, a):
			return nil, fmt.Errorf("user pool schema attribute %s cannot be modified after creation", name)
		}
	}
	for name := range previous {
		if !seen[name] {
			return nil, fmt.Errorf("user pool schema attribute %s cannot be removed after creation", name)
		}
	}
	return added, nil
}

func (h cfnCognitoUserPool) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	for _, key := range cfnCognitoFixedPoolProperties {
		if cfnComputeChanged(r.Previous, r.Properties, key) {
			return cloudformation.ResourceResult{}, fmt.Errorf("user pool property %s cannot be changed after creation", key)
		}
	}
	added, err := cfnCognitoSchemaAdditions(r.Previous, r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	m, err := cfnCognitoPoolCommon(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	m = cfnCognitoWithout(m, append([]string{"Schema"}, cfnCognitoFixedPoolProperties...)...)
	m["UserPoolId"] = r.PhysicalID
	in, err := cfnCognitoInput[api.UpdateUserPoolInput](m)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	desired, err := cfnCognitoPoolTags(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	in.UserPoolTags = api.UserPoolTagsType{}
	for key, value := range desired {
		in.UserPoolTags[api.TagKeysType(key)] = api.TagValueType(value)
	}
	// Each mutation checks the pool's private claim in its own transaction.
	owned := cfnCognitoContext(ctx, r)
	if len(added) > 0 {
		if err := cfnMessagingExec(owned, h.commands, "cognitoidp", "AddCustomAttributes", &api.AddCustomAttributesInput{UserPoolId: new(api.UserPoolIdType(r.PhysicalID)), CustomAttributes: api.CustomAttributesListType(added)}); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	if err := cfnMessagingExec(owned, h.commands, "cognitoidp", "UpdateUserPool", in); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	pool, _, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(pool), nil
}

func (h cfnCognitoUserPool) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	return cfnCognitoAbsent(cfnMessagingExec(cfnCognitoContext(ctx, r), h.commands, "cognitoidp", "DeleteUserPool", &api.DeleteUserPoolInput{UserPoolId: new(api.UserPoolIdType(r.PhysicalID))}))
}

func (h cfnCognitoUserPool) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	pool, tags, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p, err := cfnCognitoProject(pool, "AccountRecoverySetting", "AdminCreateUserConfig", "AliasAttributes", "AutoVerifiedAttributes", "DeletionProtection",
		"DeviceConfiguration", "EmailConfiguration", "EmailVerificationMessage", "EmailVerificationSubject", "LambdaConfig", "MfaConfiguration", "Policies",
		"UserAttributeUpdateSettings", "UserPoolAddOns", "UserPoolTier", "UsernameAttributes", "UsernameConfiguration", "VerificationMessageTemplate")
	if err != nil {
		return nil, err
	}
	// Templates declare custom attributes; the standard schema is implicit.
	var custom []any
	for _, a := range pool.SchemaAttributes {
		name := cfnComputeValue(a.Name)
		if strings.HasPrefix(name, "custom:") || strings.HasPrefix(name, "dev:") {
			projected, err := cfnCognitoProject(a, "AttributeDataType", "DeveloperOnlyAttribute", "Mutable", "Required", "NumberAttributeConstraints", "StringAttributeConstraints")
			if err != nil {
				return nil, err
			}
			projected["Name"] = cfnCognitoSchemaName(a)
			custom = append(custom, map[string]any(projected))
		}
	}
	if len(custom) > 0 {
		p["Schema"] = custom
	}
	public := make(map[string]any, len(tags))
	for key, value := range tags {
		public[key] = value
	}
	p["UserPoolTags"] = public
	p["UserPoolName"] = cfnComputeValue(pool.Name)
	for key, value := range h.result(pool).Attributes {
		p[key] = value
	}
	return p, nil
}

func (h cfnCognitoUserPool) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
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
