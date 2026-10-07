package integrations

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	api "stackd/internal/awsapi/wafv2"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/wafv2"
)

// CloudFormationWAFHandlers delegates AWS::WAFv2 resources to the regional
// AWS WAF owner, whose associated web ACLs filter API Gateway REST stages.
func CloudFormationWAFHandlers(commands StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{
		"AWS::WAFv2::WebACL":            cfnWAFWebACL{commands},
		"AWS::WAFv2::IPSet":             cfnWAFIPSet{commands},
		"AWS::WAFv2::WebACLAssociation": cfnWAFAssociation{commands},
	}
}

type cfnWAFWebACL struct{ commands StepFunctionsCommands }
type cfnWAFIPSet struct{ commands StepFunctionsCommands }
type cfnWAFAssociation struct{ commands StepFunctionsCommands }

const cfnWAFScope = "REGIONAL"

var (
	cfnWAFReferenceParents = map[string]bool{"IPSetReferenceStatement": true, "RegexPatternSetReferenceStatement": true, "RuleGroupReferenceStatement": true}
	cfnWAFIntegers         = map[string]bool{"Priority": true, "Limit": true, "Size": true, "EvaluationWindowSec": true, "ResponseCode": true, "ImmunityTime": true}
	cfnWAFBooleans         = map[string]bool{"CloudWatchMetricsEnabled": true, "SampledRequestsEnabled": true}
)

// cfnWAFModel converts the CloudFormation WebACL model to the WAF API model:
// reference statements use ARN instead of Arn, ByteMatchStatement accepts
// SearchString text or SearchStringBase64, and template scalars resolved by
// Ref are coerced for integer and boolean members.
func cfnWAFModel(v any, parent string) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			converted, err := cfnWAFModel(x, k)
			if err != nil {
				return nil, err
			}
			if text, ok := converted.(string); ok && cfnWAFIntegers[k] {
				n, err := strconv.ParseInt(text, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("%s must be an integer", k)
				}
				converted = n
			}
			if text, ok := converted.(string); ok && cfnWAFBooleans[k] {
				b, err := strconv.ParseBool(text)
				if err != nil {
					return nil, fmt.Errorf("%s must be a boolean", k)
				}
				converted = b
			}
			key := k
			if k == "Arn" && cfnWAFReferenceParents[parent] {
				key = "ARN"
			}
			out[key] = converted
		}
		if parent == "ByteMatchStatement" {
			text, hasText := out["SearchString"]
			encoded, hasEncoded := out["SearchStringBase64"]
			switch {
			case hasText && hasEncoded:
				return nil, fmt.Errorf("ByteMatchStatement specifies both SearchString and SearchStringBase64")
			case hasText:
				s, ok := text.(string)
				if !ok {
					return nil, fmt.Errorf("SearchString must be a string")
				}
				out["SearchString"] = base64.StdEncoding.EncodeToString([]byte(s))
			case hasEncoded:
				out["SearchString"] = encoded
				delete(out, "SearchStringBase64")
			}
		}
		return out, nil
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			converted, err := cfnWAFModel(x, parent)
			if err != nil {
				return nil, err
			}
			out[i] = converted
		}
		return out, nil
	default:
		return v, nil
	}
}

// cfnWAFProperties is the inverse of cfnWAFModel for live reads.
func cfnWAFProperties(v any, parent string) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			key := k
			if k == "ARN" && cfnWAFReferenceParents[parent] {
				key = "Arn"
			}
			out[key] = cfnWAFProperties(x, k)
		}
		if parent == "ByteMatchStatement" {
			if encoded, ok := out["SearchString"].(string); ok {
				raw, err := base64.StdEncoding.DecodeString(encoded)
				if err == nil && utf8.Valid(raw) && strings.IndexFunc(string(raw), func(r rune) bool { return !unicode.IsPrint(r) }) < 0 {
					out["SearchString"] = string(raw)
				} else {
					out["SearchStringBase64"] = encoded
					delete(out, "SearchString")
				}
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = cfnWAFProperties(x, parent)
		}
		return out
	default:
		return v
	}
}

func cfnWAFProjection(v any, parent string) (cloudformation.Properties, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	return cloudformation.Properties(cfnWAFProperties(generic, parent).(map[string]any)), nil
}

// cfnWAFDecode validates and decodes CloudFormation properties into a typed
// WAF model struct, rejecting properties outside the resource type schema.
func cfnWAFDecode(p cloudformation.Properties, out any) error {
	converted, err := cfnWAFModel(map[string]any(p), "")
	if err != nil {
		return err
	}
	return cfnMessagingDecode(cloudformation.Properties(converted.(map[string]any)), out)
}

func cfnWAFRequireScope(scope *api.Scope) error {
	if scope == nil {
		return fmt.Errorf("scope is required")
	}
	if *scope != cfnWAFScope {
		return fmt.Errorf("scope %s is not supported: CLOUDFRONT web ACLs protect Amazon CloudFront distributions, which are not implemented; use REGIONAL", *scope)
	}
	return nil
}

// cfnWAFIdentity parses the name|id|scope physical identifier.
func cfnWAFIdentity(id string) (string, string, error) {
	parts := strings.Split(id, "|")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] != cfnWAFScope {
		return "", "", fmt.Errorf("invalid WAFv2 identifier %q; expected name|id|REGIONAL", id)
	}
	return parts[0], parts[1], nil
}

func cfnWAFTagList(tags map[string]string) api.TagList {
	out := api.TagList{}
	for _, tag := range cfnComputeTagList(tags) {
		out = append(out, api.Tag{Key: new(api.TagKey(tag["Key"])), Value: new(api.TagValue(tag["Value"]))})
	}
	return out
}

func cfnWAFTags(ctx context.Context, c StepFunctionsCommands, arn string) (map[string]string, error) {
	tags := map[string]string{}
	in := &api.ListTagsForResourceInput{ResourceARN: new(api.ResourceArn(arn))}
	for {
		out, err := cfnMessagingCall[api.ListTagsForResourceOutput](ctx, c, "wafv2", "ListTagsForResource", in)
		if err != nil {
			return nil, err
		}
		if out.TagInfoForResource != nil {
			for _, tag := range out.TagInfoForResource.TagList {
				tags[cfnComputeValue(tag.Key)] = cfnComputeValue(tag.Value)
			}
		}
		if out.NextMarker == nil {
			return tags, nil
		}
		in.NextMarker = out.NextMarker
	}
}

// cfnWAFSyncTags converges public customer tags to the desired set.
func cfnWAFSyncTags(ctx context.Context, c StepFunctionsCommands, arn string, current, desired map[string]string) error {
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		keys := make(api.TagKeyList, 0, len(removed))
		for _, k := range removed {
			keys = append(keys, api.TagKey(k))
		}
		if err := cfnMessagingExec(ctx, c, "wafv2", "UntagResource", &api.UntagResourceInput{ResourceARN: new(api.ResourceArn(arn)), TagKeys: keys}); err != nil {
			return err
		}
	}
	if len(desired) == 0 {
		return nil
	}
	return cfnMessagingExec(ctx, c, "wafv2", "TagResource", &api.TagResourceInput{ResourceARN: new(api.ResourceArn(arn)), Tags: cfnWAFTagList(desired)})
}

func cfnWAFMissing(err error) bool { return cfnMessagingMissing(err, "WAFNonexistentItemException") }
func cfnWAFStale(err error) bool   { return cfnMessagingMissing(err, "WAFOptimisticLockException") }

func cfnWAFUserTags(tags map[string]string) []any {
	var out []any
	for _, tag := range cfnComputeTagList(tags) {
		out = append(out, map[string]any{"Key": tag["Key"], "Value": tag["Value"]})
	}
	return out
}

// --- AWS::WAFv2::WebACL ---

type cfnWAFWebACLProperties struct {
	Name                         *api.EntityName
	Scope                        *api.Scope
	Description                  *api.EntityDescription
	DefaultAction                *api.DefaultAction
	Rules                        api.Rules
	VisibilityConfig             *api.VisibilityConfig
	CustomResponseBodies         api.CustomResponseBodies
	AssociationConfig            *api.AssociationConfig
	DataProtectionConfig         *api.DataProtectionConfig
	ApplicationConfig            *api.ApplicationConfig
	CaptchaConfig                *api.CaptchaConfig
	ChallengeConfig              *api.ChallengeConfig
	TokenDomains                 api.TokenDomains
	OnSourceDDoSProtectionConfig *api.OnSourceDDoSProtectionConfig
	MonetizationConfig           *api.MonetizationConfig
	Tags                         []cfnMessagingTag
}

func (h cfnWAFWebACL) decode(p cloudformation.Properties) (cfnWAFWebACLProperties, error) {
	var v cfnWAFWebACLProperties
	if err := cfnWAFDecode(p, &v); err != nil {
		return v, err
	}
	if v.DefaultAction == nil || v.VisibilityConfig == nil {
		return v, fmt.Errorf("DefaultAction and VisibilityConfig are required")
	}
	if err := cfnWAFRequireScope(v.Scope); err != nil {
		return v, err
	}
	_, err := cfnComputeTags(p)
	return v, err
}

func (h cfnWAFWebACL) Validate(p cloudformation.Properties) error {
	_, err := h.decode(p)
	return err
}

func (h cfnWAFWebACL) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnComputeChanged(a, b, "Name", "Scope"), nil
}

func (h cfnWAFWebACL) get(ctx context.Context, name, id string) (*api.GetWebACLOutput, error) {
	return cfnMessagingCall[api.GetWebACLOutput](ctx, h.commands, "wafv2", "GetWebACL", &api.GetWebACLInput{Name: new(api.EntityName(name)), Id: new(api.EntityId(id)), Scope: new(api.Scope(cfnWAFScope))})
}

func (h cfnWAFWebACL) result(ctx context.Context, name, id string) (cloudformation.ResourceResult, error) {
	out, err := h.get(ctx, name, id)
	physical := name + "|" + id + "|" + cfnWAFScope
	if err != nil {
		return cloudformation.ResourceResult{PhysicalID: physical, Ref: physical}, err
	}
	acl := out.WebACL
	var capacity int64
	if acl.Capacity != nil {
		capacity = int64(*acl.Capacity)
	}
	return cloudformation.ResourceResult{PhysicalID: physical, Ref: physical, Attributes: map[string]any{
		"Arn": cfnComputeValue(acl.ARN), "Id": id, "Capacity": capacity, "LabelNamespace": cfnComputeValue(acl.LabelNamespace),
	}}, nil
}

// find locates a web ACL by name for incarnation recovery.
func (h cfnWAFWebACL) find(ctx context.Context, name string) (api.WebACLSummary, bool, error) {
	in := &api.ListWebACLsInput{Scope: new(api.Scope(cfnWAFScope))}
	for {
		out, err := cfnMessagingCall[api.ListWebACLsOutput](ctx, h.commands, "wafv2", "ListWebACLs", in)
		if err != nil {
			return api.WebACLSummary{}, false, err
		}
		for _, v := range out.WebACLs {
			if cfnComputeValue(v.Name) == name {
				return v, true, nil
			}
		}
		if out.NextMarker == nil {
			return api.WebACLSummary{}, false, nil
		}
		in.NextMarker = out.NextMarker
	}
}

func (h cfnWAFWebACL) update(ctx context.Context, name, id string, v cfnWAFWebACLProperties) error {
	for attempt := 0; ; attempt++ {
		current, err := h.get(ctx, name, id)
		if err != nil {
			return err
		}
		err = cfnMessagingExec(ctx, h.commands, "wafv2", "UpdateWebACL", &api.UpdateWebACLInput{
			Name: new(api.EntityName(name)), Id: new(api.EntityId(id)), Scope: new(api.Scope(cfnWAFScope)), LockToken: current.LockToken,
			Description: v.Description, DefaultAction: v.DefaultAction, Rules: v.Rules, VisibilityConfig: v.VisibilityConfig,
			CustomResponseBodies: v.CustomResponseBodies, AssociationConfig: v.AssociationConfig, DataProtectionConfig: v.DataProtectionConfig,
			ApplicationConfig: v.ApplicationConfig, CaptchaConfig: v.CaptchaConfig, ChallengeConfig: v.ChallengeConfig, TokenDomains: v.TokenDomains,
			OnSourceDDoSProtectionConfig: v.OnSourceDDoSProtectionConfig, MonetizationConfig: v.MonetizationConfig,
		})
		if !cfnWAFStale(err) || attempt == 2 {
			return err
		}
	}
}

func (h cfnWAFWebACL) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	v, err := h.decode(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnWAFResourceContext(ctx, r, true)
	name := cfnWAFName(r)
	out, err := cfnMessagingCall[api.CreateWebACLOutput](ctx, h.commands, "wafv2", "CreateWebACL", &api.CreateWebACLInput{
		Name: new(api.EntityName(name)), Scope: new(api.Scope(cfnWAFScope)), Description: v.Description, DefaultAction: v.DefaultAction, Rules: v.Rules,
		VisibilityConfig: v.VisibilityConfig, CustomResponseBodies: v.CustomResponseBodies, AssociationConfig: v.AssociationConfig,
		DataProtectionConfig: v.DataProtectionConfig, ApplicationConfig: v.ApplicationConfig, CaptchaConfig: v.CaptchaConfig, ChallengeConfig: v.ChallengeConfig,
		TokenDomains: v.TokenDomains, OnSourceDDoSProtectionConfig: v.OnSourceDDoSProtectionConfig, MonetizationConfig: v.MonetizationConfig, Tags: cfnWAFTagList(cfnWAFDesiredTags(r)),
	})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(ctx, name, cfnComputeValue(out.Summary.Id))
}

func (h cfnWAFWebACL) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnWAFResourceContext(ctx, r, true)
	name := cfnWAFName(r)
	existing, found, err := h.find(ctx, name)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if !found {
		return cloudformation.ResourceResult{}, cfnWAFReadError(nil, name)
	}
	return h.result(ctx, name, cfnComputeValue(existing.Id))
}

func (h cfnWAFWebACL) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnWAFResourceContext(ctx, r, false)
	v, err := h.decode(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name, id, err := cfnWAFIdentity(r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	current, err := h.get(ctx, name, id)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arn := cfnComputeValue(current.WebACL.ARN)
	tags, err := cfnWAFTags(ctx, h.commands, arn)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.update(ctx, name, id, v); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	desired := cfnWAFDesiredTags(r)
	if err := cfnWAFSyncTags(ctx, h.commands, arn, tags, desired); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(ctx, name, id)
}

func (h cfnWAFWebACL) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnWAFResourceContext(ctx, r, false)
	name, id, err := cfnWAFIdentity(r.PhysicalID)
	if err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		current, err := h.get(ctx, name, id)
		if cfnWAFMissing(err) {
			return nil
		}
		if err != nil {
			return err
		}
		err = cfnMessagingExec(ctx, h.commands, "wafv2", "DeleteWebACL", &api.DeleteWebACLInput{Name: new(api.EntityName(name)), Id: new(api.EntityId(id)), Scope: new(api.Scope(cfnWAFScope)), LockToken: current.LockToken})
		if cfnWAFMissing(err) {
			return nil
		}
		if !cfnWAFStale(err) || attempt == 2 {
			return err
		}
	}
}

func (h cfnWAFWebACL) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	name, id, err := cfnWAFIdentity(r.PhysicalID)
	if err != nil {
		return nil, err
	}
	out, err := h.get(ctx, name, id)
	if err != nil {
		return nil, cfnWAFReadError(err, r.PhysicalID)
	}
	acl := out.WebACL
	model := struct {
		DefaultAction        *api.DefaultAction       `json:"DefaultAction,omitempty"`
		Rules                api.Rules                `json:"Rules"`
		VisibilityConfig     *api.VisibilityConfig    `json:"VisibilityConfig,omitempty"`
		CustomResponseBodies api.CustomResponseBodies `json:"CustomResponseBodies,omitempty"`
		AssociationConfig    *api.AssociationConfig   `json:"AssociationConfig,omitempty"`
	}{acl.DefaultAction, acl.Rules, acl.VisibilityConfig, acl.CustomResponseBodies, acl.AssociationConfig}
	p, err := cfnWAFProjection(model, "")
	if err != nil {
		return nil, err
	}
	p["Name"], p["Id"], p["Scope"], p["Arn"], p["LabelNamespace"] = name, id, cfnWAFScope, cfnComputeValue(acl.ARN), cfnComputeValue(acl.LabelNamespace)
	if acl.Capacity != nil {
		p["Capacity"] = int64(*acl.Capacity)
	}
	if acl.Description != nil {
		p["Description"] = cfnComputeValue(acl.Description)
	}
	tags, err := cfnWAFTags(ctx, h.commands, cfnComputeValue(acl.ARN))
	if err != nil {
		return nil, err
	}
	if user := cfnWAFUserTags(tags); len(user) > 0 {
		p["Tags"] = user
	}
	return p, nil
}

func (h cfnWAFWebACL) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows := []cloudformation.ResourceDescription{}
	in := &api.ListWebACLsInput{Scope: new(api.Scope(cfnWAFScope))}
	for {
		out, err := cfnMessagingCall[api.ListWebACLsOutput](ctx, h.commands, "wafv2", "ListWebACLs", in)
		if err != nil {
			return nil, err
		}
		for _, v := range out.WebACLs {
			id := cfnComputeValue(v.Name) + "|" + cfnComputeValue(v.Id) + "|" + cfnWAFScope
			rows = append(rows, cloudformation.ResourceDescription{Identifier: id, Properties: cloudformation.Properties{"Name": cfnComputeValue(v.Name), "Id": cfnComputeValue(v.Id), "Scope": cfnWAFScope}})
		}
		if out.NextMarker == nil {
			return rows, nil
		}
		in.NextMarker = out.NextMarker
	}
}

// --- AWS::WAFv2::IPSet ---

type cfnWAFIPSetProperties struct {
	Name             *api.EntityName
	Scope            *api.Scope
	Description      *api.EntityDescription
	IPAddressVersion *api.IPAddressVersion
	Addresses        api.IPAddresses
	Tags             []cfnMessagingTag
}

func (h cfnWAFIPSet) decode(p cloudformation.Properties) (cfnWAFIPSetProperties, error) {
	var v cfnWAFIPSetProperties
	if err := cfnMessagingDecode(p, &v); err != nil {
		return v, err
	}
	if v.IPAddressVersion == nil || p["Addresses"] == nil {
		return v, fmt.Errorf("IPAddressVersion and Addresses are required")
	}
	if v.Addresses == nil {
		v.Addresses = api.IPAddresses{}
	}
	if err := cfnWAFRequireScope(v.Scope); err != nil {
		return v, err
	}
	_, err := cfnComputeTags(p)
	return v, err
}

func (h cfnWAFIPSet) Validate(p cloudformation.Properties) error {
	_, err := h.decode(p)
	return err
}

// The UpdateIPSet API cannot change IPAddressVersion, so it needs a new IP set.
func (h cfnWAFIPSet) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnComputeChanged(a, b, "Name", "Scope", "IPAddressVersion"), nil
}

func (h cfnWAFIPSet) get(ctx context.Context, name, id string) (*api.GetIPSetOutput, error) {
	return cfnMessagingCall[api.GetIPSetOutput](ctx, h.commands, "wafv2", "GetIPSet", &api.GetIPSetInput{Name: new(api.EntityName(name)), Id: new(api.EntityId(id)), Scope: new(api.Scope(cfnWAFScope))})
}

func (h cfnWAFIPSet) result(ctx context.Context, name, id string) (cloudformation.ResourceResult, error) {
	out, err := h.get(ctx, name, id)
	physical := name + "|" + id + "|" + cfnWAFScope
	if err != nil {
		return cloudformation.ResourceResult{PhysicalID: physical, Ref: physical}, err
	}
	return cloudformation.ResourceResult{PhysicalID: physical, Ref: physical, Attributes: map[string]any{"Arn": cfnComputeValue(out.IPSet.ARN), "Id": id}}, nil
}

func (h cfnWAFIPSet) find(ctx context.Context, name string) (api.IPSetSummary, bool, error) {
	in := &api.ListIPSetsInput{Scope: new(api.Scope(cfnWAFScope))}
	for {
		out, err := cfnMessagingCall[api.ListIPSetsOutput](ctx, h.commands, "wafv2", "ListIPSets", in)
		if err != nil {
			return api.IPSetSummary{}, false, err
		}
		for _, v := range out.IPSets {
			if cfnComputeValue(v.Name) == name {
				return v, true, nil
			}
		}
		if out.NextMarker == nil {
			return api.IPSetSummary{}, false, nil
		}
		in.NextMarker = out.NextMarker
	}
}

func (h cfnWAFIPSet) update(ctx context.Context, name, id string, v cfnWAFIPSetProperties) error {
	for attempt := 0; ; attempt++ {
		current, err := h.get(ctx, name, id)
		if err != nil {
			return err
		}
		if cfnComputeValue(current.IPSet.IPAddressVersion) != cfnComputeValue(v.IPAddressVersion) {
			return fmt.Errorf("IP set %s has IPAddressVersion %s; changing it requires replacement", name, cfnComputeValue(current.IPSet.IPAddressVersion))
		}
		err = cfnMessagingExec(ctx, h.commands, "wafv2", "UpdateIPSet", &api.UpdateIPSetInput{Name: new(api.EntityName(name)), Id: new(api.EntityId(id)), Scope: new(api.Scope(cfnWAFScope)), LockToken: current.LockToken, Description: v.Description, Addresses: v.Addresses})
		if !cfnWAFStale(err) || attempt == 2 {
			return err
		}
	}
}

func (h cfnWAFIPSet) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	v, err := h.decode(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnWAFResourceContext(ctx, r, true)
	name := cfnWAFName(r)
	out, err := cfnMessagingCall[api.CreateIPSetOutput](ctx, h.commands, "wafv2", "CreateIPSet", &api.CreateIPSetInput{Name: new(api.EntityName(name)), Scope: new(api.Scope(cfnWAFScope)), Description: v.Description, IPAddressVersion: v.IPAddressVersion, Addresses: v.Addresses, Tags: cfnWAFTagList(cfnWAFDesiredTags(r))})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(ctx, name, cfnComputeValue(out.Summary.Id))
}

func (h cfnWAFIPSet) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnWAFResourceContext(ctx, r, true)
	name := cfnWAFName(r)
	existing, found, err := h.find(ctx, name)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if !found {
		return cloudformation.ResourceResult{}, cfnWAFReadError(nil, name)
	}
	return h.result(ctx, name, cfnComputeValue(existing.Id))
}

func (h cfnWAFIPSet) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnWAFResourceContext(ctx, r, false)
	v, err := h.decode(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name, id, err := cfnWAFIdentity(r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	current, err := h.get(ctx, name, id)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arn := cfnComputeValue(current.IPSet.ARN)
	tags, err := cfnWAFTags(ctx, h.commands, arn)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.update(ctx, name, id, v); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	desired := cfnWAFDesiredTags(r)
	if err := cfnWAFSyncTags(ctx, h.commands, arn, tags, desired); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(ctx, name, id)
}

func (h cfnWAFIPSet) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnWAFResourceContext(ctx, r, false)
	name, id, err := cfnWAFIdentity(r.PhysicalID)
	if err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		current, err := h.get(ctx, name, id)
		if cfnWAFMissing(err) {
			return nil
		}
		if err != nil {
			return err
		}
		err = cfnMessagingExec(ctx, h.commands, "wafv2", "DeleteIPSet", &api.DeleteIPSetInput{Name: new(api.EntityName(name)), Id: new(api.EntityId(id)), Scope: new(api.Scope(cfnWAFScope)), LockToken: current.LockToken})
		if cfnWAFMissing(err) {
			return nil
		}
		if !cfnWAFStale(err) || attempt == 2 {
			return err
		}
	}
}

func (h cfnWAFIPSet) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	name, id, err := cfnWAFIdentity(r.PhysicalID)
	if err != nil {
		return nil, err
	}
	out, err := h.get(ctx, name, id)
	if err != nil {
		return nil, cfnWAFReadError(err, r.PhysicalID)
	}
	set := out.IPSet
	addresses := make([]any, 0, len(set.Addresses))
	for _, a := range set.Addresses {
		addresses = append(addresses, string(a))
	}
	p := cloudformation.Properties{"Name": name, "Id": id, "Scope": cfnWAFScope, "Arn": cfnComputeValue(set.ARN), "IPAddressVersion": cfnComputeValue(set.IPAddressVersion), "Addresses": addresses}
	if set.Description != nil {
		p["Description"] = cfnComputeValue(set.Description)
	}
	tags, err := cfnWAFTags(ctx, h.commands, cfnComputeValue(set.ARN))
	if err != nil {
		return nil, err
	}
	if user := cfnWAFUserTags(tags); len(user) > 0 {
		p["Tags"] = user
	}
	return p, nil
}

func (h cfnWAFIPSet) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows := []cloudformation.ResourceDescription{}
	in := &api.ListIPSetsInput{Scope: new(api.Scope(cfnWAFScope))}
	for {
		out, err := cfnMessagingCall[api.ListIPSetsOutput](ctx, h.commands, "wafv2", "ListIPSets", in)
		if err != nil {
			return nil, err
		}
		for _, v := range out.IPSets {
			id := cfnComputeValue(v.Name) + "|" + cfnComputeValue(v.Id) + "|" + cfnWAFScope
			rows = append(rows, cloudformation.ResourceDescription{Identifier: id, Properties: cloudformation.Properties{"Name": cfnComputeValue(v.Name), "Id": cfnComputeValue(v.Id), "Scope": cfnWAFScope}})
		}
		if out.NextMarker == nil {
			return rows, nil
		}
		in.NextMarker = out.NextMarker
	}
}

// --- AWS::WAFv2::WebACLAssociation ---

type cfnWAFAssociationProperties struct {
	ResourceArn *api.ResourceArn
	WebACLArn   *api.ResourceArn
}

func (h cfnWAFAssociation) decode(p cloudformation.Properties) (cfnWAFAssociationProperties, error) {
	var v cfnWAFAssociationProperties
	if err := cfnMessagingDecode(p, &v); err != nil {
		return v, err
	}
	if cfnComputeValue(v.ResourceArn) == "" || cfnComputeValue(v.WebACLArn) == "" {
		return v, fmt.Errorf("ResourceArn and WebACLArn are required")
	}
	return v, nil
}

func (h cfnWAFAssociation) Validate(p cloudformation.Properties) error {
	_, err := h.decode(p)
	return err
}

// Both properties are create-only: any change associates a new incarnation.
func (h cfnWAFAssociation) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnComputeChanged(a, b, "ResourceArn", "WebACLArn"), nil
}

// ownerContext fences stack commands to this association incarnation; Cloud
// Control operates on the association directly.
func (h cfnWAFAssociation) ownerContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return wafv2.WithAssociationOwner(ctx, wafv2.AssociationOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token})
}

func cfnWAFAssociationIdentity(id string) (string, string, error) {
	resource, acl, ok := strings.Cut(id, "|")
	if !ok || resource == "" || acl == "" {
		return "", "", fmt.Errorf("invalid WebACLAssociation identifier %q; expected ResourceArn|WebACLArn", id)
	}
	return resource, acl, nil
}

func (h cfnWAFAssociation) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	v, err := h.decode(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnMessagingExec(h.ownerContext(ctx, r), h.commands, "wafv2", "AssociateWebACL", &api.AssociateWebACLInput{ResourceArn: v.ResourceArn, WebACLArn: v.WebACLArn}); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnMessagingResult(string(*v.ResourceArn) + "|" + string(*v.WebACLArn)), nil
}

func (h cfnWAFAssociation) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if _, err := h.decode(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if cfnComputeChanged(r.Previous, r.Properties, "ResourceArn", "WebACLArn") {
		return cloudformation.ResourceResult{}, fmt.Errorf("ResourceArn and WebACLArn are create-only; changes require replacement")
	}
	return h.Create(ctx, r)
}

func (h cfnWAFAssociation) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	resource, acl, err := cfnWAFAssociationIdentity(r.PhysicalID)
	if err != nil {
		return err
	}
	if !r.CloudControl {
		// A later incarnation or a native association now owns the resource.
		current, err := cfnMessagingCall[api.GetWebACLForResourceOutput](ctx, h.commands, "wafv2", "GetWebACLForResource", &api.GetWebACLForResourceInput{ResourceArn: new(api.ResourceArn(resource))})
		if cfnWAFMissing(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.WebACL == nil || cfnComputeValue(current.WebACL.ARN) != acl {
			return nil
		}
	}
	err = cfnMessagingExec(h.ownerContext(ctx, r), h.commands, "wafv2", "DisassociateWebACL", &api.DisassociateWebACLInput{ResourceArn: new(api.ResourceArn(resource))})
	if cfnMessagingMissing(err, "WAFNonexistentItemException", "WAFInvalidOperationException") && !r.CloudControl {
		return nil
	}
	return err
}

func (h cfnWAFAssociation) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	resource, acl, err := cfnWAFAssociationIdentity(r.PhysicalID)
	if err != nil {
		return nil, err
	}
	out, err := cfnMessagingCall[api.GetWebACLForResourceOutput](ctx, h.commands, "wafv2", "GetWebACLForResource", &api.GetWebACLForResourceInput{ResourceArn: new(api.ResourceArn(resource))})
	if err != nil {
		return nil, cfnWAFReadError(err, r.PhysicalID)
	}
	if out.WebACL == nil || cfnComputeValue(out.WebACL.ARN) != acl {
		return nil, cfnWAFReadError(nil, r.PhysicalID)
	}
	return cloudformation.Properties{"ResourceArn": resource, "WebACLArn": acl}, nil
}

func (h cfnWAFAssociation) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	acl := cfnComputeString(r.Properties, "WebACLArn")
	if acl == "" {
		return nil, fmt.Errorf("listing WebACLAssociation resources requires WebACLArn")
	}
	out, err := cfnMessagingCall[api.ListResourcesForWebACLOutput](ctx, h.commands, "wafv2", "ListResourcesForWebACL", &api.ListResourcesForWebACLInput{WebACLArn: new(api.ResourceArn(acl)), ResourceType: new(api.ResourceType("API_GATEWAY"))})
	if err != nil {
		return nil, err
	}
	rows := []cloudformation.ResourceDescription{}
	for _, resource := range out.ResourceArns {
		rows = append(rows, cloudformation.ResourceDescription{Identifier: string(resource) + "|" + acl, Properties: cloudformation.Properties{"ResourceArn": string(resource), "WebACLArn": acl}})
	}
	return rows, nil
}

// cfnWAFReadError reports a missing resource with the code Cloud Control maps
// to ResourceNotFoundException. A nil err denotes an absent association.
func cfnWAFReadError(err error, id string) error {
	if err == nil || cfnWAFMissing(err) {
		return &awswire.Error{Code: "NotFound", Message: "WAFv2 resource " + id + " does not exist", StatusCode: 404}
	}
	return err
}

func cfnWAFResourceContext(ctx context.Context, r cloudformation.ResourceRequest, creating bool) context.Context {
	if r.CloudControl && !creating {
		return ctx
	}
	return wafv2.WithResourceOwner(ctx, wafv2.ResourceOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token})
}

func cfnWAFDesiredTags(r cloudformation.ResourceRequest) map[string]string {
	desired, _ := cfnComputeTags(r.Properties)
	for key, value := range r.Tags {
		desired[key] = value
	}
	return desired
}

// cfnWAFName selects the explicit Name or a stable incarnation-derived name
// matching the WAF entity name pattern ^[\w\-]+$.
func cfnWAFName(r cloudformation.ResourceRequest) string {
	r.PhysicalID = ""
	return cfnComputeName(r, "Name", 128)
}
