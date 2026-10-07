package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	cache "stackd/internal/awsapi/elasticache"
	memory "stackd/internal/awsapi/memorydb"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	cacheowner "stackd/internal/services/elasticache"
	memoryowner "stackd/internal/services/memorydb"
)

// Owner commands enforce IAM and native runtime admission. These helpers only
// translate CloudFormation collections; they never retain resource state.
func cfnEngineMissing(err error) bool {
	var e *awswire.Error
	return errors.As(err, &e) && (strings.Contains(e.Code, "NotFound") || e.Code == "ResourceNotFoundException")
}
func cfnEngineName(r cloudformation.ResourceRequest, property string, limit int) string {
	if r.PhysicalID != "" {
		return r.PhysicalID
	}
	if name := cfnComputeString(r.Properties, property); name != "" {
		return name
	}
	// Keep the shared incarnation hash, but make the generated prefix satisfy the
	// native cache identifier rules. Explicit names remain native-owner validated.
	name := strings.ToLower(cfnComputeName(r, property, limit))
	if name[0] >= 'a' && name[0] <= 'z' && !strings.Contains(name, "--") {
		return name
	}
	prefixEnd := len(name) - 25 // separator plus the shared 24-character hash
	var safe strings.Builder
	safe.Grow(limit)
	hyphen := false
	for i := range prefixEnd {
		ch := name[i]
		if ch == '-' {
			hyphen = safe.Len() > 0
			continue
		}
		if safe.Len() == 0 && ch >= '0' && ch <= '9' {
			safe.WriteString("cfn-")
		}
		needed := 1
		if hyphen {
			needed++
		}
		if safe.Len()+needed > limit-25 {
			break
		}
		if hyphen {
			safe.WriteByte('-')
			hyphen = false
		}
		safe.WriteByte(ch)
	}
	if safe.Len() == 0 {
		safe.WriteString("cfn")
	}
	safe.WriteString(name[prefixEnd:])
	return safe.String()
}
func cfnEngineStable(status string, ready ...string) (bool, error) {
	for _, s := range ready {
		if status == s {
			return true, nil
		}
	}
	switch strings.ToLower(status) {
	case "failed", "create_failed", "create-failed", "creation_failed", "isolated", "incompatible_parameters", "critical_action_required":
		return false, fmt.Errorf("native resource entered terminal status %s", status)
	}
	return false, nil
}
func cfnEngineSet(values []string) map[string]bool {
	m := make(map[string]bool, len(values))
	for _, v := range values {
		m[v] = true
	}
	return m
}
func cfnEngineDifference(current, desired []string) (add, remove []string) {
	a, b := cfnEngineSet(current), cfnEngineSet(desired)
	for v := range b {
		if !a[v] {
			add = append(add, v)
		}
	}
	for v := range a {
		if !b[v] {
			remove = append(remove, v)
		}
	}
	sort.Strings(add)
	sort.Strings(remove)
	return
}
func cfnEngineList[S ~[]E, E ~string](values S) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = string(v)
	}
	return out
}
func cfnCacheTags(ctx context.Context, c StepFunctionsCommands, arn string) (map[string]string, error) {
	out, err := cfnComputeCall[cache.ListTagsForResourceOutput](ctx, c, "elasticache", "ListTagsForResource", map[string]any{"ResourceName": arn})
	if err != nil {
		return nil, err
	}
	tags := map[string]string{}
	for _, t := range out.TagList {
		tags[cfnComputeValue(t.Key)] = cfnComputeValue(t.Value)
	}
	return tags, nil
}
func cfnMemoryTags(ctx context.Context, c StepFunctionsCommands, arn string) (map[string]string, error) {
	out, err := cfnComputeCall[memory.ListTagsOutput](ctx, c, "memorydb", "ListTags", map[string]any{"ResourceArn": arn})
	if err != nil {
		return nil, err
	}
	tags := map[string]string{}
	for _, t := range out.TagList {
		tags[cfnComputeValue(t.Key)] = cfnComputeValue(t.Value)
	}
	return tags, nil
}

// Native cache rows persist the private incarnation claim. Stack requests fence
// every native effect and observation to that exact incarnation; Cloud Control
// creates still claim, while its direct mutations use only current IAM.
func cfnCacheOwner(ctx context.Context, r cloudformation.ResourceRequest, kind, name string, creating bool) context.Context {
	return cacheowner.WithCloudFormationOwner(ctx, kind, name, cfnNativeComputeClaim(r), creating)
}
func cfnCacheFence(ctx context.Context, r cloudformation.ResourceRequest, kind, name string) context.Context {
	if r.CloudControl {
		return ctx
	}
	return cfnCacheOwner(ctx, r, kind, name, false)
}
func cfnMemoryOwner(ctx context.Context, r cloudformation.ResourceRequest, kind, name string, creating bool) context.Context {
	return memoryowner.WithCloudFormationOwner(ctx, kind, name, cfnNativeComputeClaim(r), creating)
}
func cfnMemoryFence(ctx context.Context, r cloudformation.ResourceRequest, kind, name string) context.Context {
	if r.CloudControl {
		return ctx
	}
	return cfnMemoryOwner(ctx, r, kind, name, false)
}

// cfnEngineAdmit creates one exact incarnation. A row visible under the exact
// claim is this incarnation's earlier admission; a same-name row owned by any
// other incarnation is never adopted. A failed command whose exact row is still
// visible reports admission so the caller returns that identity with the error.
func cfnEngineAdmit(r cloudformation.ResourceRequest, exact, creating context.Context, observe, create func(context.Context) error) (bool, error) {
	err := observe(exact)
	if err == nil {
		return true, nil
	}
	if !cfnEngineMissing(err) {
		return false, err
	}
	if err = create(creating); err == nil {
		return true, nil
	}
	if observe(exact) == nil {
		return true, err
	}
	var e *awswire.Error
	if errors.As(err, &e) && strings.Contains(e.Code, "AlreadyExists") {
		return false, cfnResourceCreateOwnedError(r, err)
	}
	return false, err
}

// cfnEngineAbsent certifies that RecoverCreation found no row for this exact
// incarnation; other failures are not proof of absence.
func cfnEngineAbsent(err error) error {
	if cfnEngineMissing(err) {
		return &awswire.Error{Code: "ResourceNotFoundException", Message: "this resource incarnation was not admitted", StatusCode: 404}
	}
	return err
}

// Stack and resource tags are customer metadata only; they carry no ownership.
func cfnEngineUserTags(r cloudformation.ResourceRequest) map[string]string {
	tags := make(map[string]string, len(r.Tags))
	for k, v := range r.Tags {
		tags[k] = v
	}
	resource, _ := cfnComputeTags(r.Properties)
	for k, v := range resource {
		tags[k] = v
	}
	return tags
}

func cfnCacheUpdateTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string, current map[string]string) error {
	desired := cfnEngineUserTags(r)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if err := cfnComputeRun(ctx, c, "elasticache", "RemoveTagsFromResource", map[string]any{"ResourceName": arn, "TagKeys": removed}); err != nil {
			return err
		}
	}
	if len(desired) == 0 {
		return nil
	}
	return cfnComputeRun(ctx, c, "elasticache", "AddTagsToResource", map[string]any{"ResourceName": arn, "Tags": cfnComputeTagList(desired)})
}
func cfnMemoryUpdateTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string, current map[string]string) error {
	desired := cfnEngineUserTags(r)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if err := cfnComputeRun(ctx, c, "memorydb", "UntagResource", map[string]any{"ResourceArn": arn, "TagKeys": removed}); err != nil {
			return err
		}
	}
	if len(desired) == 0 {
		return nil
	}
	return cfnComputeRun(ctx, c, "memorydb", "TagResource", map[string]any{"ResourceArn": arn, "Tags": cfnComputeTagList(desired)})
}
func cfnEngineParameters(raw any) ([]map[string]string, error) {
	if raw == nil {
		return nil, nil
	}
	p, ok := cfnComputeObject(raw)
	if !ok {
		return nil, fmt.Errorf("parameters must be an object")
	}
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]map[string]string, 0, len(p))
	for _, k := range keys {
		v, ok := p[k].(string)
		if !ok {
			return nil, fmt.Errorf("parameter %s must be a string", k)
		}
		out = append(out, map[string]string{"ParameterName": k, "ParameterValue": v})
	}
	return out, nil
}

func cfnEngineResult(id string, p cloudformation.Properties) (cloudformation.ResourceResult, error) {
	// Normalize typed native endpoint structures before intrinsic attribute access.
	body, err := json.Marshal(p)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	attributes := map[string]any{}
	if err = json.Unmarshal(body, &attributes); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	for key, raw := range attributes {
		if object, ok := raw.(map[string]any); ok {
			for field, v := range object {
				attributes[key+"."+field] = v
			}
		}
	}
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: attributes}, nil
}

func cfnEngineParametersMatch(current map[string]string, desired []map[string]string) bool {
	if len(current) != len(desired) {
		return false
	}
	for _, p := range desired {
		value, ok := current[p["ParameterName"]]
		if !ok || value != p["ParameterValue"] {
			return false
		}
	}
	return true
}

func cfnCacheEndpoint(v *cache.Endpoint) any {
	if v == nil || v.Port == nil {
		return nil
	}
	return map[string]any{"Address": cfnComputeValue(v.Address), "Port": fmt.Sprint(*v.Port)}
}

func cfnMemoryARNResult(id string, p cloudformation.Properties) (cloudformation.ResourceResult, error) {
	result, err := cfnEngineResult(id, p)
	if err != nil {
		return result, err
	}
	result.Ref = cfnComputeString(p, "ARN")
	if result.Ref == "" {
		result.Ref = cfnComputeString(p, "Arn")
	}
	if result.Ref == "" {
		return result, fmt.Errorf("MemoryDB owner returned no ARN")
	}
	return result, nil
}
