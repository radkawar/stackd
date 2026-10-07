package integrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	eksapi "stackd/internal/awsapi/eks"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

// CloudFormationComputeServiceHandlers binds CloudFormation types to the
// implemented ECS, EKS, Auto Scaling, Application Auto Scaling and ELBv2 owners.
// AWS::AutoScaling::LaunchConfiguration and
// AWS::ElasticLoadBalancingV2::ListenerCertificate are intentionally absent:
// neither owner implements that resource concept.
func CloudFormationComputeServiceHandlers(c StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{
		"AWS::ECS::Cluster":                           cfnECSCluster{c},
		"AWS::ECS::TaskDefinition":                    cfnECSTaskDefinition{c},
		"AWS::ECS::Service":                           cfnECSService{c},
		"AWS::EKS::Cluster":                           cfnEKSCluster{c},
		"AWS::EKS::Nodegroup":                         cfnEKSNodegroup{c},
		"AWS::EKS::Addon":                             cfnEKSAddon{c},
		"AWS::EKS::FargateProfile":                    cfnEKSFargateProfile{c},
		"AWS::EKS::AccessEntry":                       cfnEKSAccessEntry{c},
		"AWS::EKS::PodIdentityAssociation":            cfnEKSPodIdentity{c},
		"AWS::AutoScaling::AutoScalingGroup":          cfnASGGroup{c},
		"AWS::AutoScaling::LifecycleHook":             cfnASGHook{c},
		"AWS::AutoScaling::ScalingPolicy":             cfnASGPolicy{c},
		"AWS::AutoScaling::ScheduledAction":           cfnASGSchedule{c},
		"AWS::ApplicationAutoScaling::ScalableTarget": cfnAASTarget{c},
		"AWS::ApplicationAutoScaling::ScalingPolicy":  cfnAASPolicy{c},
		"AWS::ElasticLoadBalancingV2::LoadBalancer":   cfnELBLoadBalancer{c},
		"AWS::ElasticLoadBalancingV2::TargetGroup":    cfnELBTargetGroup{c},
		"AWS::ElasticLoadBalancingV2::Listener":       cfnELBListener{c},
		"AWS::ElasticLoadBalancingV2::ListenerRule":   cfnELBRule{c},
	}
}

// cfnCSValidate applies the captured registry contract and the shared tag rules.
// Owner commands remain responsible for value semantics and runtime admission.
func cfnCSValidate(typeName string, p cloudformation.Properties, unsupported ...string) error {
	if err := cloudformation.ValidateResourceProperties(typeName, p); err != nil {
		return err
	}
	for _, key := range unsupported {
		if _, ok := p[key]; ok {
			return &awswire.Error{Code: "UnsupportedOperation", Message: "property " + key + " has no implemented owner control", StatusCode: 400}
		}
	}
	_, err := cfnComputeTags(p)
	return err
}

// cfnCSReplacement follows the registry's createOnly annotations, which are the
// documented "Update requires: Replacement" properties.
func cfnCSReplacement(typeName string, a, b cloudformation.Properties) (bool, error) {
	if err := cloudformation.ValidateResourceProperties(typeName, b); err != nil {
		return false, err
	}
	err := cloudformation.ValidateResourceUpdate(typeName, a, b)
	if errors.Is(err, cloudformation.ErrCreateOnly) {
		return true, nil
	}
	return false, err
}

func cfnCSMissing(err error, codes ...string) bool {
	return cfnComputeMissing(err) || cfnMessagingMissing(err, codes...)
}

func cfnCSNotFound(what string) error {
	return &awswire.Error{Code: "ResourceNotFoundException", Message: what + " does not exist", StatusCode: 404}
}

func cfnCSUnsupported(message string) error {
	return &awswire.Error{Code: "UnsupportedOperation", Message: message, StatusCode: 400}
}

// cfnCSClientToken is stable for one resource incarnation and request kind.
func cfnCSClientToken(r cloudformation.ResourceRequest, kind string, size int) string {
	sum := sha256.Sum256([]byte(r.StackID + "/" + r.LogicalID + "/" + r.Token + "/" + kind))
	token := hex.EncodeToString(sum[:])
	if size < len(token) {
		token = token[:size]
	}
	return token
}

func cfnCSTagChanges(current, desired map[string]string) (map[string]string, []string) {
	added := map[string]string{}
	for key, value := range desired {
		if old, ok := current[key]; !ok || old != value {
			added[key] = value
		}
	}
	return added, cfnComputeRemovedTags(current, desired)
}

func cfnCSCompound(id string, count int) ([]string, error) {
	parts := strings.Split(id, "|")
	if len(parts) != count {
		return nil, fmt.Errorf("invalid resource identifier %q", id)
	}
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("invalid resource identifier %q", id)
		}
	}
	return parts, nil
}

// cfnCSCall strictly binds CloudFormation-cased properties to the owner's
// modeled input. The SDK binder ignores unknown members, so properties without
// a modeled owner field are rejected here instead of being silently dropped.
func cfnCSCall[T any](ctx context.Context, c StepFunctionsCommands, service, operation string, input map[string]any) (*T, error) {
	normalized, err := cfnCSInput(service, operation, input)
	if err != nil {
		return nil, err
	}
	return cfnComputeCall[T](ctx, c, service, operation, normalized)
}
func cfnCSRun(ctx context.Context, c StepFunctionsCommands, service, operation string, input map[string]any) error {
	normalized, err := cfnCSInput(service, operation, input)
	if err != nil {
		return err
	}
	return cfnComputeRun(ctx, c, service, operation, normalized)
}
func cfnCSInput(service, operation string, input map[string]any) (map[string]any, error) {
	model, ok := awscatalog.LookupService(service)
	if !ok {
		return nil, fmt.Errorf("service model %s is unavailable", service)
	}
	op, ok := model.Operation(operation)
	if !ok {
		return nil, fmt.Errorf("operation %s.%s is unavailable", service, operation)
	}
	data, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	var generic any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&generic); err != nil {
		return nil, err
	}
	out, err := cfnCSShape(model, op.Input, generic, "")
	if err != nil {
		return nil, &awswire.Error{Code: "InvalidRequest", Message: err.Error(), StatusCode: 400}
	}
	object, _ := out.(map[string]any)
	return object, nil
}
func cfnCSShape(model awscatalog.Service, id awscatalog.ShapeID, value any, path string) (any, error) {
	if value == nil {
		return nil, nil
	}
	shape, _ := model.Shape(id)
	switch string(shape.Kind) {
	case "structure", "union":
		object, ok := value.(map[string]any)
		if !ok {
			if p, isProps := value.(cloudformation.Properties); isProps {
				object = p
			} else {
				return nil, fmt.Errorf("%s must be an object", cfnCSPath(path))
			}
		}
		out := make(map[string]any, len(object))
		for _, key := range slices.Sorted(maps.Keys(object)) {
			var member *awscatalog.Member
			for i := range shape.Members {
				if strings.EqualFold(shape.Members[i].Name, key) {
					member = &shape.Members[i]
					break
				}
			}
			if member == nil {
				return nil, fmt.Errorf("property %s is not supported by the owner command", cfnCSPath(path+"/"+key))
			}
			if _, dup := out[member.Name]; dup {
				return nil, fmt.Errorf("property %s occurs more than once", cfnCSPath(path+"/"+key))
			}
			child, err := cfnCSShape(model, member.Target, object[key], path+"/"+key)
			if err != nil {
				return nil, err
			}
			if child != nil {
				out[member.Name] = child
			}
		}
		return out, nil
	case "list", "set":
		list, ok := value.([]any)
		if !ok {
			return nil, fmt.Errorf("%s must be a list", cfnCSPath(path))
		}
		out := make([]any, 0, len(list))
		for i, item := range list {
			child, err := cfnCSShape(model, shape.Member.Target, item, path+"/"+strconv.Itoa(i))
			if err != nil {
				return nil, err
			}
			out = append(out, child)
		}
		return out, nil
	case "map":
		object, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s must be an object", cfnCSPath(path))
		}
		out := make(map[string]any, len(object))
		for key, item := range object {
			child, err := cfnCSShape(model, shape.Value.Target, item, path+"/"+key)
			if err != nil {
				return nil, err
			}
			out[key] = child
		}
		return out, nil
	case "byte", "short", "integer", "long", "intEnum":
		if text, ok := value.(string); ok {
			if _, err := strconv.ParseInt(text, 10, 64); err != nil {
				return nil, fmt.Errorf("%s must be an integer", cfnCSPath(path))
			}
			return json.Number(text), nil
		}
		return value, nil
	case "float", "double", "bigDecimal":
		if text, ok := value.(string); ok {
			if _, err := strconv.ParseFloat(text, 64); err != nil {
				return nil, fmt.Errorf("%s must be a number", cfnCSPath(path))
			}
			return json.Number(text), nil
		}
		return value, nil
	case "boolean":
		if text, ok := value.(string); ok {
			parsed, err := strconv.ParseBool(text)
			if err != nil {
				return nil, fmt.Errorf("%s must be a boolean", cfnCSPath(path))
			}
			return parsed, nil
		}
		return value, nil
	case "string", "enum":
		switch v := value.(type) {
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64), nil
		case json.Number:
			return string(v), nil
		case bool:
			return strconv.FormatBool(v), nil
		}
		return value, nil
	}
	return value, nil
}
func cfnCSPath(path string) string {
	if path == "" {
		return "input"
	}
	return strings.TrimPrefix(path, "/")
}

// cfnCSRename moves CloudFormation property names to differently named owner
// members and omits CloudFormation-only controls handled by the adapter.
func cfnCSRename(p map[string]any, aliases map[string]string, omit ...string) map[string]any {
	out := make(map[string]any, len(p))
	for key, value := range p {
		if slices.Contains(omit, key) {
			continue
		}
		if alias, ok := aliases[key]; ok {
			key = alias
		}
		out[key] = value
	}
	return out
}

// cfnCSProject maps an owner output document onto CloudFormation names:
// first letter upper case with explicit acronym renames, preserving maps whose
// keys are customer data.
func cfnCSProject(value any, renames map[string]string, preserve ...string) (cloudformation.Properties, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var document any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	object, _ := cfnCSUpper(document, renames, preserve).(map[string]any)
	if object == nil {
		object = map[string]any{}
	}
	return cloudformation.Properties(object), nil
}
func cfnCSUpper(value any, renames map[string]string, preserve []string) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			name := key
			if renamed, ok := renames[key]; ok {
				name = renamed
			} else if key != "" {
				name = strings.ToUpper(key[:1]) + key[1:]
			}
			if slices.Contains(preserve, key) {
				out[name] = item
				continue
			}
			out[name] = cfnCSUpper(item, renames, preserve)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = cfnCSUpper(item, renames, preserve)
		}
		return out
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return n
		}
		f, _ := v.Float64()
		return f
	}
	return value
}

// cfnCSKeep retains only CloudFormation schema properties in a read model.
func cfnCSKeep(p cloudformation.Properties, keys ...string) cloudformation.Properties {
	out := cloudformation.Properties{}
	for _, key := range keys {
		if value, ok := p[key]; ok && value != nil {
			out[key] = value
		}
	}
	return out
}

func cfnCSTagMapList(tags map[string]string) []any {
	return cfnResourcePublicTags(tags)
}

func cfnCSEKSClusters(ctx context.Context, c StepFunctionsCommands) ([]string, error) {
	var names []string
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[eksapi.ListClustersResponse](ctx, c, "eks", "ListClusters", input)
		if err != nil {
			return nil, err
		}
		for _, name := range out.Clusters {
			names = append(names, string(name))
		}
		if cfnComputeValue(out.NextToken) == "" {
			return names, nil
		}
		input["nextToken"] = cfnComputeValue(out.NextToken)
	}
}
