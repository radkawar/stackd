package eks

import (
	_ "embed"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Native DescribeAddonConfiguration, captured in testdata/aws/eks/podidentity_configuration_native.json.
//
//go:embed podidentity_configuration.schema.json
var PodIdentityAddonConfigurationSchema string

var podIdentityConfigurationValidator = sync.OnceValues(func() (*jsonschema.Schema, error) {
	document, err := jsonschema.UnmarshalJSON(strings.NewReader(PodIdentityAddonConfigurationSchema))
	if err != nil {
		return nil, err
	}
	const location = "stackd://eks/pod-identity-configuration"
	compiler := jsonschema.NewCompiler()
	if err = compiler.AddResource(location, document); err != nil {
		return nil, err
	}
	return compiler.Compile(location)
})

type podIdentityAddonConfiguration map[string]any

func parsePodIdentityAddonConfiguration(raw string) (podIdentityAddonConfiguration, error) {
	if raw == "" {
		raw = "{}"
	}
	document, err := jsonschema.UnmarshalJSON(strings.NewReader(raw))
	if err != nil {
		return nil, err
	}
	schema, err := podIdentityConfigurationValidator()
	if err != nil {
		return nil, err
	}
	if err = schema.Validate(document); err != nil {
		return nil, err
	}
	configuration := podIdentityAddonConfiguration(document.(map[string]any))
	for _, name := range []string{"hybrid", "hybrid-bottlerocket"} {
		if podConfigurationObject(podConfigurationObject(configuration["daemonsets"])[name])["create"] == true {
			return nil, errors.New("hybrid pod identity agents require registered hybrid nodes, which this EC2 runtime does not provide")
		}
	}
	return configuration, nil
}
func ValidatePodIdentityAddonConfiguration(raw string) error {
	_, err := parsePodIdentityAddonConfiguration(raw)
	return err
}
func podConfigurationObject(v any) map[string]any { object, _ := v.(map[string]any); return object }
func (c podIdentityAddonConfiguration) names() (string, string) {
	const release = "eks-pod-identity-agent"
	name, _ := c["nameOverride"].(string)
	if name == "" {
		name = release
	}
	fullname, explicit := c["fullnameOverride"].(string)
	if !explicit {
		fullname = release
	} else if fullname == "" {
		fullname = release
		if !strings.Contains(release, name) {
			fullname = release + "-" + name
		}
	}
	trim := func(value string) string {
		if len(value) > 63 {
			value = value[:63]
		}
		return strings.TrimSuffix(value, "-")
	}
	return trim(fullname), trim(name)
}
func podIdentityAgentArgs(defaults map[string]string, additional any) []string {
	values := podConfigurationObject(additional)
	keys := make([]string, 0, len(defaults)+len(values))
	for key := range defaults {
		if _, overridden := values[key]; !overridden {
			keys = append(keys, key)
		}
	}
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	args := make([]string, 0, 2*len(keys))
	for _, key := range keys {
		value, exists := values[key]
		if exists {
			args = append(args, key+"="+fmt.Sprint(value))
		} else {
			args = append(args, key, defaults[key])
		}
	}
	return args
}

// Configurable affinity can narrow managed workers, but cannot give Fargate pods
// an EC2 node identity merely by changing DaemonSet scheduling or webhook order.
func (c podIdentityAddonConfiguration) affinity() (map[string]any, error) {
	cloneObject := func(value any) (map[string]any, error) {
		if value == nil {
			return map[string]any{}, nil
		}
		object, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("pod identity node affinity must contain Kubernetes objects")
		}
		return maps.Clone(object), nil
	}
	affinity, err := cloneObject(c["affinity"])
	if err != nil {
		return nil, err
	}
	node, err := cloneObject(affinity["nodeAffinity"])
	if err != nil {
		return nil, err
	}
	affinity["nodeAffinity"] = node
	required, err := cloneObject(node["requiredDuringSchedulingIgnoredDuringExecution"])
	if err != nil {
		return nil, err
	}
	node["requiredDuringSchedulingIgnoredDuringExecution"] = required
	var terms []any
	if value, ok := required["nodeSelectorTerms"]; ok {
		var valid bool
		terms, valid = value.([]any)
		if !valid {
			return nil, errors.New("pod identity nodeSelectorTerms must be an array")
		}
		terms = slices.Clone(terms)
	} else {
		terms = []any{map[string]any{}}
	}
	for i, value := range terms {
		term, err := cloneObject(value)
		if err != nil {
			return nil, err
		}
		terms[i] = term
		var expressions []any
		if value, ok := term["matchExpressions"]; ok {
			var valid bool
			expressions, valid = value.([]any)
			if !valid {
				return nil, errors.New("pod identity matchExpressions must be an array")
			}
			expressions = slices.Clone(expressions)
		}
		term["matchExpressions"] = append(expressions, map[string]any{"key": "eks.amazonaws.com/nodegroup", "operator": "Exists"}, map[string]any{"key": "eks.amazonaws.com/compute-type", "operator": "NotIn", "values": []string{"fargate", "hybrid", "auto"}})
	}
	required["nodeSelectorTerms"] = terms
	return affinity, nil
}
