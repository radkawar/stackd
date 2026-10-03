package eks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"strings"
)

// This schema advertises only settings applied to actual native objects. AWS's
// separately captured schema also has managed autoscaling, which needs its own
// node/capacity-based controller rather than an unrelated CPU HPA.
const CoreDNSConfigurationSchema = `{"$schema":"http://json-schema.org/draft-06/schema#","type":"object","additionalProperties":false,"properties":{"replicaCount":{"type":"integer"},"corefile":{"type":"string"},"affinity":{"type":["object","null"]},"nodeSelector":{"type":"object","additionalProperties":{"type":"string"}},"podAnnotations":{"type":"object","additionalProperties":{"type":"string"}},"podLabels":{"type":"object","additionalProperties":{"type":"string"}},"tolerations":{"type":"array","items":{"type":"object"}},"topologySpreadConstraints":{"type":"array","items":{"type":"object"}},"computeType":{"type":"string","enum":["ec2","fargate"]},"annotationTopologyMode":{"type":"string","enum":["Disabled","Auto"]},"resources":{"type":"object","additionalProperties":false,"properties":{"limits":{"$ref":"#/definitions/quantities"},"requests":{"$ref":"#/definitions/quantities"}}},"podDisruptionBudget":{"type":"object","additionalProperties":false,"properties":{"enabled":{"type":"boolean"},"minAvailable":{"anyOf":[{"type":"integer"},{"type":"string","pattern":".*%$"}]},"maxUnavailable":{"anyOf":[{"type":"integer"},{"type":"string","pattern":".*%$"}]}}}},"definitions":{"quantities":{"type":"object","additionalProperties":false,"properties":{"cpu":{"type":"string"},"memory":{"type":"string"}}}}}`

type CoreDNSConfiguration struct {
	ReplicaCount *int32
	Corefile     *string
	Fields       map[string]any
}

func (c CoreDNSConfiguration) MarshalJSON() ([]byte, error) {
	fields := maps.Clone(c.Fields)
	if fields == nil {
		fields = map[string]any{}
	}
	if c.ReplicaCount != nil {
		fields["replicaCount"] = *c.ReplicaCount
	}
	if c.Corefile != nil {
		fields["corefile"] = *c.Corefile
	}
	return json.Marshal(fields)
}
func ParseCoreDNSConfiguration(raw string) (CoreDNSConfiguration, error) {
	c := CoreDNSConfiguration{}
	if raw == "" {
		return c, nil
	}
	var fields map[string]any
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		return c, fmt.Errorf("invalid CoreDNS configuration: %w", err)
	}
	if fields == nil {
		return c, errors.New("CoreDNS configuration must be an object")
	}
	c.Fields = fields
	for key, value := range fields {
		valid := true
		switch key {
		case "replicaCount":
			n, ok := value.(float64)
			valid = ok && math.Trunc(n) == n && n >= math.MinInt32 && n <= math.MaxInt32
			if valid {
				count := int32(n)
				c.ReplicaCount = &count
			}
			delete(fields, key)
		case "corefile":
			text, ok := value.(string)
			valid = ok
			if valid {
				c.Corefile = &text
			}
			delete(fields, key)
		case "affinity":
			_, ok := value.(map[string]any)
			valid = ok || value == nil
		case "nodeSelector", "podAnnotations", "podLabels":
			object, ok := value.(map[string]any)
			valid = ok
			for _, v := range object {
				if _, ok = v.(string); !ok {
					valid = false
				}
			}
			if key == "podLabels" {
				if label, present := object["k8s-app"]; present {
					if label != "kube-dns" {
						valid = false
					}
					delete(object, "k8s-app")
				}
			}
			if key == "podAnnotations" {
				if _, reserved := object["stackd.eks.coredns-configuration"]; reserved {
					valid = false
				}
				if compute, present := object["eks.amazonaws.com/compute-type"]; present {
					text, ok := compute.(string)
					if !ok || text != "ec2" && text != "fargate" {
						valid = false
					}
					if other, exists := fields["computeType"]; exists {
						prior, ok := other.(string)
						if !ok || prior != text {
							valid = false
						}
					}
					fields["computeType"] = text
					delete(object, "eks.amazonaws.com/compute-type")
				}
			}
		case "tolerations", "topologySpreadConstraints":
			array, ok := value.([]any)
			valid = ok
			for _, v := range array {
				if _, ok = v.(map[string]any); !ok {
					valid = false
				}
			}
		case "resources":
			object, ok := value.(map[string]any)
			valid = ok
			for name, v := range object {
				if name != "limits" && name != "requests" {
					valid = false
				}
				quantities, ok := v.(map[string]any)
				if !ok {
					valid = false
				}
				for resource, q := range quantities {
					if resource != "cpu" && resource != "memory" {
						valid = false
					}
					if _, ok = q.(string); !ok {
						valid = false
					}
				}
			}
		case "computeType":
			valid = value == "ec2" || value == "fargate"
		case "annotationTopologyMode":
			valid = value == "Disabled" || value == "Auto"
		case "podDisruptionBudget":
			object, ok := value.(map[string]any)
			valid = ok
			for name, v := range object {
				switch name {
				case "enabled":
					if _, ok = v.(bool); !ok {
						valid = false
					}
				case "minAvailable", "maxUnavailable":
					switch v := v.(type) {
					case float64:
						if math.Trunc(v) != v {
							valid = false
						}
					case string:
						if !strings.HasSuffix(v, "%") {
							valid = false
						}
					default:
						valid = false
					}
				default:
					valid = false
				}
			}
		default:
			return c, fmt.Errorf("unsupported CoreDNS configuration field %q", key)
		}
		if !valid {
			return c, fmt.Errorf("CoreDNS configuration field %q does not match its schema", key)
		}
	}
	if fields["computeType"] == "fargate" {
		if selectors, ok := fields["nodeSelector"].(map[string]any); ok {
			if compute, present := selectors["eks.amazonaws.com/compute-type"]; present && compute != "fargate" {
				return c, errors.New("CoreDNS nodeSelector conflicts with Fargate computeType")
			}
			delete(selectors, "eks.amazonaws.com/compute-type")
		}
	}
	return c, nil
}

type coreDNSDeployment struct {
	Metadata componentMetadata `json:"metadata"`
	Spec     struct {
		Replicas int32 `json:"replicas"`
		Template struct {
			Metadata struct{ Labels, Annotations map[string]string } `json:"metadata"`
			Spec     struct {
				Containers []struct {
					Name, Image string
					Resources   map[string]any `json:"resources"`
				} `json:"containers"`
				Affinity                  map[string]any    `json:"affinity"`
				NodeSelector              map[string]string `json:"nodeSelector"`
				Tolerations               []map[string]any  `json:"tolerations"`
				TopologySpreadConstraints []map[string]any  `json:"topologySpreadConstraints"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
}

func coreDNSObservedImage(d coreDNSDeployment) string {
	for _, container := range d.Spec.Template.Spec.Containers {
		if container.Name == "coredns" {
			return container.Image
		}
	}
	return ""
}

func coreDNSObservedFields(d coreDNSDeployment) map[string]any {
	p := d.Spec.Template.Spec
	annotations := maps.Clone(d.Spec.Template.Metadata.Annotations)
	compute := annotations["eks.amazonaws.com/compute-type"]
	delete(annotations, "stackd.eks.coredns-configuration")
	delete(annotations, "eks.amazonaws.com/compute-type")
	labels := maps.Clone(d.Spec.Template.Metadata.Labels)
	delete(labels, "k8s-app")
	selector := maps.Clone(p.NodeSelector)
	if compute == "fargate" {
		delete(selector, "eks.amazonaws.com/compute-type")
	}
	fields := map[string]any{"affinity": p.Affinity, "nodeSelector": selector, "tolerations": p.Tolerations, "topologySpreadConstraints": p.TopologySpreadConstraints, "podAnnotations": annotations, "podLabels": labels}
	if compute != "" {
		fields["computeType"] = compute
	}
	for _, c := range p.Containers {
		if c.Name == "coredns" {
			fields["resources"] = c.Resources
		}
	}
	return fields
}
func coreDNSFieldsEqual(a, b any) bool {
	aa, ea := json.Marshal(a)
	bb, eb := json.Marshal(b)
	if ea != nil || eb != nil {
		return false
	}
	normalize := func(raw []byte) string {
		s := string(raw)
		if s == "{}" || s == "[]" {
			return "null"
		}
		return s
	}
	return normalize(aa) == normalize(bb)
}
func applyCoreDNSPodFields(dep map[string]any, c CoreDNSConfiguration) {
	template := dep["spec"].(map[string]any)["template"].(map[string]any)
	pod := template["spec"].(map[string]any)
	metadata, ok := template["metadata"].(map[string]any)
	if !ok {
		metadata = map[string]any{}
		template["metadata"] = metadata
	}
	for _, key := range []string{"affinity", "nodeSelector", "tolerations", "topologySpreadConstraints"} {
		if v, ok := c.Fields[key]; ok {
			pod[key] = v
		}
	}
	if resources, ok := c.Fields["resources"]; ok {
		for _, item := range pod["containers"].([]any) {
			container := item.(map[string]any)
			if container["name"] == "coredns" {
				container["resources"] = resources
			}
		}
	}
	labels := coreDNSMetadataValues(c.Fields["podLabels"])
	labels["k8s-app"] = "kube-dns"
	metadata["labels"] = labels
	annotations := coreDNSMetadataValues(c.Fields["podAnnotations"])
	metadata["annotations"] = annotations
	if compute, ok := c.Fields["computeType"]; ok {
		annotations["eks.amazonaws.com/compute-type"] = compute
	}
	if c.Fields["computeType"] == "fargate" {
		selector := coreDNSMetadataValues(c.Fields["nodeSelector"])
		selector["eks.amazonaws.com/compute-type"] = "fargate"
		pod["nodeSelector"] = selector
	}
}
func coreDNSMetadataValues(value any) map[string]any {
	result := map[string]any{}
	switch values := value.(type) {
	case map[string]any:
		for k, v := range values {
			result[k] = v
		}
	case map[string]string:
		for k, v := range values {
			result[k] = v
		}
	}
	return result
}
func (c *nativeCluster) applyCoreDNSPDB(ctx context.Context, s AddonSpecification, configuration *CoreDNSConfiguration, previous CoreDNSConfiguration) error {
	raw, present := configuration.Fields["podDisruptionBudget"]
	_, managed := previous.Fields["podDisruptionBudget"]
	if !present && !managed {
		return nil
	}
	pdb := map[string]any{"enabled": false}
	if present {
		pdb = maps.Clone(raw.(map[string]any))
	}
	enabled := true
	if v, ok := pdb["enabled"].(bool); ok {
		enabled = v
	}
	path := "/apis/policy/v1/namespaces/kube-system/poddisruptionbudgets/coredns"
	var actual struct {
		Metadata struct {
			componentMetadata
			ManagedFields []componentManagedFields `json:"managedFields"`
		} `json:"metadata"`
		Spec map[string]any `json:"spec"`
	}
	code, err := c.componentRequest(ctx, "GET", path, "", nil, &actual)
	if err != nil && code != 404 {
		return err
	}
	exists := code != 404
	if !enabled {
		if !exists {
			return nil
		}
		if actual.Metadata.Labels[addonOwnerLabel] != s.ID {
			return &AddonError{Code: "ConfigurationConflict", Message: "CoreDNS disruption budget is not managed by this add-on."}
		}
		if s.ResolveConflicts != "OVERWRITE" {
			for _, fields := range actual.Metadata.ManagedFields {
				if fields.Manager == "stackd-eks-coredns" || fields.Subresource != "" || fields.FieldsV1["f:spec"] == nil {
					continue
				}
				if s.ResolveConflicts != "PRESERVE" {
					return &AddonError{Code: "ConfigurationConflict", Message: "CoreDNS disruption budget has user-managed fields."}
				}
				preserved := map[string]any{"enabled": true}
				for _, key := range []string{"minAvailable", "maxUnavailable"} {
					if v, ok := actual.Spec[key]; ok {
						preserved[key] = v
					}
				}
				if configuration.Fields == nil {
					configuration.Fields = map[string]any{}
				}
				configuration.Fields["podDisruptionBudget"] = preserved
				return nil
			}
		}
		_, err = c.componentRequest(ctx, "DELETE", path, "application/json", map[string]any{"preconditions": map[string]string{"uid": actual.Metadata.UID, "resourceVersion": actual.Metadata.ResourceVersion}}, nil)
		return err
	}
	if _, ok := pdb["maxUnavailable"]; !ok {
		if _, ok = pdb["minAvailable"]; !ok {
			pdb["maxUnavailable"] = float64(1)
		}
	}
	object := componentObject("policy/v1", "PodDisruptionBudget", "coredns", "kube-system", s.ID)
	spec := map[string]any{"selector": map[string]any{"matchLabels": map[string]string{"k8s-app": "kube-dns"}}}
	for _, key := range []string{"minAvailable", "maxUnavailable"} {
		if v, ok := pdb[key]; ok {
			spec[key] = v
		}
	}
	object["spec"] = spec
	if err = c.componentApplyAddon(ctx, path, "stackd-eks-coredns", s.ResolveConflicts, object); err != nil {
		return err
	}
	if _, err = c.componentRequest(ctx, "GET", path, "", nil, &actual); err != nil {
		return err
	}
	for _, key := range []string{"minAvailable", "maxUnavailable"} {
		if value, ok := actual.Spec[key]; ok {
			pdb[key] = value
		} else {
			delete(pdb, key)
		}
	}
	configuration.Fields["podDisruptionBudget"] = pdb
	return nil
}
func coreDNSAppliedConfiguration(configuration CoreDNSConfiguration, deployment coreDNSDeployment, corefile string) (string, error) {
	fields := coreDNSObservedFields(deployment)
	for key := range configuration.Fields {
		if key == "podDisruptionBudget" || key == "annotationTopologyMode" {
			continue
		}
		if value, present := fields[key]; present && !coreDNSFieldsEqual(value, nil) {
			configuration.Fields[key] = value
		}
	}
	configuration.ReplicaCount = &deployment.Spec.Replicas
	configuration.Corefile = &corefile
	raw, err := json.Marshal(configuration)
	return string(raw), err
}
