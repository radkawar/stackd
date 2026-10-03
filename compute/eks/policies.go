package eks

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
)

// These allow rules are pinned from the AWS access-policy tables, retrieved
// 2026-09-27. They deliberately do not inherit Kubernetes aggregate roles, whose
// rules can widen through CRDs or differ from the AWS policy being associated.
// https://docs.aws.amazon.com/eks/latest/userguide/access-policy-permissions.html
var awsPolicyRules = makeAWSPolicyRules()

type policyRule struct {
	APIGroups       []string `json:"apiGroups,omitempty"`
	Resources       []string `json:"resources,omitempty"`
	Verbs           []string `json:"verbs"`
	NonResourceURLs []string `json:"nonResourceURLs,omitempty"`
}

type policyRole struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name   string            `json:"name"`
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Rules           []policyRule    `json:"rules"`
	AggregationRule json.RawMessage `json:"aggregationRule,omitempty"`
}

func makeAWSPolicyRules() map[string][]policyRule {
	rule := func(group, resources, verbs string) policyRule {
		return policyRule{APIGroups: []string{group}, Resources: strings.Split(resources, ","), Verbs: strings.Split(verbs, ",")}
	}
	const read = "get,list,watch"
	const mutate = "create,delete,deletecollection,patch,update"
	view := []policyRule{
		rule("apps", "controllerrevisions,daemonsets,daemonsets/status,deployments,deployments/scale,deployments/status,replicasets,replicasets/scale,replicasets/status,statefulsets,statefulsets/scale,statefulsets/status", read),
		rule("autoscaling", "horizontalpodautoscalers,horizontalpodautoscalers/status", read),
		rule("batch", "cronjobs,cronjobs/status,jobs,jobs/status", read),
		rule("discovery.k8s.io", "endpointslices", read),
		rule("extensions", "daemonsets,daemonsets/status,deployments,deployments/scale,deployments/status,ingresses,ingresses/status,networkpolicies,replicasets,replicasets/scale,replicasets/status,replicationcontrollers/scale", read),
		rule("networking.k8s.io", "ingresses,ingresses/status,networkpolicies", read),
		rule("policy", "poddisruptionbudgets,poddisruptionbudgets/status", read),
		rule("", "configmaps,endpoints,persistentvolumeclaims,persistentvolumeclaims/status,pods,replicationcontrollers,replicationcontrollers/scale,serviceaccounts,services,services/status", read),
		rule("", "bindings,events,limitranges,namespaces/status,pods/log,pods/status,replicationcontrollers/status,resourcequotas,resourcequotas/status", read),
		rule("", "namespaces", read),
	}
	edit := append([]policyRule(nil), view...)
	edit = append(edit,
		rule("apps", "daemonsets,deployments,deployments/rollback,deployments/scale,replicasets,replicasets/scale,statefulsets,statefulsets/scale", mutate),
		rule("autoscaling", "horizontalpodautoscalers", mutate),
		rule("batch", "cronjobs,jobs", mutate),
		rule("extensions", "daemonsets,deployments,deployments/rollback,deployments/scale,ingresses,networkpolicies,replicasets,replicasets/scale,replicationcontrollers/scale", mutate),
		rule("networking.k8s.io", "ingresses,networkpolicies", mutate),
		rule("policy", "poddisruptionbudgets", mutate),
		rule("", "pods/attach,pods/exec,pods/portforward,pods/proxy,secrets,services/proxy", read),
		rule("", "serviceaccounts", "impersonate"),
		rule("", "pods,pods/attach,pods/exec,pods/portforward,pods/proxy", mutate),
		rule("", "configmaps,events,persistentvolumeclaims,replicationcontrollers,replicationcontrollers/scale,secrets,serviceaccounts,services,services/proxy", mutate),
	)
	admin := append([]policyRule(nil), edit...)
	admin = append(admin,
		rule("authorization.k8s.io", "localsubjectaccessreviews", "create"),
		rule("rbac.authorization.k8s.io", "rolebindings,roles", "create,delete,deletecollection,get,list,patch,update,watch"),
	)
	return map[string][]policyRule{
		"view": view, "edit": edit, "admin": admin,
		"cluster-admin": {rule("*", "*", "*"), {NonResourceURLs: []string{"*"}, Verbs: []string{"*"}}},
	}
}

func (c *nativeCluster) ensurePolicyRole(ctx context.Context, role string) (string, error) {
	rules, ok := awsPolicyRules[role]
	if !ok {
		return "", errors.New("eks: unsupported AWS access policy")
	}
	data, err := json.Marshal(rules)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	name := "stackd-eks-" + c.state.Token[:16] + "-" + hex.EncodeToString(hash[:16])
	wanted := policyRole{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole", Rules: rules}
	wanted.Metadata.Name = name
	wanted.Metadata.Labels = map[string]string{ownerLabel: c.state.Token[:32]}
	path := c.nativeURL() + "/apis/rbac.authorization.k8s.io/v1/clusterroles"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, path+"/"+name, nil)
	if err != nil {
		return "", err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return "", err
	}
	if response.StatusCode == http.StatusNotFound {
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		data, err = json.Marshal(wanted)
		if err != nil {
			return "", err
		}
		request, err = http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(data))
		if err != nil {
			return "", err
		}
		request.Header.Set("Content-Type", "application/json")
		response, err = c.client.Do(request)
		if err != nil {
			return "", err
		}
		defer response.Body.Close()
		io.Copy(io.Discard, response.Body)
		if response.StatusCode != http.StatusCreated {
			return "", fmt.Errorf("eks: native AWS policy creation returned %d", response.StatusCode)
		}
		return name, nil
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("eks: native AWS policy lookup returned %d", response.StatusCode)
	}
	var actual policyRole
	if err = json.NewDecoder(response.Body).Decode(&actual); err != nil {
		return "", err
	}
	if actual.Metadata.Labels[ownerLabel] != wanted.Metadata.Labels[ownerLabel] || !reflect.DeepEqual(actual.Rules, wanted.Rules) || len(actual.AggregationRule) != 0 {
		return "", errors.New("eks: native role differs from pinned AWS access policy")
	}
	return name, nil
}
