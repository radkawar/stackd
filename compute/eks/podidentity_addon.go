package eks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

const PodIdentityAddonVersion = "v1.3.10-eksbuild.3"

// Workers import the official image before joining an offline cluster.
const PodIdentityAgentImage = "602401143452.dkr.ecr.us-east-1.amazonaws.com/eks/eks-pod-identity-agent:v0.1.37@sha256:ed04f52bd6414e76ce0064925ed2182c645cb6e5a35910550b7ee3ad43b03cf4"

func podIdentityObjectPaths(name string) []string {
	return []string{"/apis/apps/v1/namespaces/kube-system/daemonsets/" + url.PathEscape(name), "/api/v1/namespaces/kube-system/configmaps/" + url.PathEscape(name+"-ca"), "/api/v1/namespaces/kube-system/serviceaccounts/" + url.PathEscape(name)}
}
func (c *nativeCluster) removePodIdentityAgent(ctx context.Context, name, id string, preserve bool) error {
	paths := podIdentityObjectPaths(name)
	for _, path := range paths {
		var object struct{ Metadata componentMetadata }
		code, err := c.componentRequest(ctx, http.MethodGet, path, "", nil, &object)
		if code == 404 {
			continue
		}
		if err != nil {
			return err
		}
		if object.Metadata.Labels[addonOwnerLabel] != id {
			return errors.New("eks: refusing to delete an unowned pod identity agent object")
		}
		if preserve {
			_, err = c.componentRequest(ctx, http.MethodPatch, path, "application/merge-patch+json", map[string]any{"metadata": map[string]any{"resourceVersion": object.Metadata.ResourceVersion, "labels": map[string]any{addonOwnerLabel: nil}}}, nil)
		} else {
			_, err = c.componentRequest(ctx, http.MethodDelete, path, "application/json", map[string]any{"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Foreground", "preconditions": map[string]string{"uid": object.Metadata.UID}}, nil)
		}
		if err != nil {
			return err
		}
	}
	if !preserve {
		for _, path := range paths {
			if err := c.waitComponentDeleted(ctx, path); err != nil {
				return err
			}
		}
	}
	return nil
}
func (k *K3d) ReconcilePodIdentityAddon(ctx context.Context, s AddonSpecification) (AddonObservation, error) {
	if s.Version != PodIdentityAddonVersion {
		return AddonObservation{}, errors.New("eks: unsupported pod identity agent version")
	}
	config, err := parsePodIdentityAddonConfiguration(s.Configuration)
	if err != nil {
		return AddonObservation{}, err
	}
	previous, err := parsePodIdentityAddonConfiguration(s.PreviousConfiguration)
	if err != nil {
		return AddonObservation{}, err
	}
	name, selectorName := config.names()
	previousName, _ := previous.names()
	paths := podIdentityObjectPaths(name)
	daemonPath, caPath, accountPath := paths[0], paths[1], paths[2]
	k.op.Lock()
	defer k.op.Unlock()
	c, err := k.componentCluster(s.ClusterID)
	if err != nil {
		return AddonObservation{}, err
	}
	if _, err = k.ownedContainers(ctx, c.state); err != nil {
		return AddonObservation{}, err
	}
	if s.Delete {
		if err = c.removePodIdentityAgent(ctx, name, s.ID, s.Preserve); err != nil {
			return AddonObservation{}, err
		}
		if name != previousName {
			if err = c.removePodIdentityAgent(ctx, previousName, s.ID, s.Preserve); err != nil {
				return AddonObservation{}, err
			}
		}
		return AddonObservation{}, nil
	}
	var current struct {
		Metadata componentMetadata
	}
	code, err := c.componentRequest(ctx, http.MethodGet, daemonPath, "", nil, &current)
	exists := code != 404
	if err != nil && exists {
		return AddonObservation{}, err
	}
	if s.Observe {
		if !exists {
			return AddonObservation{}, &AddonError{Code: "K8sResourceNotFound", Message: "Pod identity agent DaemonSet is missing."}
		}
		if current.Metadata.Labels[addonOwnerLabel] != s.ID {
			return AddonObservation{}, &AddonError{Code: "ConfigurationConflict", Message: "Pod identity agent ownership changed."}
		}
		if err = c.observePodIdentityAgent(ctx, daemonPath); err != nil {
			return AddonObservation{}, err
		}
		return AddonObservation{Configuration: s.PreviousConfiguration}, nil
	}
	endpoint, err := url.Parse(c.podIdentityEndpoint)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.User != nil {
		return AddonObservation{}, errors.New("eks: a reachable signed EKS Auth endpoint is required for the node agent")
	}
	if s.ClusterName == "" || s.Region == "" {
		return AddonObservation{}, errors.New("eks: cluster name and region are required for the node agent")
	}
	args := podIdentityAgentArgs(map[string]string{"--cluster-name": s.ClusterName, "--endpoint": endpoint.String(), "--bind-hosts": "169.254.170.23", "--port": "80", "--probe-port": "2703"}, podConfigurationObject(config["agent"])["additionalArgs"])
	if exists {
		if owner := current.Metadata.Labels[addonOwnerLabel]; owner != "" && owner != s.ID {
			return AddonObservation{}, &AddonError{Code: "ConfigurationConflict", Message: "Pod identity agent belongs to another add-on incarnation."}
		}
	}
	for _, path := range []string{accountPath, caPath} {
		var object struct{ Metadata componentMetadata }
		code, e := c.componentRequest(ctx, http.MethodGet, path, "", nil, &object)
		if e != nil && code != 404 {
			return AddonObservation{}, e
		}
		if code != 404 {
			if owner := object.Metadata.Labels[addonOwnerLabel]; owner != "" && owner != s.ID {
				return AddonObservation{}, &AddonError{Code: "ConfigurationConflict", Message: "Pod identity agent supporting object belongs to another add-on incarnation."}
			}
		}
	}
	// A renamed host-network DaemonSet cannot overlap the previous listener.
	if previousName != name && s.PreviousConfiguration != "" {
		if err = c.removePodIdentityAgent(ctx, previousName, s.ID, false); err != nil {
			return AddonObservation{}, err
		}
	}
	account := componentObject("v1", "ServiceAccount", name, "kube-system", s.ID)
	if err = c.componentApplyAddon(ctx, accountPath, "stackd-eks-pod-identity", s.ResolveConflicts, account); err != nil {
		return AddonObservation{}, err
	}
	labels := map[string]any{"app.kubernetes.io/name": selectorName, "app.kubernetes.io/instance": "eks-pod-identity-agent", addonOwnerLabel: s.ID}
	for key, value := range podConfigurationObject(config["podLabels"]) {
		if key != addonOwnerLabel {
			labels[key] = value
		}
	}
	pullPolicy := "Always"
	if value, ok := podConfigurationObject(config["image"])["pullPolicy"].(string); ok {
		pullPolicy = value
	}
	agent := map[string]any{"name": "eks-pod-identity-agent", "image": PodIdentityAgentImage, "imagePullPolicy": pullPolicy, "command": []string{"/go-runner", "/eks-pod-identity-agent", "server"}, "args": args, "env": []any{map[string]string{"name": "AWS_REGION", "value": s.Region}}, "securityContext": map[string]any{"capabilities": map[string]any{"add": []string{"NET_BIND_SERVICE"}}}, "volumeMounts": []any{map[string]string{"name": "jwk-cache", "mountPath": "/var/lib/eks-pod-identity-agent"}}, "ports": []any{map[string]any{"name": "probes-port", "containerPort": 2703}}, "readinessProbe": map[string]any{"httpGet": map[string]any{"host": "127.0.0.1", "path": "/readyz", "port": 2703}, "initialDelaySeconds": 1, "timeoutSeconds": 10, "failureThreshold": 30}, "livenessProbe": map[string]any{"httpGet": map[string]any{"host": "127.0.0.1", "path": "/healthz", "port": 2703}, "initialDelaySeconds": 30, "timeoutSeconds": 10}}
	affinity, err := config.affinity()
	if err != nil {
		return AddonObservation{}, err
	}
	podSpec := map[string]any{"serviceAccountName": name, "automountServiceAccountToken": true, "hostNetwork": true, "dnsPolicy": "ClusterFirstWithHostNet", "priorityClassName": "system-node-critical", "terminationGracePeriodSeconds": 30, "tolerations": []any{map[string]string{"operator": "Exists"}}, "nodeSelector": map[string]string{"kubernetes.io/os": "linux"}, "affinity": affinity, "volumes": []any{map[string]any{"name": "jwk-cache", "emptyDir": map[string]any{}}}, "containers": []any{agent}}
	initConfig := podConfigurationObject(config["init"])
	if initConfig["create"] != false {
		podSpec["initContainers"] = []any{map[string]any{"name": "eks-pod-identity-agent-init", "image": PodIdentityAgentImage, "imagePullPolicy": pullPolicy, "command": []string{"/go-runner", "/eks-pod-identity-agent", "initialize"}, "args": podIdentityAgentArgs(nil, initConfig["additionalArgs"]), "securityContext": map[string]any{"privileged": true}}}
	}
	for _, field := range []string{"priorityClassName", "tolerations", "nodeSelector", "imagePullSecrets"} {
		if value, ok := config[field]; ok {
			podSpec[field] = value
		}
	}
	if value, ok := config["resources"]; ok {
		agent["resources"] = value
	}
	if len(k.config.PodIdentityCA) > 0 {
		ca := componentObject("v1", "ConfigMap", name+"-ca", "kube-system", s.ID)
		ca["data"] = map[string]string{"ca.crt": string(k.config.PodIdentityCA)}
		if err = c.componentApplyAddon(ctx, caPath, "stackd-eks-pod-identity", s.ResolveConflicts, ca); err != nil {
			return AddonObservation{}, err
		}
		// The official agent replaces the SDK HTTP client, so its transport uses Go's system CA roots.
		agent["env"] = append(agent["env"].([]any), map[string]string{"name": "SSL_CERT_FILE", "value": "/etc/stackd-eks-auth/ca.crt"})
		agent["volumeMounts"] = append(agent["volumeMounts"].([]any), map[string]any{"name": "eks-auth-ca", "mountPath": "/etc/stackd-eks-auth", "readOnly": true})
		podSpec["volumes"] = append(podSpec["volumes"].([]any), map[string]any{"name": "eks-auth-ca", "configMap": map[string]string{"name": name + "-ca"}})
	}
	annotations := map[string]any{"eks.amazonaws.com/skip-containers": "eks-pod-identity-agent,eks-pod-identity-agent-init"}
	for key, value := range podConfigurationObject(config["podAnnotations"]) {
		annotations[key] = value
	}
	metadata := map[string]any{"labels": labels, "annotations": annotations}
	strategy := any(map[string]any{"type": "RollingUpdate", "rollingUpdate": map[string]any{"maxUnavailable": "10%"}})
	if value, ok := config["updateStrategy"]; ok {
		strategy = value
	}
	daemon := componentObject("apps/v1", "DaemonSet", name, "kube-system", s.ID)
	daemon["spec"] = map[string]any{"selector": map[string]any{"matchLabels": map[string]string{"app.kubernetes.io/name": selectorName, "app.kubernetes.io/instance": "eks-pod-identity-agent"}}, "updateStrategy": strategy, "template": map[string]any{"metadata": metadata, "spec": podSpec}}
	if err = c.componentApplyAddon(ctx, daemonPath, "stackd-eks-pod-identity", s.ResolveConflicts, daemon); err != nil {
		return AddonObservation{}, err
	}
	if err = c.observePodIdentityAgent(ctx, daemonPath); err != nil {
		return AddonObservation{}, err
	}
	actual, err := json.Marshal(config)
	if err != nil {
		return AddonObservation{}, err
	}
	return AddonObservation{Configuration: string(actual)}, nil
}
func (c *nativeCluster) observePodIdentityAgent(ctx context.Context, path string) error {
	var daemon struct {
		Metadata componentMetadata
		Status   struct {
			ObservedGeneration                                                             int64
			DesiredNumberScheduled, NumberReady, UpdatedNumberScheduled, NumberUnavailable int32
		}
	}
	if _, err := c.componentRequest(ctx, http.MethodGet, path, "", nil, &daemon); err != nil {
		return err
	}
	if daemon.Status.ObservedGeneration >= daemon.Metadata.Generation && daemon.Status.NumberReady == daemon.Status.DesiredNumberScheduled && daemon.Status.UpdatedNumberScheduled == daemon.Status.DesiredNumberScheduled && daemon.Status.NumberUnavailable == 0 {
		return nil
	}
	return &AddonPending{Message: fmt.Sprintf("Pod identity agent has %d ready and %d updated of %d desired nodes.", daemon.Status.NumberReady, daemon.Status.UpdatedNumberScheduled, daemon.Status.DesiredNumberScheduled)}
}
