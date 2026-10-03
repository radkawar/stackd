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
	"strconv"
	"strings"
	"time"
)

const addonOwnerLabel = "stackd.eks.addon"

type componentOwnerReference struct {
	UID        string `json:"uid"`
	Kind       string `json:"kind"`
	Controller bool   `json:"controller"`
}

type componentMetadata struct {
	Name              string                    `json:"name"`
	Namespace         string                    `json:"namespace,omitempty"`
	UID               string                    `json:"uid,omitempty"`
	ResourceVersion   string                    `json:"resourceVersion,omitempty"`
	Generation        int64                     `json:"generation,omitempty"`
	Labels            map[string]string         `json:"labels,omitempty"`
	Annotations       map[string]string         `json:"annotations,omitempty"`
	OwnerReferences   []componentOwnerReference `json:"ownerReferences,omitempty"`
	DeletionTimestamp string                    `json:"deletionTimestamp,omitempty"`
}

type componentManagedFields struct {
	Manager     string         `json:"manager"`
	Subresource string         `json:"subresource,omitempty"`
	FieldsV1    map[string]any `json:"fieldsV1"`
}

func (k *K3d) componentCluster(id string) (*nativeCluster, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	c := k.clusters[id]
	if c == nil || k.closed {
		return nil, errors.New("eks: native cluster is not attached")
	}
	return c, nil
}
func (c *nativeCluster) componentRequest(ctx context.Context, method, path, contentType string, body any, out any) (int, error) {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return 0, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.nativeURL()+path, bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var status struct{ Message string }
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&status)
		return resp.StatusCode, fmt.Errorf("eks: Kubernetes %s %s: %d %s", method, path, resp.StatusCode, status.Message)
	}
	if out != nil {
		err = json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
	} else {
		_, err = io.Copy(io.Discard, resp.Body)
	}
	return resp.StatusCode, err
}
func (c *nativeCluster) componentApply(ctx context.Context, path, manager string, force bool, object any) error {
	_, err := c.componentRequest(ctx, http.MethodPatch, path+"?fieldManager="+manager+"&force="+strconv.FormatBool(force), "application/apply-patch+yaml", object, nil)
	return err
}

// Preserve takes shared ownership of the live values owned by other managers.
// NONE leaves conflict detection to server-side apply; only OVERWRITE may force.
// See https://kubernetes.io/docs/reference/using-api/server-side-apply/#conflicts.
func (c *nativeCluster) componentApplyAddon(ctx context.Context, path, manager, mode string, object map[string]any) error {
	if mode == "PRESERVE" {
		var current map[string]any
		code, err := c.componentRequest(ctx, http.MethodGet, path, "", nil, &current)
		if err != nil && code != http.StatusNotFound {
			return err
		}
		if code != http.StatusNotFound {
			metadata, _ := current["metadata"].(map[string]any)
			labels, _ := metadata["labels"].(map[string]any)
			owner, _ := addonObjectField(object["metadata"].(map[string]any)["labels"], addonOwnerLabel)
			if existing := labels[addonOwnerLabel]; existing != nil && existing != owner {
				return &AddonError{Code: "ConfigurationConflict", Message: "Kubernetes object belongs to another add-on incarnation."}
			}
			fields, _ := metadata["managedFields"].([]any)
			for _, raw := range fields {
				entry, _ := raw.(map[string]any)
				if entry["manager"] == manager || entry["subresource"] != nil && entry["subresource"] != "" {
					continue
				}
				if fieldSet, ok := entry["fieldsV1"].(map[string]any); ok {
					preserveAddonFields(object, current, fieldSet)
				}
			}
			// Fence the read used for PRESERVE. A concurrent user edit must conflict,
			// not be replaced by the value read before that edit.
			object["metadata"].(map[string]any)["resourceVersion"] = metadata["resourceVersion"]
		}
	}
	code, err := c.componentRequest(ctx, http.MethodPatch, path+"?fieldManager="+manager+"&force="+strconv.FormatBool(mode == "OVERWRITE"), "application/apply-patch+yaml", object, nil)
	if code == http.StatusConflict {
		return &AddonError{Code: "ConfigurationConflict", Message: err.Error()}
	}
	return err
}

func addonObjectField(object any, key string) (any, bool) {
	switch value := object.(type) {
	case map[string]any:
		field, ok := value[key]
		return field, ok
	case map[string]string:
		field, ok := value[key]
		return field, ok
	}
	return nil, false
}

func preserveAddonFields(desired, actual any, fields map[string]any) any {
	if len(fields) == 0 {
		return actual
	}
	for key, raw := range fields {
		children, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if field, ok := strings.CutPrefix(key, "f:"); ok {
			want, supplied := addonObjectField(desired, field)
			live, exists := addonObjectField(actual, field)
			if !supplied || !exists {
				continue
			}
			preserved := preserveAddonFields(want, live, children)
			switch object := desired.(type) {
			case map[string]any:
				object[field] = preserved
			case map[string]string:
				if value, ok := preserved.(string); ok {
					object[field] = value
				}
			}
		} else if selector, ok := strings.CutPrefix(key, "k:"); ok {
			var keys map[string]any
			if json.Unmarshal([]byte(selector), &keys) != nil {
				continue
			}
			wanted, _ := desired.([]any)
			live, _ := actual.([]any)
			matches := func(item any) bool {
				for name, expected := range keys {
					value, present := addonObjectField(item, name)
					if !present || !coreDNSFieldsEqual(value, expected) {
						return false
					}
				}
				return true
			}
			for i, item := range wanted {
				if !matches(item) {
					continue
				}
				for _, observed := range live {
					if matches(observed) {
						wanted[i] = preserveAddonFields(item, observed, children)
						break
					}
				}
			}
		}
	}
	return desired
}
func componentObject(apiVersion, kind, name, namespace, owner string) map[string]any {
	return map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": map[string]any{"name": name, "namespace": namespace, "labels": map[string]string{addonOwnerLabel: owner}}}
}
func (k *K3d) ReconcileAddon(ctx context.Context, s AddonSpecification) (observation AddonObservation, resultErr error) {
	if s.Name == "eks-pod-identity-agent" {
		return k.ReconcilePodIdentityAddon(ctx, s)
	}
	image, supported := CoreDNSImageForVersion(s.Version)
	if s.Name != "coredns" || !supported {
		return AddonObservation{}, errors.New("eks: unsupported native add-on")
	}
	mutated := false
	defer func() { observation.Mutated = mutated }()
	k.op.Lock()
	defer k.op.Unlock()
	c, err := k.componentCluster(s.ClusterID)
	if err != nil {
		return AddonObservation{}, err
	}
	if _, err = k.ownedContainers(ctx, c.state); err != nil {
		return AddonObservation{}, err
	}
	// k3s rewrites packaged manifests on startup; its documented .skip sentinel
	// prevents that deploy controller from undoing accepted managed configuration.
	if _, err = k.command(ctx, "docker", "exec", "k3d-"+c.state.Name+"-server-0", "touch", "/var/lib/rancher/k3s/server/manifests/coredns.yaml.skip"); err != nil {
		return AddonObservation{}, err
	}
	resources := []struct{ path, kind, name, version, namespace string }{
		{"/apis/apps/v1/namespaces/kube-system/deployments/coredns", "Deployment", "coredns", "apps/v1", "kube-system"},
		{"/api/v1/namespaces/kube-system/configmaps/coredns", "ConfigMap", "coredns", "v1", "kube-system"},
		{"/api/v1/namespaces/kube-system/services/kube-dns", "Service", "kube-dns", "v1", "kube-system"},
		{"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/system:coredns", "ClusterRoleBinding", "system:coredns", "rbac.authorization.k8s.io/v1", ""},
		{"/apis/rbac.authorization.k8s.io/v1/clusterroles/system:coredns", "ClusterRole", "system:coredns", "rbac.authorization.k8s.io/v1", ""},
		{"/api/v1/namespaces/kube-system/serviceaccounts/coredns", "ServiceAccount", "coredns", "v1", "kube-system"},
		{"/apis/policy/v1/namespaces/kube-system/poddisruptionbudgets/coredns", "PodDisruptionBudget", "coredns", "policy/v1", "kube-system"},
	}
	if s.Delete {
		deleted := make([]string, 0, len(resources))
		for _, r := range resources {
			var obj struct {
				Metadata componentMetadata `json:"metadata"`
			}
			code, e := c.componentRequest(ctx, "GET", r.path, "", nil, &obj)
			if code == 404 {
				continue
			}
			if e != nil {
				return AddonObservation{}, e
			}
			if obj.Metadata.Labels[addonOwnerLabel] != s.ID {
				if s.PreviousVersion == "" || r.kind == "PodDisruptionBudget" {
					continue
				}
				return AddonObservation{}, errors.New("eks: refusing to delete an add-on object whose ownership changed")
			}
			if s.Preserve {
				_, e = c.componentRequest(ctx, "PATCH", r.path, "application/merge-patch+json", map[string]any{"metadata": map[string]any{"resourceVersion": obj.Metadata.ResourceVersion, "labels": map[string]any{addonOwnerLabel: nil}}}, nil)
			} else {
				_, e = c.componentRequest(ctx, "DELETE", r.path, "application/json", map[string]any{"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Foreground", "preconditions": map[string]string{"uid": obj.Metadata.UID}}, nil)
			}
			if e != nil {
				return AddonObservation{}, e
			}
			if !s.Preserve {
				deleted = append(deleted, r.path)
			}
		}
		for _, path := range deleted {
			if err = c.waitComponentDeleted(ctx, path); err != nil {
				return AddonObservation{}, err
			}
		}
		return AddonObservation{}, nil
	}
	desired, err := ParseCoreDNSConfiguration(s.Configuration)
	if err != nil {
		return AddonObservation{}, err
	}
	previous, err := ParseCoreDNSConfiguration(s.PreviousConfiguration)
	if err != nil {
		return AddonObservation{}, err
	}
	var deployment coreDNSDeployment
	code, err := c.componentRequest(ctx, "GET", resources[0].path, "", nil, &deployment)
	exists := code != 404
	if err != nil && exists {
		return AddonObservation{}, err
	}
	var cm struct {
		Metadata componentMetadata `json:"metadata"`
		Data     map[string]string `json:"data"`
	}
	code, err = c.componentRequest(ctx, "GET", resources[1].path, "", nil, &cm)
	if err != nil && code != 404 {
		return AddonObservation{}, err
	}
	if s.Observe || s.Rollout {
		if !exists {
			return AddonObservation{}, &AddonError{Code: "K8sResourceNotFound", Message: "CoreDNS deployment is missing."}
		}
		if deployment.Metadata.Labels[addonOwnerLabel] != s.ID || cm.Metadata.Labels[addonOwnerLabel] != s.ID {
			return AddonObservation{}, &AddonError{Code: "ConfigurationConflict", Message: "CoreDNS object ownership changed."}
		}
		if s.Rollout && s.ResolveConflicts != "PRESERVE" && desired.ReplicaCount != nil && deployment.Spec.Replicas != *desired.ReplicaCount {
			return AddonObservation{}, &AddonError{Code: "ConfigurationConflict", Message: "CoreDNS replica count changed during rollout."}
		}
		observation.Configuration = s.PreviousConfiguration
		if !s.Observe {
			observation.Configuration, err = coreDNSAppliedConfiguration(desired, deployment, cm.Data["Corefile"])
			if err != nil {
				return AddonObservation{}, err
			}
		}
		if s.ResolveConflicts == "PRESERVE" {
			image = coreDNSObservedImage(deployment)
		}
		if err = c.coreDNSReadiness(ctx, deployment.Spec.Replicas, image); err != nil {
			return observation, err
		}
		return observation, nil
	}
	replicas := int32(1)
	if desired.ReplicaCount != nil {
		replicas = *desired.ReplicaCount
	}
	corefile := defaultCorefile
	if cm.Data["Corefile"] != "" && desired.Corefile == nil && s.PreviousConfiguration == "" {
		corefile = cm.Data["Corefile"]
	}
	if desired.Corefile != nil {
		corefile = *desired.Corefile
	}
	// Keep the managed manifest complete across creation and reconciliation:
	// server-side apply removes previously owned fields omitted by this manager.
	sa := componentObject("v1", "ServiceAccount", "coredns", "kube-system", s.ID)
	role := componentObject("rbac.authorization.k8s.io/v1", "ClusterRole", "system:coredns", "", s.ID)
	role["rules"] = []any{map[string]any{"apiGroups": []string{""}, "resources": []string{"endpoints", "services", "pods", "namespaces"}, "verbs": []string{"list", "watch"}}, map[string]any{"apiGroups": []string{"discovery.k8s.io"}, "resources": []string{"endpointslices"}, "verbs": []string{"list", "watch"}}}
	binding := componentObject("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "system:coredns", "", s.ID)
	binding["roleRef"] = map[string]string{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:coredns"}
	binding["subjects"] = []any{map[string]string{"kind": "ServiceAccount", "name": "coredns", "namespace": "kube-system"}}
	config := componentObject("v1", "ConfigMap", "coredns", "kube-system", s.ID)
	config["data"] = map[string]string{"Corefile": corefile}
	service := componentObject("v1", "Service", "kube-dns", "kube-system", s.ID)
	service["spec"] = map[string]any{"clusterIP": "10.43.0.10", "selector": map[string]string{"k8s-app": "kube-dns"}, "ports": []any{map[string]any{"name": "dns", "port": 53, "protocol": "UDP"}, map[string]any{"name": "dns-tcp", "port": 53, "protocol": "TCP"}}}
	if mode, ok := desired.Fields["annotationTopologyMode"]; ok {
		service["metadata"].(map[string]any)["annotations"] = map[string]any{"service.kubernetes.io/topology-mode": mode}
	}
	dep := componentObject("apps/v1", "Deployment", "coredns", "kube-system", s.ID)
	dep["spec"] = map[string]any{"replicas": replicas, "selector": map[string]any{"matchLabels": map[string]string{"k8s-app": "kube-dns"}}, "template": map[string]any{"metadata": map[string]any{"labels": map[string]string{"k8s-app": "kube-dns"}}, "spec": map[string]any{"serviceAccountName": "coredns", "dnsPolicy": "Default", "containers": []any{map[string]any{"name": "coredns", "image": image, "args": []string{"-conf", "/etc/coredns/Corefile"}, "volumeMounts": []any{map[string]any{"name": "config", "mountPath": "/etc/coredns"}}, "ports": []any{map[string]any{"containerPort": 53, "protocol": "UDP"}, map[string]any{"containerPort": 53, "protocol": "TCP"}}, "readinessProbe": map[string]any{"httpGet": map[string]any{"path": "/ready", "port": 8181}}}}, "volumes": []any{map[string]any{"name": "config", "configMap": map[string]any{"name": "coredns"}}}}}}
	applyCoreDNSPodFields(dep, desired)
	hash := sha256.Sum256([]byte(corefile))
	template := dep["spec"].(map[string]any)["template"].(map[string]any)
	metadata, ok := template["metadata"].(map[string]any)
	if !ok {
		metadata = map[string]any{}
		template["metadata"] = metadata
	}
	annotations, ok := metadata["annotations"].(map[string]any)
	if !ok {
		annotations = map[string]any{}
		metadata["annotations"] = annotations
	}
	annotations["stackd.eks.coredns-configuration"] = hex.EncodeToString(hash[:])
	objects := []map[string]any{dep, config, service, binding, role, sa}
	// Required RBAC precedes deployment startup. Kubernetes owns field conflicts
	// for every object, including RBAC, Service and ConfigMap fields.
	for _, i := range []int{5, 4, 3, 1, 2, 0} {
		if err = c.componentApplyAddon(ctx, resources[i].path, "stackd-eks-coredns", s.ResolveConflicts, objects[i]); err != nil {
			return AddonObservation{}, err
		}
		mutated = true
	}
	if err = c.applyCoreDNSPDB(ctx, s, &desired, previous); err != nil {
		return AddonObservation{}, err
	}
	if _, err = c.componentRequest(ctx, "GET", resources[0].path, "", nil, &deployment); err != nil {
		return AddonObservation{}, err
	}
	if _, err = c.componentRequest(ctx, "GET", resources[1].path, "", nil, &cm); err != nil {
		return AddonObservation{}, err
	}
	corefile = cm.Data["Corefile"]
	if s.ResolveConflicts == "PRESERVE" {
		image = coreDNSObservedImage(deployment)
	}
	observation.Configuration, err = coreDNSAppliedConfiguration(desired, deployment, corefile)
	if err != nil {
		return AddonObservation{}, err
	}
	if err = c.coreDNSReadiness(ctx, deployment.Spec.Replicas, image); err != nil {
		return observation, err
	}
	return observation, nil
}
func (c *nativeCluster) waitComponentDeleted(ctx context.Context, path string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for {
		code, err := c.componentRequest(ctx, "GET", path, "", nil, nil)
		if code == 404 {
			return nil
		}
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
func (c *nativeCluster) coreDNSReadiness(ctx context.Context, replicas int32, image string) error {
	var deployment struct {
		Metadata componentMetadata `json:"metadata"`
		Spec     struct {
			Template struct {
				Spec struct {
					Containers []struct{ Name, Image string } `json:"containers"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
		Status struct {
			ObservedGeneration                 int64 `json:"observedGeneration"`
			AvailableReplicas, UpdatedReplicas int32
		} `json:"status"`
	}
	if _, err := c.componentRequest(ctx, "GET", "/apis/apps/v1/namespaces/kube-system/deployments/coredns", "", nil, &deployment); err != nil {
		return err
	}
	found := false
	for _, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name != "coredns" {
			continue
		}
		found = true
		if container.Image != image {
			return &AddonError{Code: "ConfigurationConflict", Message: "CoreDNS image differs from the managed version."}
		}
	}
	if !found {
		return &AddonError{Code: "K8sResourceNotFound", Message: "CoreDNS container is missing from its deployment."}
	}
	const pendingMessage = "CoreDNS deployment has not reached its requested ready replicas"
	revision := deployment.Metadata.Annotations["deployment.kubernetes.io/revision"]
	if deployment.Status.ObservedGeneration < deployment.Metadata.Generation || revision == "" {
		return &AddonPending{Message: pendingMessage}
	}
	if deployment.Status.UpdatedReplicas == replicas && (replicas > 0 && deployment.Status.AvailableReplicas >= replicas || replicas == 0 && deployment.Status.AvailableReplicas == 0) {
		return nil
	}
	// Failed pods from the previous ReplicaSet can outlive a rollback patch.
	// Only the observed Deployment's current controller revision owns failure.
	var replicaSets struct {
		Items []struct {
			Metadata componentMetadata `json:"metadata"`
		} `json:"items"`
	}
	if _, err := c.componentRequest(ctx, "GET", "/apis/apps/v1/namespaces/kube-system/replicasets?labelSelector=k8s-app%3Dkube-dns", "", nil, &replicaSets); err != nil {
		return err
	}
	var currentReplicaSet string
	for i := range replicaSets.Items {
		metadata := &replicaSets.Items[i].Metadata
		if metadata.DeletionTimestamp != "" || metadata.Annotations["deployment.kubernetes.io/revision"] != revision {
			continue
		}
		for _, owner := range metadata.OwnerReferences {
			if owner.Controller && owner.Kind == "Deployment" && owner.UID == deployment.Metadata.UID {
				currentReplicaSet = metadata.UID
				break
			}
		}
		if currentReplicaSet != "" {
			break
		}
	}
	if currentReplicaSet == "" {
		return &AddonPending{Message: pendingMessage}
	}
	var pods struct {
		Items []struct {
			Metadata componentMetadata `json:"metadata"`
			Status   struct {
				Conditions []struct{ Type, Status, Reason, Message string } `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if _, err := c.componentRequest(ctx, "GET", "/api/v1/namespaces/kube-system/pods?labelSelector=k8s-app%3Dkube-dns", "", nil, &pods); err != nil {
		return err
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Metadata.DeletionTimestamp != "" {
			continue
		}
		current := false
		for _, owner := range pod.Metadata.OwnerReferences {
			if owner.Controller && owner.Kind == "ReplicaSet" && owner.UID == currentReplicaSet {
				current = true
				break
			}
		}
		if !current {
			continue
		}
		for _, condition := range pod.Status.Conditions {
			if condition.Type == "PodScheduled" && condition.Status == "False" && condition.Reason == "Unschedulable" {
				return &AddonError{Code: "InsufficientNumberOfReplicas", Message: condition.Message}
			}
		}
	}
	return &AddonPending{Message: pendingMessage}
}
