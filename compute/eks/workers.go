package eks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// WorkerBootstrap is private execution material. It must never enter EKS API responses.
type WorkerBootstrap struct {
	ServerURL, Token string
	FlannelPort      int
}

// Worker is an observed Kubernetes node, not an EC2 inventory projection.
type Worker struct {
	Name, UID, ProviderID, InternalIP, Version string
	Ready, Unschedulable                       bool
}
type WorkerTaint struct {
	Key    string `json:"key"`
	Value  string `json:"value,omitempty"`
	Effect string `json:"effect"`
}
type WorkerConfiguration struct {
	Name, UID, Nodegroup string
	Labels               map[string]string
	Taints               []WorkerTaint
}

// WorkerRuntime acts only on the exact-owned cluster's private Kubernetes API.
type WorkerRuntime interface {
	WorkerBootstrap(context.Context, string) (WorkerBootstrap, error)
	ObserveWorkers(context.Context, string) ([]Worker, error)
	ReconcileWorkerNetwork(context.Context, string, string, []WorkerPeer) error
	ConfigureWorker(context.Context, string, WorkerConfiguration) error
	CordonWorker(context.Context, string, string, string) error
	DrainWorker(context.Context, string, string, string, bool) (bool, error)
	DeleteWorker(context.Context, string, string, string) error
}

func (k *K3d) workerCluster(id string) (*nativeCluster, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	c := k.clusters[id]
	if k.closed || c == nil {
		return nil, errors.New("eks: native cluster is not attached")
	}
	return c, nil
}
func (k *K3d) WorkerBootstrap(ctx context.Context, id string) (WorkerBootstrap, error) {
	c, err := k.workerCluster(id)
	if err != nil {
		return WorkerBootstrap{}, err
	}
	if c.state.WorkerAdvertiseHost == "" {
		return WorkerBootstrap{}, errors.New("eks: an explicit guest-reachable worker advertise host is required")
	}
	containers, err := k.ownedContainers(ctx, c.state)
	if err != nil {
		return WorkerBootstrap{}, err
	}
	for _, v := range containers {
		if v.Name == "/k3d-"+c.state.Name+"-server-0" {
			token, e := k.command(ctx, "docker", "exec", v.ID, "cat", "/var/lib/rancher/k3s/server/agent-token")
			if e != nil {
				return WorkerBootstrap{}, e
			}
			if strings.TrimSpace(string(token)) == "" {
				return WorkerBootstrap{}, errors.New("eks: native agent join token is empty")
			}
			return WorkerBootstrap{ServerURL: "https://" + net.JoinHostPort(c.state.WorkerAdvertiseHost, strconv.Itoa(c.state.NativePort)), Token: strings.TrimSpace(string(token)), FlannelPort: c.state.NativePort}, nil
		}
	}
	return WorkerBootstrap{}, errors.New("eks: exact-owned server is absent")
}

type workerNode struct {
	Metadata struct {
		Name            string            `json:"name"`
		UID             string            `json:"uid"`
		ResourceVersion string            `json:"resourceVersion"`
		Labels          map[string]string `json:"labels"`
		Annotations     map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		ProviderID    string        `json:"providerID"`
		Unschedulable bool          `json:"unschedulable"`
		Taints        []WorkerTaint `json:"taints"`
	} `json:"spec"`
	Status struct {
		Addresses  []struct{ Type, Address string } `json:"addresses"`
		Conditions []struct{ Type, Status string }  `json:"conditions"`
		NodeInfo   struct {
			KubeletVersion string `json:"kubeletVersion"`
		} `json:"nodeInfo"`
	} `json:"status"`
}

func (c *nativeCluster) workerRequest(ctx context.Context, method, path string, in, out any) (int, error) {
	var body io.Reader
	if in != nil {
		b, e := json.Marshal(in)
		if e != nil {
			return 0, e
		}
		body = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, c.nativeURL()+path, body)
	if e != nil {
		return 0, e
	}
	req.Header.Set("Content-Type", "application/json")
	if method == http.MethodPatch {
		req.Header.Set("Content-Type", "application/merge-patch+json")
	}
	res, e := c.client.Do(req)
	if e != nil {
		return 0, e
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return res.StatusCode, fmt.Errorf("eks: Kubernetes %s %s returned %d: %s", method, path, res.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil {
		e = json.NewDecoder(io.LimitReader(res.Body, 16<<20)).Decode(out)
	} else {
		_, e = io.Copy(io.Discard, res.Body)
	}
	return res.StatusCode, e
}
func (k *K3d) ObserveWorkers(ctx context.Context, id string) ([]Worker, error) {
	c, e := k.workerCluster(id)
	if e != nil {
		return nil, e
	}
	var list struct {
		Items []workerNode `json:"items"`
	}
	if _, e = c.workerRequest(ctx, http.MethodGet, "/api/v1/nodes", nil, &list); e != nil {
		return nil, e
	}
	out := make([]Worker, 0, len(list.Items))
	for _, n := range list.Items {
		v := Worker{Name: n.Metadata.Name, UID: n.Metadata.UID, ProviderID: n.Spec.ProviderID, Version: n.Status.NodeInfo.KubeletVersion, Unschedulable: n.Spec.Unschedulable}
		for _, a := range n.Status.Addresses {
			if a.Type == "InternalIP" {
				v.InternalIP = a.Address
			}
		}
		for _, s := range n.Status.Conditions {
			if s.Type == "Ready" {
				v.Ready = s.Status == "True"
			}
		}
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b Worker) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}
func (c *nativeCluster) exactWorker(ctx context.Context, name, uid string) (workerNode, int, error) {
	var n workerNode
	status, e := c.workerRequest(ctx, http.MethodGet, "/api/v1/nodes/"+url.PathEscape(name), nil, &n)
	if e == nil && (uid == "" || n.Metadata.UID != uid) {
		e = errors.New("eks: refusing a replaced Kubernetes node incarnation")
	}
	return n, status, e
}

const managedWorkerFields = "eks.amazonaws.com/managed-fields"

type workerFields struct {
	Labels []string      `json:"labels"`
	Taints []WorkerTaint `json:"taints"`
}

func (k *K3d) ConfigureWorker(ctx context.Context, id string, w WorkerConfiguration) error {
	c, e := k.workerCluster(id)
	if e != nil {
		return e
	}
	n, _, e := c.exactWorker(ctx, w.Name, w.UID)
	if e != nil {
		return e
	}
	var previous workerFields
	if raw := n.Metadata.Annotations[managedWorkerFields]; raw != "" {
		if e = json.Unmarshal([]byte(raw), &previous); e != nil {
			return e
		}
	}
	labels := map[string]any{}
	for _, key := range previous.Labels {
		if _, ok := w.Labels[key]; !ok {
			labels[key] = nil
		}
	}
	fields := workerFields{Taints: w.Taints}
	for key, v := range w.Labels {
		labels[key] = v
		fields.Labels = append(fields.Labels, key)
	}
	labels["eks.amazonaws.com/nodegroup"] = w.Nodegroup
	taints := make([]WorkerTaint, 0, len(n.Spec.Taints)+len(w.Taints))
	for _, t := range n.Spec.Taints {
		if !slices.ContainsFunc(previous.Taints, func(p WorkerTaint) bool { return p.Key == t.Key && p.Effect == t.Effect }) && !slices.ContainsFunc(w.Taints, func(p WorkerTaint) bool { return p.Key == t.Key && p.Effect == t.Effect }) {
			taints = append(taints, t)
		}
	}
	taints = append(taints, w.Taints...)
	slices.Sort(fields.Labels)
	raw, e := json.Marshal(fields)
	if e != nil {
		return e
	}
	unchanged := n.Metadata.Annotations[managedWorkerFields] == string(raw) && slices.Equal(taints, n.Spec.Taints)
	for key, value := range labels {
		current, exists := n.Metadata.Labels[key]
		if value == nil {
			unchanged = unchanged && !exists
		} else {
			unchanged = unchanged && exists && current == value
		}
	}
	if unchanged {
		return nil
	}
	_, e = c.workerRequest(ctx, http.MethodPatch, "/api/v1/nodes/"+url.PathEscape(w.Name), map[string]any{"metadata": map[string]any{"uid": w.UID, "resourceVersion": n.Metadata.ResourceVersion, "labels": labels, "annotations": map[string]string{managedWorkerFields: string(raw)}}, "spec": map[string]any{"taints": taints}}, nil)
	return e
}

// CordonWorker prevents scheduling on the exact node without evicting its Pods.
func (k *K3d) CordonWorker(ctx context.Context, id, name, uid string) error {
	c, err := k.workerCluster(id)
	if err != nil {
		return err
	}
	n, status, err := c.exactWorker(ctx, name, uid)
	if status == http.StatusNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	return c.cordonWorker(ctx, name, uid, &n)
}

func (c *nativeCluster) cordonWorker(ctx context.Context, name, uid string, n *workerNode) error {
	const excludeExternalLoadBalancers = "node.kubernetes.io/exclude-from-external-load-balancers"
	if n.Spec.Unschedulable && n.Metadata.Labels[excludeExternalLoadBalancers] == "true" {
		return nil
	}
	_, err := c.workerRequest(ctx, http.MethodPatch, "/api/v1/nodes/"+url.PathEscape(name), map[string]any{
		"metadata": map[string]any{"uid": uid, "resourceVersion": n.Metadata.ResourceVersion, "labels": map[string]string{excludeExternalLoadBalancers: "true"}},
		"spec":     map[string]bool{"unschedulable": true},
	}, nil)
	return err
}

// DrainWorker cordons first and submits real policy/v1 evictions. PDB rejection
// remains pending; force uses UID-preconditioned deletion rather than fake success.
func (k *K3d) DrainWorker(ctx context.Context, id, name, uid string, force bool) (bool, error) {
	c, e := k.workerCluster(id)
	if e != nil {
		return false, e
	}
	n, status, e := c.exactWorker(ctx, name, uid)
	if status == 404 {
		return true, nil
	}
	if e != nil {
		return false, e
	}
	if e = c.cordonWorker(ctx, name, uid, &n); e != nil {
		return false, e
	}
	var pods struct {
		Items []struct {
			Metadata struct {
				Name, Namespace, UID string
				Annotations          map[string]string
				OwnerReferences      []struct{ Kind string }
			}
			Status struct{ Phase string }
		} `json:"items"`
	}
	if _, e = c.workerRequest(ctx, http.MethodGet, "/api/v1/pods?fieldSelector="+url.QueryEscape("spec.nodeName="+name), nil, &pods); e != nil {
		return false, e
	}
	pending := false
	for _, p := range pods.Items {
		if p.Status.Phase == "Succeeded" || p.Status.Phase == "Failed" || p.Metadata.Annotations["kubernetes.io/config.mirror"] != "" || slices.ContainsFunc(p.Metadata.OwnerReferences, func(o struct{ Kind string }) bool { return o.Kind == "DaemonSet" }) {
			continue
		}
		pending = true
		path := "/api/v1/namespaces/" + url.PathEscape(p.Metadata.Namespace) + "/pods/" + url.PathEscape(p.Metadata.Name)
		options := map[string]any{"preconditions": map[string]string{"uid": p.Metadata.UID}}
		if force {
			options["gracePeriodSeconds"] = 0
			status, e = c.workerRequest(ctx, http.MethodDelete, path, options, nil)
		} else {
			status, e = c.workerRequest(ctx, http.MethodPost, path+"/eviction", map[string]any{"apiVersion": "policy/v1", "kind": "Eviction", "metadata": map[string]string{"name": p.Metadata.Name, "namespace": p.Metadata.Namespace}, "deleteOptions": options}, nil)
		}
		if e != nil && status != 404 && status != 429 && status != 409 {
			return false, e
		}
	}
	return !pending, nil
}
func (k *K3d) DeleteWorker(ctx context.Context, id, name, uid string) error {
	c, e := k.workerCluster(id)
	if e != nil {
		return e
	}
	_, status, e := c.exactWorker(ctx, name, uid)
	if status == 404 {
		return nil
	}
	if e != nil {
		return e
	}
	status, e = c.workerRequest(ctx, http.MethodDelete, "/api/v1/nodes/"+url.PathEscape(name), map[string]any{"preconditions": map[string]string{"uid": uid}}, nil)
	if status == 404 {
		return nil
	}
	return e
}
