package eks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

const PodIdentityAudience = "pods.eks.amazonaws.com"

var ErrPodIdentityToken = errors.New("kubernetes pod identity token is invalid")
var ErrPodIdentityTokenExpired = errors.New("kubernetes pod identity token has expired")

// PodIdentitySubject contains only TokenReview-authenticated claims cross-checked
// against the current Pod, ServiceAccount and Node objects. No JWT is decoded.
type PodIdentitySubject struct {
	Namespace, ServiceAccount, ServiceAccountUID         string
	PodName, PodUID, NodeName, NodeUID, InstanceID, Zone string
}
type PodIdentityRuntime interface {
	ReviewPodIdentityToken(context.Context, string, string) (PodIdentitySubject, error)
}

func (k *K3d) ReviewPodIdentityToken(ctx context.Context, id, token string) (PodIdentitySubject, error) {
	k.mu.RLock()
	c := k.clusters[id]
	closed := k.closed
	k.mu.RUnlock()
	if closed || c == nil {
		return PodIdentitySubject{}, errors.New("eks: cluster runtime is unavailable")
	}
	return c.reviewPodIdentityToken(ctx, token)
}
func (c *nativeCluster) podIdentityRequest(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.nativeURL()+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		io.Copy(io.Discard, response.Body)
		if response.StatusCode == 404 {
			return ErrPodIdentityToken
		}
		return fmt.Errorf("eks: Kubernetes pod identity request returned %d", response.StatusCode)
	}
	if out == nil {
		_, err = io.Copy(io.Discard, response.Body)
		return err
	}
	return json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(out)
}

type podIdentityObjectMeta struct {
	Name, Namespace, UID, ResourceVersion string
	DeletionTimestamp                     *string
	Labels, Annotations                   map[string]string
}

func (c *nativeCluster) reviewPodIdentityToken(ctx context.Context, token string) (PodIdentitySubject, error) {
	var subject PodIdentitySubject
	if token == "" || len(token) > 65536 {
		return subject, ErrPodIdentityToken
	}
	request := map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "spec": map[string]any{"token": token, "audiences": []string{PodIdentityAudience}}}
	var review struct {
		Status struct {
			Authenticated bool
			Audiences     []string
			Error         string
			User          struct {
				Username, UID string
				Extra         map[string][]string
			}
		}
	}
	if err := c.podIdentityRequest(ctx, http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", request, &review); err != nil {
		return subject, err
	}
	if !review.Status.Authenticated && strings.Contains(review.Status.Error, "service account token has expired") {
		return subject, ErrPodIdentityTokenExpired
	}
	if !review.Status.Authenticated || !slices.Contains(review.Status.Audiences, PodIdentityAudience) {
		return subject, ErrPodIdentityToken
	}
	parts := strings.Split(review.Status.User.Username, ":")
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" || parts[2] == "" || parts[3] == "" || review.Status.User.UID == "" {
		return subject, ErrPodIdentityToken
	}
	subject.Namespace, subject.ServiceAccount, subject.ServiceAccountUID = parts[2], parts[3], review.Status.User.UID
	claim := func(name string) string {
		values := review.Status.User.Extra["authentication.kubernetes.io/"+name]
		if len(values) != 1 {
			return ""
		}
		return values[0]
	}
	subject.PodName, subject.PodUID = claim("pod-name"), claim("pod-uid")
	if subject.PodName == "" || subject.PodUID == "" {
		return subject, ErrPodIdentityToken
	}
	var pod struct {
		Metadata podIdentityObjectMeta
		Spec     struct{ ServiceAccountName, NodeName string }
	}
	path := "/api/v1/namespaces/" + url.PathEscape(subject.Namespace)
	if err := c.podIdentityRequest(ctx, http.MethodGet, path+"/pods/"+url.PathEscape(subject.PodName), nil, &pod); err != nil {
		return subject, err
	}
	if pod.Metadata.UID != subject.PodUID || pod.Metadata.DeletionTimestamp != nil || pod.Spec.ServiceAccountName != subject.ServiceAccount || pod.Spec.NodeName == "" {
		return subject, ErrPodIdentityToken
	}
	var sa struct{ Metadata podIdentityObjectMeta }
	if err := c.podIdentityRequest(ctx, http.MethodGet, path+"/serviceaccounts/"+url.PathEscape(subject.ServiceAccount), nil, &sa); err != nil {
		return subject, err
	}
	if sa.Metadata.UID != subject.ServiceAccountUID || sa.Metadata.DeletionTimestamp != nil {
		return subject, ErrPodIdentityToken
	}
	subject.NodeName = pod.Spec.NodeName
	if name := claim("node-name"); name != "" && name != subject.NodeName {
		return subject, ErrPodIdentityToken
	}
	var node struct {
		Metadata podIdentityObjectMeta
		Spec     struct{ ProviderID string }
		Status   struct {
			Conditions []struct{ Type, Status string }
		}
	}
	if err := c.podIdentityRequest(ctx, http.MethodGet, "/api/v1/nodes/"+url.PathEscape(subject.NodeName), nil, &node); err != nil {
		return subject, err
	}
	if node.Metadata.UID == "" || node.Metadata.DeletionTimestamp != nil {
		return subject, ErrPodIdentityToken
	}
	subject.NodeUID = node.Metadata.UID
	if uid := claim("node-uid"); uid != "" && uid != subject.NodeUID {
		return subject, ErrPodIdentityToken
	}
	ready := false
	for _, condition := range node.Status.Conditions {
		if condition.Type == "Ready" && condition.Status == "True" {
			ready = true
		}
	}
	if !ready {
		return subject, ErrPodIdentityToken
	}
	if strings.HasPrefix(node.Spec.ProviderID, "aws:///") {
		provider := strings.Split(strings.TrimPrefix(node.Spec.ProviderID, "aws:///"), "/")
		if len(provider) == 2 {
			subject.Zone, subject.InstanceID = provider[0], provider[1]
		}
	}
	return subject, nil
}
