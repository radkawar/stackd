package eks

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

const irsaTokenPath = "/var/run/secrets/eks.amazonaws.com/serviceaccount"

type workloadIdentityPod struct {
	Metadata podIdentityObjectMeta
	Spec     map[string]any
}

func (k *K3d) workloadIdentityPatch(ctx context.Context, c *nativeCluster, namespace string, pod workloadIdentityPod) ([]byte, error) {
	name, _ := pod.Spec["serviceAccountName"].(string)
	if name == "" {
		name = "default"
	}
	sa, err := c.irsaServiceAccount(ctx, namespace, name)
	if err != nil {
		return nil, err
	}
	k.mu.RLock()
	region, service := c.region, c.podIdentityService
	k.mu.RUnlock()
	// Native EKS selects an association before a ServiceAccount role annotation.
	// Fargate skips that unsupported credential path but still receives IRSA.
	patch, err := k.podIdentityAdmissionPatch(ctx, c, namespace, name, pod, service)
	if err != nil || len(patch) != 0 {
		return patch, err
	}
	return irsaPatch(pod, sa, region)
}

func (c *nativeCluster) irsaServiceAccount(ctx context.Context, namespace, name string) (podIdentityObjectMeta, error) {
	var sa struct{ Metadata podIdentityObjectMeta }
	path := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/serviceaccounts/" + url.PathEscape(name)
	if err := c.podIdentityRequest(ctx, http.MethodGet, path, nil, &sa); err != nil {
		if errors.Is(err, ErrPodIdentityToken) {
			return podIdentityObjectMeta{}, nil
		}
		return podIdentityObjectMeta{}, err
	}
	return sa.Metadata, nil
}

func irsaTokenExpiration(annotations map[string]string, fallback int64) int64 {
	value, ok := annotations["eks.amazonaws.com/token-expiration"]
	if !ok {
		return fallback
	}
	expiration, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}
	return max(expiration, 600)
}

func workloadIdentitySkippedContainers(annotations map[string]string) []string {
	value := annotations["eks.amazonaws.com/skip-containers"]
	names, err := csv.NewReader(strings.NewReader(value)).Read()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil
	}
	return names
}

func irsaPatch(pod workloadIdentityPod, sa podIdentityObjectMeta, region string) ([]byte, error) {
	role := sa.Annotations["eks.amazonaws.com/role-arn"]
	if role == "" {
		return nil, nil
	}
	audience, annotated := sa.Annotations["eks.amazonaws.com/audience"]
	if !annotated {
		audience = "sts.amazonaws.com"
	}
	expiration := irsaTokenExpiration(pod.Metadata.Annotations, irsaTokenExpiration(sa.Annotations, 86400))
	regional := true
	if value, ok := sa.Annotations["eks.amazonaws.com/sts-regional-endpoints"]; ok {
		if parsed, err := strconv.ParseBool(value); err == nil {
			regional = parsed
		}
	}
	skip := workloadIdentitySkippedContainers(pod.Metadata.Annotations)
	volumes, _ := pod.Spec["volumes"].([]any)
	volumes = podIdentityAppend(volumes, "aws-iam-token", map[string]any{"name": "aws-iam-token", "projected": map[string]any{"defaultMode": 420, "sources": []any{map[string]any{"serviceAccountToken": map[string]any{"audience": audience, "expirationSeconds": expiration, "path": "token"}}}}})
	patches := []map[string]any{{"op": "add", "path": "/spec/volumes", "value": volumes}}
	for _, field := range []string{"containers", "initContainers"} {
		containers, _ := pod.Spec[field].([]any)
		if len(containers) == 0 {
			continue
		}
		for _, raw := range containers {
			container, ok := raw.(map[string]any)
			if !ok {
				return nil, errors.New("invalid container")
			}
			name, _ := container["name"].(string)
			if slices.Contains(skip, name) {
				continue
			}
			env, _ := container["env"].([]any)
			var webIdentityDefined, regionDefined, regionalDefined bool
			for _, raw := range env {
				entry, _ := raw.(map[string]any)
				switch entry["name"] {
				case "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE":
					webIdentityDefined = true
				case "AWS_REGION", "AWS_DEFAULT_REGION":
					regionDefined = true
				case "AWS_STS_REGIONAL_ENDPOINTS":
					regionalDefined = true
				}
			}
			// Preserve a caller's complete credential and endpoint configuration,
			// including its decision not to mount the projected token.
			if webIdentityDefined && regionDefined && regionalDefined {
				continue
			}
			if regional && !regionalDefined {
				env = append(env, map[string]any{"name": "AWS_STS_REGIONAL_ENDPOINTS", "value": "regional"})
			}
			if !regionDefined && region != "" {
				env = append(env, map[string]any{"name": "AWS_DEFAULT_REGION", "value": region}, map[string]any{"name": "AWS_REGION", "value": region})
			}
			if !webIdentityDefined {
				env = append(env, map[string]any{"name": "AWS_ROLE_ARN", "value": role}, map[string]any{"name": "AWS_WEB_IDENTITY_TOKEN_FILE", "value": irsaTokenPath + "/token"})
			}
			if len(env) != 0 {
				container["env"] = env
			}
			mounts, _ := container["volumeMounts"].([]any)
			container["volumeMounts"] = podIdentityAppend(mounts, "aws-iam-token", map[string]any{"name": "aws-iam-token", "mountPath": irsaTokenPath, "readOnly": true})
		}
		patches = append(patches, map[string]any{"op": "add", "path": "/spec/" + field, "value": containers})
	}
	return json.Marshal(patches)
}
