package eks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
)

// AWSAuthReader reads the actual Kubernetes authenticator configuration using
// private runtime credentials. Callers must invoke it outside storage callbacks.
type AWSAuthReader interface {
	ReadAWSAuth(context.Context, string) (map[string]string, error)
}

func (k *K3d) ReadAWSAuth(ctx context.Context, id string) (map[string]string, error) {
	k.mu.RLock()
	cluster := k.clusters[id]
	k.mu.RUnlock()
	if cluster == nil {
		return nil, errors.New("eks: Kubernetes cluster is not attached")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, cluster.nativeURL()+"/api/v1/namespaces/kube-system/configmaps/aws-auth", nil)
	if err != nil {
		return nil, err
	}
	response, err := cluster.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		_, err = io.Copy(io.Discard, response.Body)
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("eks: native aws-auth query returned %d", response.StatusCode)
	}
	var config struct {
		Data map[string]string `json:"data"`
	}
	if err = json.NewDecoder(response.Body).Decode(&config); err != nil {
		return nil, err
	}
	return config.Data, nil
}

// resolveNamespaces discovers the actual namespace set. Policy scope matching
// never examines the public request URL and never authorizes a request itself.
func (c *nativeCluster) resolveNamespaces(ctx context.Context, patterns []string) ([]string, error) {
	var names []string
	continuation := ""
	for {
		query := url.Values{"limit": {"500"}}
		if continuation != "" {
			query.Set("continue", continuation)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.nativeURL()+"/api/v1/namespaces?"+query.Encode(), nil)
		if err != nil {
			return nil, err
		}
		response, err := c.client.Do(request)
		if err != nil {
			return nil, err
		}
		var namespaces struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []struct {
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
			} `json:"items"`
		}
		err = json.NewDecoder(response.Body).Decode(&namespaces)
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("eks: native namespace discovery returned %d", response.StatusCode)
		}
		if err != nil {
			return nil, err
		}
		for _, namespace := range namespaces.Items {
			for _, pattern := range patterns {
				if namespacePatternMatches(pattern, namespace.Metadata.Name) {
					names = append(names, namespace.Metadata.Name)
					break
				}
			}
		}
		continuation = namespaces.Metadata.Continue
		if continuation == "" {
			slices.Sort(names)
			return slices.Compact(names), nil
		}
	}
}

func namespacePatternMatches(pattern, namespace string) bool {
	p, n, star, retry := 0, 0, -1, 0
	for n < len(namespace) {
		if p < len(pattern) && (pattern[p] == '?' || pattern[p] == namespace[n]) {
			p++
			n++
		} else if p < len(pattern) && pattern[p] == '*' {
			star, retry = p, n
			p++
		} else if star >= 0 {
			retry++
			p, n = star+1, retry
		} else {
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
