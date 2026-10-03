package eks

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	sdksts "github.com/aws/aws-sdk-go-v2/service/sts"
	native "stackd/compute/eks"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
)

// Kubernetes authentication checks a bounded, cluster-bound STS presign locally.
// No token URL is fetched; the shared gateway remains the only SigV4 verifier.
func (s *Service) kubernetesHandler(key Key, id string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == r.Header.Get("Authorization") || len(token) > 16384 {
			s.logAuthentication(r.Context(), key, id, "", native.Identity{}, errors.New("missing or invalid bearer token"))
			s.kubeFailure(w, 401, "Unauthorized")
			return
		}
		presigned, e := tokenRequest(r.Context(), token, key)
		if e != nil || s.authenticate == nil {
			cause := e
			if cause == nil {
				cause = errors.New("IAM authenticator unavailable")
			}
			s.logAuthentication(r.Context(), key, id, "", native.Identity{}, cause)
			s.kubeFailure(w, 401, "Unauthorized")
			return
		}
		signed, rejected := s.authenticate(presigned.Request, "sts", presigned.Region)
		if rejected != nil {
			s.logAuthentication(r.Context(), key, id, "", native.Identity{}, rejected)
			s.kubeFailure(w, 401, "Unauthorized")
			return
		}
		m := awsctx.FromContext(signed.Context())
		identity, _, needsConfigMap, e := s.kubernetesIdentity(signed.Context(), key, id, m, nil, false)
		if e == nil && needsConfigMap {
			reader, ok := s.runtime.(native.AWSAuthReader)
			if !ok {
				e = errors.New("kubernetes aws-auth reader unavailable")
			} else {
				var data map[string]string
				data, e = reader.ReadAWSAuth(signed.Context(), id)
				if e == nil {
					// Re-read current mode, entries and IAM incarnation after the native
					// read. No external Kubernetes effect holds a storage transaction.
					identity, _, _, e = s.kubernetesIdentity(signed.Context(), key, id, m, data, true)
				}
			}
		}
		principal, _ := principalIdentity(m)
		s.logAuthentication(signed.Context(), key, id, principal, identity, e)
		if e != nil {
			s.kubeFailure(w, 401, "Unauthorized")
			return
		}
		s.runtime.Proxy(w, r, id, identity)
	})
}
func (s *Service) kubeFailure(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": message, "reason": http.StatusText(status), "code": status})
}

type kubernetesToken struct {
	Request *http.Request
	Region  string
}

func tokenRequest(ctx context.Context, token string, key Key) (kubernetesToken, error) {
	const prefix = "k8s-aws-v1."
	if !strings.HasPrefix(token, prefix) {
		return kubernetesToken{}, errors.New("invalid EKS token")
	}
	b, e := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, prefix))
	if e != nil {
		return kubernetesToken{}, e
	}
	u, e := url.Parse(string(b))
	if e != nil {
		return kubernetesToken{}, e
	}
	if u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Path != "/" && u.Path != "" {
		return kubernetesToken{}, errors.New("invalid STS token URL")
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return kubernetesToken{}, e
	}
	credential := strings.Split(q.Get("X-Amz-Credential"), "/")
	if len(credential) != 5 || credential[3] != "sts" || credential[4] != "aws4_request" || !validSTSEndpoint(ctx, u.Host, credential[2], key.Partition) {
		return kubernetesToken{}, errors.New("invalid STS token endpoint scope")
	}
	allowed := map[string]bool{"Action": true, "Version": true, "X-Amz-Algorithm": true, "X-Amz-Credential": true, "X-Amz-Date": true, "X-Amz-Expires": true, "X-Amz-SignedHeaders": true, "X-Amz-Signature": true, "X-Amz-Security-Token": true}
	for k, v := range q {
		if !allowed[k] || len(v) != 1 {
			return kubernetesToken{}, errors.New("invalid STS token query")
		}
	}
	if q.Get("Action") != "GetCallerIdentity" || q.Get("Version") != "2011-06-15" || q.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" {
		return kubernetesToken{}, errors.New("invalid STS token action")
	}
	headers := strings.Split(q.Get("X-Amz-SignedHeaders"), ";")
	if !slices.Contains(headers, "x-k8s-aws-id") || !slices.Contains(headers, "host") {
		return kubernetesToken{}, errors.New("cluster binding is not signed")
	}
	expires, e := strconv.Atoi(q.Get("X-Amz-Expires"))
	if e != nil || expires < 0 || expires > 900 {
		return kubernetesToken{}, errors.New("invalid EKS token expiry")
	}
	issued, e := time.Parse("20060102T150405Z", q.Get("X-Amz-Date"))
	if e != nil || time.Now().After(issued.Add(15*time.Minute)) || issued.After(time.Now().Add(15*time.Minute)) {
		return kubernetesToken{}, errors.New("expired EKS token")
	}
	r, e := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if e != nil {
		return kubernetesToken{}, e
	}
	r.Header.Set("x-k8s-aws-id", key.Name)
	return kubernetesToken{Request: r, Region: credential[2]}, nil
}

func validSTSEndpoint(ctx context.Context, host, region, partition string) bool {
	if awscatalog.RegionPartition(region) != partition {
		return false
	}
	if host == "sts.amazonaws.com" {
		return partition == "aws" && region == "us-east-1"
	}
	resolver := sdksts.NewDefaultEndpointResolverV2()
	for _, fips := range []bool{false, true} {
		for _, dual := range []bool{false, true} {
			endpoint, err := resolver.ResolveEndpoint(ctx, sdksts.EndpointParameters{Region: &region, UseFIPS: &fips, UseDualStack: &dual})
			if err == nil && endpoint.URI.Host == host {
				return true
			}
		}
	}
	return false
}
