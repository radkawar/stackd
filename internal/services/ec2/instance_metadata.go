package ec2

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
)

func launchMetadataOptions(image api.Image, in *api.InstanceMetadataOptionsRequest) (*api.InstanceMetadataOptionsResponse, error) {
	out := &api.InstanceMetadataOptionsResponse{HttpEndpoint: new(api.InstanceMetadataEndpointState("enabled")), HttpProtocolIpv6: new(api.InstanceMetadataProtocolState("disabled")), HttpPutResponseHopLimit: new(api.Integer(1)), HttpTokens: new(api.HttpTokensState("optional")), InstanceMetadataTags: new(api.InstanceMetadataTagsState("disabled")), State: new(api.InstanceMetadataOptionsState("pending"))}
	if str(image.ImdsSupport) == "v2.0" {
		out.HttpTokens = new(api.HttpTokensState("required"))
		out.HttpPutResponseHopLimit = new(api.Integer(2))
	}
	if in != nil {
		if err := applyMetadataOptions(out, *in); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func applyMetadataOptions(out *api.InstanceMetadataOptionsResponse, in api.InstanceMetadataOptionsRequest) error {
	if in.HttpTokens != nil {
		if str(in.HttpTokens) != "optional" && str(in.HttpTokens) != "required" {
			return failure("InvalidParameterValue", "HttpTokens must be optional or required.")
		}
		out.HttpTokens = in.HttpTokens
	}
	if in.HttpEndpoint != nil {
		if str(in.HttpEndpoint) != "enabled" && str(in.HttpEndpoint) != "disabled" {
			return failure("InvalidParameterValue", "HttpEndpoint must be enabled or disabled.")
		}
		out.HttpEndpoint = in.HttpEndpoint
	}
	if in.HttpPutResponseHopLimit != nil {
		if *in.HttpPutResponseHopLimit < 1 || *in.HttpPutResponseHopLimit > 64 {
			return failure("InvalidParameterValue", "HttpPutResponseHopLimit must be between 1 and 64.")
		}
		out.HttpPutResponseHopLimit = in.HttpPutResponseHopLimit
	}
	if in.InstanceMetadataTags != nil {
		if str(in.InstanceMetadataTags) != "enabled" && str(in.InstanceMetadataTags) != "disabled" {
			return failure("InvalidParameterValue", "InstanceMetadataTags must be enabled or disabled.")
		}
		out.InstanceMetadataTags = in.InstanceMetadataTags
	}
	if in.HttpProtocolIpv6 != nil {
		if str(in.HttpProtocolIpv6) != "enabled" && str(in.HttpProtocolIpv6) != "disabled" {
			return failure("InvalidParameterValue", "HttpProtocolIpv6 must be enabled or disabled.")
		}
		if str(in.HttpProtocolIpv6) == "enabled" {
			return unsupported("IPv6 metadata networking is not implemented.")
		}
		out.HttpProtocolIpv6 = in.HttpProtocolIpv6
	}
	return nil
}

func (s *Service) modifyInstanceMetadataOptions(ctx context.Context, tx Transaction, in *api.ModifyInstanceMetadataOptionsRequest) (*api.ModifyInstanceMetadataOptionsResult, error) {
	record, err := loadInstance(ctx, tx, str(in.InstanceId))
	if err != nil {
		return nil, err
	}
	metadata := api.CloneInstanceMetadataOptionsResponse(*record.Data.MetadataOptions)
	if err := applyMetadataOptions(&metadata, api.InstanceMetadataOptionsRequest{HttpEndpoint: in.HttpEndpoint, HttpProtocolIpv6: in.HttpProtocolIpv6, HttpTokens: in.HttpTokens, HttpPutResponseHopLimit: in.HttpPutResponseHopLimit, InstanceMetadataTags: in.InstanceMetadataTags}); err != nil {
		return nil, err
	}
	conditions := map[string][]string{"ec2:MetadataHttpTokens": {str(metadata.HttpTokens)}, "ec2:MetadataHttpEndpoint": {str(metadata.HttpEndpoint)}, "ec2:MetadataHttpPutResponseHopLimit": {strconv.Itoa(int(*metadata.HttpPutResponseHopLimit))}, "ec2:InstanceMetadataTags": {str(metadata.InstanceMetadataTags)}}
	if err := s.authorizeWith(ctx, "ModifyInstanceMetadataOptions", "instance", record.Key.ID, record.Data.Tags, conditions); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if state := instanceState(record); state == "terminated" || state == "shutting-down" {
		return nil, failure("IncorrectInstanceState", "The instance cannot be modified in its current state.")
	}
	if str(metadata.InstanceMetadataTags) == "enabled" {
		if err := validateMetadataTags(record.Data.Tags); err != nil {
			return nil, err
		}
	}
	before := record.Data.MetadataOptions
	changed := str(before.HttpTokens) != str(metadata.HttpTokens) ||
		str(before.HttpEndpoint) != str(metadata.HttpEndpoint) ||
		str(before.HttpProtocolIpv6) != str(metadata.HttpProtocolIpv6) ||
		*before.HttpPutResponseHopLimit != *metadata.HttpPutResponseHopLimit ||
		str(before.InstanceMetadataTags) != str(metadata.InstanceMetadataTags)
	running := instanceState(record) == "running"
	if changed {
		state := api.InstanceMetadataOptionsState("pending")
		if running {
			state = "applied"
		}
		metadata.State = &state
	}
	record.Data.MetadataOptions = &metadata
	record.Generation++
	setInstanceCommand(ctx, &record)
	if err := tx.PutInstance(record); err != nil {
		return nil, err
	}
	if str(metadata.State) != "pending" {
		// Native running and stopped no-ops also return pending acceptance.
		// This response snapshot is separate from the committed application state.
		accepted := metadata
		accepted.State = new(api.InstanceMetadataOptionsState("pending"))
		return &api.ModifyInstanceMetadataOptionsResult{InstanceId: record.Data.InstanceId, InstanceMetadataOptions: &accepted}, nil
	}
	return &api.ModifyInstanceMetadataOptionsResult{InstanceId: record.Data.InstanceId, InstanceMetadataOptions: &metadata}, nil
}

func instanceServiceContext(ctx context.Context, key ResourceKey) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, ServicePrincipal: awsctx.ServicePrincipal{Name: "ec2.amazonaws.com", SourceARN: resourceARN(key.Scope, "instance", key.ID)}})
}

// InstanceMetadataHandler must only be mounted on the native guest's private
// metadata listener. Instance identity comes from the attachment owner, never
// from a host header, query parameter, client IP header or bearer role ARN.
func (s *Service) InstanceMetadataHandler(key ResourceKey) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := instanceServiceContext(r.Context(), key)
		var record InstanceRecord
		err := s.repository.View(ctx, func(tx Reader) error {
			var err error
			record, err = tx.Instance(key)
			if err != nil {
				return err
			}
			record.Data, err = instanceProjection(ctx, tx, record)
			return err
		})
		if err != nil || instanceState(record) == "stopped" || instanceState(record) == "terminated" || record.Data.MetadataOptions == nil || str(record.Data.MetadataOptions.HttpEndpoint) != "enabled" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Server", "EC2ws")
		w.Header().Set("Content-Type", "text/plain")
		metadataPath := path.Clean(r.URL.Path)
		if metadataPath == "/latest/api/token" {
			if r.Method != http.MethodPut {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if _, present := r.Header["X-Forwarded-For"]; present {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			ttl, err := strconv.Atoi(r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds"))
			if err != nil || ttl < 0 || ttl > 21600 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			writer, ok := w.(interface{ SetHopLimit(int) error })
			if !ok || writer.SetHopLimit(int(*record.Data.MetadataOptions.HttpPutResponseHopLimit)) != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			token, err := newMetadataToken(record.MetadataTokenKey, s.clock.Now().Add(time.Duration(ttl)*time.Second))
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("X-aws-ec2-metadata-token-ttl-seconds", strconv.Itoa(ttl))
			_, _ = w.Write([]byte(token))
			return
		}
		token := r.Header.Get("X-aws-ec2-metadata-token")
		if token != "" {
			ttl, valid := metadataTokenTTL(record.MetadataTokenKey, token, s.clock.Now())
			if !valid {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("X-aws-ec2-metadata-token-ttl-seconds", strconv.Itoa(ttl))
		} else if str(record.Data.MetadataOptions.HttpTokens) == "required" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPut {
			version, route, _ := strings.Cut(strings.TrimPrefix(metadataPath, "/"), "/")
			if _, known := instanceMetadataCategories[version]; known && strings.TrimSuffix(route, "/") == "api/token" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "OPTIONS, GET, HEAD")
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		body, contentType, status := s.instanceMetadata(ctx, record, metadataPath, token != "")
		if status == http.StatusNotFound {
			body, contentType = []byte(instanceMetadataNotFoundBody), "text/html"
		}
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(status)
		if r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
	})
}

func newMetadataToken(key []byte, expiry time.Time) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("missing instance metadata signing key")
	}
	var token [72]byte
	binary.BigEndian.PutUint64(token[:8], uint64(expiry.UnixNano()))
	if _, err := rand.Read(token[8:40]); err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(token[:40])
	copy(token[40:], mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString(token[:]), nil
}
func metadataTokenTTL(key []byte, value string, now time.Time) (int, bool) {
	if len(key) != 32 {
		return 0, false
	}
	token, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(token) != 72 {
		return 0, false
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(token[:40])
	remaining := time.Unix(0, int64(binary.BigEndian.Uint64(token[:8]))).Sub(now)
	if !hmac.Equal(token[40:], mac.Sum(nil)) || remaining <= 0 {
		return 0, false
	}
	return int((remaining + time.Second - 1) / time.Second), true
}

func metadataText(value string) ([]byte, string, int) {
	return []byte(value), "text/plain", http.StatusOK
}
func metadataJSON(value any) ([]byte, string, int) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, "", http.StatusInternalServerError
	}
	return body, "application/json", http.StatusOK
}
