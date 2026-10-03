package ec2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
)

type metadataHTTPObservation struct {
	Path, Method   string
	TokenSupplied  bool `json:"token_supplied"`
	Code           int
	Headers        map[string]string
	RequestHeaders map[string]string `json:"request_headers"`
	Body           *string
}

type metadataHTTPFixture struct {
	Account, Region string
	Owned           struct{ Instances []string }
	HTTP            []metadataHTTPObservation `json:"metadata_http"`
}

func readMetadataHTTPFixture(t *testing.T, name string) metadataHTTPFixture {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/ec2/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture metadataHTTPFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

type metadataTestInstance struct {
	service *Service
	clock   *clock.Manual
	ctx     context.Context
	record  InstanceRecord
}

func newMetadataTestInstance(t *testing.T) metadataTestInstance {
	t.Helper()
	const account = "000000000000"
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: account, Region: "us-east-1", PrincipalARN: "arn:aws:iam::" + account + ":root", PrincipalID: account})
	source := clock.NewManual(time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC))
	s := New(Config{Clock: source})
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	instanceKey := key(ctx, "i-0123456789abcdef0")
	record := InstanceRecord{Key: instanceKey, Generation: 1, Intent: InstanceIntentObserve, MetadataTokenKey: bytes.Repeat([]byte{1}, 32), Data: api.Instance{
		InstanceId:      new(api.String(instanceKey.ID)),
		State:           &api.InstanceState{Name: new(api.InstanceStateName("running")), Code: new(api.Integer(16))},
		MetadataOptions: &api.InstanceMetadataOptionsResponse{HttpEndpoint: new(api.InstanceMetadataEndpointState("enabled")), HttpTokens: new(api.HttpTokensState("required")), HttpPutResponseHopLimit: new(api.Integer(1)), InstanceMetadataTags: new(api.InstanceMetadataTagsState("disabled"))},
	}}
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutInstance(record) }); err != nil {
		t.Fatal(err)
	}
	return metadataTestInstance{service: s, clock: source, ctx: ctx, record: record}
}

func metadataHTTPRequest(t *testing.T, s *Service, instance ResourceKey, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, "http://169.254.169.254"+path, nil)
	if token != "" {
		request.Header.Set("X-aws-ec2-metadata-token", token)
	}
	if method == http.MethodPut {
		// The retained guest probe supplies this header on every PUT,
		// including version-specific paths that must not issue a token.
		request.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "300")
	}
	response := httptest.NewRecorder()
	s.InstanceMetadataHandler(instance).ServeHTTP(response, request)
	return response
}

// The real handler reads a retained instance and verifies legitimately signed,
// instance-bound tokens. This is HTTP protocol coverage, not a guest TCP/TTL
// proof: no fake SetHopLimit writer or latest PUT token issuance is used here.
func TestNativeInstanceMetadataHTTPRoutes(t *testing.T) {
	local := newMetadataTestInstance(t)
	token, err := newMetadataToken(local.record.MetadataTokenKey, local.clock.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, name := range []string{"instances_metadata_matrix_handoff", "instances_metadata_routes_handoff"} {
		fixture := readMetadataHTTPFixture(t, name)
		if len(fixture.Owned.Instances) != 1 {
			t.Fatal("metadata capture must identify its actual instance")
		}
		normalize := strings.NewReplacer(fixture.Owned.Instances[0], local.record.Key.ID, fixture.Account, local.record.Key.Scope.AccountID)
		for _, row := range fixture.HTTP {
			body := ""
			if row.Body != nil {
				body = normalize.Replace(*row.Body)
			}
			identity := fmt.Sprintf("%s %s token=%t status=%d body=%s", row.Method, row.Path, row.TokenSupplied, row.Code, body)
			if seen[identity] {
				continue // Earlier captures and repeated directory polls add no new contract.
			}
			seen[identity] = true
			t.Run(fmt.Sprintf("%s/%s%s/token=%t", name, row.Method, row.Path, row.TokenSupplied), func(t *testing.T) {
				if row.Method == http.MethodPut && strings.TrimSuffix(row.Path, "/") == "/latest/api/token" {
					t.Skip("Token issuance requires the native guest socket hop-limit proof, not a recorder that pretends to set TTL.")
				}
				if row.Code == http.StatusOK && strings.HasSuffix(strings.TrimSuffix(row.Path, "/"), "/meta-data") {
					t.Skip("Native metadata menus include unimplemented categories; a partial menu is not a normalized native response.")
				}
				if row.Code == http.StatusOK && row.Body == nil {
					t.Skip("This user-data observation retains a digest rather than replayable response bytes.")
				}
				requestToken := ""
				if row.TokenSupplied {
					requestToken = token
				}
				response := metadataHTTPRequest(t, local.service, local.record.Key, row.Method, row.Path, requestToken)
				if response.Code != row.Code {
					t.Fatalf("HTTP %d, native %d: %s", response.Code, row.Code, response.Body.String())
				}
				// Generic native XHTML 404 pages are not metadata documents.
				// Pin their status/admission precedence, not incidental markup.
				if row.Code != http.StatusNotFound {
					if response.Body.String() != body {
						t.Fatalf("body = %q, native %q", response.Body.String(), body)
					}
					if got := response.Header().Get("Content-Type"); got != row.Headers["Content-Type"] {
						t.Fatalf("Content-Type = %q, native %q", got, row.Headers["Content-Type"])
					}
				}
			})
		}
	}
}

func TestInstanceMetadataTokenBindingAndExpiry(t *testing.T) {
	local := newMetadataTestInstance(t)
	expiry := local.clock.Now().Add(time.Minute)
	token, err := newMetadataToken(local.record.MetadataTokenKey, expiry)
	if err != nil {
		t.Fatal(err)
	}
	other := local.record
	other.Key.ID = "i-0123456789abcdef1"
	other.Data.InstanceId = new(api.String(other.Key.ID))
	other.MetadataTokenKey = bytes.Repeat([]byte{2}, 32)
	if err := local.service.repository.Update(local.ctx, func(tx Transaction) error { return tx.PutInstance(other) }); err != nil {
		t.Fatal(err)
	}
	const path = "/latest/meta-data/instance-id"
	for _, test := range []struct {
		name, method, token string
		instance            ResourceKey
		status              int
		body                string
	}{
		{"own-token", http.MethodGet, token, local.record.Key, http.StatusOK, local.record.Key.ID},
		{"other-instance", http.MethodGet, token, other.Key, http.StatusUnauthorized, ""},
		{"malformed-token", http.MethodGet, "not-a-token", local.record.Key, http.StatusUnauthorized, ""},
		{"head", http.MethodHead, token, local.record.Key, http.StatusOK, ""},
		{"auth-before-method", http.MethodPost, "", local.record.Key, http.StatusUnauthorized, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := metadataHTTPRequest(t, local.service, test.instance, test.method, path, test.token)
			if response.Code != test.status || response.Body.String() != test.body {
				t.Fatalf("HTTP %d body %q, want %d %q", response.Code, response.Body.String(), test.status, test.body)
			}
		})
	}
	local.clock.Advance(expiry.Add(-time.Nanosecond).Sub(local.clock.Now()))
	response := metadataHTTPRequest(t, local.service, local.record.Key, http.MethodGet, path, token)
	if response.Code != http.StatusOK || response.Body.String() != local.record.Key.ID {
		t.Fatalf("token expired before its boundary: HTTP %d %q", response.Code, response.Body.String())
	}
	if ttl := response.Header().Get("X-aws-ec2-metadata-token-ttl-seconds"); ttl != "1" {
		t.Fatalf("remaining token lifetime before expiry = %q, want 1 second", ttl)
	}
	local.clock.Advance(time.Nanosecond)
	response = metadataHTTPRequest(t, local.service, local.record.Key, http.MethodGet, path, token)
	if response.Code != http.StatusUnauthorized || response.Body.Len() != 0 {
		t.Fatalf("token accepted at expiry: HTTP %d %q", response.Code, response.Body.String())
	}
	fresh, err := newMetadataToken(local.record.MetadataTokenKey, local.clock.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	local.record.MetadataTokenKey = bytes.Repeat([]byte{3}, 32)
	if err := local.service.repository.Update(local.ctx, func(tx Transaction) error { return tx.PutInstance(local.record) }); err != nil {
		t.Fatal(err)
	}
	response = metadataHTTPRequest(t, local.service, local.record.Key, http.MethodGet, path, fresh)
	if response.Code != http.StatusUnauthorized || response.Body.Len() != 0 {
		t.Fatalf("old signing key survived retained key replacement: HTTP %d %q", response.Code, response.Body.String())
	}
}

// Native directory membership establishes category versions. Leaf values come
// from the real typed ENI owner, not a callback returning canned network data.
func TestNativeInstanceMetadataNetworkVersionGate(t *testing.T) {
	fixture := readMetadataHTTPFixture(t, "instances_metadata_matrix_handoff")
	local := newMetadataTestInstance(t)
	vpc := VPCRecord{Key: key(local.ctx, "vpc-0123456789abcdef0"), Data: api.Vpc{VpcId: new(api.String("vpc-0123456789abcdef0")), CidrBlock: new(api.String("10.0.0.0/16"))}}
	subnet := SubnetRecord{Key: key(local.ctx, "subnet-0123456789abcdef0"), Data: api.Subnet{SubnetId: new(api.String("subnet-0123456789abcdef0")), VpcId: vpc.Data.VpcId, CidrBlock: new(api.String("10.0.1.0/24"))}}
	eni := NetworkInterfaceRecord{Key: key(local.ctx, "eni-0123456789abcdef0"), Data: api.NetworkInterface{
		NetworkInterfaceId: new(api.String("eni-0123456789abcdef0")), OwnerId: new(api.String(local.record.Key.Scope.AccountID)),
		MacAddress: new(api.String("02:00:00:00:00:01")), PrivateIpAddress: new(api.String("10.0.1.10")), VpcId: vpc.Data.VpcId, SubnetId: subnet.Data.SubnetId,
		Attachment: &api.NetworkInterfaceAttachment{InstanceId: local.record.Data.InstanceId, DeviceIndex: new(api.Integer(0))},
	}}
	local.record.Data.NetworkInterfaces = append(local.record.Data.NetworkInterfaces, api.InstanceNetworkInterface{NetworkInterfaceId: eni.Data.NetworkInterfaceId})
	if err := local.service.repository.Update(local.ctx, func(tx Transaction) error {
		if err := tx.PutVPC(vpc); err != nil {
			return err
		}
		if err := tx.PutSubnet(subnet); err != nil {
			return err
		}
		if err := tx.PutNetworkInterface(eni); err != nil {
			return err
		}
		return tx.PutInstance(local.record)
	}); err != nil {
		t.Fatal(err)
	}
	token, err := newMetadataToken(local.record.MetadataTokenKey, local.clock.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, row := range fixture.HTTP {
		if row.Code != http.StatusOK || row.Body == nil || !strings.HasSuffix(row.Path, "/meta-data/") {
			continue
		}
		version, _, _ := strings.Cut(strings.TrimPrefix(row.Path, "/"), "/")
		if seen[version] {
			continue
		}
		seen[version] = true
		t.Run(version, func(t *testing.T) {
			path := "/" + version + "/meta-data/network/interfaces/macs/" + str(eni.Data.MacAddress) + "/interface-id"
			response := metadataHTTPRequest(t, local.service, local.record.Key, http.MethodGet, path, token)
			if !slices.Contains(strings.Split(*row.Body, "\n"), "network/") {
				if response.Code != http.StatusNotFound {
					t.Fatalf("network category leaked into native old version: HTTP %d %q", response.Code, response.Body.String())
				}
				return
			}
			if response.Code != http.StatusOK || response.Body.String() != eni.Key.ID {
				t.Fatalf("owned ENI metadata = HTTP %d %q, want 200 %q", response.Code, response.Body.String(), eni.Key.ID)
			}
		})
	}
}
