package ec2

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	api "stackd/internal/awsapi/ec2"
)

// Retain the native launch, ENI, subnet and VPC envelopes as the state inputs;
// metadata leaf responses are expectations, not callbacks producing values.
func nativeMetadataDepthInstance(t *testing.T, name string) (metadataTestInstance, metadataHTTPFixture) {
	t.Helper()
	local := newMetadataTestInstance(t)
	fixture := readMetadataHTTPFixture(t, name+"_handoff")
	raw, err := os.ReadFile("../../../testdata/aws/ec2/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	normalize := strings.NewReplacer(fixture.Account, local.record.Key.Scope.AccountID, fixture.Owned.Instances[0], local.record.Key.ID)
	var capture struct {
		Calls []struct {
			Label  string
			Output struct {
				Vpc          *api.Vpc
				Subnet       *api.Subnet
				Reservations []struct {
					ReservationId string
					Instances     []api.Instance
				}
			}
		}
	}
	if err := json.Unmarshal([]byte(normalize.Replace(string(raw))), &capture); err != nil {
		t.Fatal(err)
	}
	var vpc VPCRecord
	var subnet SubnetRecord
	for _, call := range capture.Calls {
		switch call.Label {
		case "owned-vpc":
			vpc = VPCRecord{Key: key(local.ctx, str(call.Output.Vpc.VpcId)), Data: *call.Output.Vpc}
		case "owned-subnet":
			subnet = SubnetRecord{Key: key(local.ctx, str(call.Output.Subnet.SubnetId)), Data: *call.Output.Subnet}
		case "imds-route-running-1":
			local.record.Data = call.Output.Reservations[0].Instances[0]
			local.record.ReservationID = call.Output.Reservations[0].ReservationId
		}
	}
	for _, mapping := range local.record.Data.BlockDeviceMappings {
		local.record.MetadataBlockDevices = append(local.record.MetadataBlockDevices, str(mapping.DeviceName))
	}
	for _, row := range fixture.HTTP {
		if row.Path == "/latest/meta-data/public-keys/0/openssh-key" && row.Body != nil {
			// Import's public bytes are retained only as a digest in the SDK
			// fixture. The nonsecret guest observation supplies that public key;
			// strip native formatting so the test still checks name/comment rules.
			parts := strings.Fields(*row.Body)
			local.record.PublicKey = parts[0] + " " + parts[1] + " ignored-import-comment"
		}
	}
	local.record.Data.IamInstanceProfile = nil // The IAM owner has independent fixtures.
	if local.record.Data.Placement != nil && local.record.Data.Placement.AvailabilityZoneId == nil {
		local.record.Data.Placement.AvailabilityZoneId = new(api.AvailabilityZoneId(str(subnet.Data.AvailabilityZoneId)))
	}
	if err := local.service.repository.Update(local.ctx, func(tx Transaction) error {
		if err := tx.PutVPC(vpc); err != nil {
			return err
		}
		if err := tx.PutSubnet(subnet); err != nil {
			return err
		}
		for _, attached := range local.record.Data.NetworkInterfaces {
			encoded, err := json.Marshal(attached)
			if err != nil {
				return err
			}
			var eni api.NetworkInterface
			if err := json.Unmarshal(encoded, &eni); err != nil {
				return err
			}
			eni.Attachment.InstanceId = local.record.Data.InstanceId
			if err := tx.PutNetworkInterface(NetworkInterfaceRecord{Key: key(local.ctx, str(eni.NetworkInterfaceId)), Data: eni}); err != nil {
				return err
			}
		}
		return tx.PutInstance(local.record)
	}); err != nil {
		t.Fatal(err)
	}
	return local, fixture
}

func TestNativeInstanceMetadataDepth(t *testing.T) {
	local, fixture := nativeMetadataDepthInstance(t, "instances_metadata_depth")
	token, err := newMetadataToken(local.record.MetadataTokenKey, local.clock.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	normalize := strings.NewReplacer(fixture.Account, local.record.Key.Scope.AccountID, fixture.Owned.Instances[0], local.record.Key.ID)
	seen := map[string]bool{}
	for _, row := range fixture.HTTP {
		if row.Code == http.StatusOK && (strings.HasSuffix(strings.TrimSuffix(row.Path, "/"), "/meta-data") || row.Body == nil || row.Method == http.MethodPut) {
			continue // Partial root menus, redacted user data and native token TTL are separate contracts.
		}
		identity := row.Method + " " + row.Path
		if row.TokenSupplied {
			identity += " authenticated"
		}
		if seen[identity] {
			continue
		}
		seen[identity] = true
		t.Run(identity, func(t *testing.T) {
			request := httptest.NewRequest(row.Method, "http://169.254.169.254"+row.Path, nil)
			if row.TokenSupplied {
				request.Header.Set("X-aws-ec2-metadata-token", token)
			}
			if row.Method == http.MethodPut {
				request.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "300")
			}
			for name, value := range row.RequestHeaders {
				request.Header.Set(name, value)
			}
			response := httptest.NewRecorder()
			local.service.InstanceMetadataHandler(local.record.Key).ServeHTTP(response, request)
			if response.Code != row.Code {
				t.Fatalf("HTTP %d, native %d: %s", response.Code, row.Code, response.Body.String())
			}
			if row.Code == http.StatusNotFound {
				if got := response.Header().Get("Content-Type"); got != row.Headers["Content-Type"] {
					t.Fatalf("404 content type = %q, native %q", got, row.Headers["Content-Type"])
				}
				return
			}
			if row.Body != nil {
				want := normalize.Replace(*row.Body)
				if row.Path == "/latest/dynamic/instance-identity/document" {
					var gotJSON, wantJSON any
					if err := json.Unmarshal(response.Body.Bytes(), &gotJSON); err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal([]byte(want), &wantJSON); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(gotJSON, wantJSON) {
						t.Fatalf("identity document = %v, native %v", gotJSON, wantJSON)
					}
				} else if response.Body.String() != want {
					t.Fatalf("body = %q, native %q", response.Body.String(), want)
				}
			}
			for _, header := range []string{"Content-Type", "Allow"} {
				if got := response.Header().Get(header); got != row.Headers[header] {
					t.Fatalf("%s = %q, native %q", header, got, row.Headers[header])
				}
			}
			if row.Method == http.MethodHead && response.Header().Get("Content-Length") != row.Headers["Content-Length"] {
				t.Fatalf("HEAD length = %q, native %q", response.Header().Get("Content-Length"), row.Headers["Content-Length"])
			}
		})
	}
}

func TestNativeInstanceMetadataSecondaryDevice(t *testing.T) {
	local, fixture := nativeMetadataDepthInstance(t, "instances_metadata_secondary")
	// A subsequent hot attachment must not change the launch/start snapshot.
	local.record.Data.BlockDeviceMappings = append(local.record.Data.BlockDeviceMappings, api.InstanceBlockDeviceMapping{DeviceName: new(api.String("/dev/sdg"))})
	if err := local.service.repository.Update(local.ctx, func(tx Transaction) error { return tx.PutInstance(local.record) }); err != nil {
		t.Fatal(err)
	}
	token, err := newMetadataToken(local.record.MetadataTokenKey, local.clock.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.HTTP {
		if row.Method != http.MethodGet || !strings.HasPrefix(row.Path, "/latest/meta-data/block-device-mapping") || strings.HasSuffix(row.Path, "/") {
			continue
		}
		response := metadataHTTPRequest(t, local.service, local.record.Key, row.Method, row.Path, token)
		if response.Code != row.Code || (row.Code == http.StatusOK && response.Body.String() != *row.Body) {
			t.Fatalf("%s = %d %q; native %d %q", row.Path, response.Code, response.Body.String(), row.Code, *row.Body)
		}
	}
	response := metadataHTTPRequest(t, local.service, local.record.Key, http.MethodGet, "/latest/meta-data/block-device-mapping/ebs2", token)
	if response.Code != http.StatusNotFound {
		t.Fatalf("hot attachment prematurely published: %d %q", response.Code, response.Body.String())
	}
}

func TestInstanceMetadataOwnerMutationsAndIsolation(t *testing.T) {
	local, _ := nativeMetadataDepthInstance(t, "instances_metadata_depth")
	token, err := newMetadataToken(local.record.MetadataTokenKey, local.clock.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	read := func(path string, status int, want string) {
		t.Helper()
		response := metadataHTTPRequest(t, local.service, local.record.Key, http.MethodGet, "/latest/"+path, token)
		if response.Code != status || (status == http.StatusOK && response.Body.String() != want) {
			t.Fatalf("%s = %d %q, want %d %q", path, response.Code, response.Body.String(), status, want)
		}
	}
	mac := str(local.record.Data.NetworkInterfaces[0].MacAddress)
	eniKey := key(local.ctx, str(local.record.Data.NetworkInterfaces[0].NetworkInterfaceId))
	if err := local.service.repository.Update(local.ctx, func(tx Transaction) error {
		eni, err := tx.NetworkInterface(eniKey)
		if err != nil {
			return err
		}
		foreign := cloneNetworkInterface(eni)
		foreign.Key.Scope.AccountID = "999999999999"
		foreign.Data.Groups = api.GroupIdentifierList{{GroupId: new(api.String("sg-foreign")), GroupName: new(api.String("foreign"))}}
		if err := tx.PutNetworkInterface(foreign); err != nil {
			return err
		}
		eni.Data.Groups = api.GroupIdentifierList{{GroupId: new(api.String("sg-current")), GroupName: new(api.String("current"))}}
		eni.Data.PrivateIpAddresses = append(eni.Data.PrivateIpAddresses, api.NetworkInterfacePrivateIpAddress{PrivateIpAddress: new(api.String("10.237.0.17")), Primary: new(api.Boolean(false))})
		if err := tx.PutNetworkInterface(eni); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	read("meta-data/security-groups", 200, "current")
	read("meta-data/network/interfaces/macs/"+mac+"/security-group-ids", 200, "sg-current")
	read("meta-data/network/interfaces/macs/"+mac+"/local-ipv4s", 200, str(local.record.Data.PrivateIpAddress)+"\n10.237.0.17")
	if err := local.service.repository.Update(local.ctx, func(tx Transaction) error {
		local.record.Data.State.Name = new(api.InstanceStateName("stopping"))
		return tx.PutInstance(local.record)
	}); err != nil {
		t.Fatal(err)
	}
	read("meta-data/instance-action", 200, "none")
	read("meta-data/instance-life-cycle", 200, "on-demand")
	if err := local.service.repository.Update(local.ctx, func(tx Transaction) error {
		local.record.Data.State.Name = new(api.InstanceStateName("stopped"))
		return tx.PutInstance(local.record)
	}); err != nil {
		t.Fatal(err)
	}
	response := metadataHTTPRequest(t, local.service, local.record.Key, http.MethodGet, "/latest/meta-data/instance-id", token)
	if response.Code != http.StatusNotFound {
		t.Fatalf("stopped guest metadata = HTTP %d", response.Code)
	}
}

func TestNativeInstanceMetadataTokenTTLRejections(t *testing.T) {
	local := newMetadataTestInstance(t)
	fixture := readMetadataHTTPFixture(t, "instances_metadata_empty_tags_handoff")
	for _, row := range fixture.HTTP {
		ttl, supplied := row.RequestHeaders["X-aws-ec2-metadata-token-ttl-seconds"]
		if !supplied || row.Code != http.StatusBadRequest {
			continue
		}
		t.Run(ttl, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPut, "http://169.254.169.254"+row.Path, nil)
			request.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", ttl)
			response := httptest.NewRecorder()
			local.service.InstanceMetadataHandler(local.record.Key).ServeHTTP(response, request)
			// Rejected headers must fail before attempting native socket TTL
			// effects. No pretend SetHopLimit writer is supplied.
			if response.Code != row.Code {
				t.Fatalf("HTTP %d, native %d", response.Code, row.Code)
			}
		})
	}
}

func TestNativeInstanceMetadataTagSetVersionGate(t *testing.T) {
	local, _ := nativeMetadataDepthInstance(t, "instances_metadata_depth")
	token, err := newMetadataToken(local.record.MetadataTokenKey, local.clock.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	matrix := readMetadataHTTPFixture(t, "instances_metadata_matrix_handoff")
	seen := map[string]bool{}
	for _, row := range matrix.HTTP {
		if row.Code != http.StatusOK || row.Body == nil || !strings.HasSuffix(row.Path, "/meta-data/") {
			continue
		}
		version, _, _ := strings.Cut(strings.TrimPrefix(row.Path, "/"), "/")
		if seen[version] {
			continue
		}
		seen[version] = true
		response := metadataHTTPRequest(t, local.service, local.record.Key, http.MethodGet, "/"+version+"/meta-data/tag-sets/instance", token)
		want := http.StatusNotFound
		if strings.Contains(*row.Body, "tag-sets/") {
			want = http.StatusOK
		}
		if response.Code != want {
			t.Fatalf("tag sets in native version %s = HTTP %d, want %d", version, response.Code, want)
		}
	}
}
