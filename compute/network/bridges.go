package network

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"stackd/compute/docker"
)

// BridgeLabel and the native name retain existing VPC bridge identities. A bridge
// is shared by container endpoints and guest TAPs, not owned by either runtime.
const BridgeLabel = "stackd.ecs.network"

type Bridge struct {
	Name   string
	Device string
}

// Bridges serializes attachment creation against removal across compute drivers.
// Native endpoints and bridge ports own lifetime; there is no second refcount.
type Bridges struct {
	client *docker.Client
	mu     sync.Mutex
}

func NewBridges(client *docker.Client) (*Bridges, error) {
	if client == nil {
		return nil, errors.New("native bridge management requires a Docker client")
	}
	return &Bridges{client: client}, nil
}

// WithBridge holds shared ownership until attach has created its native port or
// endpoint. Attach may install policy, but must not reenter WithBridge or Release.
func (b *Bridges) WithBridge(ctx context.Context, spec Specification, attach func(Bridge) error) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if spec.NetworkID == "" || !spec.Pool.IsValid() || !spec.Pool.Addr().Is4() || !spec.Pool.Contains(spec.Gateway) || !spec.Pool.Contains(spec.Address) || spec.Address == spec.Gateway {
		return errors.New("compute networking requires a VPC identity, IPv4 pool and distinct in-pool gateway/address")
	}
	bridge, err := b.prepareBridge(ctx, spec)
	if err != nil {
		return err
	}
	// The host lock is already released: attach may install packet policy.
	return attach(bridge)
}

func (b *Bridges) prepareBridge(ctx context.Context, spec Specification) (Bridge, error) {
	name := bridgeName(spec.NetworkID)
	input := struct {
		Name           string
		Driver         string
		CheckDuplicate bool
		IPAM           struct {
			Driver string
			Config []struct {
				Subnet, Gateway string
				AuxAddress      map[string]string `json:"AuxiliaryAddresses"`
			}
		}
		Labels map[string]string
	}{Name: name, Driver: "bridge", CheckDuplicate: true, Labels: map[string]string{BridgeLabel: spec.NetworkID}}
	input.IPAM.Driver = "default"
	input.IPAM.Config = append(input.IPAM.Config, struct {
		Subnet, Gateway string
		AuxAddress      map[string]string `json:"AuxiliaryAddresses"`
	}{spec.Pool.String(), spec.Gateway.String(), map[string]string{"amazon-dns": spec.Pool.Addr().Next().Next().String()}})
	request, err := json.Marshal(input)
	if err != nil {
		return Bridge{}, err
	}
	output, err := b.runNativeOperation(ctx, spec.NetworkID, []string{
		"BRIDGE_REQUEST=" + string(request), "BRIDGE_NETWORK_ID=" + spec.NetworkID,
		"BRIDGE_NAME=" + name, "BRIDGE_POOL=" + spec.Pool.String(),
	}, true)
	if err != nil {
		return Bridge{}, fmt.Errorf("admit/create compute network: %w", err)
	}
	var info bridgeInfo
	if err := json.Unmarshal(output, &info); err != nil {
		return Bridge{}, fmt.Errorf("decode admitted compute bridge: %w", err)
	}
	if info.Driver != "bridge" || info.Labels[BridgeLabel] != spec.NetworkID || len(info.ID) < 12 {
		return Bridge{}, errors.New("native bridge admission returned an invalid network identity")
	}
	return Bridge{Name: name, Device: info.device()}, nil
}

// The helper owns flock through admission and the actual Engine request, not
// merely through the controller's observation of that request. Its local socket
// must identify the same Engine selected by the controller before any mutation.
const nativeBridgeScript = `
python3 - <<'PY'
import http.client
import ipaddress
import json
import os
import socket
import subprocess
import urllib.parse

class Engine(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect("/var/run/docker.sock")

def request(method, path, body=None):
    connection = Engine("localhost")
    try:
        connection.request(method, "/v1.41" + path, body, {"Content-Type": "application/json"})
        response = connection.getresponse()
        data = json.load(response)
        return response.status, data
    finally:
        connection.close()

status, engine = request("GET", "/info")
if status != 200 or engine.get("ID") != os.environ["NATIVE_ENGINE_ID"]:
    raise SystemExit("bridge admission requires the selected daemon's /var/run/docker.sock")
pool = ipaddress.IPv4Network(os.environ["BRIDGE_POOL"], strict=False)
tables = json.loads(subprocess.check_output(["nft", "-j", "list", "tables"]))
for row in tables["nftables"]:
    table = row.get("table", {})
    name = table.get("name", "")
    if table.get("family") != "ip" or not name.startswith("stackd_public_"):
        continue
    state = json.loads(subprocess.check_output(["nft", "-j", "list", "table", "ip", name]))
    identities = [row["chain"].get("comment", "") for row in state["nftables"]
                  if row.get("chain", {}).get("name") == "identity"]
    if len(identities) != 1 or len(identities[0].split()) != 4:
        raise SystemExit("public table lacks a unique valid native identity: " + name)
    address = ipaddress.IPv4Address(identities[0].split()[0])
    if name != "stackd_public_" + address.packed.hex():
        raise SystemExit("invalid native public address identity: " + name)
    if address in pool:
        raise SystemExit("private VPC pool %s overlaps native public IPv4 %s (%s)" % (pool, address, name))

name = os.environ["BRIDGE_NAME"]
path = "/networks/" + urllib.parse.quote(name, safe="")
status, info = request("GET", path)
if status == 404:
    status, created = request("POST", "/networks/create", os.environ["BRIDGE_REQUEST"])
    if status != 201:
        raise SystemExit("create compute network (native default IPAM requires non-overlapping pools): " + str(created))
    status, info = request("GET", path)
if status != 200:
    raise SystemExit("inspect compute network: " + str(info))
if (info.get("Driver") != "bridge"
        or (info.get("Labels") or {}).get("stackd.ecs.network") != os.environ["BRIDGE_NETWORK_ID"]
        or len(info.get("Id", "")) < 12):
    raise SystemExit("native network is not an owned VPC bridge: " + name)
ipam = info.get("IPAM") or {}
configurations = ipam.get("Config") or []
expected = json.loads(os.environ["BRIDGE_REQUEST"])["IPAM"]["Config"][0]
if (ipam.get("Driver") != "default" or len(configurations) != 1
        or ipaddress.IPv4Network(configurations[0].get("Subnet", ""), strict=False) != pool
        or configurations[0].get("Gateway") != expected["Gateway"]):
    raise SystemExit("native VPC bridge IPAM differs from requested pool/gateway: "
                     + name + " requested " + str(pool) + " gateway " + expected["Gateway"]
                     + " observed " + json.dumps(ipam))
print(json.dumps({key: info.get(key) for key in ("Id", "Driver", "Labels", "Options")}))
PY
`

// Release removes an unused native bridge. Docker does not count guest TAPs as
// endpoints, so Linux bridge membership must also be empty before deletion.
func (b *Bridges) Release(ctx context.Context, networkID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	info, err := b.inspect(ctx, bridgeName(networkID), networkID)
	if notFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	output, err := docker.RunHelper(ctx, b.client, "network-ports", docker.ContainerConfig{
		Image:      docker.ToolkitImage,
		Entrypoint: []string{"ip", "-j", "link", "show", "master", info.device()},
		Labels:     map[string]string{"stackd.network": networkID},
		HostConfig: docker.ContainerHostConfig{
			NetworkMode: "host", ReadonlyRootfs: true,
			CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"},
			Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 32,
			LogConfig: docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "1m", "max-file": "1"}},
		},
	})
	if err != nil {
		return fmt.Errorf("inspect compute bridge ports: %w", err)
	}
	var ports []json.RawMessage
	if err := json.Unmarshal(output, &ports); err != nil {
		return fmt.Errorf("decode compute bridge ports: %w", err)
	}
	if len(ports) != 0 {
		return nil
	}
	err = b.client.JSON(ctx, http.MethodDelete, "/networks/"+url.PathEscape(info.ID), nil, nil)
	if err == nil || notFound(err) {
		return nil
	}
	var remote *docker.Error
	if errors.As(err, &remote) && remote.StatusCode == http.StatusForbidden && strings.Contains(remote.Message, "active endpoints") {
		return nil
	}
	return fmt.Errorf("remove unused compute network: %w", err)
}

type bridgeInfo struct {
	ID              string `json:"Id"`
	Driver          string
	Labels, Options map[string]string
}

func (b *Bridges) inspect(ctx context.Context, name, networkID string) (bridgeInfo, error) {
	var info bridgeInfo
	if err := b.client.JSON(ctx, http.MethodGet, "/networks/"+url.PathEscape(name), nil, &info); err != nil {
		return info, fmt.Errorf("inspect compute network: %w", err)
	}
	if info.Driver != "bridge" || info.Labels[BridgeLabel] != networkID || len(info.ID) < 12 {
		return info, fmt.Errorf("native network %s is not an owned VPC bridge for %s", name, networkID)
	}
	return info, nil
}

func (b bridgeInfo) device() string {
	if name := b.Options["com.docker.network.bridge.name"]; name != "" {
		return name
	}
	return "br-" + b.ID[:12]
}

func bridgeName(networkID string) string {
	return fmt.Sprintf("stackd-ecs-network-%x", sha256.Sum256([]byte(networkID)))
}

func notFound(err error) bool {
	var remote *docker.Error
	return errors.As(err, &remote) && remote.StatusCode == http.StatusNotFound
}
