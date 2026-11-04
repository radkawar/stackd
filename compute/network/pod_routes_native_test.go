package network

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"stackd/compute/docker"
)

// A real socket on a worker's connected CNI prefix, not an EC2-local alias,
// exercises daemon-host policy lookup, Docker isolation, gateway SNAT and the
// conntracked return path. The worker is deliberately on a separate bridge.
func TestDaemonPodRoutePacketPathAndWithdrawal(t *testing.T) {
	client := daemonNetworkTestEngine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	bridges, err := NewDaemonBridges(client)
	if err != nil {
		t.Fatal(err)
	}
	suffix := rand.Text()
	cluster, workerName := "native-pods-"+suffix, "pod-worker-"+strings.ToLower(suffix)
	owner := fmt.Sprintf("%x", sha256.Sum256([]byte(suffix)))
	workerNetwork := "stackd-pod-worker-" + suffix
	var workerNetworkID, workerID, albID, heldID string
	spec := Specification{NetworkID: "native-pod-vpc-" + suffix, Pool: netip.MustParsePrefix("10.254.245.0/24"), Gateway: netip.MustParseAddr("10.254.245.1"), Address: netip.MustParseAddr("10.254.245.10"), MAC: "02:cc:fe:f5:00:0a"}
	table := fmt.Sprintf("stackd_elbv2_%x", sha256.Sum256([]byte(suffix)))
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), time.Minute)
		defer done()
		if err := bridges.RemovePolicy(cleanup, table, owner); err != nil {
			t.Error(err)
		}
		for _, id := range []string{heldID, albID, workerID} {
			if id != "" {
				if err := client.RemoveContainer(cleanup, id); err != nil {
					t.Error(err)
				}
			}
		}
		if workerNetworkID != "" {
			if err := client.JSON(cleanup, "DELETE", "/networks/"+workerNetworkID, nil, nil); err != nil {
				t.Error(err)
			}
		}
		if err := bridges.Release(cleanup, spec.NetworkID); err != nil {
			t.Error(err)
		}
	})
	labels := map[string]string{"stackd.eks.id": cluster, "stackd.eks.owner": owner}
	var created struct {
		ID string `json:"Id"`
	}
	if err := client.JSON(ctx, "POST", "/networks/create", map[string]any{"Name": workerNetwork, "Driver": "bridge", "Labels": labels, "IPAM": map[string]any{"Config": []map[string]string{{"Subnet": "10.254.244.0/24", "Gateway": "10.254.244.1"}}}}, &created); err != nil {
		t.Fatal(err)
	}
	workerNetworkID = created.ID
	server := "import socket,threading\n" +
		"def echo():\n s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('10.243.199.2',18081));s.listen();c,a=s.accept()\n while True:\n  data=c.recv(128)\n  if not data: break\n  c.sendall(data)\n c.close()\n" +
		"threading.Thread(target=echo,daemon=True).start()\n" +
		"s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('10.243.199.2',18080));s.listen()\nwhile True:\n c,a=s.accept();c.sendall(a[0].encode());c.close()\n"
	workerConfig := struct {
		docker.ContainerConfig
		Hostname string
	}{docker.ContainerConfig{
		Image: docker.ToolkitImage, Labels: labels,
		Entrypoint: []string{"/bin/sh", "-ec"}, Cmd: []string{"ip link add cni0 type bridge; ip address add 10.243.199.2/24 dev cni0; ip link set cni0 up; exec python3 -u -c '" + strings.ReplaceAll(server, "'", "'\"'\"'") + "'"},
		NetworkingConfig: &docker.ContainerNetworkingConfig{EndpointsConfig: map[string]docker.ContainerEndpointConfig{workerNetwork: {IPAMConfig: docker.ContainerEndpointIPAMConfig{IPv4Address: "10.254.244.2"}}}},
		HostConfig:       docker.ContainerHostConfig{NetworkMode: workerNetwork, ReadonlyRootfs: true, CapDrop: []string{"ALL"}, CapAdd: []string{"NET_ADMIN"}, Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 32},
	}, workerName}
	if err := client.JSON(ctx, "POST", "/containers/create", workerConfig, &created); err != nil {
		t.Fatal(err)
	}
	workerID = created.ID
	if err := client.JSON(ctx, "POST", "/containers/"+workerID+"/start", nil, nil); err != nil {
		t.Fatal(err)
	}
	// Readiness probes the actual listener inside the worker namespace.
	if _, err := docker.RunHelper(ctx, client, "pod-worker-ready", docker.ContainerConfig{Image: docker.ToolkitImage, Entrypoint: []string{"python3", "-c", "import socket,time\nfor n in range(100):\n try:\n  s=socket.create_connection(('10.243.199.2',18080),.1);s.close();break\n except OSError: time.sleep(.05)\nelse: raise RuntimeError('worker listener unavailable')"}, HostConfig: docker.ContainerHostConfig{NetworkMode: "container:" + workerID, ReadonlyRootfs: true, CapDrop: []string{"ALL"}, Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 32}}); err != nil {
		t.Fatal(err)
	}
	var bridge Bridge
	if err := bridges.WithBridge(ctx, spec, func(b Bridge) error { bridge = b; return nil }); err != nil {
		t.Fatal(err)
	}
	albConfig := docker.ContainerConfig{Image: docker.ToolkitImage, Entrypoint: []string{"sleep", "240"}, NetworkingConfig: &docker.ContainerNetworkingConfig{EndpointsConfig: map[string]docker.ContainerEndpointConfig{bridge.Name: {MacAddress: spec.MAC, IPAMConfig: docker.ContainerEndpointIPAMConfig{IPv4Address: spec.Address.String()}}}}, HostConfig: docker.ContainerHostConfig{NetworkMode: bridge.Name, ReadonlyRootfs: true, CapDrop: []string{"ALL"}, Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 32}}
	if err := client.JSON(ctx, "POST", "/containers/create", albConfig, &created); err != nil {
		t.Fatal(err)
	}
	albID = created.ID
	if err := client.JSON(ctx, "POST", "/containers/"+albID+"/start", nil, nil); err != nil {
		t.Fatal(err)
	}
	helper := func(mode string, command ...string) []byte {
		t.Helper()
		output, err := docker.RunHelper(ctx, client, "pod-native-probe", docker.ContainerConfig{Image: docker.ToolkitImage, Entrypoint: command, HostConfig: docker.ContainerHostConfig{NetworkMode: mode, ReadonlyRootfs: true, CapDrop: []string{"ALL"}, CapAdd: []string{"NET_ADMIN"}, Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 32}})
		if err != nil {
			t.Fatal(err)
		}
		return output
	}
	index, err := strconv.Atoi(strings.TrimSpace(string(helper("container:"+albID, "cat", "/sys/class/net/eth0/iflink"))))
	if err != nil {
		t.Fatal(err)
	}
	var links []struct {
		IfIndex int    `json:"ifindex"`
		IfName  string `json:"ifname"`
	}
	if err := json.Unmarshal(helper("host", "ip", "-j", "link", "show", "master", bridge.Device), &links); err != nil {
		t.Fatal(err)
	}
	peer := ""
	for _, link := range links {
		if link.IfIndex == index {
			peer = link.IfName
		}
	}
	if peer == "" {
		t.Fatal("ALB native peer not found")
	}
	all := IPRule{CIDR: netip.MustParsePrefix("0.0.0.0/0"), Protocol: -1}
	policy := Policy{Subnet: spec.Pool, SecurityEgress: []IPRule{all}, ACLIngress: []ACLRule{{Rule: all, Number: 100, Allow: true}}, ACLEgress: []ACLRule{{Rule: all, Number: 100, Allow: true}}, PodRoutes: []PodRoute{{Prefix: netip.MustParsePrefix("10.243.199.0/24"), ClusterID: cluster, OwnerToken: owner, NodeName: workerName, NodeUID: "node-uid", ResourceVersion: "1", ContainerID: workerID, NetworkID: workerNetworkID, WorkerIP: netip.MustParseAddr("10.254.244.2")}}}
	install := func(p Policy) error {
		return bridges.ApplyPolicy(ctx, table, spec, p, peer, Options{PublicOwner: owner}, bridge)
	}
	probe := func(want string) {
		t.Helper()
		code := "import socket\ntry:\n s=socket.create_connection(('10.243.199.2',18080),1);print(s.recv(128).decode());s.close()\nexcept OSError: print('blocked')"
		if got := strings.TrimSpace(string(helper("container:"+albID, "python3", "-c", code))); got != want {
			t.Fatalf("actual pod-prefix socket response = %q, want %q", got, want)
		}
	}
	if err := install(policy); err != nil {
		t.Fatal(err)
	}
	probe("10.254.244.1") // proves scoped worker-gateway SNAT and real reply.
	pathWitness := func() (string, int) {
		t.Helper()
		code := "import json,subprocess\nrows=json.loads(subprocess.check_output(['nft','-j','list','table','ip'," + strconv.Quote("stackd_pods_"+strings.TrimPrefix(table, "stackd_elbv2_")) + "]))['nftables']\nchains={r['chain']['name']:r['chain'] for r in rows if 'chain' in r}\ndata=json.loads(bytes.fromhex(''.join(chains[k]['comment'] for k in sorted(chains) if k.startswith('identity_'))))\nprint(json.dumps({'Token':data['Token'],'Table':data['Table']}))"
		var witness struct {
			Token string
			Table int
		}
		if err := json.Unmarshal(helper("host", "python3", "-c", code), &witness); err != nil {
			t.Fatal(err)
		}
		return witness.Token, witness.Table
	}
	initialToken, initialTable := pathWitness()
	// Keep one real TCP socket open across both an identical policy refresh and
	// a status-only Kubernetes resourceVersion change. Reconnecting would hide
	// accidental conntrack retirement or a changed gateway-SNAT incarnation.
	heldCode := "import signal,socket,time\nrunning=True\ndef stop(*args):\n global running\n running=False\nsignal.signal(signal.SIGUSR1,stop)\ns=socket.create_connection(('10.243.199.2',18081),2);s.settimeout(2)\npayload=b'held-connection'\nwhile running:\n s.sendall(payload);assert s.recv(len(payload),socket.MSG_WAITALL)==payload;time.sleep(.05)\ns.close()\n"
	heldConfig := docker.ContainerConfig{Image: docker.ToolkitImage, Entrypoint: []string{"python3", "-c", heldCode}, HostConfig: docker.ContainerHostConfig{NetworkMode: "container:" + albID, ReadonlyRootfs: true, CapDrop: []string{"ALL"}, Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 32}}
	if err := client.JSON(ctx, "POST", "/containers/create", heldConfig, &created); err != nil {
		t.Fatal(err)
	}
	heldID = created.ID
	if err := client.JSON(ctx, "POST", "/containers/"+heldID+"/start", nil, nil); err != nil {
		t.Fatal(err)
	}
	helper("container:"+workerID, "python3", "-c", "import time\nfor n in range(100):\n rows=[r.split() for r in open('/proc/net/tcp').readlines()[1:]]\n if any(r[1].endswith(':46A1') and r[3]=='01' for r in rows): break\n time.sleep(.05)\nelse: raise RuntimeError('held connection did not establish')")
	if err := install(policy); err != nil {
		t.Fatal(err)
	}
	metadataOnly := policy
	metadataOnly.PodRoutes = append([]PodRoute(nil), policy.PodRoutes...)
	metadataOnly.PodRoutes[0].ResourceVersion = "2"
	if err := install(metadataOnly); err != nil {
		t.Fatal(err)
	}
	if err := client.JSON(ctx, "POST", "/containers/"+heldID+"/kill?signal=SIGUSR1", nil, nil); err != nil {
		t.Fatal(err)
	}
	var heldExit struct{ StatusCode int }
	if err := client.JSON(ctx, "POST", "/containers/"+heldID+"/wait", nil, &heldExit); err != nil || heldExit.StatusCode != 0 {
		t.Fatalf("held connection did not survive unchanged and metadata-only reapply: exit=%d error=%v", heldExit.StatusCode, err)
	}
	if token, number := pathWitness(); token != initialToken || number != initialTable {
		t.Fatal("unchanged or metadata-only refresh replaced the native packet-path incarnation")
	}
	// Foreign additions to the witnessed route table must fail closed, not be
	// silently adopted or flushed by the stable-path optimization.
	number := strconv.Itoa(initialTable)
	helper("host", "ip", "-4", "route", "add", "blackhole", "198.18.0.0/24", "table", number, "proto", "99")
	foreignAdded := true
	t.Cleanup(func() {
		if !foreignAdded {
			return
		}
		cleanup, done := context.WithTimeout(context.Background(), time.Minute)
		defer done()
		_, err := docker.RunHelper(cleanup, client, "pod-foreign-fixture-cleanup", docker.ContainerConfig{Image: docker.ToolkitImage, Entrypoint: []string{"ip", "-4", "route", "del", "blackhole", "198.18.0.0/24", "table", number, "proto", "99"}, HostConfig: docker.ContainerHostConfig{NetworkMode: "host", ReadonlyRootfs: true, CapDrop: []string{"ALL"}, CapAdd: []string{"NET_ADMIN"}, Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 32}})
		if err != nil {
			t.Error(err)
		}
	})
	var foreignErr *PodRouteInstallError
	if err := install(policy); !errors.As(err, &foreignErr) {
		t.Fatalf("foreign route modification accepted: %v", err)
	}
	probe("blocked")
	var foreignRows []struct {
		Dst      string
		Protocol any
	}
	if err := json.Unmarshal(helper("host", "ip", "-N", "-j", "-4", "route", "show", "table", number), &foreignRows); err != nil {
		t.Fatal(err)
	}
	retainedForeign := false
	for _, row := range foreignRows {
		if row.Dst == "198.18.0.0/24" && fmt.Sprint(row.Protocol) == "99" {
			retainedForeign = true
		}
	}
	if !retainedForeign {
		t.Fatal("reconciliation deleted a foreign route")
	}
	helper("host", "ip", "-4", "route", "del", "blackhole", "198.18.0.0/24", "table", number, "proto", "99")
	foreignAdded = false
	if err := install(policy); err != nil {
		t.Fatal(err)
	}
	denied := policy
	denied.SecurityEgress = nil
	if err := install(denied); err != nil {
		t.Fatal(err)
	}
	probe("blocked")
	denied = policy
	denied.ACLIngress = nil
	if err := install(denied); err != nil {
		t.Fatal(err)
	}
	probe("blocked")
	// A stale exact worker tuple cannot leave the old route carrying traffic.
	stale := policy
	stale.PodRoutes = append([]PodRoute(nil), policy.PodRoutes...)
	stale.PodRoutes[0].WorkerIP = netip.MustParseAddr("10.254.244.3")
	var routeErr *PodRouteInstallError
	if err := install(stale); !errors.As(err, &routeErr) {
		t.Fatalf("stale worker tuple accepted: %v", err)
	}
	probe("blocked")
	// A newly opened manager reconciles from native witnesses, not memory.
	restarted, err := NewDaemonBridges(client)
	if err != nil {
		t.Fatal(err)
	}
	policy.PodRoutes = nil
	if err := restarted.ApplyPolicy(ctx, table, spec, policy, peer, Options{PublicOwner: owner}, bridge); err != nil {
		t.Fatal(err)
	}
	probe("blocked")
	if err := restarted.RemovePolicy(ctx, table, owner); err != nil {
		t.Fatal(err)
	}
	var tables struct {
		NFTables []struct {
			Table *struct {
				Name string `json:"name"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(helper("host", "nft", "-j", "list", "tables"), &tables); err != nil {
		t.Fatal(err)
	}
	for _, entry := range tables.NFTables {
		if entry.Table != nil && entry.Table.Name == "stackd_pods_"+strings.TrimPrefix(table, "stackd_elbv2_") {
			t.Fatal("ALB deletion retained its pod routing witness")
		}
	}
}
