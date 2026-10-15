package network

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"stackd/compute/docker"
)

// This exercises a real group bind and real IPv4 packet at an isolated native
// bridge verdict. It is not an EC2 API assertion or a manufactured observation.
func TestFlowCollectorDockerNativeReplay(t *testing.T) {
	client := daemonNetworkTestEngine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	unique := fmt.Sprintf("%x", sha256.Sum256([]byte(rand.Text())))[:12]
	namespace := "native-flow-test-" + unique
	collector, err := NewDockerFlowCollector(client, namespace)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		// This test owns a fresh random namespace, never an adopted user receiver.
		if err := client.RemoveContainer(cleanup, collector.name); err != nil {
			t.Error(err)
		}
		if err := client.JSON(cleanup, "DELETE", "/volumes/"+collector.volume, nil, nil); err != nil {
			t.Error(err)
		}
	})
	if err := collector.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	health, err := collector.Health(ctx)
	if err != nil || !health.Ready || health.Group == 0 || health.EngineID == "" || health.BootID == "" {
		t.Fatalf("actual NFLOG bind not ready: %+v %v", health, err)
	}
	identity := FlowIdentity{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", VPCID: "vpc-" + unique, SubnetID: "subnet-" + unique, InterfaceID: "eni-" + unique}
	spec := Specification{NetworkID: identity.VPCARN(), FlowIdentity: identity, Pool: netip.MustParsePrefix("10.254.241.0/24"), Gateway: netip.MustParseAddr("10.254.241.1"), Address: netip.MustParseAddr("10.254.241.10"), MAC: "02:00:00:fa:f1:10"}
	bridges, err := NewDaemonBridges(client)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		if err := bridges.Release(cleanup, spec.NetworkID); err != nil {
			t.Error(err)
		}
	})
	var bridge Bridge
	if err := bridges.WithBridge(ctx, spec, func(value Bridge) error { bridge = value; return nil }); err != nil {
		t.Fatal(err)
	}
	peer, sender := "flp"+unique[:10], "fls"+unique[:10]
	table := "stackd_ec2_" + unique
	helper := func(script string, capabilities ...string) ([]byte, error) {
		return docker.RunHelper(ctx, client, "flow-native-fixture", docker.ContainerConfig{
			Image: docker.ToolkitImage, Entrypoint: []string{"/bin/sh", "-ec", script},
			HostConfig: docker.ContainerHostConfig{NetworkMode: "host", ReadonlyRootfs: true, CapDrop: []string{"ALL"}, CapAdd: capabilities, SecurityOpt: []string{"no-new-privileges:true"}, Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 16},
		})
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		_, err := docker.RunHelper(cleanup, client, "flow-native-fixture-cleanup", docker.ContainerConfig{
			Image: docker.ToolkitImage, Entrypoint: []string{"/bin/sh", "-ec", "nft destroy table bridge " + table + "; ip link del " + peer},
			HostConfig: docker.ContainerHostConfig{NetworkMode: "host", ReadonlyRootfs: true, CapDrop: []string{"ALL"}, CapAdd: []string{"NET_ADMIN"}, SecurityOpt: []string{"no-new-privileges:true"}, Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 16},
		})
		if err != nil {
			t.Error(err)
		}
	})
	output, err := helper("ip link add "+peer+" type veth peer name "+sender+"; ip link set "+peer+" master "+bridge.Device+"; ip link set "+peer+" up; ip link set "+sender+" up; ip -j link show dev "+bridge.Device, "NET_ADMIN")
	if err != nil {
		t.Fatal(err)
	}
	var link []struct {
		Address string `json:"address"`
	}
	if err := json.Unmarshal(output, &link); err != nil || len(link) != 1 {
		t.Fatalf("inspect actual fixture bridge: %s %v", output, err)
	}
	binding := FlowBinding{Identity: identity, NetworkID: spec.NetworkID, PolicyTable: table, PublicOwner: namespace, Bridge: bridge.Device, PeerName: peer, Address: spec.Address, MAC: spec.MAC, Generation: "epoch-" + unique}
	registration, err := collector.Register(ctx, binding)
	if err != nil {
		t.Fatal(err)
	}
	rules := fmt.Sprintf(`table bridge %s {
 comment "stackd:%s"
 counter flow_from_accept { }
 chain flow_identity { comment "sf:%x:%s:%s"; }
 chain flow_controller { comment "%x"; }
 chain input { type filter hook input priority -300; policy accept;
 iifname "%s" ether type ip ip saddr %s ip daddr %s ip protocol udp udp sport 49123 udp dport 49124 log prefix "%s" group %d snaplen 128 queue-threshold 1 counter name flow_from_accept accept
 }
}
`, table, table, sha256.Sum256([]byte(namespace)), registration.Token, registration.Generation, sha256.Sum256([]byte(namespace)), peer, spec.Address, spec.Gateway, registration.Prefix("egress", "ACCEPT"), registration.Group)
	// The witness uses the first 16 digest bytes, not a namespace-sized comment.
	fullDigest := fmt.Sprintf("%x", sha256.Sum256([]byte(namespace)))
	rules = strings.Replace(rules, "sf:"+fullDigest+":", "sf:"+fullDigest[:32]+":", 1)
	if _, err := helper("printf '%s' '"+rules+"' | nft -f -", "NET_ADMIN"); err != nil {
		t.Fatal(err)
	}
	packetScript := fmt.Sprintf(`import socket,struct
src=socket.inet_aton(%q); dst=socket.inet_aton(%q)
payload=b'stackd-native-flow-body-not-retained'
udp=struct.pack('!HHHH',49123,49124,8+len(payload),0)+payload
ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),123,0,64,17,0,src,dst)
words=struct.unpack('!10H',ip); checksum=sum(words)
while checksum>>16: checksum=(checksum&65535)+(checksum>>16)
ip=ip[:10]+struct.pack('!H',(~checksum)&65535)+ip[12:]
frame=bytes.fromhex(%q.replace(':',''))+bytes.fromhex(%q.replace(':',''))+b'\x08\x00'+ip+udp
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)
s.bind((%q,0)); s.send(frame); s.close()
`, spec.Address.String(), spec.Gateway.String(), link[0].Address, spec.MAC, sender)
	if _, err := helper("python3 -c '"+strings.ReplaceAll(packetScript, "'", "'\"'\"'")+"'", "NET_RAW"); err != nil {
		t.Fatal(err)
	}
	var observation *FlowObservation
	var batch FlowBatch
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for observation == nil {
		batch, err = collector.Read(ctx, 0, FlowReadLimits{MaxRecords: 1024, MaxBytes: 1 << 20})
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range batch.Records {
			if record.Observation != nil && record.Observation.SourcePort == 49123 {
				observation = record.Observation
			}
		}
		if observation != nil {
			break
		}
		select {
		case <-deadline.C:
			t.Fatalf("no actual native packet observation: %+v", batch)
		case <-time.After(100 * time.Millisecond):
		}
	}
	if observation.Binding.Identity != identity || observation.Action != "ACCEPT" || observation.Direction != "egress" || observation.Packets != 1 || observation.IPBytes != uint32(28+len("stackd-native-flow-body-not-retained")) || observation.SourceAddress != spec.Address || observation.DestinationAddress != spec.Gateway || observation.ObservedAt.IsZero() {
		t.Fatalf("incorrect actual native packet evidence: %+v", observation)
	}
	if err := collector.Close(); err != nil {
		t.Fatal(err)
	}
	successor, err := NewDockerFlowCollector(client, namespace)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := successor.Read(ctx, 0, FlowReadLimits{MaxRecords: 1024, MaxBytes: 1 << 20})
	if err != nil || len(retained.Records) < len(batch.Records) {
		t.Fatalf("controller restart lost native replay: %+v %v", retained, err)
	}
	found := false
	for _, record := range retained.Records {
		if record.Observation != nil && record.Observation.SourcePort == 49123 {
			found = true
		}
	}
	if !found {
		t.Fatal("retained receiver did not replay actual native packet")
	}
	archive, err := successor.Archive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(archive)
	for {
		_, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			archive.Close()
			t.Fatal(err)
		}
		data, err := io.ReadAll(io.LimitReader(reader, 8<<20))
		if err != nil {
			archive.Close()
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("stackd-native-flow-body-not-retained")) {
			archive.Close()
			t.Fatal("collector persisted customer payload")
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := successor.Ack(ctx, retained.Cursor); err != nil {
		t.Fatal(err)
	}
	acked, err := successor.Read(ctx, retained.Cursor, FlowReadLimits{MaxRecords: 1024})
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range acked.Records {
		if record.Observation != nil && record.Observation.SourcePort == 49123 {
			t.Fatal("durably acknowledged native observation replayed")
		}
	}
	beforeRestart, err := successor.Health(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.JSON(ctx, "POST", "/containers/"+successor.name+"/stop?t=2", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := successor.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	afterRestart, err := successor.Read(ctx, retained.Cursor, FlowReadLimits{MaxRecords: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if afterRestart.Health.Generation == beforeRestart.Generation || afterRestart.Health.Group != beforeRestart.Group {
		t.Fatalf("receiver restart did not retain group and establish new generation: %+v %+v", beforeRestart, afterRestart.Health)
	}
	restartGap := false
	for _, record := range afterRestart.Records {
		if record.Gap != nil && record.Gap.Reason == "receiver-start-uncertain-coverage" {
			restartGap = true
		}
	}
	if !restartGap {
		t.Fatal("receiver restart silently claimed healthy coverage")
	}
}
