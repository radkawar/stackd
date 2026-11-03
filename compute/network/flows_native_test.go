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
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"stackd/compute/docker"
)

// This exercises a real group bind and real IPv4 UDP/TCP-control frames at an
// isolated native bridge verdict. It is not an EC2 API assertion, a socket-call
// packet estimate, or a manufactured observation; it does not prove TCP payloads.
func TestFlowCollectorDockerNativeReplay(t *testing.T) {
	current := flowReceiverScript
	predecessor, err := os.ReadFile("testdata/flows_receiver_24a6a69.py")
	if err != nil {
		t.Fatal(err)
	}
	for _, upgrade := range []bool{false, true} {
		name := "current"
		if upgrade {
			name = "predecessor-upgrade"
		}
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { flowReceiverScript = current })
			if upgrade {
				flowReceiverScript = string(predecessor)
			}
			testFlowCollectorDockerNativeReplay(t, current, upgrade)
		})
	}
	t.Run("unrecognized-revision", testFlowCollectorRejectsUnknownReceiverRevision)
}

func testFlowCollectorDockerNativeReplay(t *testing.T, current string, upgrade bool) {
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
	targetPeer, targetSink := "flt"+unique[:10], "flr"+unique[:10]
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
			Image: docker.ToolkitImage, Entrypoint: []string{"/bin/sh", "-ec", "nft destroy table bridge " + table + "; ip link del " + peer + "; ip link del " + targetPeer},
			HostConfig: docker.ContainerHostConfig{NetworkMode: "host", ReadonlyRootfs: true, CapDrop: []string{"ALL"}, CapAdd: []string{"NET_ADMIN"}, SecurityOpt: []string{"no-new-privileges:true"}, Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 16},
		})
		if err != nil {
			t.Error(err)
		}
	})
	output, err := helper("ip link add "+peer+" type veth peer name "+sender+"; ip link set "+peer+" master "+bridge.Device+"; ip link set "+peer+" up; ip link set "+sender+" up; ip link add "+targetPeer+" type veth peer name "+targetSink+"; ip link set "+targetSink+" address 02:00:00:fa:f1:11; ip link set "+targetPeer+" master "+bridge.Device+"; ip link set "+targetPeer+" up; ip link set "+targetSink+" up; bridge fdb replace 02:00:00:fa:f1:11 dev "+targetPeer+" master static; ip -j link show dev "+bridge.Device, "NET_ADMIN")
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
	targetBinding := binding
	targetBinding.Identity.InterfaceID += "-target"
	targetBinding.PeerName = targetPeer
	targetBinding.Address = netip.MustParseAddr("10.254.241.11")
	targetBinding.MAC = "02:00:00:fa:f1:11"
	targetBinding.PolicyTable += "1"
	targetBinding.Generation += "-target"
	_, err = collector.Register(ctx, targetBinding)
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
 iifname "%s" ether type ip ip saddr %s ip daddr %s ip protocol tcp tcp sport 49200-49207 tcp dport 49124 log prefix "%s" group %d snaplen 128 queue-threshold 1 counter name flow_from_accept accept
 }
}
`, table, table, sha256.Sum256([]byte(namespace)), registration.Token, registration.Generation, sha256.Sum256([]byte(namespace)), peer, spec.Address, spec.Gateway, registration.Prefix("egress", "ACCEPT"), registration.Group, peer, spec.Address, spec.Gateway, registration.Prefix("egress", "ACCEPT"), registration.Group)
	// The witness uses the first 16 digest bytes, not a namespace-sized comment.
	fullDigest := fmt.Sprintf("%x", sha256.Sum256([]byte(namespace)))
	rules = strings.Replace(rules, "sf:"+fullDigest+":", "sf:"+fullDigest[:32]+":", 1)
	if _, err := helper("printf '%s' '"+rules+"' | nft -f -", "NET_ADMIN"); err != nil {
		t.Fatal(err)
	}
	packetScript := func(port uint16, destination netip.Addr, destinationMAC string) string {
		return fmt.Sprintf(`import socket,struct
src=socket.inet_aton(%q); dst=socket.inet_aton(%q)
payload=b'stackd-native-flow-body-not-retained'
udp=struct.pack('!HHHH',%d,49124,8+len(payload),0)+payload
ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),123,0,64,17,0,src,dst)
words=struct.unpack('!10H',ip); checksum=sum(words)
while checksum>>16: checksum=(checksum&65535)+(checksum>>16)
ip=ip[:10]+struct.pack('!H',(~checksum)&65535)+ip[12:]
frame=bytes.fromhex(%q.replace(':',''))+bytes.fromhex(%q.replace(':',''))+b'\x08\x00'+ip+udp
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)
s.bind((%q,0)); s.send(frame); s.close()
`, spec.Address.String(), destination.String(), port, destinationMAC, spec.MAC, sender)
	}
	if _, err := helper("python3 -c '"+strings.ReplaceAll(packetScript(49123, spec.Gateway, link[0].Address), "'", "'\"'\"'")+"'", "NET_RAW"); err != nil {
		t.Fatal(err)
	}
	// Explicit header-only frames give independent exact packet/byte expectations:
	// SYN, SYNACK, pure ACK, FIN, FINACK, RST, RSTACK and ECN SYNACK. Each uses a
	// distinct tuple so missing, duplicate or incorrectly decoded frames fail.
	tcpFlags := []uint8{0x02, 0x12, 0x10, 0x01, 0x11, 0x04, 0x14, 0xd2}
	tcpScript := fmt.Sprintf(`import socket,struct
src=socket.inet_aton(%q); dst=socket.inet_aton(%q)
def checksum(data):
 if len(data)%%2: data+=b'\x00'
 value=sum(struct.unpack('!%%dH'%%(len(data)//2),data))
 while value>>16: value=(value&65535)+(value>>16)
 return (~value)&65535
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)
s.bind((%q,0))
for index,flags in enumerate((2,18,16,1,17,4,20,210)):
 options=b'\x01\x01\x00\x00'
 tcp=struct.pack('!HHIIBBHHH',49200+index,49124,1,2,0x80,flags,65535,0,0)+b'\x01'*12
 pseudo=src+dst+struct.pack('!BBH',0,6,len(tcp))
 tcp=tcp[:16]+struct.pack('!H',checksum(pseudo+tcp))+tcp[18:]
 ip=struct.pack('!BBHHHBBH4s4s',0x46,0,24+len(tcp),200+index,0,64,6,0,src,dst)+options
 ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
 frame=bytes.fromhex(%q.replace(':',''))+bytes.fromhex(%q.replace(':',''))+b'\x08\x00'+ip+tcp
 if s.send(frame)!=len(frame): raise RuntimeError('short native TCP frame write')
s.close()
`, spec.Address.String(), spec.Gateway.String(), sender, link[0].Address, spec.MAC)
	if _, err := helper("python3 -c '"+strings.ReplaceAll(tcpScript, "'", "'\"'\"'")+"'", "NET_RAW"); err != nil {
		t.Fatal(err)
	}
	assertTCPControls := func(records []FlowRecord) int {
		t.Helper()
		seen := make(map[uint16]bool)
		for _, record := range records {
			value := record.Observation
			if value == nil || value.SourcePort < 49200 || value.SourcePort > 49207 {
				continue
			}
			index := int(value.SourcePort - 49200)
			if seen[value.SourcePort] || value.Binding.Identity != identity || value.Action != "ACCEPT" || value.Direction != "egress" || value.Protocol != 6 || value.TCPFlags != tcpFlags[index] || value.DestinationPort != 49124 || value.Packets != 1 || value.IPBytes != 56 || value.SourceAddress != spec.Address || value.DestinationAddress != spec.Gateway || value.ObservedAt.IsZero() || value.PeerWitness != nil {
				t.Fatalf("incorrect actual native TCP-control evidence: %+v", value)
			}
			seen[value.SourcePort] = true
		}
		return len(seen)
	}
	var observation *FlowObservation
	var batch FlowBatch
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for observation == nil || assertTCPControls(batch.Records) != len(tcpFlags) {
		batch, err = collector.Read(ctx, 0, FlowReadLimits{MaxRecords: 1024, MaxBytes: 1 << 20})
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range batch.Records {
			if record.Observation != nil && record.Observation.SourcePort == 49123 {
				observation = record.Observation
			}
		}
		if observation != nil && assertTCPControls(batch.Records) == len(tcpFlags) {
			break
		}
		select {
		case <-deadline.C:
			t.Fatalf("no actual native packet observation: %+v", batch)
		case <-time.After(100 * time.Millisecond):
		}
	}
	if observation.Binding.Identity != identity || observation.Action != "ACCEPT" || observation.Direction != "egress" || observation.Packets != 1 || observation.IPBytes != uint32(28+len("stackd-native-flow-body-not-retained")) || observation.SourceAddress != spec.Address || observation.DestinationAddress != spec.Gateway || observation.ObservedAt.IsZero() || observation.PeerWitness != nil {
		t.Fatalf("incorrect actual native packet evidence: %+v", observation)
	}
	beforeID, err := collector.ownedContainer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := collector.Close(); err != nil {
		t.Fatal(err)
	}
	successor, err := NewDockerFlowCollector(client, namespace)
	if err != nil {
		t.Fatal(err)
	}
	flowReceiverScript = current
	if err := successor.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	afterID, err := successor.ownedContainer(ctx)
	if err != nil || (beforeID != afterID) != upgrade {
		t.Fatalf("unexpected receiver adoption/replacement: before=%s after=%s upgrade=%t err=%v", beforeID, afterID, upgrade, err)
	}
	retained, err := successor.Read(ctx, 0, FlowReadLimits{MaxRecords: 1024, MaxBytes: 1 << 20})
	if err != nil || len(retained.Records) < len(batch.Records) {
		t.Fatalf("controller restart lost native replay: %+v %v", retained, err)
	}
	if retained.Health.Group != health.Group {
		t.Fatal("receiver adoption/upgrade changed the retained NFLOG group")
	}
	for _, original := range batch.Records {
		if original.Observation == nil {
			continue
		}
		matched := false
		for _, replay := range retained.Records {
			if replay.Cursor == original.Cursor && reflect.DeepEqual(replay, original) {
				matched = true
			}
		}
		if !matched {
			t.Fatalf("receiver adoption/upgrade changed a pending actual packet: %+v", original)
		}
	}
	if upgrade {
		upgradeGap, restartGap := false, false
		for _, record := range retained.Records {
			if record.Gap != nil {
				upgradeGap = upgradeGap || record.Gap.Reason == "receiver-software-upgrade-uncertain-coverage"
				restartGap = restartGap || record.Gap.Reason == "receiver-start-uncertain-coverage"
			}
		}
		if !upgradeGap || !restartGap {
			t.Fatalf("compatible receiver upgrade omitted explicit uncertainty: %+v", retained)
		}
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
	if assertTCPControls(retained.Records) != len(tcpFlags) {
		t.Fatal("retained receiver did not replay every actual native TCP-control frame")
	}
	// Reverify attachment lifetimes after a possible software restart. The
	// target needs authoritative registration, not its own capture policy.
	registration, err = successor.Register(ctx, binding)
	if err != nil {
		t.Fatal(err)
	}
	targetRegistration, err := successor.Register(ctx, targetBinding)
	if err != nil {
		t.Fatal(err)
	}
	forwardRules := fmt.Sprintf(`add chain bridge %s forward { type filter hook forward priority -300; policy accept; }
add rule bridge %s forward iifname "%s" oifname "%s" ether type ip ip saddr %s ip daddr %s udp sport 49301 udp dport 49124 log prefix "%s" group %d snaplen 128 queue-threshold 1 drop
add rule bridge %s forward iifname "%s" oifname "%s" ether type ip ip saddr %s ip daddr %s udp sport 49300-49304 udp dport 49124 log prefix "%s" group %d snaplen 128 queue-threshold 1
add rule bridge %s forward iifname "%s" oifname "%s" ether type ip ip saddr %s ip daddr %s udp sport 49300-49304 udp dport 49124 log prefix "%s" group %d snaplen 128 queue-threshold 1 accept
`, table, table, peer, targetPeer, spec.Address, targetBinding.Address, registration.Prefix("egress", "REJECT"), registration.Group,
		table, peer, targetPeer, spec.Address, targetBinding.Address, registration.Prefix("egress", "ACCEPT"), registration.Group,
		table, peer, targetPeer, spec.Address, targetBinding.Address, targetRegistration.Prefix("ingress", "ACCEPT"), registration.Group)
	// RTM_NEWLINK can report harmless attribute updates without replacing,
	// renaming, moving or disabling either native attachment.
	if _, err := helper("ip link set "+bridge.Device+" alias stackd-flow-proof; ip link set "+targetPeer+" alias stackd-flow-proof", "NET_ADMIN"); err != nil {
		t.Fatal(err)
	}
	if _, err := helper("printf '%s' '"+forwardRules+"' | nft -f -", "NET_ADMIN"); err != nil {
		t.Fatal(err)
	}
	sendForward := func(port uint16) {
		t.Helper()
		script := packetScript(port, targetBinding.Address, targetBinding.MAC)
		if _, err := helper("python3 -c '"+strings.ReplaceAll(script, "'", "'\"'\"'")+"'", "NET_RAW"); err != nil {
			t.Fatal(err)
		}
	}
	assertForward := func(port uint16, wantPath bool, action string) {
		t.Helper()
		until := time.Now().Add(10 * time.Second)
		for {
			retained, err = successor.Read(ctx, 0, FlowReadLimits{MaxRecords: 1024, MaxBytes: 1 << 20})
			if err != nil {
				t.Fatal(err)
			}
			egress, ingress := 0, 0
			for _, record := range retained.Records {
				value := record.Observation
				if value == nil || value.SourcePort != port {
					continue
				}
				if value.Packets != 1 || value.IPBytes != uint32(28+len("stackd-native-flow-body-not-retained")) || value.SourceAddress != spec.Address || value.DestinationAddress != targetBinding.Address {
					t.Fatalf("forward enrichment changed actual packet counts: %+v", value)
				}
				if value.Direction == "ingress" {
					ingress++
					if value.PeerWitness != nil || value.Binding.Identity != targetBinding.Identity || value.Action != "ACCEPT" {
						t.Fatalf("ingress received egress path evidence: %+v", value)
					}
				} else {
					egress++
					if value.Action != action || (value.PeerWitness != nil) != wantPath {
						t.Fatalf("incorrect actual bridge-FORWARD proof (want path=%t): %+v", wantPath, value)
					}
					if proof := value.PeerWitness; proof != nil {
						if proof.Target.Identity != targetBinding.Identity || proof.Target.NetworkID != binding.NetworkID ||
							proof.PhysicalInput != value.Binding.PeerIfIndex || proof.PhysicalOutput != proof.Target.PeerIfIndex ||
							proof.SourceMAC != spec.MAC || proof.DestinationMAC != targetBinding.MAC || proof.Hook != 2 ||
							value.TimestampSource != "kernel" || value.ObservedAt.Before(proof.TargetRegisteredAt) {
							t.Fatalf("incorrect immutable native peer witness: %+v", proof)
						}
					}
				}
			}
			wantIngress := 1
			if action == "REJECT" {
				wantIngress = 0
			}
			if egress == 1 && ingress == wantIngress {
				return
			}
			if egress > 1 || ingress > wantIngress || time.Now().After(until) {
				t.Fatalf("actual forward packets missing/duplicated: port=%d egress=%d ingress=%d", port, egress, ingress)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	sendForward(49300)
	assertForward(49300, true, "ACCEPT")
	sendForward(49301)
	assertForward(49301, false, "REJECT")
	// A link lifetime event invalidates evidence even when name/MAC/IP remain.
	if _, err := helper("ip link set "+targetPeer+" down; ip link set "+targetPeer+" up; bridge fdb replace "+targetBinding.MAC+" dev "+targetPeer+" master static", "NET_ADMIN"); err != nil {
		t.Fatal(err)
	}
	sendForward(49302)
	assertForward(49302, false, "ACCEPT")
	if _, err := successor.Register(ctx, binding); err != nil {
		t.Fatal(err)
	}
	if _, err := successor.Register(ctx, targetBinding); err != nil {
		t.Fatal(err)
	}
	sendForward(49303)
	assertForward(49303, true, "ACCEPT")
	foreign := targetBinding
	foreign.Identity.VPCID += "-foreign"
	foreign.NetworkID = foreign.Identity.VPCARN()
	foreign.Generation += "-foreign"
	foreignSpec := spec
	foreignSpec.FlowIdentity, foreignSpec.NetworkID = foreign.Identity, foreign.NetworkID
	foreignSpec.Pool = netip.MustParsePrefix("10.254.242.0/24")
	foreignSpec.Gateway = netip.MustParseAddr("10.254.242.1")
	foreignSpec.Address = netip.MustParseAddr("10.254.242.11")
	if err := bridges.WithBridge(ctx, foreignSpec, func(Bridge) error { return nil }); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		if err := bridges.Release(cleanup, foreignSpec.NetworkID); err != nil {
			t.Error(err)
		}
	})
	if _, err := successor.Register(ctx, foreign); err == nil || !strings.Contains(err.Error(), "bridge is not owned by the full VPC identity") {
		t.Fatalf("foreign VPC registration did not fail ownership admission: %v", err)
	}
	// A refused foreign owner must not invalidate the actual local attachment.
	sendForward(49304)
	assertForward(49304, true, "ACCEPT")
	replayed, err := successor.Read(ctx, 0, FlowReadLimits{MaxRecords: 1024, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, original := range retained.Records {
		if original.Observation == nil || original.Observation.SourcePort < 49300 || original.Observation.SourcePort > 49304 {
			continue
		}
		matched := false
		for _, replay := range replayed.Records {
			matched = matched || (replay.Cursor == original.Cursor && reflect.DeepEqual(replay, original))
		}
		if !matched {
			t.Fatal("later attachment changes altered frozen native replay")
		}
	}
	retained = replayed
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
		if value := record.Observation; value != nil && (value.SourcePort == 49123 || (value.SourcePort >= 49300 && value.SourcePort <= 49304)) {
			t.Fatal("durably acknowledged native observation replayed")
		}
	}
	if assertTCPControls(acked.Records) != 0 {
		t.Fatal("durably acknowledged native TCP-control observation replayed")
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
