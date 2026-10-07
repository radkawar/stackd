package network

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
)

var policyTableName = regexp.MustCompile(`^stackd_(ec2|ecs|elbv2|lambda)_[a-f0-9]+$`)
var publicPool = netip.MustParsePrefix("198.18.0.0/15")

// ApplyPolicy installs outside-customer packet policy and the EC2-owned public
// mapping. Native ownership, not the caller's previous Specification, determines
// what is retired after reassociation or controller restart.
// Callers must serialize current authoritative policy reads with their installs:
// an old assignment snapshot must not be submitted after its successor. EC2
// lifecycle reconciliation supplies this ordering; native flock alone cannot
// determine which control-plane snapshot is current.
func (b *Bridges) ApplyPolicy(ctx context.Context, name string, spec Specification, policy Policy, peer string, options Options, bridge Bridge) error {
	if !policyTableName.MatchString(name) {
		return errors.New("invalid native attachment policy identity")
	}
	if policy.PublicIPv4.IsValid() && !publicPool.Contains(policy.PublicIPv4) {
		return errors.New("native public IPv4 assignment must use the host-local 198.18.0.0/15 benchmark pool")
	}
	if policy.PublicIPv4.IsValid() && (spec.Pool.Contains(policy.PublicIPv4) || policy.PublicIPv4 == spec.Address) {
		return errors.New("native public IPv4 assignment overlaps the attachment's private VPC")
	}
	rules, err := Rules(name, spec, policy, peer, options)
	if err != nil {
		return err
	}
	public, table := "", ""
	if policy.PublicEgress && policy.PublicIPv4.Is4() {
		public = policy.PublicIPv4.String()
		table = fmt.Sprintf("stackd_public_%x", policy.PublicIPv4.As4())
	}
	return b.installPolicy(ctx, name, options.PublicOwner, rules, []string{
		"PUBLIC=" + public, "PUBLIC_TABLE=" + table,
		"PRIVATE=" + spec.Address.String(), "POOL=" + spec.Pool.String(),
		"BRIDGE=" + bridge.Device, "GATEWAY=" + spec.Gateway.String(),
	})
}

// RemovePolicy removes only mappings still owned by this attachment. In
// particular a former owner's late cleanup cannot remove a reassociated EIP.
func (b *Bridges) RemovePolicy(ctx context.Context, name, publicOwner string) error {
	if !policyTableName.MatchString(name) {
		return errors.New("invalid native attachment policy identity")
	}
	rules := "destroy table netdev " + name + "\ndestroy table bridge " + name + "\n"
	return b.installPolicy(ctx, name, publicOwner, rules, []string{"PUBLIC=", "PUBLIC_TABLE="})
}

func (b *Bridges) installPolicy(ctx context.Context, name, publicOwner, rules string, environment []string) error {
	if publicOwner == "" {
		return errors.New("native packet policy requires a persistent public-address controller identity")
	}
	environment = append(environment, "OWNER="+name, "RULES="+rules, fmt.Sprintf("CONTROLLER=%x", sha256.Sum256([]byte(publicOwner))))
	_, err := b.runNativeOperation(ctx, name, environment, false)
	if err != nil {
		return fmt.Errorf("install native attachment/public policy: %w", err)
	}
	return nil
}

// Default local admission requires the daemon-host /run/lock mount. Device/inode
// alone cannot identify a remote host, hence the boot identity. Explicit
// NewDaemonBridges admission obtains and verifies this witness inside the daemon
// host/VM instead and verifies its Engine socket before accepting any mutation.
const nativeLockCheckScript = `
exec 9</run/lock/stackd-public-network.lock
flock -x -w 15 9
lock_identity="$(cat /proc/sys/kernel/random/boot_id) $(stat -Lc '%d:%i' /proc/self/fd/9)"
if [ "$lock_identity" != "$NATIVE_LOCK_IDENTITY" ]; then
    printf '%s\n' "native networking requires the controller to share the daemon-host /run/lock inode" >&2
    exit 1
fi
`

// The retained native table/identity comment is the cleanup witness, not a second
// address registry. Reassignment first revokes the old bridge admission and
// quarantines the public address; only after conntrack retirement and the exact
// /32 route update is the new mapping enabled. Failure leaves it fail-closed.
// Docker's documented DOCKER-USER chain admits only this exact DNAT tuple; the
// destination bridge still evaluates SG/NACL policy before guest delivery.
// Docker's direct-routing raw guard also needs an exact tracked-reply exception.
// It does not bypass the subsequent bridge SG/NACL evaluation.
const nativePolicyScript = `
fail() { printf '%s\n' "$*" >&2; exit 1; }
tables=$(nft -j list tables)
rows=""
for table in $(printf '%s' "$tables" | jq -r '.nftables[].table? | select(.family == "ip" and (.name | startswith("stackd_public_"))) | .name'); do
    state=$(nft -j list table ip "$table")
    owner=$(printf '%s' "$state" | jq -r '.nftables[] | select(has("table")) | .table.comment // ""')
    if [ "$owner" != "stackd:$OWNER" ] && [ "$table" != "$PUBLIC_TABLE" ]; then continue; fi
    case "$owner" in stackd:stackd_ec2_*|stackd:stackd_ecs_*|stackd:stackd_elbv2_*|stackd:stackd_lambda_*) ;; *) fail "public table is not owned: $table";; esac
    controller=$(printf '%s' "$state" | jq -r '.nftables[].chain? | select(.name == "controller") | .comment // ""')
    [ "$controller" = "$CONTROLLER" ] || fail "public IPv4 belongs to another native controller: $table"
    identity=$(printf '%s' "$state" | jq -r '.nftables[].chain? | select(.name == "identity") | .comment // ""')
    [ -n "$identity" ] || fail "public table lacks native identity: $table"
    set -- $identity
    [ "$#" = 4 ] || fail "invalid native public identity: $table"
    route=$(ip -N -j -4 route show table main exact "$1/32")
    # The exact /32, local protocol marker and address-table witness own the
    # route. Its next hop can differ after an interrupted reassociation.
    printf '%s' "$route" | jq -e 'all(.[]; .protocol == 242 or .protocol == "242")' > /dev/null || fail "public /32 route is not owned: $1"
    # A pure SG/NACL update does not reset surviving connections.
    if [ "$table" = "$PUBLIC_TABLE" ] && [ "$owner" = "stackd:$OWNER" ] && [ "$identity" = "$PUBLIC $PRIVATE $BRIDGE $GATEWAY" ] && ! printf '%s' "$state" | jq -e '.nftables[].chain? | select(.name == "quarantine_in")' > /dev/null; then
        continue
    fi
    rows="$rows$table ${owner#stackd:} $identity
"
done
if [ -n "$PUBLIC" ]; then
    nft list chain ip filter DOCKER-USER > /dev/null || fail "public ingress requires Docker iptables-nft DOCKER-USER"
    nft list chain ip raw PREROUTING > /dev/null || fail "public return traffic requires Docker iptables-nft raw PREROUTING"
    connected=$(ip -N -j -4 route show table main match "$PUBLIC/32")
    printf '%s' "$connected" | jq -e 'all(.[]; (.protocol | tostring) != "2" or (.scope | tostring) != "253")' > /dev/null || fail "public IPv4 overlaps a connected host/private network"
    route=$(ip -j -4 route show table main exact "$PUBLIC/32")
    if [ "$(printf '%s' "$route" | jq length)" != 0 ]; then
        printf '%s' "$tables" | jq -e --arg name "$PUBLIC_TABLE" '.nftables[].table? | select(.family == "ip" and .name == $name and (.comment | startswith("stackd:stackd_")))' > /dev/null || fail "refusing an unowned public /32 route"
    fi
    if ! printf '%s' "$tables" | jq -e --arg name "$PUBLIC_TABLE" '.nftables[].table? | select(.family == "ip" and .name == $name)' > /dev/null; then
        # Persist native ownership before creating the route, so even a
        # failed first install can be removed or resumed after restart.
        rows="$rows$PUBLIC_TABLE $OWNER $PUBLIC $PRIVATE $BRIDGE $GATEWAY
"
    fi
fi
stage=""
prepared_current=false
finish="$RULES
"
# Rows are old native witnesses plus the authoritative first assignment.
while read -r table owner public private bridge gateway; do
    [ -n "$table" ] || continue
    # Upgrade the current attachment from its authoritative policy before
    # quarantining it. A retained pre-public-network table has no public_*
    # chains; do not assume the previous controller installed today's schema.
    if [ "$owner" = "$OWNER" ] && [ -n "$PUBLIC" ] && [ "$prepared_current" = false ]; then
        stage="$RULES
$stage"
        prepared_current=true
    fi
    if [ "$owner" = "$OWNER" ] && [ "$prepared_current" = true ] || printf '%s' "$tables" | jq -e --arg name "$owner" '.nftables[].table? | select(.family == "bridge" and .name == $name)' > /dev/null; then
        stage="$stage
flush chain bridge $owner public_from
add rule bridge $owner public_from counter drop
flush chain bridge $owner public_to
add rule bridge $owner public_to counter drop
"
    fi
    # Keep the cleanup witness across partial failure and process restart.
    stage="$stage
destroy table ip $table
table ip $table {
 comment \"stackd:$owner\"
 chain identity { comment \"$public $private $bridge $gateway\"; }
 chain controller { comment \"$CONTROLLER\"; }
 chain quarantine_in { type filter hook prerouting priority -310; policy accept; ip daddr $public drop; }
 chain quarantine_out { type filter hook output priority -310; policy accept; ip daddr $public drop; }
}
"
    for target in "filter DOCKER-USER" "raw PREROUTING"; do
        handles=$(nft -j list chain ip $target | jq -r --arg owner "$table" '.nftables[].rule? | select(.comment == $owner) | .handle')
        for handle in $handles; do stage="$stage
delete rule ip $target handle $handle
"; done
    done
    finish="$finish
destroy table ip $table
"
done <<EOF
$rows
EOF
if [ -n "$stage" ]; then printf '%s' "$stage" | nft -f -; fi
retire() {
    if result=$(conntrack -D -f ipv4 "$@" 2>&1); then return; fi
    case "$result" in *"0 flow entries have been deleted"*) ;; *) fail "$result";; esac
}
while read -r table owner public private bridge gateway; do
    [ -n "$table" ] || continue
    retire --orig-dst "$public"
    # Public-source NAT is visible in the reply destination, not reply source.
    # A private reply source also matches unrelated SG-established VPC traffic.
    retire --orig-src "$private" --reply-dst "$public"
    # Upstream MASQ uses the host address rather than the public address. Inspect
    # only this attachment's SNAT tuples and retain private destinations, even
    # when another native service has applied NAT to that private connection.
    python3 - "$private" "$bridge" "$gateway" <<'PY'
import ipaddress
import json
import subprocess
import sys
import xml.etree.ElementTree as ET

private, bridge, gateway = sys.argv[1:]
addresses = json.loads(subprocess.check_output(["ip", "-j", "address", "show"]))
links = [link for link in addresses if link["ifname"] == bridge]
# A removed bridge cannot carry its former attachment's external traffic. Do
# not mistake a later attachment reusing its private IP for that old owner.
if not links:
    sys.exit(0)
pools = [ipaddress.ip_network(address["local"] + "/" + str(address["prefixlen"]), strict=False)
         for link in links for address in link["addr_info"]
         if address["family"] == "inet" and address["local"] == gateway]
if not pools:
    raise RuntimeError("native attachment bridge lacks its retained gateway")

with subprocess.Popen(["conntrack", "-L", "-f", "ipv4", "--orig-src", private,
                       "--src-nat", "-o", "xml"], stdout=subprocess.PIPE) as dump:
    if dump.stdout.peek(1):
        events = ET.iterparse(dump.stdout, events=("start", "end"))
        _, root = next(events)
        for event, flow in events:
            if event != "end" or flow.tag != "flow":
                continue
            original = flow.find("meta[@direction='original']")
            reply = flow.find("meta[@direction='reply']")
            destination = original.findtext("layer3/dst")
            if not any(ipaddress.ip_address(destination) in pool for pool in pools):
                protocol = original.find("layer4")
                command = ["conntrack", "-D", "-f", "ipv4", "--src-nat",
                           "--orig-src", private, "--orig-dst", destination,
                           "--reply-src", reply.findtext("layer3/src"),
                           "--reply-dst", reply.findtext("layer3/dst"),
                           "-p", protocol.attrib["protonum"],
                           "--zone", flow.findtext("meta[@direction='independent']/zone", "0")]
                for field, option in (("sport", "--sport"), ("dport", "--dport"),
                                      ("id", "--icmp-id"), ("type", "--icmp-type"),
                                      ("code", "--icmp-code")):
                    value = protocol.findtext(field)
                    if value is not None:
                        command.extend((option, value))
                result = subprocess.run(command, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.PIPE, text=True)
                if result.returncode and "0 flow entries have been deleted" not in result.stderr:
                    raise RuntimeError(result.stderr)
            root.clear()
    if dump.wait():
        raise RuntimeError("listing native attachment SNAT tuples failed")
PY
    if [ "$public" != "$PUBLIC" ] && [ "$(ip -j -4 route show table main exact "$public/32" | jq length)" != 0 ]; then
        ip -4 route del "$public/32" proto 242
    fi
done <<EOF
$rows
EOF
if [ -n "$PUBLIC" ]; then
    ip -4 route replace "$PUBLIC/32" dev "$BRIDGE" src "$GATEWAY" proto 242
    # Host-local clients see the allocated address. External flows use the
    # Docker host's routable source, never advertise benchmark space upstream.
    # Preserve the external source through Docker's default bridge MASQ.
    # Assigned peers reaching another local public mapping use their own public
    # source first, including same-bridge hairpin flows.
    finish="$finish
destroy table ip $PUBLIC_TABLE
table ip $PUBLIC_TABLE {
 comment \"stackd:$OWNER\"
 chain identity { comment \"$PUBLIC $PRIVATE $BRIDGE $GATEWAY\"; }
 chain controller { comment \"$CONTROLLER\"; }
 chain inbound { type nat hook prerouting priority -101; policy accept; ip daddr $PUBLIC dnat to $PRIVATE; }
 chain local { type nat hook output priority -101; policy accept; ip daddr $PUBLIC dnat to $PRIVATE; }
 chain host_source { type nat hook input priority 99; policy accept; iifname \"$BRIDGE\" ip saddr $PRIVATE ip daddr != $POOL snat to $PUBLIC; }
 chain public_peer_source { type nat hook postrouting priority 98; policy accept; iifname \"$BRIDGE\" ip saddr $PRIVATE ct status dnat ct original ip daddr 198.18.0.0/15 snat to $PUBLIC; }
 chain inbound_source { type nat hook postrouting priority 99; policy accept; ip daddr $PRIVATE ct status dnat ct original ip daddr $PUBLIC snat to ip saddr; }
 chain upstream_source { type nat hook postrouting priority 99; policy accept; iifname \"$BRIDGE\" ip saddr $PRIVATE ip daddr != $POOL oifname != \"$BRIDGE\" masquerade; }
}
"
    # Replace, rather than accumulate, exact-owned Docker admission rules.
    for target in "filter DOCKER-USER" "raw PREROUTING"; do
        handles=$(nft -j list chain ip $target | jq -r --arg owner "$PUBLIC_TABLE" '.nftables[].rule? | select(.comment == $owner) | .handle')
        for handle in $handles; do finish="$finish
delete rule ip $target handle $handle
"; done
    done
    finish="$finish
insert rule ip filter DOCKER-USER oifname \"$BRIDGE\" ip daddr $PRIVATE ct status dnat ct original ip daddr $PUBLIC counter accept comment \"$PUBLIC_TABLE\"
insert rule ip raw PREROUTING iifname \"$BRIDGE\" ip saddr $PRIVATE ct direction reply ct status dnat ct original ip daddr $PUBLIC counter accept comment \"$PUBLIC_TABLE\"
"
fi
printf '%s' "$finish" | nft -f -
`
