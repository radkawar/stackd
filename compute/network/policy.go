package network

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
)

// Options selects the attachment's actual control-plane endpoints. Guest enables
// DHCP and IMDS; an optional Callback names this attachment's host listener.
// An empty Callback grants no control-plane packet exemption.
type Options struct {
	Callback string
	Guest    bool
	// PublicOwner is the existing persistent controller identity: the guest
	// network state directory, immutable task ARN or retained service attachment.
	PublicOwner string
	// flow is supplied only after authoritative native collector registration.
	flow *policyFlowCapture
}

// Rules renders one attachment's native nftables transaction. Netdev guards run
// on the host peer, before customer packet sockets. Bridge hooks supply SG
// connection tracking; ordered ACLs run first and cannot be bypassed by it.
func Rules(name string, network Specification, policy Policy, peer string, options Options) (string, error) {
	host, portNumber := "", 0
	if options.Callback != "" {
		callbackHost, port, err := net.SplitHostPort(options.Callback)
		if err != nil || callbackHost != network.Gateway.String() {
			return "", errors.New("network policy callback differs from retained gateway")
		}
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return "", errors.New("network policy callback port is invalid")
		}
		host, portNumber = callbackHost, number
	}
	mac, err := net.ParseMAC(network.MAC)
	if err != nil || len(mac) != 6 {
		return "", errors.New("network policy requires an Ethernet MAC")
	}
	address, pool := network.Address.String(), network.Pool.String()
	flow := options.flow
	var b strings.Builder
	fmt.Fprintf(&b, "destroy table netdev %s\ndestroy table bridge %s\n", name, name)
	fmt.Fprintf(&b, "table netdev %s {\n", name)
	flow.writeChains(&b, name, network, options, false)
	fmt.Fprintf(&b, "chain source { type filter hook ingress device %q priority -500; policy drop;\n", peer)
	fmt.Fprintf(&b, "ether saddr != %s counter %s\n", mac, flow.drop("from"))
	fmt.Fprintf(&b, "ether type arp arp htype 1 arp ptype ip arp hlen 6 arp plen 4 arp operation { request, reply } arp saddr ether %s arp saddr ip %s arp daddr ip %s accept\n", mac, address, pool)
	// Source routing must not rewrite the destination after policy evaluation.
	fmt.Fprintf(&b, "ip option lsrr exists counter %s\nip option ssrr exists counter %s\n", flow.drop("from"), flow.drop("from"))
	if options.Guest {
		fmt.Fprintf(&b, "ether type arp arp operation request arp saddr ether %s arp saddr ip 0.0.0.0 arp daddr ip %s accept\n", mac, address)
		fmt.Fprintf(&b, "ether type ip ip saddr { 0.0.0.0, %s } ip daddr { 255.255.255.255, %s } udp sport 68 udp dport 67 accept\n", address, network.Gateway)
		fmt.Fprintf(&b, "ether type ip ip saddr %s ip daddr 169.254.169.254 tcp dport 80 accept\n", address)
	}
	fmt.Fprintf(&b, "ether type ip ip saddr %s ip daddr != 169.254.0.0/16 accept\n", address)
	flow.writeDefaultDrop(&b, "from")
	b.WriteString("}\n")
	fmt.Fprintf(&b, "chain destination { type filter hook egress device %q priority -500; policy drop;\n", peer)
	fmt.Fprintf(&b, "ether type arp arp htype 1 arp ptype ip arp hlen 6 arp plen 4 arp operation { request, reply } arp saddr ip %s arp daddr ip %s accept\n", pool, address)
	fmt.Fprintf(&b, "ip option lsrr exists counter %s\nip option ssrr exists counter %s\n", flow.drop("to"), flow.drop("to"))
	if options.Guest {
		fmt.Fprintf(&b, "ether type ip ip saddr %s ip daddr { 255.255.255.255, %s } udp sport 67 udp dport 68 accept\n", network.Gateway, address)
	}
	fmt.Fprintf(&b, "ether daddr %s ether type ip ip daddr %s accept\n", mac, address)
	flow.writeDefaultDrop(&b, "to")
	b.WriteString("}\n}\n")
	fmt.Fprintf(&b, "table bridge %s {\n", name)
	flow.writeChains(&b, name, network, options, true)
	writeNATChains(&b, policy.NATRoutes, flow)
	writePrivateChains(&b, policy.PrivateRoutes, flow)
	for _, direction := range []string{"from", "to"} {
		field, acl, sg, callbackMatch := "daddr", policy.ACLEgress, policy.SecurityEgress, fmt.Sprintf("ip daddr %s tcp dport %d", host, portNumber)
		if direction == "to" {
			field, acl, sg, callbackMatch = "saddr", policy.ACLIngress, policy.SecurityIngress, fmt.Sprintf("ip saddr %s tcp sport %d", host, portNumber)
		}
		// These chains are also the native revocation point when the shared
		// public-address installer moves an address to another attachment.
		fmt.Fprintf(&b, "chain public_%s {\n", direction)
		if !policy.PublicEgress || !policy.PublicIPv4.Is4() {
			writeNATAdmission(&b, policy.NATRoutes, direction, flow)
		}
		b.WriteString("}\n")
		// The reserved gateway is not a customer ENI. Host-local public DNAT
		// selects it as the source, but NAT conntrack flags need not survive
		// into the bridge hook. Both directions must still evaluate NACLs.
		fmt.Fprintf(&b, "chain acl_%s {\nct status != dnat ip %s %s ip %s != %s return\n", direction, field, policy.Subnet, field, network.Gateway)
		ordered := slices.Clone(acl)
		slices.SortFunc(ordered, func(a, b ACLRule) int {
			if a.Number < b.Number {
				return -1
			}
			if a.Number > b.Number {
				return 1
			}
			return 0
		})
		for _, rule := range ordered {
			verdict := flow.drop(direction)
			if rule.Allow {
				verdict = "return"
			}
			fmt.Fprintf(&b, "%s counter %s\n", nftIPMatch(rule.Rule, field), verdict)
		}
		fmt.Fprintf(&b, "counter %s\n}\n", flow.drop(direction))
		fmt.Fprintf(&b, "chain %s {\nether type arp return\nether type != ip counter drop\n", direction)
		if options.Callback != "" {
			fmt.Fprintf(&b, "%s return\n", callbackMatch)
		}
		if options.Guest {
			if direction == "from" {
				fmt.Fprintf(&b, "ip saddr { 0.0.0.0, %s } ip daddr { 255.255.255.255, %s } udp sport 68 udp dport 67 return\n", address, network.Gateway)
				b.WriteString("ip daddr 169.254.169.254 tcp dport 80 return\n")
			} else {
				fmt.Fprintf(&b, "ip saddr %s ip daddr { 255.255.255.255, %s } udp sport 67 udp dport 68 return\n", network.Gateway, address)
				b.WriteString("ip saddr 169.254.169.254 tcp sport 80 return\n")
			}
			// Only AmazonProvidedDNS bypasses SG/NACL policy. Custom DHCP DNS
			// servers are ordinary destinations and still require authorization.
			for _, dns := range network.DNS {
				if dns != network.Pool.Addr().Next().Next() {
					continue
				}
				portField := "dport"
				if direction == "to" {
					portField = "sport"
				}
				fmt.Fprintf(&b, "ip %s %s udp %s 53 return\nip %s %s tcp %s 53 return\n", field, dns, portField, field, dns, portField)
			}
		}
		writePrivateAdmission(&b, policy.PrivateRoutes, direction, pool)
		fmt.Fprintf(&b, "ip %s != %s jump public_%s\n", field, pool, direction)
		if direction == "to" {
			fmt.Fprintf(&b, "ct status dnat ct original ip daddr != %s jump public_to\n", pool)
		}
		fmt.Fprintf(&b, "jump acl_%s\nct state invalid counter %s\nct state established,related return\n", direction, flow.drop(direction))
		for _, rule := range sg {
			fmt.Fprintf(&b, "%s counter return\n", nftIPMatch(rule, field))
		}
		fmt.Fprintf(&b, "counter %s\n}\n", flow.drop(direction))
	}
	if flow == nil {
		fmt.Fprintf(&b, "chain input { type filter hook input priority 0; policy accept; iifname %q jump from; }\n", peer)
		fmt.Fprintf(&b, "chain output { type filter hook output priority 0; policy accept; oifname %q jump to; }\n", peer)
		fmt.Fprintf(&b, "chain forward { type filter hook forward priority 0; policy accept; iifname %q jump from; oifname %q jump to; }\n}\n", peer, peer)
	} else {
		// An intermediate ACL/route/SG return is not admission. Observe only
		// after the complete ENI policy has returned to its hook caller.
		from := fmt.Sprintf("iifname %q jump from; iifname %q jump flow_from_accept;", peer, peer)
		// The destination netdev guard runs later. Its failure must produce
		// REJECT only, not an earlier bridge ACCEPT for the same ENI.
		to := fmt.Sprintf("oifname %q jump to; oifname %q ether daddr %s ip daddr %s ip option lsrr missing ip option ssrr missing jump flow_to_accept;", peer, peer, mac, address)
		fmt.Fprintf(&b, "chain input { type filter hook input priority 0; policy accept; %s }\n", from)
		fmt.Fprintf(&b, "chain output { type filter hook output priority 0; policy accept; %s }\n", to)
		// Independent attachment tables have no ordering at equal priority.
		// Finish every source ENI's admission before any destination ENI's
		// admission: a destination rejection must not erase source ACCEPT,
		// and a source rejection must prevent destination ACCEPT. Both phases
		// keep the existing chain/verdict order and remain after conntrack.
		fmt.Fprintf(&b, "chain forward_from { type filter hook forward priority -1; policy accept; %s }\n", from)
		fmt.Fprintf(&b, "chain forward_to { type filter hook forward priority 1; policy accept; %s }\n}\n", to)
	}
	return b.String(), nil
}

type policyFlowCapture struct {
	namespace    string
	registration FlowRegistration
}

func (f *policyFlowCapture) drop(direction string) string {
	if f == nil {
		return "drop"
	}
	return "jump flow_" + direction + "_drop"
}

func (f *policyFlowCapture) writeDefaultDrop(b *strings.Builder, direction string) {
	if f != nil {
		fmt.Fprintf(b, "counter %s\n", f.drop(direction))
	}
}

func (f *policyFlowCapture) writeChains(b *strings.Builder, table string, spec Specification, options Options, accepts bool) {
	if f == nil {
		return
	}
	fmt.Fprintf(b, "comment %q\n", "stackd:"+table)
	// The immutable witness survives controller restart and identifies the
	// registration to retire only after its last native rule is gone.
	digest := sha256.Sum256([]byte(f.namespace))
	witness := "sf:" + hex.EncodeToString(digest[:16]) + ":" + f.registration.Token + ":" + f.registration.Generation
	fmt.Fprintf(b, "chain flow_identity { comment %q; }\n", witness)
	fmt.Fprintf(b, "chain flow_controller { comment \"%x\"; }\n", sha256.Sum256([]byte(options.PublicOwner)))
	// nft comments have a small userdata bound. Keep even the maximum allowed
	// UTF-8 namespace recoverable without an oversized identity comment.
	for offset := 0; offset < len(f.namespace); offset += 32 {
		end := min(offset+32, len(f.namespace))
		fmt.Fprintf(b, "chain flow_namespace_%02d { comment %q; }\n", offset/32, hex.EncodeToString([]byte(f.namespace[offset:end])))
	}
	for _, direction := range []string{"from", "to"} {
		nativeDirection := "egress"
		if direction == "to" {
			nativeDirection = "ingress"
		}
		for _, action := range []string{"reject", "accept"} {
			if action == "accept" && !accepts {
				continue
			}
			name := "flow_" + direction + "_" + action
			fmt.Fprintf(b, "counter %s { }\nchain %s {\n", name, name)
			writeFlowExclusions(b, spec, options)
			// NFLOG is non-terminating: neither receiver failure nor queue
			// pressure changes the original policy verdict.
			fmt.Fprintf(b, "counter name %s log group %d prefix %q queue-threshold 1 snaplen 128\n}\n", name, f.registration.Group, f.registration.Prefix(nativeDirection, strings.ToUpper(action)))
		}
		fmt.Fprintf(b, "chain flow_%s_drop { jump flow_%s_reject; drop; }\n", direction, direction)
	}
}

func writeFlowExclusions(b *strings.Builder, spec Specification, options Options) {
	b.WriteString("ether type != ip return\n")
	// These provider endpoints are excluded regardless of whether DHCP selected
	// custom DNS. In particular, no blanket UDP/TCP port 53 exemption is used.
	for _, field := range []string{"saddr", "daddr"} {
		fmt.Fprintf(b, "ip %s { 169.254.169.254, 169.254.169.123 } return\n", field)
		port := "dport"
		if field == "saddr" {
			port = "sport"
		}
		for _, protocol := range []string{"udp", "tcp"} {
			fmt.Fprintf(b, "ip %s { %s, 169.254.169.253 } %s %s 53 return\n", field, spec.Pool.Addr().Next().Next(), protocol, port)
		}
	}
	// The bridge gateway may be the ordinary application peer after supported
	// host-local public /32 DNAT. An address-only gateway exclusion would hide
	// both request and reply; exclude actual control tuples, not that address.
	b.WriteString("udp sport 68 udp dport 67 return\nudp sport 67 udp dport 68 return\n")
	b.WriteString("ip daddr { 169.254.169.250, 169.254.169.251 } tcp dport 1688 return\nip saddr { 169.254.169.250, 169.254.169.251 } tcp sport 1688 return\n")
	if options.Callback != "" {
		host, port, _ := net.SplitHostPort(options.Callback) // Rules validated it.
		fmt.Fprintf(b, "ip daddr %s tcp dport %s return\nip saddr %s tcp sport %s return\n", host, port, host, port)
	}
}

func nftIPMatch(rule IPRule, field string) string {
	match := "ip " + field + " " + rule.CIDR.String()
	if rule.Protocol == -1 {
		return match
	}
	match += " ip protocol " + strconv.Itoa(rule.Protocol)
	switch rule.Protocol {
	case 6, 17:
		protocol := "tcp"
		if rule.Protocol == 17 {
			protocol = "udp"
		}
		match += " " + protocol + " dport " + strconv.Itoa(rule.FromPort)
		if rule.ToPort != rule.FromPort {
			match += "-" + strconv.Itoa(rule.ToPort)
		}
	case 1:
		if rule.ICMPType != -1 {
			match += " icmp type " + strconv.Itoa(rule.ICMPType)
		}
		if rule.ICMPCode != -1 {
			match += " icmp code " + strconv.Itoa(rule.ICMPCode)
		}
	}
	return match
}
