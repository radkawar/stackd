package network

import (
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
	var b strings.Builder
	fmt.Fprintf(&b, "destroy table netdev %s\ndestroy table bridge %s\n", name, name)
	fmt.Fprintf(&b, "table netdev %s {\n", name)
	fmt.Fprintf(&b, "chain source { type filter hook ingress device %q priority -500; policy drop;\n", peer)
	fmt.Fprintf(&b, "ether saddr != %s counter drop\n", mac)
	fmt.Fprintf(&b, "ether type arp arp htype 1 arp ptype ip arp hlen 6 arp plen 4 arp operation { request, reply } arp saddr ether %s arp saddr ip %s arp daddr ip %s accept\n", mac, address, pool)
	// Source routing must not rewrite the destination after policy evaluation.
	b.WriteString("ip option lsrr exists counter drop\nip option ssrr exists counter drop\n")
	if options.Guest {
		fmt.Fprintf(&b, "ether type arp arp operation request arp saddr ether %s arp saddr ip 0.0.0.0 arp daddr ip %s accept\n", mac, address)
		fmt.Fprintf(&b, "ether type ip ip saddr { 0.0.0.0, %s } ip daddr { 255.255.255.255, %s } udp sport 68 udp dport 67 accept\n", address, network.Gateway)
		fmt.Fprintf(&b, "ether type ip ip saddr %s ip daddr 169.254.169.254 tcp dport 80 accept\n", address)
	}
	fmt.Fprintf(&b, "ether type ip ip saddr %s ip daddr != 169.254.0.0/16 accept\n}\n", address)
	fmt.Fprintf(&b, "chain destination { type filter hook egress device %q priority -500; policy drop;\n", peer)
	fmt.Fprintf(&b, "ether type arp arp htype 1 arp ptype ip arp hlen 6 arp plen 4 arp operation { request, reply } arp saddr ip %s arp daddr ip %s accept\n", pool, address)
	b.WriteString("ip option lsrr exists counter drop\nip option ssrr exists counter drop\n")
	if options.Guest {
		fmt.Fprintf(&b, "ether type ip ip saddr %s ip daddr { 255.255.255.255, %s } udp sport 67 udp dport 68 accept\n", network.Gateway, address)
	}
	fmt.Fprintf(&b, "ether daddr %s ether type ip ip daddr %s accept\n}\n}\n", mac, address)
	fmt.Fprintf(&b, "table bridge %s {\n", name)
	for _, direction := range []string{"from", "to"} {
		field, acl, sg, callbackMatch := "daddr", policy.ACLEgress, policy.SecurityEgress, fmt.Sprintf("ip daddr %s tcp dport %d", host, portNumber)
		if direction == "to" {
			field, acl, sg, callbackMatch = "saddr", policy.ACLIngress, policy.SecurityIngress, fmt.Sprintf("ip saddr %s tcp sport %d", host, portNumber)
		}
		// These chains are also the native revocation point when the shared
		// public-address installer moves an address to another attachment.
		fmt.Fprintf(&b, "chain public_%s {\n", direction)
		if !policy.PublicEgress || !policy.PublicIPv4.Is4() {
			b.WriteString("counter drop\n")
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
			verdict := "drop"
			if rule.Allow {
				verdict = "return"
			}
			fmt.Fprintf(&b, "%s counter %s\n", nftIPMatch(rule.Rule, field), verdict)
		}
		b.WriteString("counter drop\n}\n")
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
		fmt.Fprintf(&b, "ip %s != %s jump public_%s\n", field, pool, direction)
		if direction == "to" {
			fmt.Fprintf(&b, "ct status dnat ct original ip daddr != %s jump public_to\n", pool)
		}
		fmt.Fprintf(&b, "jump acl_%s\nct state invalid counter drop\nct state established,related return\n", direction)
		for _, rule := range sg {
			fmt.Fprintf(&b, "%s counter return\n", nftIPMatch(rule, field))
		}
		b.WriteString("counter drop\n}\n")
	}
	fmt.Fprintf(&b, "chain input { type filter hook input priority 0; policy accept; iifname %q jump from; }\n", peer)
	fmt.Fprintf(&b, "chain output { type filter hook output priority 0; policy accept; oifname %q jump to; }\n", peer)
	fmt.Fprintf(&b, "chain forward { type filter hook forward priority 0; policy accept; iifname %q jump from; oifname %q jump to; }\n}\n", peer, peer)
	return b.String(), nil
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
