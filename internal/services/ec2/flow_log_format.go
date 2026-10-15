package ec2

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

var flowLogFieldVersions = map[string]int{
	"version": 2, "account-id": 2, "interface-id": 2, "srcaddr": 2, "dstaddr": 2, "srcport": 2, "dstport": 2, "protocol": 2, "packets": 2, "bytes": 2, "start": 2, "end": 2, "action": 2, "log-status": 2,
	"vpc-id": 3, "subnet-id": 3, "instance-id": 3, "tcp-flags": 3, "type": 3, "pkt-srcaddr": 3, "pkt-dstaddr": 3, "region": 4, "az-id": 4, "flow-direction": 5,
}

func validateFlowLogFormat(format string) (int, error) {
	fields := strings.Fields(format)
	if len(fields) == 0 || len(format) > 10000 {
		return 0, failure("InvalidParameterValue", "LogFormat must contain supported field tokens.")
	}
	version := 2
	for _, field := range fields {
		if !strings.HasPrefix(field, "${") || !strings.HasSuffix(field, "}") {
			return 0, failure("InvalidParameterValue", "LogFormat must be a space-separated list of ${field} tokens.")
		}
		name := field[2 : len(field)-1]
		v, ok := flowLogFieldVersions[name]
		if !ok {
			// TODO: Comeback implement additional flow-log enrichment fields from real native observations.
			return 0, unsupported("Flow-log field " + name + " is not supported.")
		}
		if v > version {
			version = v
		}
	}
	return version, nil
}
func flowLogHeader(format string) string {
	fields := strings.Fields(format)
	for i, f := range fields {
		fields[i] = f[2 : len(f)-1]
	}
	return strings.Join(fields, " ")
}
func formatFlowLog(r FlowLogRecord, a FlowLogAggregateRecord) string {
	absent := func(v string) string {
		if v == "" {
			return "-"
		}
		return v
	}
	values := map[string]string{"version": strconv.Itoa(r.FormatVersion), "account-id": a.Interface.Key.Scope.AccountID, "interface-id": a.Interface.Key.ID, "vpc-id": absent(a.Interface.VPCID), "subnet-id": absent(a.Interface.SubnetID), "instance-id": absent(a.Interface.InstanceID), "region": a.Interface.Key.Scope.Region, "az-id": absent(a.Interface.AvailabilityZoneID), "start": strconv.FormatInt(a.Start.Unix(), 10), "end": strconv.FormatInt(a.End.Unix(), 10), "log-status": "OK"}
	if r.Key.Scope.AccountID != a.Interface.Key.Scope.AccountID {
		values["instance-id"] = "-"
	}
	if a.Lost {
		values["log-status"] = "SKIPDATA"
	} else {
		kind := "IPv4"
		if ip, e := netip.ParseAddr(a.SourceAddress); e == nil && ip.Is6() {
			kind = "IPv6"
		}
		values["srcaddr"], values["dstaddr"] = a.SourceAddress, a.DestinationAddress
		values["srcport"], values["dstport"] = fmt.Sprint(a.SourcePort), fmt.Sprint(a.DestinationPort)
		values["protocol"] = fmt.Sprint(a.Protocol)
		values["packets"], values["bytes"] = fmt.Sprint(a.Packets), fmt.Sprint(a.Bytes)
		values["action"], values["flow-direction"] = a.Action, a.Direction
		values["tcp-flags"], values["type"] = fmt.Sprint(a.TCPFlags), kind
		values["pkt-srcaddr"], values["pkt-dstaddr"] = a.SourceAddress, a.DestinationAddress
		if address, err := netip.ParseAddr(a.Interface.Address); err == nil && address.Is4() && kind == "IPv4" {
			if a.Direction == "egress" {
				values["srcaddr"] = address.String()
			}
			if a.Direction == "ingress" {
				values["dstaddr"] = address.String()
			}
		}
	}
	fields := strings.Fields(r.LogFormat)
	for i, f := range fields {
		fields[i] = absent(values[f[2:len(f)-1]])
	}
	return strings.Join(fields, " ")
}
