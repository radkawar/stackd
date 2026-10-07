package ec2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	api "stackd/internal/awsapi/ec2"
	"strings"
)

type pageItem struct {
	ID     string
	Tags   api.TagList
	Fields map[string][]string
}
type pageToken struct {
	Scope                       Scope
	Operation, Selection, After string
}

func stringsOf[S ~[]E, E ~string](v S) []string {
	out := make([]string, len(v))
	for i, x := range v {
		out[i] = string(x)
	}
	return out
}
func maxResults[T ~int32](v *T) *int32 {
	if v == nil {
		return nil
	}
	return new(int32(*v))
}
func canonicalCIDR(raw string) (string, error) {
	p, err := netip.ParsePrefix(raw)
	if err != nil {
		return "", failure("InvalidParameterValue", "Value ("+raw+") for parameter cidrBlock is invalid.")
	}
	return p.Masked().String(), nil
}
func missing(kind, id string) error {
	if kind == "natgateway" || kind == "vpc-endpoint" {
		return networkOwnerMissing(kind, id)
	}
	if kind == "launch-template" {
		return launchTemplateMissing(id, "")
	}
	if kind == "instance" {
		return failure("InvalidInstanceID.NotFound", "The instance ID '"+id+"' does not exist")
	}
	if kind == "elastic-ip" {
		return publicAddressMissing(id, "")
	}
	if kind == "key-pair" {
		return failure("InvalidKeyPair.NotFound", "The key pair '"+id+"' does not exist")
	}
	codes := map[string]string{"vpc": "InvalidVpcID.NotFound", "subnet": "InvalidSubnetID.NotFound", "security-group": "InvalidGroup.NotFound", "security-group-rule": "InvalidSecurityGroupRuleId.NotFound", "route-table": "InvalidRouteTableID.NotFound", "internet-gateway": "InvalidInternetGatewayID.NotFound", "network-interface": "InvalidNetworkInterfaceID.NotFound", "network-acl": "InvalidNetworkAclID.NotFound", "dhcp-options": "InvalidDhcpOptionsID.NotFound"}
	names := map[string]string{"vpc": "vpc ID", "subnet": "subnet ID", "security-group": "security group", "security-group-rule": "security group rule ID", "route-table": "routeTable ID", "internet-gateway": "internetGateway ID", "network-interface": "networkInterface ID", "network-acl": "networkAcl ID", "dhcp-options": "dhcpOptions ID"}
	code := codes[kind]
	if code == "" {
		code = "InvalidID.NotFound"
	}
	return failure(code, fmt.Sprintf("The %s '%s' does not exist", names[kind], id))
}
func resourceKind(id string) string {
	switch {
	case strings.HasPrefix(id, "nat-"):
		return "natgateway"
	case strings.HasPrefix(id, "vpce-"):
		return "vpc-endpoint"
	case strings.HasPrefix(id, "lt-"):
		return "launch-template"
	case strings.HasPrefix(id, "eipalloc-"):
		return "elastic-ip"
	case strings.HasPrefix(id, "i-"):
		return "instance"
	case strings.HasPrefix(id, "ami-"):
		return "image"
	case strings.HasPrefix(id, "key-"):
		return "key-pair"
	case strings.HasPrefix(id, "vpc-"):
		return "vpc"
	case strings.HasPrefix(id, "subnet-"):
		return "subnet"
	case strings.HasPrefix(id, "sgr-"):
		return "security-group-rule"
	case strings.HasPrefix(id, "sg-"):
		return "security-group"
	case strings.HasPrefix(id, "rtb-"):
		return "route-table"
	case strings.HasPrefix(id, "igw-"):
		return "internet-gateway"
	case strings.HasPrefix(id, "eni-"):
		return "network-interface"
	case strings.HasPrefix(id, "acl-"):
		return "network-acl"
	case strings.HasPrefix(id, "dopt-"):
		return "dhcp-options"
	}
	return ""
}
func allowedFilters(op string) map[string]bool {
	fields := ""
	switch op {
	case "DescribeNatGateways":
		fields = "nat-gateway-id subnet-id vpc-id state connectivity-type nat-gateway-address.allocation-id nat-gateway-address.private-ip nat-gateway-address.public-ip"
	case "DescribeVpcEndpoints":
		fields = "vpc-endpoint-id vpc-id service-name vpc-endpoint-type state subnet-id route-table-id group-id owner-id"
	case "DescribeVpcEndpointServices":
		fields = "owner service-name service-region service-type supported-ip-address-types"
	case "DescribeLaunchTemplates":
		fields = "create-time launch-template-name"
	case "DescribeLaunchTemplateVersions":
		fields = "create-time ebs-optimized http-endpoint http-protocol-ipv4 http-tokens host-resource-group-arn iam-instance-profile image-id instance-type is-default-version kernel-id license-configuration-arn network-card-index ram-disk-id"
	case "DescribeAddresses":
		fields = "allocation-id association-id domain instance-id network-interface-id network-interface-owner-id private-ip-address public-ip public-ipv4-pool network-border-group"
	case "DescribeIamInstanceProfileAssociations":
		fields = "instance-id state"
	case "DescribeInstances":
		fields = "instance-id image-id instance-type instance-state-name instance-state-code reservation-id subnet-id vpc-id availability-zone availability-zone-id private-ip-address private-dns-name ip-address dns-name key-name client-token root-device-type architecture virtualization-type iam-instance-profile.arn group-id group-name network-interface.network-interface-id block-device-mapping.volume-id metadata-options.http-tokens metadata-options.http-endpoint metadata-options.instance-metadata-tags operator.managed operator.principal"
	case "DescribeInstanceStatus":
		fields = "instance-state-name instance-state-code availability-zone availability-zone-id instance-status.status instance-status.reachability system-status.status system-status.reachability attached-ebs-status.status application-status.status operator.managed operator.principal event.code event.description event.instance-event-id event.not-after event.not-before event.not-before-deadline"
	case "DescribeInstanceCreditSpecifications":
		fields = "instance-id"
	case "DescribeInstanceTypes":
		fields = instanceTypeFilterNames
	case "DescribeKeyPairs":
		fields = "key-pair-id fingerprint key-name"
	case "DescribeDhcpOptions":
		fields = "dhcp-options-id owner-id key value"
	case "DescribeVpcs":
		fields = "vpc-id cidr cidr-block cidrBlock state owner-id is-default dhcp-options-id instance-tenancy cidr-block-association.cidr-block cidr-block-association.association-id cidr-block-association.state"
	case "DescribeSubnets":
		fields = "subnet-id vpc-id cidr cidr-block cidrBlock state owner-id availability-zone availability-zone-id available-ip-address-count default-for-az defaultForAz map-public-ip-on-launch"
	case "DescribeSecurityGroups":
		fields = "group-id group-name vpc-id owner-id description ip-permission.from-port ip-permission.to-port ip-permission.protocol ip-permission.cidr ip-permission.ipv6-cidr ip-permission.group-id ip-permission.group-name ip-permission.user-id egress.ip-permission.from-port egress.ip-permission.to-port egress.ip-permission.protocol egress.ip-permission.cidr egress.ip-permission.ipv6-cidr egress.ip-permission.group-id egress.ip-permission.group-name egress.ip-permission.user-id"
	case "DescribeSecurityGroupRules":
		fields = "group-id group-owner-id security-group-rule-id is-egress"
	case "DescribeRouteTables":
		fields = "route-table-id vpc-id owner-id association.route-table-association-id association.route-table-id association.subnet-id association.main association.gateway-id route.destination-cidr-block route.gateway-id route.state route.origin"
	case "DescribeInternetGateways":
		fields = "internet-gateway-id owner-id attachment.vpc-id attachment.state"
	case "DescribeNetworkInterfaces":
		fields = "network-interface-id owner-id requester-id requester-managed availability-zone availability-zone-id subnet-id vpc-id mac-address description interface-type source-dest-check status private-ip-address private-dns-name group-id group-name addresses.private-ip-address addresses.primary addresses.private-dns-name association.allocation-id association.association-id association.ip-owner-id association.public-dns-name association.public-ip addresses.association.ip-owner-id addresses.association.public-ip attachment.attach-time attachment.attachment-id attachment.delete-on-termination attachment.device-index attachment.instance-id attachment.instance-owner-id attachment.nat-gateway-id attachment.status ipv6-addresses.ipv6-address ipv6-native operator.managed operator.principal"
	case "DescribeNetworkAcls":
		fields = "network-acl-id vpc-id owner-id default association.association-id association.network-acl-id association.subnet-id entry.cidr entry.egress entry.protocol entry.rule-action entry.rule-number entry.port-range.from entry.port-range.to entry.icmp.code entry.icmp.type"
	case "DescribeTags":
		fields = "resource-id resource-type key value"
	}
	out := map[string]bool{}
	if op != "DescribeInstanceStatus" && op != "DescribeIamInstanceProfileAssociations" && op != "DescribeLaunchTemplateVersions" {
		out["tag-key"], out["tag-value"], out["tag:"] = true, true, true
	}
	if op == "DescribeVpcEndpointServices" {
		delete(out, "tag-value")
	}
	for _, f := range strings.Fields(fields) {
		out[f] = true
	}
	return out
}

type compiledFilter struct {
	name     string
	patterns []*regexp.Regexp
}

func compileFilters(filters api.FilterList) []compiledFilter {
	out := make([]compiledFilter, 0, len(filters))
	for _, f := range filters {
		compiled := compiledFilter{name: str(f.Name)}
		for _, pattern := range f.Values {
			// EC2 filter wildcards do not apply path-separator semantics.
			var b strings.Builder
			b.WriteString("(?s)^")
			escaped := false
			for _, r := range pattern {
				if escaped {
					b.WriteString(regexp.QuoteMeta(string(r)))
					escaped = false
					continue
				}
				switch r {
				case '\\':
					escaped = true
				case '*':
					b.WriteString(".*")
				case '?':
					b.WriteString(".")
				default:
					b.WriteString(regexp.QuoteMeta(string(r)))
				}
			}
			if escaped {
				b.WriteString(`\\`)
			}
			b.WriteByte('$')
			compiled.patterns = append(compiled.patterns, regexp.MustCompile(b.String()))
		}
		out = append(out, compiled)
	}
	return out
}
func (f compiledFilter) matches(value string) bool {
	for _, pattern := range f.patterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}
func matchesFilters(item pageItem, filters []compiledFilter) bool {
	for _, f := range filters {
		matched := false
		switch {
		case strings.HasPrefix(f.name, "tag:"):
			for _, t := range item.Tags {
				if str(t.Key) == strings.TrimPrefix(f.name, "tag:") && f.matches(str(t.Value)) {
					matched = true
					break
				}
			}
		case f.name == "tag-key":
			for _, t := range item.Tags {
				if f.matches(str(t.Key)) {
					matched = true
					break
				}
			}
		case f.name == "tag-value":
			for _, t := range item.Tags {
				if f.matches(str(t.Value)) {
					matched = true
					break
				}
			}
		default:
			for _, v := range item.Fields[f.name] {
				if f.matches(v) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}
	return true
}
func selectPage(ctx context.Context, op string, ids []string, filters api.FilterList, max *int32, token *api.String, items []pageItem) ([]string, *api.String, error) {
	if max != nil && (*max < 5 || *max > 1000) {
		return nil, nil, failure("InvalidParameterValue", "Value for parameter maxResults is invalid. The valid range is 5 to 1000.")
	}
	if len(ids) > 0 && (max != nil || str(token) != "") {
		return nil, nil, failure("InvalidParameterCombination", "The parameter MaxResults cannot be used with the parameter resource IDs.")
	}
	return selectPageItems(ctx, op, ids, filters, max, token, items)
}

// selectPageItems shares filtering and scoped cursors; operation owners admit
// their request bounds before selection.
func selectPageItems(ctx context.Context, op string, ids []string, filters api.FilterList, max *int32, token *api.String, items []pageItem) ([]string, *api.String, error) {
	allow := allowedFilters(op)
	for _, f := range filters {
		if !allow[str(f.Name)] && !(allow["tag:"] && strings.HasPrefix(str(f.Name), "tag:")) {
			return nil, nil, failure("InvalidParameterValue", "The filter '"+str(f.Name)+"' is invalid")
		}
	}
	kind := map[string]string{"DescribeVpcs": "vpc", "DescribeSubnets": "subnet", "DescribeSecurityGroups": "security-group", "DescribeSecurityGroupRules": "security-group-rule", "DescribeRouteTables": "route-table", "DescribeInternetGateways": "internet-gateway", "DescribeNetworkInterfaces": "network-interface", "DescribeNetworkAcls": "network-acl", "DescribeDhcpOptions": "dhcp-options"}[op]
	if op == "DescribeNatGateways" {
		kind = "natgateway"
	}
	if op == "DescribeVpcEndpoints" {
		kind = "vpc-endpoint"
	}
	if op == "DescribeInstances" || op == "DescribeInstanceStatus" || op == "DescribeInstanceCreditSpecifications" {
		kind = "instance"
	}
	wanted := map[string]bool{}
	for _, id := range ids {
		wanted[id] = true
		found := false
		for _, item := range items {
			if item.ID == id {
				found = true
				break
			}
		}
		if !found {
			return nil, nil, missing(kind, id)
		}
	}
	// These operations paginate a VPC-scoped scan, then apply other filters.
	// Native SG tokens reject changing the VPC selection but accept tag changes.
	selection := filters
	if op == "DescribeSecurityGroups" || op == "DescribeSubnets" {
		selection = nil
		for _, filter := range filters {
			if str(filter.Name) == "vpc-id" {
				selection = append(selection, filter)
			}
		}
	}
	encoded, _ := json.Marshal(selection)
	digest := fmt.Sprintf("%x", sha256.Sum256(encoded))
	cursor := pageToken{Scope: scopeFor(ctx), Operation: op, Selection: digest}
	if str(token) != "" {
		cursor = pageToken{}
		raw, err := base64.RawURLEncoding.DecodeString(str(token))
		if err != nil || json.Unmarshal(raw, &cursor) != nil || cursor.Scope != scopeFor(ctx) || cursor.Operation != op || cursor.Selection == "" || cursor.After == "" || (op != "DescribeSubnets" && cursor.Selection != digest) {
			if op == "DescribeIamInstanceProfileAssociations" {
				return nil, nil, failure("InvalidNextToken", "Pagination token is invalid")
			}
			return nil, nil, failure("InvalidParameterValue", "The nextToken is invalid.")
		}
	}
	slices.SortFunc(items, func(a, b pageItem) int { return strings.Compare(a.ID, b.ID) })
	selected := []string{}
	limit := len(items) + 1
	if max != nil {
		limit = int(*max)
	}
	compiled := compileFilters(filters)
	if op == "DescribeSubnets" && cursor.Selection != digest {
		// A changed VPC selection retains a scan cursor even when the new
		// selection removes every item from this continuation window.
		scanned := 0
		for _, item := range items {
			if item.ID <= cursor.After {
				continue
			}
			cursor.After = item.ID
			scanned++
			if matchesFilters(item, compiled) {
				selected = append(selected, item.ID)
			}
			if scanned == limit {
				break
			}
		}
		if scanned > 0 {
			cursor.Selection = digest
			raw, _ := json.Marshal(cursor)
			return selected, new(api.String(base64.RawURLEncoding.EncodeToString(raw))), nil
		}
		return selected, nil, nil
	}
	if op == "DescribeSecurityGroups" && len(ids) == 0 {
		// MaxResults limits the scan, not the number of matches after tag/name
		// filtering. A final nonempty scan still has a token when MaxResults is
		// supplied; omitting MaxResults exhausts the remainder in one response.
		scanned := 0
		scopeFilters := compileFilters(selection)
		for _, item := range items {
			if item.ID <= cursor.After || !matchesFilters(item, scopeFilters) {
				continue
			}
			cursor.After = item.ID
			scanned++
			if matchesFilters(item, compiled) {
				selected = append(selected, item.ID)
			}
			if scanned == limit {
				break
			}
		}
		if scanned > 0 && max != nil {
			raw, _ := json.Marshal(cursor)
			return selected, new(api.String(base64.RawURLEncoding.EncodeToString(raw))), nil
		}
		return selected, nil, nil
	}
	for _, item := range items {
		if item.ID <= cursor.After || len(wanted) > 0 && !wanted[item.ID] || !matchesFilters(item, compiled) {
			continue
		}
		selected = append(selected, item.ID)
		if len(selected) > limit {
			break
		}
	}
	more := len(selected) > limit
	if more {
		selected = selected[:limit]
	}
	if len(selected) > 0 && more {
		cursor.After = selected[len(selected)-1]
		cursor.Selection = digest
		raw, _ := json.Marshal(cursor)
		return selected, new(api.String(base64.RawURLEncoding.EncodeToString(raw))), nil
	}
	return selected, nil, nil
}
