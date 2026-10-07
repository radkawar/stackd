package ec2

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strconv"

	api "stackd/internal/awsapi/ec2"
)

func newNetworkACL(vpc VPCRecord, id string, isDefault bool, tags api.TagList) NetworkACLRecord {
	entries := api.NetworkAclEntryList{}
	for _, egress := range []bool{true, false} {
		if isDefault {
			entries = append(entries, api.NetworkAclEntry{CidrBlock: new(api.String("0.0.0.0/0")), Egress: new(api.Boolean(egress)), Protocol: new(api.String("-1")), RuleAction: new(api.RuleActionAllow), RuleNumber: new(api.Integer(100))})
		}
		entries = append(entries, api.NetworkAclEntry{CidrBlock: new(api.String("0.0.0.0/0")), Egress: new(api.Boolean(egress)), Protocol: new(api.String("-1")), RuleAction: new(api.RuleActionDeny), RuleNumber: new(api.Integer(32767))})
	}
	return NetworkACLRecord{Key: ResourceKey{Scope: vpc.Key.Scope, ID: id}, Data: api.NetworkAcl{
		NetworkAclId: new(api.String(id)), VpcId: new(api.String(vpc.Key.ID)), OwnerId: new(api.String(vpc.Key.Scope.AccountID)), IsDefault: new(api.Boolean(isDefault)), Tags: tags,
		Entries: entries, Associations: api.NetworkAclAssociationList{},
	}}
}

func networkACLFor(ctx context.Context, tx Reader, id string) (NetworkACLRecord, error) {
	record, err := tx.NetworkACL(key(ctx, id))
	if errors.Is(err, ErrNotFound) {
		return record, missing("network-acl", id)
	}
	return record, err
}

func (s *Service) createNetworkACL(ctx context.Context, tx Transaction, req *api.CreateNetworkAclRequest) (*api.CreateNetworkAclResult, error) {
	tags, err := CreationTags(req.TagSpecifications, "network-acl")
	if err != nil {
		return nil, err
	}
	if err := s.authorizeCreate(ctx, "CreateNetworkAcl", "network-acl", "*", tags); err != nil {
		return nil, err
	}
	vpc, err := routingVPCFor(ctx, tx, str(req.VpcId))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "CreateNetworkAcl", "vpc", vpc.Key.ID, vpc.Data.Tags); err != nil {
		return nil, err
	}
	creation, err := networkCreation(tx, vpc.Key.Scope, "CreateNetworkAcl", req.ClientToken, vpc.Key.ID, tags)
	if err != nil {
		return nil, err
	}
	if err := dryRun(req.DryRun); err != nil {
		return nil, err
	}
	if creation.ResourceID != "" {
		record, err := tx.NetworkACL(ResourceKey{Scope: vpc.Key.Scope, ID: creation.ResourceID})
		if errors.Is(err, ErrNotFound) {
			return nil, creationMismatch()
		}
		if err != nil {
			return nil, err
		}
		record.Data.Tags = creation.Tags
		return networkACLCreateResult(record.Data, creation.clientToken()), nil
	}
	id, err := tx.NextID(scopeFor(ctx), "acl")
	if err != nil {
		return nil, err
	}
	record := newNetworkACL(vpc, id, false, tags)
	if err := tx.PutNetworkACL(record); err != nil {
		return nil, err
	}
	if creation.Key.Token != "" {
		creation.ResourceID = id
		if err := tx.PutNetworkCreation(creation); err != nil {
			return nil, err
		}
	}
	return networkACLCreateResult(record.Data, creation.clientToken()), nil
}

// The repository has detached this data. Empty protocol-specific structures
// belong only to the create response; existing entry values remain unchanged.
func networkACLCreateResult(data api.NetworkAcl, token *api.String) *api.CreateNetworkAclResult {
	for i := range data.Entries {
		if data.Entries[i].IcmpTypeCode == nil {
			data.Entries[i].IcmpTypeCode = &api.IcmpTypeCode{}
		}
		if data.Entries[i].PortRange == nil {
			data.Entries[i].PortRange = &api.PortRange{}
		}
	}
	return &api.CreateNetworkAclResult{NetworkAcl: &data, ClientToken: token}
}

func (s *Service) describeNetworkACLs(ctx context.Context, tx Transaction, req *api.DescribeNetworkAclsRequest) (*api.DescribeNetworkAclsResult, error) {
	if err := s.authorize(ctx, "DescribeNetworkAcls", "", "*", nil); err != nil {
		return nil, err
	}
	if err := dryRun(req.DryRun); err != nil {
		return nil, err
	}
	records, err := s.visibleNetworkACLs(ctx, tx)
	if err != nil {
		return nil, err
	}
	items := make([]pageItem, 0, len(records))
	byID := make(map[string]api.NetworkAcl, len(records))
	for _, record := range records {
		data := record.Data
		fields := map[string][]string{"network-acl-id": {record.Key.ID}, "vpc-id": {str(data.VpcId)}, "owner-id": {str(data.OwnerId)}, "default": {strconv.FormatBool(routingBool(data.IsDefault))}, "association.association-id": {}, "association.network-acl-id": {}, "association.subnet-id": {}, "entry.cidr": {}, "entry.egress": {}, "entry.protocol": {}, "entry.rule-action": {}, "entry.rule-number": {}, "entry.port-range.from": {}, "entry.port-range.to": {}, "entry.icmp.code": {}, "entry.icmp.type": {}}
		for _, association := range data.Associations {
			fields["association.association-id"] = append(fields["association.association-id"], str(association.NetworkAclAssociationId))
			fields["association.network-acl-id"] = append(fields["association.network-acl-id"], str(association.NetworkAclId))
			fields["association.subnet-id"] = append(fields["association.subnet-id"], str(association.SubnetId))
		}
		for _, entry := range data.Entries {
			fields["entry.cidr"] = append(fields["entry.cidr"], str(entry.CidrBlock))
			fields["entry.egress"] = append(fields["entry.egress"], strconv.FormatBool(routingBool(entry.Egress)))
			fields["entry.protocol"] = append(fields["entry.protocol"], str(entry.Protocol))
			fields["entry.rule-action"] = append(fields["entry.rule-action"], str(entry.RuleAction))
			if entry.RuleNumber != nil {
				fields["entry.rule-number"] = append(fields["entry.rule-number"], strconv.Itoa(int(*entry.RuleNumber)))
			}
			if entry.PortRange != nil {
				if entry.PortRange.From != nil {
					fields["entry.port-range.from"] = append(fields["entry.port-range.from"], strconv.Itoa(int(*entry.PortRange.From)))
				}
				if entry.PortRange.To != nil {
					fields["entry.port-range.to"] = append(fields["entry.port-range.to"], strconv.Itoa(int(*entry.PortRange.To)))
				}
			}
			if entry.IcmpTypeCode != nil {
				if entry.IcmpTypeCode.Code != nil {
					fields["entry.icmp.code"] = append(fields["entry.icmp.code"], strconv.Itoa(int(*entry.IcmpTypeCode.Code)))
				}
				if entry.IcmpTypeCode.Type != nil {
					fields["entry.icmp.type"] = append(fields["entry.icmp.type"], strconv.Itoa(int(*entry.IcmpTypeCode.Type)))
				}
			}
		}
		items = append(items, pageItem{ID: record.Key.ID, Tags: data.Tags, Fields: fields})
		byID[record.Key.ID] = data
	}
	ids, token, err := selectPage(ctx, "DescribeNetworkAcls", stringsOf(req.NetworkAclIds), req.Filters, maxResults(req.MaxResults), req.NextToken, items)
	if err != nil {
		return nil, err
	}
	result := &api.DescribeNetworkAclsResult{NetworkAcls: api.NetworkAclList{}, NextToken: token}
	for _, id := range ids {
		result.NetworkAcls = append(result.NetworkAcls, byID[id])
	}
	return result, nil
}

func (s *Service) deleteNetworkACL(ctx context.Context, tx Transaction, req *api.DeleteNetworkAclRequest) (*emptyResult, error) {
	record, err := networkACLFor(ctx, tx, str(req.NetworkAclId))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "DeleteNetworkAcl", "network-acl", record.Key.ID, record.Data.Tags); err != nil {
		return nil, err
	}
	if routingBool(record.Data.IsDefault) || len(record.Data.Associations) != 0 {
		return nil, failure("DependencyViolation", fmt.Sprintf("The networkAcl '%s' has dependencies and cannot be deleted.", record.Key.ID))
	}
	if err := dryRun(req.DryRun); err != nil {
		return nil, err
	}
	if err := tx.DeleteNetworkACL(record.Key); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}

func networkACLEntryNumber(number *api.Integer, egress *api.Boolean) error {
	if number == nil || egress == nil {
		return failure("MissingParameter", "RuleNumber and Egress are required")
	}
	if *number < 1 || *number > 32766 {
		return failure("InvalidParameterValue", "RuleNumber must be between 1 and 32766; the default deny rule cannot be changed")
	}
	return nil
}

func networkACLEntry(req *api.CreateNetworkAclEntryRequest) (api.NetworkAclEntry, error) {
	entry := api.NetworkAclEntry{}
	if err := networkACLEntryNumber(req.RuleNumber, req.Egress); err != nil {
		return entry, err
	}
	if req.Ipv6CidrBlock != nil {
		return entry, unsupported("IPv6 network ACL entries are not supported")
	}
	if req.Protocol == nil || req.RuleAction == nil || req.CidrBlock == nil {
		return entry, failure("MissingParameter", "Protocol, RuleAction and CidrBlock are required")
	}
	if *req.RuleAction != api.RuleActionAllow && *req.RuleAction != api.RuleActionDeny {
		return entry, failure("InvalidParameterValue", "RuleAction must be allow or deny")
	}
	protocol, err := strconv.Atoi(str(req.Protocol))
	if err != nil || protocol < -1 || protocol > 255 {
		return entry, failure("InvalidParameterValue", "Protocol must be -1 or a number from 0 through 255")
	}
	cidr, err := canonicalCIDR(str(req.CidrBlock))
	if err != nil {
		return entry, err
	}
	prefix, _ := netip.ParsePrefix(cidr)
	if !prefix.Addr().Is4() {
		return entry, failure("InvalidParameterValue", "CidrBlock must contain an IPv4 CIDR")
	}
	entry = api.NetworkAclEntry{CidrBlock: new(api.String(cidr)), Egress: new(*req.Egress), Protocol: new(api.String(strconv.Itoa(protocol))), RuleAction: new(*req.RuleAction), RuleNumber: new(*req.RuleNumber)}
	if protocol == 6 || protocol == 17 {
		p := req.PortRange
		if p == nil || p.From == nil || p.To == nil {
			return api.NetworkAclEntry{}, failure("MissingParameter", "PortRange.From and PortRange.To are required for TCP and UDP")
		}
		if *p.From < 0 || *p.To > 65535 || *p.From > *p.To {
			return api.NetworkAclEntry{}, failure("InvalidParameterValue", "PortRange must be ordered and within 0 through 65535")
		}
		entry.PortRange = &api.PortRange{From: new(*p.From), To: new(*p.To)}
	} else if req.PortRange != nil {
		return api.NetworkAclEntry{}, unsupported("PortRange is supported only for TCP and UDP network ACL entries")
	}
	if protocol == 1 {
		icmp := req.IcmpTypeCode
		if icmp == nil || icmp.Type == nil || icmp.Code == nil {
			return api.NetworkAclEntry{}, failure("MissingParameter", "IcmpTypeCode.Type and IcmpTypeCode.Code are required for ICMP")
		}
		if *icmp.Type < -1 || *icmp.Type > 255 || *icmp.Code < -1 || *icmp.Code > 255 || (*icmp.Type == -1 && *icmp.Code != -1) {
			return api.NetworkAclEntry{}, failure("InvalidParameterValue", "Invalid ICMP type or code")
		}
		entry.IcmpTypeCode = &api.IcmpTypeCode{Type: new(*icmp.Type), Code: new(*icmp.Code)}
	} else if req.IcmpTypeCode != nil {
		return api.NetworkAclEntry{}, unsupported("IcmpTypeCode is supported only for ICMP network ACL entries")
	}
	return entry, nil
}

func networkACLEntryIndex(entries api.NetworkAclEntryList, number api.Integer, egress bool) int {
	for i, entry := range entries {
		if entry.RuleNumber != nil && *entry.RuleNumber == number && routingBool(entry.Egress) == egress {
			return i
		}
	}
	return -1
}

func absentNetworkACLEntry(id string, number api.Integer, egress bool) error {
	direction := "ingress"
	if egress {
		direction = "egress"
	}
	return failure("InvalidNetworkAclEntry.NotFound", fmt.Sprintf("no %s entry with number %d in network ACL %s", direction, number, id))
}

func (s *Service) writeNetworkACLEntry(ctx context.Context, tx Transaction, req *api.CreateNetworkAclEntryRequest, replace bool) (*emptyResult, error) {
	action := "CreateNetworkAclEntry"
	if replace {
		action = "ReplaceNetworkAclEntry"
	}
	record, err := networkACLFor(ctx, tx, str(req.NetworkAclId))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, action, "network-acl", record.Key.ID, record.Data.Tags); err != nil {
		return nil, err
	}
	entry, err := networkACLEntry(req)
	if err != nil {
		return nil, err
	}
	index := networkACLEntryIndex(record.Data.Entries, *entry.RuleNumber, routingBool(entry.Egress))
	if replace && index < 0 {
		return nil, absentNetworkACLEntry(record.Key.ID, *entry.RuleNumber, routingBool(entry.Egress))
	}
	if !replace && index >= 0 && !reflect.DeepEqual(record.Data.Entries[index], entry) {
		return nil, failure("NetworkAclEntryAlreadyExists", "A different entry already exists with this rule number and direction")
	}
	if err := dryRun(req.DryRun); err != nil {
		return nil, err
	}
	slot := record.Key.ID + "|" + strconv.FormatBool(routingBool(entry.Egress)) + "|" + strconv.FormatInt(int64(*entry.RuleNumber), 10)
	if err := relationAdmission(ctx, tx, "NetworkAclEntry", slot, slot); err != nil {
		return nil, err
	}
	if index >= 0 {
		record.Data.Entries[index] = entry
	} else {
		record.Data.Entries = append(record.Data.Entries, entry)
	}
	sort.Slice(record.Data.Entries, func(i, j int) bool {
		a, b := record.Data.Entries[i], record.Data.Entries[j]
		if routingBool(a.Egress) != routingBool(b.Egress) {
			return routingBool(a.Egress)
		}
		return *a.RuleNumber < *b.RuleNumber
	})
	if err := tx.PutNetworkACL(record); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}

func (s *Service) createNetworkACLEntry(ctx context.Context, tx Transaction, req *api.CreateNetworkAclEntryRequest) (*emptyResult, error) {
	return s.writeNetworkACLEntry(ctx, tx, req, false)
}

func (s *Service) replaceNetworkACLEntry(ctx context.Context, tx Transaction, req *api.ReplaceNetworkAclEntryRequest) (*emptyResult, error) {
	return s.writeNetworkACLEntry(ctx, tx, &api.CreateNetworkAclEntryRequest{
		NetworkAclId: req.NetworkAclId, RuleNumber: req.RuleNumber, Egress: req.Egress, Protocol: req.Protocol, RuleAction: req.RuleAction,
		CidrBlock: req.CidrBlock, Ipv6CidrBlock: req.Ipv6CidrBlock, PortRange: req.PortRange, IcmpTypeCode: req.IcmpTypeCode, DryRun: req.DryRun,
	}, true)
}

func (s *Service) deleteNetworkACLEntry(ctx context.Context, tx Transaction, req *api.DeleteNetworkAclEntryRequest) (*emptyResult, error) {
	record, err := networkACLFor(ctx, tx, str(req.NetworkAclId))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "DeleteNetworkAclEntry", "network-acl", record.Key.ID, record.Data.Tags); err != nil {
		return nil, err
	}
	if err := networkACLEntryNumber(req.RuleNumber, req.Egress); err != nil {
		return nil, err
	}
	index := networkACLEntryIndex(record.Data.Entries, *req.RuleNumber, routingBool(req.Egress))
	if index < 0 {
		return nil, absentNetworkACLEntry(record.Key.ID, *req.RuleNumber, routingBool(req.Egress))
	}
	if err := dryRun(req.DryRun); err != nil {
		return nil, err
	}
	slot := record.Key.ID + "|" + strconv.FormatBool(routingBool(req.Egress)) + "|" + strconv.FormatInt(int64(*req.RuleNumber), 10)
	if err := relationAdmission(ctx, tx, "NetworkAclEntry", slot, ""); err != nil {
		return nil, err
	}
	record.Data.Entries = append(record.Data.Entries[:index], record.Data.Entries[index+1:]...)
	if err := tx.PutNetworkACL(record); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}

func networkACLAssociationFor(ctx context.Context, tx Reader, id string) (NetworkACLRecord, int, error) {
	records, err := tx.NetworkACLs(scopeFor(ctx))
	if err != nil {
		return NetworkACLRecord{}, 0, err
	}
	for _, record := range records {
		for i, association := range record.Data.Associations {
			if str(association.NetworkAclAssociationId) == id {
				return record, i, nil
			}
		}
	}
	return NetworkACLRecord{}, 0, failure("InvalidAssociationID.NotFound", fmt.Sprintf("The association ID '%s' does not exist", id))
}

func (s *Service) replaceNetworkACLAssociation(ctx context.Context, tx Transaction, req *api.ReplaceNetworkAclAssociationRequest) (*api.ReplaceNetworkAclAssociationResult, error) {
	source, index, err := networkACLAssociationFor(ctx, tx, str(req.AssociationId))
	if err != nil {
		return nil, err
	}
	target, err := networkACLFor(ctx, tx, str(req.NetworkAclId))
	if err != nil {
		return nil, err
	}
	for _, record := range []NetworkACLRecord{source, target} {
		if err := s.authorize(ctx, "ReplaceNetworkAclAssociation", "network-acl", record.Key.ID, record.Data.Tags); err != nil {
			return nil, err
		}
	}
	association := source.Data.Associations[index]
	subnet, err := tx.Subnet(key(ctx, str(association.SubnetId)))
	if errors.Is(err, ErrNotFound) {
		return nil, missing("subnet", str(association.SubnetId))
	}
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "ReplaceNetworkAclAssociation", "subnet", subnet.Key.ID, subnet.Data.Tags); err != nil {
		return nil, err
	}
	if str(source.Data.VpcId) != str(target.Data.VpcId) || str(subnet.Data.VpcId) != str(target.Data.VpcId) {
		return nil, failure("InvalidParameterValue", "Network ACL and subnet belong to different networks")
	}
	if err := dryRun(req.DryRun); err != nil {
		return nil, err
	}
	id, err := tx.NextID(scopeFor(ctx), "aclassoc")
	if err != nil {
		return nil, err
	}
	if err := relationAdmission(ctx, tx, "SubnetNetworkAclAssociation", subnet.Key.ID, id); err != nil {
		return nil, err
	}
	association.NetworkAclAssociationId = new(api.String(id))
	association.NetworkAclId = new(api.String(target.Key.ID))
	if source.Key == target.Key {
		source.Data.Associations[index] = association
		if err := tx.PutNetworkACL(source); err != nil {
			return nil, err
		}
	} else {
		source.Data.Associations = append(source.Data.Associations[:index], source.Data.Associations[index+1:]...)
		target.Data.Associations = append(target.Data.Associations, association)
		if err := tx.PutNetworkACL(source); err != nil {
			return nil, err
		}
		if err := tx.PutNetworkACL(target); err != nil {
			return nil, err
		}
	}
	return &api.ReplaceNetworkAclAssociationResult{NewAssociationId: new(api.String(id))}, nil
}
