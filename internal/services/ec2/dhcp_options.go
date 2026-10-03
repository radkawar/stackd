package ec2

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/ec2"
)

func registerDHCPOptions(s *Service) {
	register(s, "CreateDhcpOptions", s.createDHCPOptions)
	register(s, "DescribeDhcpOptions", s.describeDHCPOptions)
	register(s, "AssociateDhcpOptions", s.associateDHCPOptions)
	register(s, "DeleteDhcpOptions", s.deleteDHCPOptions)
}

// The regional default is initialized once, in the same transaction as its
// first consumer. The separate row survives deletion so discovery cannot
// resurrect a default the account deliberately removed.
func ensureDefaultDHCPOptions(ctx context.Context, tx Transaction) (string, error) {
	scope := scopeFor(ctx)
	defaults, err := tx.DHCPDefaults(scope)
	if err == nil {
		if defaults.OptionsID == "" {
			return "default", nil
		}
		if _, err := tx.DHCPOptions(ResourceKey{Scope: scope, ID: defaults.OptionsID}); err != nil {
			return "", err
		}
		return defaults.OptionsID, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return "", err
	}
	id, err := tx.NextID(scope, "dopt")
	if err != nil {
		return "", err
	}
	domain := scope.Region + ".compute.internal"
	if scope.Region == "us-east-1" {
		domain = "ec2.internal"
	}
	record := DHCPOptionsRecord{Key: ResourceKey{Scope: scope, ID: id}, Data: api.DhcpOptions{
		DhcpOptionsId: new(api.String(id)), OwnerId: new(api.String(scope.AccountID)), Tags: api.TagList{},
		DhcpConfigurations: api.DhcpConfigurationList{
			{Key: new(api.String("domain-name")), Values: api.DhcpConfigurationValueList{{Value: new(api.String(domain))}}},
			{Key: new(api.String("domain-name-servers")), Values: api.DhcpConfigurationValueList{{Value: new(api.String("AmazonProvidedDNS"))}}},
		},
	}}
	if err := tx.PutDHCPOptions(record); err != nil {
		return "", err
	}
	if err := tx.PutDHCPDefaults(DHCPDefaultsRecord{Scope: scope, OptionsID: id}); err != nil {
		return "", err
	}
	return id, nil
}

func dhcpOptionsFor(ctx context.Context, tx Reader, id string) (DHCPOptionsRecord, error) {
	if !strings.HasPrefix(id, "dopt-") || (len(id) != 13 && len(id) != 22) {
		return DHCPOptionsRecord{}, failure("InvalidDhcpOptionsId.Malformed", fmt.Sprintf("Invalid id: %q (expecting \"dopt-...\")", id))
	}
	for _, c := range id[5:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return DHCPOptionsRecord{}, failure("InvalidDhcpOptionsId.Malformed", fmt.Sprintf("Invalid id: %q (expecting \"dopt-...\")", id))
		}
	}
	record, err := tx.DHCPOptions(key(ctx, id))
	if errors.Is(err, ErrNotFound) {
		return record, missing("dhcp-options", id)
	}
	return record, err
}

func dhcpConfigurations(input api.NewDhcpConfigurationList) (api.DhcpConfigurationList, error) {
	if len(input) == 0 {
		return nil, failure("MissingParameter", "The request must contain the parameter dhcpConfigurations")
	}
	valuesByKey := map[string][]string{}
	for _, config := range input {
		name := str(config.Key)
		switch name {
		case "domain-name", "domain-name-servers", "ntp-servers", "netbios-name-servers", "netbios-node-type", "ipv6-address-preferred-lease-time":
		default:
			return nil, failure("InvalidParameterValue", "Unknown DHCP option: "+name)
		}
		if len(config.Values) == 0 {
			return nil, failure("InvalidParameterValue", "Empty DHCP option value: "+name)
		}
		for _, value := range config.Values {
			valuesByKey[name] = append(valuesByKey[name], strings.Split(string(value), ",")...)
		}
	}
	names := make([]string, 0, len(valuesByKey))
	for name := range valuesByKey {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make(api.DhcpConfigurationList, 0, len(names))
	for _, name := range names {
		values := valuesByKey[name]
		invalid := func() error {
			return failure("InvalidParameterValue", "Invalid DHCP option value for "+name+": "+strings.Join(values, ","))
		}
		switch name {
		case "domain-name":
			for _, value := range values {
				if value == "" || len(value) > 255 {
					return nil, invalid()
				}
			}
		case "domain-name-servers", "ntp-servers", "netbios-name-servers":
			v4, v6 := 0, 0
			for _, value := range values {
				if name == "domain-name-servers" && value == "AmazonProvidedDNS" {
					v4++
					continue
				}
				address, err := netip.ParseAddr(value)
				if err != nil || address.Zone() != "" || (name == "netbios-name-servers" && !address.Is4()) {
					return nil, invalid()
				}
				if address.Is4() {
					v4++
				} else {
					v6++
				}
			}
			if v4 > 4 || v6 > 4 {
				return nil, invalid()
			}
		case "netbios-node-type":
			// Native accepts the signed-byte range, not only the four
			// node types recommended in the user guide.
			if len(values) != 1 {
				return nil, invalid()
			}
			if _, err := strconv.ParseInt(values[0], 10, 8); err != nil {
				return nil, invalid()
			}
		case "ipv6-address-preferred-lease-time":
			if len(values) != 1 {
				return nil, invalid()
			}
			n, err := strconv.ParseInt(values[0], 10, 32)
			if err != nil || n < 140 {
				return nil, invalid()
			}
		}
		config := api.DhcpConfiguration{Key: new(api.String(name)), Values: make(api.DhcpConfigurationValueList, 0, len(values))}
		for _, value := range values {
			config.Values = append(config.Values, api.AttributeValue{Value: new(api.String(value))})
		}
		out = append(out, config)
	}
	return out, nil
}

func (s *Service) createDHCPOptions(ctx context.Context, tx Transaction, req *api.CreateDhcpOptionsRequest) (*api.CreateDhcpOptionsResult, error) {
	tags, err := CreationTags(req.TagSpecifications, "dhcp-options")
	if err != nil {
		return nil, err
	}
	if err := s.authorizeCreate(ctx, "CreateDhcpOptions", "dhcp-options", "*", tags); err != nil {
		return nil, err
	}
	if err := dryRun(req.DryRun); err != nil {
		return nil, err
	}
	configs, err := dhcpConfigurations(req.DhcpConfigurations)
	if err != nil {
		return nil, err
	}
	id, err := tx.NextID(scopeFor(ctx), "dopt")
	if err != nil {
		return nil, err
	}
	if tags == nil {
		tags = api.TagList{}
	}
	record := DHCPOptionsRecord{Key: key(ctx, id), Data: api.DhcpOptions{DhcpOptionsId: new(api.String(id)), OwnerId: new(api.String(scopeFor(ctx).AccountID)), Tags: tags, DhcpConfigurations: configs}}
	if err := tx.PutDHCPOptions(record); err != nil {
		return nil, err
	}
	return &api.CreateDhcpOptionsResult{DhcpOptions: &record.Data}, nil
}

func (s *Service) describeDHCPOptions(ctx context.Context, tx Transaction, req *api.DescribeDhcpOptionsRequest) (*api.DescribeDhcpOptionsResult, error) {
	if err := s.authorize(ctx, "DescribeDhcpOptions", "", "*", nil); err != nil {
		return nil, err
	}
	if err := dryRun(req.DryRun); err != nil {
		return nil, err
	}
	if _, err := ensureDefaultDHCPOptions(ctx, tx); err != nil {
		return nil, err
	}
	records, err := s.visibleDHCPOptions(ctx, tx)
	if err != nil {
		return nil, err
	}
	items := make([]pageItem, 0, len(records))
	byID := make(map[string]api.DhcpOptions, len(records))
	for _, record := range records {
		fields := map[string][]string{"dhcp-options-id": {record.Key.ID}, "owner-id": {str(record.Data.OwnerId)}, "key": {}, "value": {}}
		for _, config := range record.Data.DhcpConfigurations {
			fields["key"] = append(fields["key"], str(config.Key))
			for _, value := range config.Values {
				fields["value"] = append(fields["value"], str(value.Value))
			}
		}
		items = append(items, pageItem{ID: record.Key.ID, Tags: record.Data.Tags, Fields: fields})
		byID[record.Key.ID] = record.Data
	}
	ids, token, err := selectPage(ctx, "DescribeDhcpOptions", stringsOf(req.DhcpOptionsIds), req.Filters, maxResults(req.MaxResults), req.NextToken, items)
	if err != nil {
		return nil, err
	}
	out := &api.DescribeDhcpOptionsResult{DhcpOptions: api.DhcpOptionsList{}, NextToken: token}
	for _, id := range ids {
		out.DhcpOptions = append(out.DhcpOptions, byID[id])
	}
	return out, nil
}

func (s *Service) associateDHCPOptions(ctx context.Context, tx Transaction, req *api.AssociateDhcpOptionsRequest) (*emptyResult, error) {
	vpc, err := routingVPCFor(ctx, tx, str(req.VpcId))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "AssociateDhcpOptions", "vpc", vpc.Key.ID, vpc.Data.Tags); err != nil {
		return nil, err
	}
	id := str(req.DhcpOptionsId)
	if id != "default" {
		record, err := dhcpOptionsFor(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		if err := s.authorize(ctx, "AssociateDhcpOptions", "dhcp-options", id, record.Data.Tags); err != nil {
			return nil, err
		}
	}
	if err := dryRun(req.DryRun); err != nil {
		return nil, err
	}
	vpc.Data.DhcpOptionsId = new(api.String(id))
	if err := tx.PutVPC(vpc); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}

func (s *Service) deleteDHCPOptions(ctx context.Context, tx Transaction, req *api.DeleteDhcpOptionsRequest) (*emptyResult, error) {
	record, err := dhcpOptionsFor(ctx, tx, str(req.DhcpOptionsId))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "DeleteDhcpOptions", "dhcp-options", record.Key.ID, record.Data.Tags); err != nil {
		return nil, err
	}
	if err := dryRun(req.DryRun); err != nil {
		return nil, err
	}
	vpcs, err := tx.VPCs(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	for _, vpc := range vpcs {
		if str(vpc.Data.DhcpOptionsId) == record.Key.ID {
			return nil, failure("DependencyViolation", fmt.Sprintf("The dhcpOptions '%s' has dependencies and cannot be deleted.", record.Key.ID))
		}
	}
	defaults, err := tx.DHCPDefaults(scopeFor(ctx))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err == nil && defaults.OptionsID == record.Key.ID {
		defaults.OptionsID = ""
		if err := tx.PutDHCPDefaults(defaults); err != nil {
			return nil, err
		}
	}
	if err := tx.DeleteDHCPOptions(record.Key); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}
