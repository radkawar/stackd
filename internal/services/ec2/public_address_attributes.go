package ec2

import (
	"context"
	"strings"

	api "stackd/internal/awsapi/ec2"
)

func validateAllocationID(id string) error {
	valid := strings.HasPrefix(id, "eipalloc-") && (len(id) == 17 || len(id) == 26)
	if valid {
		for _, c := range id[9:] {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				valid = false
				break
			}
		}
	}
	if !valid {
		return failure("InvalidAllocationID.Malformed", "Invalid allocation ID '"+id+"'.")
	}
	return nil
}

func (s *Service) describeAddressesAttribute(ctx context.Context, tx Transaction, in *api.DescribeAddressesAttributeRequest) (*api.DescribeAddressesAttributeResult, error) {
	if err := s.authorize(ctx, "DescribeAddressesAttribute", "", "*", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if in.Attribute != nil && str(in.Attribute) != "domain-name" {
		return nil, failure("InvalidParameterValue", "The attribute must be domain-name.")
	}
	if in.MaxResults != nil && (*in.MaxResults < 1 || *in.MaxResults > 1000) {
		return nil, failure("InvalidParameterValue", "Value for parameter maxResults is invalid. The valid range is 1 to 1000.")
	}
	for _, id := range in.AllocationIds {
		if err := validateAllocationID(string(id)); err != nil {
			return nil, err
		}
		if _, err := loadPublicAddress(ctx, tx, string(id), ""); err != nil {
			return nil, err
		}
	}
	rows, err := tx.PublicAddresses(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	items := make([]pageItem, 0, len(rows))
	data := make(map[string]api.AddressAttribute, len(rows))
	for _, row := range rows {
		if row.Automatic {
			continue
		}
		items = append(items, pageItem{ID: row.Key.ID})
		// No custom reverse DNS is installed for these allocations. Absence is
		// real state, not a synthesized AWS hostname or a successful PTR update.
		// TODO: Comeback implement ModifyAddressAttribute/ResetAddressAttribute
		// only with real forward-DNS verification and reverse-DNS publication.
		data[row.Key.ID] = api.AddressAttribute{AllocationId: new(api.AllocationId(row.Key.ID)), PublicIp: new(api.PublicIpAddress(str(row.Data.PublicIp)))}
	}
	ids, next, err := selectPageItems(ctx, "DescribeAddressesAttribute", stringsOf(in.AllocationIds), nil, maxResults(in.MaxResults), (*api.String)(in.NextToken), items)
	if err != nil {
		return nil, err
	}
	out := &api.DescribeAddressesAttributeResult{Addresses: api.AddressSet{}, NextToken: (*api.NextToken)(next)}
	for _, id := range ids {
		out.Addresses = append(out.Addresses, data[id])
	}
	return out, nil
}
