package route53

import (
	"cmp"
	"fmt"
	"slices"
	api "stackd/internal/awsapi/route53"
	"strings"
)

func invalid(message string) error { return failure("InvalidChangeBatch", message) }
func recordKey(r RecordSet) string { return r.Name + "\x00" + r.Type + "\x00" + r.Identifier }
func recordEqual(a, b RecordSet) bool {
	return a.Name == b.Name && a.Type == b.Type && a.Identifier == b.Identifier && a.TTL == b.TTL && a.Weighted == b.Weighted && a.Weight == b.Weight && a.MultiValue == b.MultiValue && slices.Equal(a.Values, b.Values) && (a.Alias == nil && b.Alias == nil || a.Alias != nil && b.Alias != nil && *a.Alias == *b.Alias)
}
func (s *Service) recordInput(z Zone, in *api.ResourceRecordSet) (RecordSet, error) {
	if in == nil {
		return RecordSet{}, invalid("ResourceRecordSet is required.")
	}
	r := RecordSet{Type: value(in.Type), Identifier: value(in.SetIdentifier)}
	var e error
	r.Name, e = canonicalName(value(in.Name), true)
	if e != nil {
		return r, invalid(e.Error())
	}
	if !inZone(r.Name, z.Name) {
		return r, invalid("Record name is not within the hosted zone.")
	}
	if _, ok := recordTypes[r.Type]; !ok {
		return r, invalid("Unsupported resource record type.")
	}
	// TODO: Comeback: health, failover, latency, geolocation/geoproximity and CIDR routing require actual health/location authorities, not synthetic healthy answers.
	if in.HealthCheckId != nil || in.Failover != nil || in.GeoLocation != nil || in.GeoProximityLocation != nil || in.CidrRoutingConfig != nil || in.Region != nil || in.TrafficPolicyInstanceId != nil {
		return r, invalid("Health checks, failover, latency, geo, CIDR and traffic-policy routing are unavailable.")
	}
	r.Weighted = in.Weight != nil
	if r.Weighted {
		r.Weight = int64(*in.Weight)
		if r.Weight < 0 || r.Weight > 255 {
			return r, invalid("Weight must be between 0 and 255.")
		}
	}
	r.MultiValue = in.MultiValueAnswer != nil && bool(*in.MultiValueAnswer)
	if r.Weighted && r.MultiValue || r.Identifier != "" && !(r.Weighted || r.MultiValue) || (r.Weighted || r.MultiValue) && r.Identifier == "" {
		return r, invalid("Weighted and multivalue records require SetIdentifier and cannot combine routing policies.")
	}
	if len(r.Identifier) > 128 {
		return r, invalid("SetIdentifier exceeds 128 characters.")
	}
	if r.Type == "CNAME" && r.Name == z.Name {
		return r, invalid("CNAME is not permitted at the hosted zone apex.")
	}
	if r.Type == "NS" && strings.HasPrefix(r.Name, "*.") {
		return r, invalid("Wildcard NS records are not permitted.")
	}
	if r.Type == "SOA" && r.Name != z.Name {
		return r, invalid("SOA is only permitted at the hosted zone apex.")
	}
	if (r.Type == "NS" || r.Type == "SOA") && (r.Weighted || r.MultiValue) {
		return r, invalid("NS and SOA records require simple routing.")
	}
	if r.MultiValue && r.Type == "CNAME" {
		return r, invalid("CNAME records do not support multivalue routing.")
	}
	if in.AliasTarget != nil {
		a := in.AliasTarget
		if a.EvaluateTargetHealth == nil || bool(*a.EvaluateTargetHealth) {
			return r, invalid("EvaluateTargetHealth must be false; target-health routing is unavailable.")
		}
		if r.MultiValue || in.TTL != nil || len(in.ResourceRecords) != 0 {
			return r, invalid("Alias records cannot specify TTL, ResourceRecords or multivalue routing.")
		}
		// TODO: Comeback: extend same-zone aliases to the remaining supported record types; external aliases require their actual target owners.
		if r.Type != "A" && r.Type != "AAAA" {
			return r, invalid("Aliases currently support A and AAAA records only.")
		}
		name, e := canonicalName(value(a.DNSName), false)
		if e != nil {
			return r, invalid(e.Error())
		}
		r.Alias = &AliasTarget{HostedZoneID: cleanID(value(a.HostedZoneId)), DNSName: name}
		if r.Alias.HostedZoneID == "" {
			return r, invalid("Alias hosted zone ID is required.")
		}
		return r, nil
	}
	if in.TTL == nil || int64(*in.TTL) < 0 || int64(*in.TTL) > 2147483647 {
		return r, invalid("TTL must be between 0 and 2147483647.")
	}
	r.TTL = int64(*in.TTL)
	if len(in.ResourceRecords) == 0 || len(in.ResourceRecords) > 1000 {
		return r, invalid("ResourceRecords must contain between 1 and 1000 values.")
	}
	if (r.Type == "CNAME" || r.Type == "SOA" || r.Weighted || r.MultiValue) && len(in.ResourceRecords) != 1 {
		return r, invalid("CNAME, SOA, weighted and multivalue record sets require one value.")
	}
	for _, v := range in.ResourceRecords {
		_, canonical, e := parseRData(r.Type, value(v.Value))
		if e != nil {
			return r, invalid(e.Error())
		}
		r.Values = append(r.Values, canonical)
	}
	slices.Sort(r.Values)
	if len(slices.Compact(slices.Clone(r.Values))) != len(r.Values) {
		return r, invalid("Duplicate resource record values are not permitted.")
	}
	return r, nil
}
func validateRecords(z Zone) error {
	groups := map[string][]RecordSet{}
	names := map[string]bool{}
	for _, r := range z.Records {
		groups[r.Name+"\x00"+r.Type] = append(groups[r.Name+"\x00"+r.Type], r)
		names[r.Name] = names[r.Name] || r.Type == "CNAME"
	}
	for _, r := range z.Records {
		if names[r.Name] && r.Type != "CNAME" {
			return invalid("CNAME cannot coexist with other record types at the same name.")
		}
	}
	for _, group := range groups {
		first := group[0]
		if len(group) > 100 {
			return invalid("A routing group cannot exceed 100 record sets.")
		}
		for _, r := range group[1:] {
			if first.Identifier == "" || r.Identifier == "" || first.Weighted != r.Weighted || first.MultiValue != r.MultiValue {
				return invalid("Record sets with the same name/type must use the same routing policy.")
			}
			if first.Weighted && first.Alias == nil && r.Alias == nil && first.TTL != r.TTL {
				return invalid("Weighted records with the same name/type must have the same TTL.")
			}
		}
	}
	for _, r := range z.Records {
		if r.Alias != nil && r.Alias.HostedZoneID == z.ID {
			if !inZone(r.Alias.DNSName, z.Name) {
				return invalid("Same-zone alias target is outside the hosted zone.")
			}
			if delegationAt(z, r.Alias.DNSName) != nil {
				return invalid("Alias target is below a delegation boundary.")
			}
			if e := validateAliasChain(z, r, map[string]bool{}); e != nil {
				return e
			}
		}
	}
	return nil
}
func validateAliasChain(z Zone, r RecordSet, seen map[string]bool) error {
	if r.Alias == nil || r.Alias.HostedZoneID != z.ID {
		return nil
	}
	key := recordKey(r)
	if seen[key] {
		return invalid("Alias records cannot form a cycle.")
	}
	seen[key] = true
	defer delete(seen, key)
	found := false
	for _, target := range z.Records {
		if target.Name == r.Alias.DNSName && target.Type == r.Type {
			found = true
			if e := validateAliasChain(z, target, seen); e != nil {
				return e
			}
		}
	}
	if !found {
		return invalid("Same-zone alias target must exist with the same record type.")
	}
	return nil
}
func (s *Service) changeResourceRecordSets(tx Transaction, in *api.ChangeResourceRecordSetsRequest) (*api.ChangeResourceRecordSetsResponse, error) {
	z, e := tx.Zone(cleanID(value(in.HostedZoneId)))
	if e != nil || z.Scope != scopeFor(tx.Context()) {
		if e != nil && e != ErrNotFound {
			return nil, e
		}
		return nil, failure("NoSuchHostedZone", "No hosted zone exists with the specified ID.")
	}
	if in.ChangeBatch == nil || len(in.ChangeBatch.Changes) == 0 || len(in.ChangeBatch.Changes) > 1000 {
		return nil, invalid("ChangeBatch must contain between 1 and 1000 changes.")
	}
	conditions := map[string][]string{}
	records := make([]RecordSet, len(in.ChangeBatch.Changes))
	actions := make([]string, len(records))
	count := 0
	for i, c := range in.ChangeBatch.Changes {
		r, e := s.recordInput(z, c.ResourceRecordSet)
		if e != nil {
			return nil, e
		}
		records[i] = r
		actions[i] = value(c.Action)
		if actions[i] != "CREATE" && actions[i] != "UPSERT" && actions[i] != "DELETE" {
			return nil, invalid("Action must be CREATE, UPSERT or DELETE.")
		}
		conditions["route53:ChangeResourceRecordSetsNormalizedRecordNames"] = append(conditions["route53:ChangeResourceRecordSetsNormalizedRecordNames"], strings.TrimSuffix(r.Name, "."))
		conditions["route53:ChangeResourceRecordSetsRecordTypes"] = append(conditions["route53:ChangeResourceRecordSetsRecordTypes"], r.Type)
		conditions["route53:ChangeResourceRecordSetsActions"] = append(conditions["route53:ChangeResourceRecordSetsActions"], actions[i])
		units := max(1, len(r.Values))
		if actions[i] == "UPSERT" {
			units *= 2
		}
		count += units
	}
	if count > 1000 {
		return nil, invalid("The change batch exceeds 1000 resource record elements.")
	}
	if e = s.authorize(tx, "ChangeResourceRecordSets", zoneARN(z), conditions); e != nil {
		return nil, e
	}
	if s.release == nil {
		return nil, failure("NotImplemented", "An explicit authoritative DNS endpoint is required to change records.")
	}
	for i, r := range records {
		if actions[i] == "DELETE" || r.Alias == nil || r.Alias.HostedZoneID == z.ID {
			continue
		}
		if s.aliases == nil {
			return nil, invalid("No owner is configured for the alias target.")
		}
		if e = s.aliases.ValidateAlias(tx.Context(), *r.Alias, recordTypes[r.Type]); e != nil {
			return nil, invalid("Alias target is unavailable: " + e.Error())
		}
	}
	binding := cloudFormationOwnership(tx.Context())
	stamp := binding != nil && binding.claim != ""
	deleted := map[string]bool{}
	for i, r := range records {
		key := recordKey(r)
		index := slices.IndexFunc(z.Records, func(existing RecordSet) bool { return recordKey(existing) == key })
		switch actions[i] {
		case "CREATE":
			if stamp {
				r.Owner = binding.claim
			}
			if index < 0 {
				z.Records = append(z.Records, r)
			} else if stamp && z.Records[index].Owner == binding.claim {
				z.Records[index] = r
			} else {
				return nil, invalid("The resource record set already exists.")
			}
		case "UPSERT":
			if stamp {
				if index >= 0 && binding.enforce && z.Records[index].Owner != binding.claim {
					return nil, invalid("The resource record set belongs to another CloudFormation resource.")
				}
				r.Owner = binding.claim
			} else if index >= 0 {
				r.Owner = z.Records[index].Owner
			}
			if index < 0 {
				z.Records = append(z.Records, r)
			} else {
				z.Records[index] = r
			}
		case "DELETE":
			if deleted[key] {
				return nil, invalid("A record set cannot be deleted twice in one batch.")
			}
			deleted[key] = true
			if index < 0 {
				return nil, invalid("DELETE must match the existing record set, including TTL and all values.")
			}
			if stamp {
				if binding.enforce && z.Records[index].Owner != binding.claim {
					return nil, invalid("The resource record set belongs to another CloudFormation resource.")
				}
			} else if !recordEqual(z.Records[index], r) {
				return nil, invalid("DELETE must match the existing record set, including TTL and all values.")
			}
			if r.Name == z.Name && (r.Type == "NS" || r.Type == "SOA") {
				return nil, invalid("The apex NS and SOA records cannot be deleted.")
			}
			z.Records = slices.Delete(z.Records, index, index+1)
		}
	}
	if e = validateRecords(z); e != nil {
		return nil, e
	}
	if e = tx.PutZone(z); e != nil {
		return nil, e
	}
	change, e := s.newChange(tx, z, value(in.ChangeBatch.Comment))
	return &api.ChangeResourceRecordSetsResponse{ChangeInfo: change}, e
}
func recordOutput(r RecordSet) api.ResourceRecordSet {
	out := api.ResourceRecordSet{Name: new(api.DNSName(r.Name)), Type: new(api.RRType(r.Type))}
	if r.Alias != nil {
		out.AliasTarget = &api.AliasTarget{HostedZoneId: new(api.ResourceId(r.Alias.HostedZoneID)), DNSName: new(api.DNSName(r.Alias.DNSName)), EvaluateTargetHealth: new(api.AliasHealthEnabled(false))}
	} else {
		out.TTL = new(api.TTL(r.TTL))
		for _, v := range r.Values {
			out.ResourceRecords = append(out.ResourceRecords, api.ResourceRecord{Value: new(api.RData(v))})
		}
	}
	if r.Identifier != "" {
		out.SetIdentifier = new(api.ResourceRecordSetIdentifier(r.Identifier))
	}
	if r.Weighted {
		out.Weight = new(api.ResourceRecordSetWeight(r.Weight))
	}
	if r.MultiValue {
		out.MultiValueAnswer = new(api.ResourceRecordSetMultiValueAnswer(true))
	}
	return out
}
func compareRecord(a, b RecordSet) int {
	if c := cmp.Compare(reverseName(a.Name), reverseName(b.Name)); c != 0 {
		return c
	}
	if c := cmp.Compare(recordTypes[a.Type], recordTypes[b.Type]); c != 0 {
		return c
	}
	return cmp.Compare(a.Identifier, b.Identifier)
}
func (s *Service) listResourceRecordSets(tx Transaction, in *api.ListResourceRecordSetsRequest) (*api.ListResourceRecordSetsResponse, error) {
	z, e := s.zone(tx, value(in.HostedZoneId), "ListResourceRecordSets")
	if e != nil {
		return nil, e
	}
	cloudFormationOwnership(tx.Context()).observe(z)
	n, e := pageSize(in.MaxItems)
	if e != nil {
		return nil, e
	}
	start := RecordSet{Type: value(in.StartRecordType), Identifier: value(in.StartRecordIdentifier)}
	if in.StartRecordName != nil {
		start.Name, e = canonicalName(value(in.StartRecordName), true)
		if e != nil {
			return nil, failure("InvalidInput", e.Error())
		}
	} else if in.StartRecordType != nil || in.StartRecordIdentifier != nil {
		return nil, failure("InvalidInput", "StartRecordType and StartRecordIdentifier require StartRecordName.")
	}
	if start.Identifier != "" && start.Type == "" {
		return nil, failure("InvalidInput", "StartRecordIdentifier requires StartRecordType.")
	}
	if start.Type != "" {
		if _, ok := recordTypes[start.Type]; !ok {
			return nil, failure("InvalidInput", fmt.Sprintf("Unsupported StartRecordType %s.", start.Type))
		}
	}
	slices.SortFunc(z.Records, compareRecord)
	out := &api.ListResourceRecordSetsResponse{ResourceRecordSets: api.ResourceRecordSets{}, IsTruncated: new(api.PageTruncated(false)), MaxItems: new(api.Integer(n))}
	for _, r := range z.Records {
		if start.Name != "" && compareRecord(r, start) < 0 {
			continue
		}
		if len(out.ResourceRecordSets) == n {
			out.IsTruncated = new(api.PageTruncated(true))
			out.NextRecordName = new(api.DNSName(r.Name))
			out.NextRecordType = new(api.RRType(r.Type))
			if r.Identifier != "" {
				out.NextRecordIdentifier = new(api.ResourceRecordSetIdentifier(r.Identifier))
			}
			break
		}
		out.ResourceRecordSets = append(out.ResourceRecordSets, recordOutput(r))
	}
	return out, nil
}
