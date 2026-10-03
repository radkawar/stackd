package route53

import (
	"cmp"
	"errors"
	"slices"
	api "stackd/internal/awsapi/route53"
	"strconv"
	"strings"
	"time"
)

func (s *Service) zone(r Reader, id, op string) (Zone, error) {
	z, e := r.Zone(cleanID(id))
	if errors.Is(e, ErrNotFound) || e == nil && z.Scope != scopeFor(r.Context()) {
		return Zone{}, failure("NoSuchHostedZone", "No hosted zone exists with the specified ID.")
	}
	if e != nil {
		return Zone{}, e
	}
	if e = s.authorize(r, op, zoneARN(z), nil); e != nil {
		return Zone{}, e
	}
	return z, nil
}
func nameservers(z Zone) []string {
	out := make([]string, 4)
	for i := range out {
		out[i] = "ns-" + strconv.Itoa(i+1) + "." + strings.ToLower(z.ID) + ".stackd.invalid."
	}
	return out
}
func delegation(z Zone) *api.DelegationSet {
	v := &api.DelegationSet{}
	for _, n := range nameservers(z) {
		v.NameServers = append(v.NameServers, api.DNSName(n))
	}
	return v
}
func zoneOutput(z Zone) *api.HostedZone {
	return &api.HostedZone{Id: new(api.ResourceId("/hostedzone/" + z.ID)), Name: new(api.DNSName(z.Name)), CallerReference: new(api.Nonce(z.CallerReference)), Config: &api.HostedZoneConfig{Comment: new(api.ResourceDescription(z.Comment)), PrivateZone: new(api.IsPrivateZone(false))}, ResourceRecordSetCount: new(api.HostedZoneRRSetCount(len(z.Records)))}
}
func (s *Service) newChange(tx Transaction, z Zone, comment string) (*api.ChangeInfo, error) {
	now := s.clock.Now()
	c := Change{Scope: z.Scope, ID: identifier("C"), ZoneID: z.ID, Comment: comment, Submitted: now, Ready: now.Add(time.Second)}
	if e := tx.PutChange(c); e != nil {
		return nil, e
	}
	return s.changeOutput(c), nil
}
func (s *Service) changeOutput(c Change) *api.ChangeInfo {
	status := api.ChangeStatusPENDING
	if !s.clock.Now().Before(c.Ready) {
		status = api.ChangeStatusINSYNC
	}
	return &api.ChangeInfo{Id: new(api.ResourceId("/change/" + c.ID)), Status: &status, SubmittedAt: new(api.TimeStamp(c.Submitted)), Comment: new(api.ResourceDescription(c.Comment))}
}
func (s *Service) createHostedZone(tx Transaction, in *api.CreateHostedZoneRequest) (*api.CreateHostedZoneResponse, error) {
	if e := s.authorize(tx, "CreateHostedZone", "", nil); e != nil {
		return nil, e
	}
	if s.release == nil {
		return nil, failure("NotImplemented", "An explicit authoritative DNS endpoint is required to create hosted zones.")
	}
	name, e := canonicalName(value(in.Name), false)
	if e != nil {
		return nil, failure("InvalidDomainName", e.Error())
	}
	reference := value(in.CallerReference)
	if reference == "" || len(reference) > 128 {
		return nil, failure("InvalidInput", "CallerReference must contain 1 to 128 characters.")
	}
	if in.VPC != nil || in.HostedZoneConfig != nil && in.HostedZoneConfig.PrivateZone != nil && bool(*in.HostedZoneConfig.PrivateZone) {
		return nil, failure("InvalidInput", "Private hosted zones require an isolated VPC resolver boundary, which is unavailable.")
	}
	if in.DelegationSetId != nil {
		return nil, failure("InvalidInput", "Reusable delegation sets are not supported.")
	}
	zones, e := tx.Zones()
	if e != nil {
		return nil, e
	}
	scope := scopeFor(tx.Context())
	for _, z := range zones {
		if z.Scope == scope && z.CallerReference == reference {
			return nil, failure("HostedZoneAlreadyExists", "A hosted zone with this CallerReference already exists.")
		}
	}
	z := Zone{Scope: scope, ID: identifier("Z"), Name: name, CallerReference: reference, Created: s.clock.Now()}
	if in.HostedZoneConfig != nil {
		z.Comment = value(in.HostedZoneConfig.Comment)
	}
	if len(z.Comment) > 256 {
		return nil, failure("InvalidInput", "Comment exceeds 256 characters.")
	}
	ns := nameservers(z)
	z.Records = []RecordSet{{Name: name, Type: "NS", TTL: 172800, Values: ns}, {Name: name, Type: "SOA", TTL: 900, Values: []string{ns[0] + " hostmaster." + name + " 1 7200 900 1209600 86400"}}}
	if e = tx.PutZone(z); e != nil {
		return nil, e
	}
	change, e := s.newChange(tx, z, "")
	if e != nil {
		return nil, e
	}
	return &api.CreateHostedZoneResponse{HostedZone: zoneOutput(z), DelegationSet: delegation(z), ChangeInfo: change, Location: new(api.ResourceURI("/2013-04-01/hostedzone/" + z.ID))}, nil
}
func (s *Service) getHostedZone(tx Transaction, in *api.GetHostedZoneRequest) (*api.GetHostedZoneResponse, error) {
	z, e := s.zone(tx, value(in.Id), "GetHostedZone")
	if e != nil {
		return nil, e
	}
	return &api.GetHostedZoneResponse{HostedZone: zoneOutput(z), DelegationSet: delegation(z)}, nil
}
func (s *Service) updateHostedZoneComment(tx Transaction, in *api.UpdateHostedZoneCommentRequest) (*api.UpdateHostedZoneCommentResponse, error) {
	z, e := s.zone(tx, value(in.Id), "UpdateHostedZoneComment")
	if e != nil {
		return nil, e
	}
	if in.Comment != nil {
		z.Comment = value(in.Comment)
	}
	if len(z.Comment) > 256 {
		return nil, failure("InvalidInput", "Comment exceeds 256 characters.")
	}
	if e = tx.PutZone(z); e != nil {
		return nil, e
	}
	return &api.UpdateHostedZoneCommentResponse{HostedZone: zoneOutput(z)}, nil
}
func (s *Service) deleteHostedZone(tx Transaction, in *api.DeleteHostedZoneRequest) (*api.DeleteHostedZoneResponse, error) {
	z, e := s.zone(tx, value(in.Id), "DeleteHostedZone")
	if e != nil {
		return nil, e
	}
	for _, r := range z.Records {
		if r.Name != z.Name || (r.Type != "NS" && r.Type != "SOA") {
			return nil, failure("HostedZoneNotEmpty", "The hosted zone contains non-default resource record sets.")
		}
	}
	if e = tx.DeleteZone(z.ID); e != nil {
		return nil, e
	}
	change, e := s.newChange(tx, z, "")
	return &api.DeleteHostedZoneResponse{ChangeInfo: change}, e
}
func (s *Service) getChange(tx Transaction, in *api.GetChangeRequest) (*api.GetChangeResponse, error) {
	c, e := tx.Change(cleanID(value(in.Id)))
	if errors.Is(e, ErrNotFound) || e == nil && c.Scope != scopeFor(tx.Context()) {
		return nil, failure("NoSuchChange", "No change exists with the specified ID.")
	}
	if e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "GetChange", "arn:"+c.Partition+":route53:::change/"+c.ID, nil); e != nil {
		return nil, e
	}
	return &api.GetChangeResponse{ChangeInfo: s.changeOutput(c)}, nil
}
func pageSize(p *api.Integer) (int, error) {
	if p == nil {
		return 100, nil
	}
	n := int(*p)
	if n < 1 || n > 1000 {
		return 0, failure("InvalidInput", "MaxItems must be between 1 and 1000.")
	}
	return n, nil
}
func (s *Service) ownedZones(tx Transaction, op string) ([]Zone, error) {
	if e := s.authorize(tx, op, "", nil); e != nil {
		return nil, e
	}
	zones, e := tx.Zones()
	if e != nil {
		return nil, e
	}
	scope := scopeFor(tx.Context())
	return slices.DeleteFunc(zones, func(z Zone) bool { return z.Scope != scope }), nil
}
func (s *Service) getHostedZoneCount(tx Transaction, _ *api.GetHostedZoneCountRequest) (*api.GetHostedZoneCountResponse, error) {
	zones, e := s.ownedZones(tx, "GetHostedZoneCount")
	if e != nil {
		return nil, e
	}
	return &api.GetHostedZoneCountResponse{HostedZoneCount: new(api.HostedZoneCount(len(zones)))}, nil
}
func (s *Service) listHostedZones(tx Transaction, in *api.ListHostedZonesRequest) (*api.ListHostedZonesResponse, error) {
	zones, e := s.ownedZones(tx, "ListHostedZones")
	if e != nil {
		return nil, e
	}
	n, e := pageSize(in.MaxItems)
	if e != nil {
		return nil, e
	}
	if in.DelegationSetId != nil {
		return nil, failure("InvalidInput", "Reusable delegation sets are not supported.")
	}
	if t := value(in.HostedZoneType); t != "" && t != "PrivateHostedZone" {
		return nil, failure("InvalidInput", "Invalid HostedZoneType.")
	}
	if in.HostedZoneType != nil {
		zones = nil
	}
	marker := cleanID(value(in.Marker))
	out := &api.ListHostedZonesResponse{HostedZones: api.HostedZones{}, Marker: new(api.PageMarker(marker)), MaxItems: new(api.Integer(n)), IsTruncated: new(api.PageTruncated(false))}
	for _, z := range zones {
		if z.ID < marker {
			continue
		}
		if len(out.HostedZones) == n {
			out.IsTruncated = new(api.PageTruncated(true))
			out.NextMarker = new(api.PageMarker(z.ID))
			break
		}
		out.HostedZones = append(out.HostedZones, *zoneOutput(z))
	}
	return out, nil
}
func reverseName(n string) string {
	labels := strings.Split(strings.TrimSuffix(n, "."), ".")
	slices.Reverse(labels)
	return strings.Join(labels, ".") + "."
}
func (s *Service) listHostedZonesByName(tx Transaction, in *api.ListHostedZonesByNameRequest) (*api.ListHostedZonesByNameResponse, error) {
	zones, e := s.ownedZones(tx, "ListHostedZonesByName")
	if e != nil {
		return nil, e
	}
	n, e := pageSize(in.MaxItems)
	if e != nil {
		return nil, e
	}
	start := ""
	if in.DNSName != nil {
		start, e = canonicalName(value(in.DNSName), false)
		if e != nil {
			return nil, failure("InvalidInput", e.Error())
		}
	} else if in.HostedZoneId != nil {
		return nil, failure("InvalidInput", "HostedZoneId requires DNSName.")
	}
	slices.SortFunc(zones, func(a, b Zone) int {
		if c := cmp.Compare(reverseName(a.Name), reverseName(b.Name)); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})
	out := &api.ListHostedZonesByNameResponse{HostedZones: api.HostedZones{}, DNSName: in.DNSName, HostedZoneId: in.HostedZoneId, MaxItems: new(api.Integer(n)), IsTruncated: new(api.PageTruncated(false))}
	for _, z := range zones {
		if start != "" && (reverseName(z.Name) < reverseName(start) || z.Name == start && z.ID < cleanID(value(in.HostedZoneId))) {
			continue
		}
		if len(out.HostedZones) == n {
			out.IsTruncated = new(api.PageTruncated(true))
			out.NextDNSName = new(api.DNSName(z.Name))
			out.NextHostedZoneId = new(api.ResourceId(z.ID))
			break
		}
		out.HostedZones = append(out.HostedZones, *zoneOutput(z))
	}
	return out, nil
}
