package route53

import (
	"context"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"math/rand/v2"
	"slices"
	"stackd/compute/dns"
	"strings"
)

// LookupDNS is public authority, not an account-scoped API. The outermost retained
// zone controls its subtree. A child zone becomes visible only through an exact
// NS delegation to its assigned name servers. Ambiguous roots fail closed.
func (s *Service) LookupDNS(ctx context.Context, q dnsmessage.Question) (dns.Result, error) {
	if q.Class != dnsmessage.ClassINET {
		return dns.Result{}, nil
	}
	var zones []Zone
	if err := s.repository.View(ctx, func(r Reader) error { var e error; zones, e = r.Zones(); return e }); err != nil {
		return dns.Result{}, err
	}
	// Runtime target observations occur after releasing the resource snapshot.
	name := strings.ToLower(q.Name.String())
	var roots []Zone
	for _, z := range zones {
		if !inZone(name, z.Name) {
			continue
		}
		if len(roots) == 0 || len(z.Name) < len(roots[0].Name) {
			roots = []Zone{z}
		} else if z.Name == roots[0].Name {
			roots = append(roots, z)
		}
	}
	if len(roots) == 0 {
		return dns.Result{}, nil
	}
	if len(roots) != 1 {
		return dns.Result{}, errors.New("ambiguous public hosted zone: explicit parent NS delegation is required")
	}
	zone := roots[0]
	for range len(zones) + 1 {
		delegation := delegationAt(zone, name)
		if delegation == nil {
			return s.answerZone(ctx, zone, name, q.Type, map[string]bool{})
		}
		var children []Zone
		for _, candidate := range zones {
			if candidate.Name == delegation.Name && sameNames(nameservers(candidate), delegation.Values) {
				children = append(children, candidate)
			}
		}
		if len(children) > 1 {
			return dns.Result{}, errors.New("ambiguous delegated hosted zone")
		}
		if len(children) == 0 {
			authorities, e := recordResources(*delegation, delegation.Name)
			if e != nil {
				return dns.Result{}, e
			}
			result := dns.Result{Authoritative: true, Exists: true, Referral: true, Authorities: authorities}
			for _, rr := range zone.Records {
				if (rr.Type == "A" || rr.Type == "AAAA") && inZone(rr.Name, delegation.Name) && slices.Contains(delegation.Values, rr.Name) {
					glue, e := recordResources(rr, rr.Name)
					if e != nil {
						return dns.Result{}, e
					}
					result.Additionals = append(result.Additionals, glue...)
				}
			}
			return result, nil
		}
		zone = children[0]
	}
	return dns.Result{}, errors.New("cyclic hosted zone delegation")
}
func sameNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, n := range a {
		if !slices.Contains(b, n) {
			return false
		}
	}
	return true
}
func delegationAt(z Zone, name string) *RecordSet {
	var result *RecordSet
	for i := range z.Records {
		r := &z.Records[i]
		if r.Type == "NS" && r.Name != z.Name && inZone(name, r.Name) && (result == nil || len(r.Name) < len(result.Name)) {
			result = r
		}
	}
	return result
}
func nameExists(z Zone, name string) bool {
	if name == z.Name {
		return true
	}
	for _, r := range z.Records {
		if inZone(r.Name, name) {
			return true
		}
	}
	return false
}
func wildcardName(z Zone, name string) string {
	if nameExists(z, name) {
		return name
	}
	parent := name
	for parent != z.Name {
		dot := strings.IndexByte(parent, '.')
		if dot < 0 {
			return name
		}
		parent = parent[dot+1:]
		if nameExists(z, parent) {
			candidate := "*." + parent
			if nameExists(z, candidate) {
				return candidate
			}
			return name
		}
	}
	return name
}
func selectedRecords(records []RecordSet) []RecordSet {
	if len(records) == 0 {
		return nil
	}
	if records[0].Weighted {
		var total uint64
		for _, r := range records {
			total += uint64(r.Weight)
		}
		if total == 0 {
			return records[rand.IntN(len(records)):][:1]
		}
		choice := rand.Uint64N(total)
		for i, r := range records {
			if choice < uint64(r.Weight) {
				return records[i : i+1]
			}
			choice -= uint64(r.Weight)
		}
	}
	if records[0].MultiValue && len(records) > 8 {
		picked := slices.Clone(records)
		rand.Shuffle(len(picked), func(i, j int) { picked[i], picked[j] = picked[j], picked[i] })
		return picked[:8]
	}
	return records
}
func recordResources(r RecordSet, name string) ([]dnsmessage.Resource, error) {
	n, e := dnsmessage.NewName(name)
	if e != nil {
		return nil, e
	}
	out := make([]dnsmessage.Resource, 0, len(r.Values))
	for _, v := range r.Values {
		body, _, e := parseRData(r.Type, v)
		if e != nil {
			return nil, e
		}
		out = append(out, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: n, Type: recordTypes[r.Type], Class: dnsmessage.ClassINET, TTL: uint32(r.TTL)}, Body: body})
	}
	return out, nil
}
func negative(z Zone, result dns.Result) (dns.Result, error) {
	for _, r := range z.Records {
		if r.Type == "SOA" && r.Name == z.Name {
			records, e := recordResources(r, z.Name)
			if e != nil {
				return result, e
			}
			for i := range records {
				soa := records[i].Body.(*dnsmessage.SOAResource)
				records[i].Header.TTL = min(records[i].Header.TTL, soa.MinTTL)
			}
			result.Authorities = records
			break
		}
	}
	return result, nil
}
func (s *Service) answerZone(ctx context.Context, z Zone, name string, kind dnsmessage.Type, seen map[string]bool) (dns.Result, error) {
	if len(seen) >= 16 || seen[name] {
		return dns.Result{}, errors.New("DNS alias or CNAME cycle")
	}
	seen[name] = true
	defer delete(seen, name)
	owner := wildcardName(z, name)
	result := dns.Result{Authoritative: true, Exists: nameExists(z, owner)}
	var records []RecordSet
	for _, r := range z.Records {
		if r.Name == owner && (recordTypes[r.Type] == kind || r.Type == "CNAME") {
			records = append(records, r)
		}
	}
	for _, r := range selectedRecords(records) {
		if r.Alias != nil {
			var answers []dnsmessage.Resource
			var e error
			if r.Alias.HostedZoneID == z.ID {
				if delegationAt(z, r.Alias.DNSName) != nil {
					return result, errors.New("alias target is below a delegation boundary")
				}
				target, e := s.answerZone(ctx, z, r.Alias.DNSName, kind, seen)
				if e != nil {
					return result, e
				}
				answers = target.Answers
			} else {
				if s.aliases == nil {
					return result, errors.New("alias owner unavailable")
				}
				answers, e = s.aliases.ResolveAlias(ctx, *r.Alias, kind)
				if e != nil {
					return result, e
				}
			}
			n, e := dnsmessage.NewName(name)
			if e != nil {
				return result, e
			}
			for _, a := range answers {
				a.Header.Name = n
				result.Answers = append(result.Answers, a)
			}
			continue
		}
		answers, e := recordResources(r, name)
		if e != nil {
			return result, e
		}
		result.Answers = append(result.Answers, answers...)
		if r.Type == "CNAME" && kind != dnsmessage.TypeCNAME && len(r.Values) == 1 {
			target := r.Values[0]
			if inZone(target, z.Name) && delegationAt(z, target) == nil {
				next, e := s.answerZone(ctx, z, target, kind, seen)
				if e != nil {
					return result, e
				}
				result.Answers = append(result.Answers, next.Answers...)
				result.Exists = next.Exists
				result.Authorities = next.Authorities
			}
		}
	}
	if len(result.Answers) == 0 {
		return negative(z, result)
	}
	if len(records) != 0 && records[0].MultiValue {
		ttl := result.Answers[0].Header.TTL
		for _, answer := range result.Answers[1:] {
			ttl = min(ttl, answer.Header.TTL)
		}
		for i := range result.Answers {
			result.Answers[i].Header.TTL = ttl
		}
	}
	return result, nil
}
