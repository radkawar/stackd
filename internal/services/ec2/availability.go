package ec2

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"slices"
	"strings"
	"time"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// RegionAccess borrows the Account service's scoped opt-in state; EC2 does not
// maintain a second mutable copy of account region settings.
type RegionAccess interface {
	RegionEnabled(context.Context, string, string, time.Time) (bool, error)
}

//go:embed availability_metadata.json
var availabilityMetadataJSON []byte

type physicalRegionZones struct {
	Names []string                 `json:"names"`
	Zones api.AvailabilityZoneList `json:"zones"`
}

type availabilityCatalogue struct {
	Regions map[string]api.Region          `json:"regions"`
	Zones   map[string]physicalRegionZones `json:"zones"`
}

var physicalAvailability = func() availabilityCatalogue {
	var catalogue availabilityCatalogue
	if err := json.Unmarshal(availabilityMetadataJSON, &catalogue); err != nil {
		panic("ec2: invalid embedded availability metadata: " + err.Error())
	}
	return catalogue
}()

func registerAvailability(s *Service) {
	register(s, "DescribeAvailabilityZones", s.describeAvailabilityZones)
	register(s, "DescribeRegions", s.describeRegions)
}

func (s *Service) regionOptInStatus(ctx context.Context, region awscatalog.CommercialRegion) (string, error) {
	if !region.OptInRequired {
		return "opt-in-not-required", nil
	}
	if s.regions == nil {
		return "", unsupported("Account region opt-in state is not configured.")
	}
	enabled, err := s.regions.RegionEnabled(ctx, scopeFor(ctx).AccountID, region.Name, s.clock.Now())
	if err != nil {
		return "", err
	}
	if enabled {
		return "opted-in", nil
	}
	return "not-opted-in", nil
}

// availableZones resolves names from immutable physical metadata. In the eight
// legacy commercial regions with account-dependent naming, a scope-hashed
// rotation pairs the captured legal name set with sorted real physical IDs.
// This is an emulator assignment, not the capture account's AWS assignment.
// Uniform-name regions retain AWS's observed names. Parent names are resolved
// through the same mapping. No mutable state or suffix-derived physical IDs exist.
func (s *Service) availableZones(ctx context.Context) (api.AvailabilityZoneList, error) {
	scope := scopeFor(ctx)
	if scope.Partition != "aws" {
		// TODO: Comeback capture authoritative physical zones for non-commercial partitions.
		return nil, unsupported("Availability zone metadata is unavailable for partition " + scope.Partition + ".")
	}
	metadata, ok := physicalAvailability.Zones[scope.Region]
	if !ok {
		// TODO: Comeback capture ap-east-2 (native AuthFailure), me-south-1
		// (native endpoint connection timeout), and newly introduced regions.
		return nil, unsupported("Availability zone metadata is unavailable for region " + scope.Region + ".")
	}
	for _, region := range awscatalog.CommercialRegions() {
		if region.Name != scope.Region {
			continue
		}
		status, err := s.regionOptInStatus(ctx, region)
		if err != nil {
			return nil, err
		}
		if status == "not-opted-in" {
			return nil, &awswire.Error{Code: "AuthFailure", Message: "AWS was not able to validate the provided access credentials", StatusCode: 401}
		}
		break
	}
	offset := 0
	if len(metadata.Names) > 0 {
		hash := sha256.Sum256([]byte(scope.Partition + "\x00" + scope.AccountID + "\x00" + scope.Region))
		offset = int(binary.BigEndian.Uint64(hash[:8]) % uint64(len(metadata.Names)))
	}
	out := make(api.AvailabilityZoneList, 0, len(metadata.Zones))
	namesByID := make(map[string]string, len(metadata.Zones))
	standard := 0
	for _, physical := range metadata.Zones {
		zone := api.CloneAvailabilityZone(physical)
		if str(zone.ZoneType) == "availability-zone" && len(metadata.Names) > 0 {
			zone.ZoneName = new(api.String(metadata.Names[(standard+offset)%len(metadata.Names)]))
			standard++
		}
		namesByID[str(zone.ZoneId)] = str(zone.ZoneName)
		out = append(out, zone)
	}
	for i := range out {
		if parentID := str(out[i].ParentZoneId); parentID != "" {
			name, ok := namesByID[parentID]
			if !ok {
				return nil, unsupported("Parent availability zone metadata is unavailable for " + parentID + ".")
			}
			out[i].ParentZoneName = new(api.String(name))
		}
	}
	slices.SortFunc(out, func(a, b api.AvailabilityZone) int { return strings.Compare(str(a.ZoneName), str(b.ZoneName)) })
	return out, nil
}

// CloudFormationAvailabilityZones uses the same physical inventory and
// account naming as subnet placement. Default subnets filter standard zones
// only when this account owns at least one in the requested region.
func (s *Service) CloudFormationAvailabilityZones(ctx context.Context, region string) ([]string, error) {
	metadata := awsctx.FromContext(ctx)
	if region != "" {
		metadata.Region = region
	}
	ctx = awsctx.WithMetadata(ctx, metadata)
	if len(metadata.CalledVia) == 0 || metadata.CalledVia[len(metadata.CalledVia)-1] != "cloudformation.amazonaws.com" {
		ctx = awsctx.WithViaService(ctx, "cloudformation.amazonaws.com")
	}
	for _, action := range []string{"DescribeAvailabilityZones", "DescribeAccountAttributes", "DescribeSubnets"} {
		if err := s.authorize(ctx, action, "", "", nil); err != nil {
			return nil, err
		}
	}
	zones, err := s.availableZones(ctx)
	if err != nil {
		return nil, err
	}
	defaults := map[string]bool{}
	err = s.repository.View(ctx, func(r Reader) error {
		subnets, err := r.Subnets(scopeFor(ctx))
		if err != nil {
			return err
		}
		for _, subnet := range subnets {
			if boolValue(subnet.Data.DefaultForAz) {
				defaults[str(subnet.Data.AvailabilityZone)] = true
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(zones))
	for _, zone := range zones {
		if str(zone.ZoneType) != "availability-zone" || str(zone.State) != "available" || str(zone.OptInStatus) == "not-opted-in" {
			continue
		}
		name := str(zone.ZoneName)
		if len(defaults) == 0 || defaults[name] {
			out = append(out, name)
		}
	}
	return out, nil
}

func availabilityFilters(filters api.FilterList, allowed string) ([]compiledFilter, error) {
	fields := strings.Fields(allowed)
	for _, filter := range filters {
		if !slices.Contains(fields, str(filter.Name)) {
			return nil, failure("InvalidParameterValue", "The filter '"+str(filter.Name)+"' is invalid")
		}
	}
	return compileFilters(filters), nil
}

func zoneFilterFields(zone api.AvailabilityZone) map[string][]string {
	messages := make([]string, 0, len(zone.Messages))
	for _, message := range zone.Messages {
		messages = append(messages, str(message.Message))
	}
	return map[string][]string{
		"group-long-name": {str(zone.GroupLongName)}, "group-name": {str(zone.GroupName)},
		"message": messages, "opt-in-status": {str(zone.OptInStatus)},
		"parent-zone-id": {str(zone.ParentZoneId)}, "parent-zone-name": {str(zone.ParentZoneName)},
		"region-name": {str(zone.RegionName)}, "state": {str(zone.State)},
		"zone-id": {str(zone.ZoneId)}, "zone-name": {str(zone.ZoneName)}, "zone-type": {str(zone.ZoneType)},
	}
}

func (s *Service) describeAvailabilityZones(ctx context.Context, _ Transaction, in *api.DescribeAvailabilityZonesRequest) (*api.DescribeAvailabilityZonesResult, error) {
	if err := s.authorize(ctx, "DescribeAvailabilityZones", "", "", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if len(in.ZoneNames) > 0 && len(in.ZoneIds) > 0 {
		return nil, failure("InvalidParameterCombination", "The parameter zoneIds cannot be used with the parameter zoneNames")
	}
	filters, err := availabilityFilters(in.Filters, "group-long-name group-name message opt-in-status parent-zone-id parent-zone-name region-name state zone-id zone-name zone-type")
	if err != nil {
		return nil, err
	}
	zones, err := s.availableZones(ctx)
	if err != nil {
		return nil, err
	}
	names, ids := stringsOf(in.ZoneNames), stringsOf(in.ZoneIds)
	visibleNames, visibleIDs := map[string]bool{}, map[string]bool{}
	out := &api.DescribeAvailabilityZonesResult{AvailabilityZones: api.AvailabilityZoneList{}}
	for _, zone := range zones {
		if !boolValue(in.AllAvailabilityZones) && str(zone.OptInStatus) == "not-opted-in" {
			continue
		}
		name, id := str(zone.ZoneName), str(zone.ZoneId)
		visibleNames[name], visibleIDs[id] = true, true
		if len(names) > 0 && !slices.Contains(names, name) || len(ids) > 0 && !slices.Contains(ids, id) {
			continue
		}
		if matchesFilters(pageItem{Fields: zoneFilterFields(zone)}, filters) {
			out.AvailabilityZones = append(out.AvailabilityZones, zone)
		}
	}
	for _, selection := range []struct {
		values  []string
		visible map[string]bool
		kind    string
	}{{names, visibleNames, "zone"}, {ids, visibleIDs, "zone-id"}} {
		var invalid []string
		for _, value := range selection.values {
			if !selection.visible[value] {
				invalid = append(invalid, value)
			}
		}
		if len(invalid) > 0 {
			return nil, failure("InvalidParameterValue", "Invalid availability "+selection.kind+": ["+strings.Join(invalid, ", ")+"]")
		}
	}
	return out, nil
}

func (s *Service) describeRegions(ctx context.Context, _ Transaction, in *api.DescribeRegionsRequest) (*api.DescribeRegionsResult, error) {
	if err := s.authorize(ctx, "DescribeRegions", "", "", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if scopeFor(ctx).Partition != "aws" {
		// TODO: Comeback capture EC2 region discovery in non-commercial partitions.
		return nil, unsupported("Region metadata is unavailable for partition " + scopeFor(ctx).Partition + ".")
	}
	filters, err := availabilityFilters(in.Filters, "endpoint opt-in-status region-name")
	if err != nil {
		return nil, err
	}
	names := stringsOf(in.RegionNames)
	for _, name := range names {
		if _, ok := physicalAvailability.Regions[name]; !ok {
			return nil, failure("InvalidParameterValue", "Invalid region: ["+name+"]")
		}
	}
	out := &api.DescribeRegionsResult{Regions: api.RegionList{}}
	for _, region := range awscatalog.CommercialRegions() {
		if len(names) > 0 && !slices.Contains(names, region.Name) {
			continue
		}
		status, err := s.regionOptInStatus(ctx, region)
		if err != nil {
			return nil, err
		}
		if !boolValue(in.AllRegions) && len(names) == 0 && status == "not-opted-in" {
			continue
		}
		metadata, ok := physicalAvailability.Regions[region.Name]
		if !ok {
			return nil, unsupported("Region metadata is unavailable for region " + region.Name + ".")
		}
		item := api.CloneRegion(metadata)
		item.OptInStatus = new(api.String(status))
		if matchesFilters(pageItem{Fields: map[string][]string{"endpoint": {str(item.Endpoint)}, "opt-in-status": {status}, "region-name": {region.Name}}}, filters) {
			out.Regions = append(out.Regions, item)
		}
	}
	return out, nil
}
