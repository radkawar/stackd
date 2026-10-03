package guardduty

import (
	"cmp"
	"errors"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	api "stackd/internal/awsapi/guardduty"
)

var filterNamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{3,64}$`)
var filterDescriptionPattern = regexp.MustCompile(`^[a-zA-Z0-9 .:_{}\[\]()/\t\n\v\f\r-]*$`)

func filterARN(sc Scope, detector, name string) string {
	return detectorARN(sc, detector) + "/filter/" + name
}
func validateFilterOptions(name, action, description string, rank *api.FilterRank) error {
	if !filterNamePattern.MatchString(name) {
		return invalid("Invalid filter name")
	}
	if action != "NOOP" && action != "ARCHIVE" {
		return invalid("Filter action must be NOOP or ARCHIVE")
	}
	if utf8.RuneCountInString(description) > 512 {
		return invalid("Filter description exceeds 512 characters")
	}
	if !filterDescriptionPattern.MatchString(description) {
		return invalid("Invalid characters in filter description")
	}
	if rank != nil && (*rank < 1 || *rank > 100) {
		return invalid("Filter rank must be between 1 and 100")
	}
	return nil
}
func (s *Service) loadFilter(tx Reader, detector, name, action string) (Filter, error) {
	sc := scopeFor(tx.Context())
	f, err := tx.Filter(sc, detector, name)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return f, err
	}
	if e := s.authorize(tx.Context(), action, filterARN(sc, detector, name), f.Tags, nil, nil); e != nil {
		return f, e
	}
	if err != nil {
		return f, invalid("The requested filter does not exist")
	}
	return f, nil
}
func registerFilters(s *Service) {
	register(s, "CreateFilter", func(tx Transaction, in *api.CreateFilterRequest) (*api.CreateFilterResponse, error) {
		sc := scopeFor(tx.Context())
		id, name := value(in.DetectorId), value(in.Name)
		arn := filterARN(sc, id, name)
		tags := stringTags(in.Tags)
		keys := slices.Sorted(maps.Keys(tags))
		existing, err := tx.Filter(sc, id, name)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		if e := s.authorize(tx.Context(), "CreateFilter", arn, existing.Tags, tags, keys); e != nil {
			return nil, e
		}
		if len(tags) > 0 {
			if e := s.authorize(tx.Context(), "TagResource", arn, existing.Tags, tags, keys); e != nil {
				return nil, e
			}
		}
		if _, e := tx.Detector(sc, id); e != nil {
			return nil, e
		}
		action := value(in.Action)
		if in.Action == nil {
			action = "NOOP"
		}
		if e := validateFilterOptions(name, action, value(in.Description), in.Rank); e != nil {
			return nil, e
		}
		if in.FindingCriteria == nil || len(in.FindingCriteria.Criterion) == 0 {
			return nil, invalid("FindingCriteria must contain a criterion")
		}
		if e := validateCriteria(in.FindingCriteria); e != nil {
			return nil, e
		}
		if e := validateTags(tags); e != nil {
			return nil, e
		}
		token := value(in.ClientToken)
		if len(token) > 64 {
			return nil, invalid("ClientToken exceeds 64 characters")
		}
		out := &api.CreateFilterResponse{}
		text(&out.Name, name)
		if err == nil && token != "" && existing.ClientToken == token {
			return out, nil
		}
		if err == nil {
			return nil, invalid("A filter with this name already exists")
		}
		filters, e := tx.Filters(sc, id)
		if e != nil {
			return nil, e
		}
		if len(filters) >= 100 {
			return nil, invalid("The maximum number of filters has been reached")
		}
		rank := int32(1)
		if in.Rank != nil {
			rank = min(int32(*in.Rank), int32(len(filters)+1))
		}
		now := s.clock.Now()
		f := Filter{Scope: sc, DetectorID: id, Name: name, ARN: arn, Action: action, Description: value(in.Description), DescriptionSet: in.Description != nil, ClientToken: token, Rank: rank, Version: 1, Created: now, Updated: now, Criteria: api.CloneFindingCriteria(*in.FindingCriteria), Tags: tags}
		if e := placeFilter(tx, filters, f, 0); e != nil {
			return nil, e
		}
		return out, nil
	})
	register(s, "GetFilter", func(tx Transaction, in *api.GetFilterRequest) (*api.GetFilterResponse, error) {
		f, e := s.loadFilter(tx, value(in.DetectorId), value(in.FilterName), "GetFilter")
		if e != nil {
			return nil, e
		}
		o := &api.GetFilterResponse{Tags: outputTags(f.Tags), FindingCriteria: new(filterOutputCriteria(f.Criteria)), CreatedAt: &f.Created, UpdatedAt: &f.Updated}
		text(&o.Name, f.Name)
		text(&o.Action, f.Action)
		if f.DescriptionSet {
			text(&o.Description, f.Description)
		}
		rank, version := api.FilterRank(f.Rank), api.FilterVersion(f.Version)
		o.Rank = &rank
		o.Version = &version
		return o, nil
	})
	register(s, "UpdateFilter", func(tx Transaction, in *api.UpdateFilterRequest) (*api.UpdateFilterResponse, error) {
		f, e := s.loadFilter(tx, value(in.DetectorId), value(in.FilterName), "UpdateFilter")
		if e != nil {
			return nil, e
		}
		oldRank := f.Rank
		if in.Action != nil {
			f.Action = value(in.Action)
		}
		if in.Description != nil {
			f.Description = value(in.Description)
			f.DescriptionSet = true
		}
		if e := validateFilterOptions(f.Name, f.Action, f.Description, in.Rank); e != nil {
			return nil, e
		}
		if in.FindingCriteria != nil {
			if len(in.FindingCriteria.Criterion) == 0 {
				return nil, invalid("FindingCriteria must contain a criterion")
			}
			if e := validateCriteria(in.FindingCriteria); e != nil {
				return nil, e
			}
			f.Criteria = api.CloneFindingCriteria(*in.FindingCriteria)
		}
		if in.Rank != nil {
			f.Rank = int32(*in.Rank)
		}
		f.Updated = s.clock.Now()
		f.Version++
		all, e := tx.Filters(f.Scope, f.DetectorID)
		if e != nil {
			return nil, e
		}
		if f.Rank > int32(len(all)) {
			return nil, invalid("The parameter rank is out-of-bounds")
		}
		if e := placeFilter(tx, all, f, oldRank); e != nil {
			return nil, e
		}
		o := &api.UpdateFilterResponse{}
		text(&o.Name, f.Name)
		return o, nil
	})
	register(s, "DeleteFilter", func(tx Transaction, in *api.DeleteFilterRequest) (*api.DeleteFilterResponse, error) {
		f, e := s.loadFilter(tx, value(in.DetectorId), value(in.FilterName), "DeleteFilter")
		if e != nil {
			return nil, e
		}
		all, e := tx.Filters(f.Scope, f.DetectorID)
		if e != nil {
			return nil, e
		}
		if e := tx.DeleteFilter(f.Scope, f.DetectorID, f.Name); e != nil {
			return nil, e
		}
		for _, other := range all {
			if other.Rank > f.Rank {
				other.Rank--
				if e := tx.PutFilter(other); e != nil {
					return nil, e
				}
			}
		}
		return &api.DeleteFilterResponse{}, nil
	})
	register(s, "ListFilters", func(tx Transaction, in *api.ListFiltersRequest) (*api.ListFiltersResponse, error) {
		d, e := s.loadDetector(tx, value(in.DetectorId), "ListFilters")
		if e != nil {
			return nil, e
		}
		kind := "filters:" + d.ID
		limit, after, e := page(tx.Context(), kind, in.MaxResults, value(in.NextToken))
		if e != nil {
			return nil, e
		}
		all, e := tx.Filters(d.Scope, d.ID)
		if e != nil {
			return nil, e
		}
		slices.SortFunc(all, func(a, b Filter) int {
			if n := cmp.Compare(a.Rank, b.Rank); n != 0 {
				return n
			}
			return cmp.Compare(a.Name, b.Name)
		})
		afterRank, afterName := 0, ""
		if after != "" {
			rank, name, ok := strings.Cut(after, ":")
			var err error
			afterRank, err = strconv.Atoi(rank)
			if !ok || err != nil {
				return nil, invalid("Invalid filter pagination cursor")
			}
			afterName = name
		}
		o := &api.ListFiltersResponse{FilterNames: api.FilterNames{}}
		lastRank := int32(0)
		for _, f := range all {
			if int(f.Rank) < afterRank || (int(f.Rank) == afterRank && f.Name <= afterName) {
				continue
			}
			if len(o.FilterNames) == limit {
				last := strconv.Itoa(int(lastRank)) + ":" + string(o.FilterNames[len(o.FilterNames)-1])
				text(&o.NextToken, pageToken(tx.Context(), kind, last))
				break
			}
			o.FilterNames = append(o.FilterNames, api.FilterName(f.Name))
			lastRank = f.Rank
		}
		return o, nil
	})
}

// Rank shifts and insertion share the caller's repository transaction.
func placeFilter(tx Transaction, all []Filter, f Filter, oldRank int32) error {
	for _, other := range all {
		if other.Name == f.Name {
			continue
		}
		rank := other.Rank
		if oldRank == 0 {
			if rank >= f.Rank {
				other.Rank++
			}
		} else if f.Rank < oldRank {
			if rank >= f.Rank && rank < oldRank {
				other.Rank++
			}
		} else if f.Rank > oldRank {
			if rank > oldRank && rank <= f.Rank {
				other.Rank--
			}
		}
		if other.Rank != rank {
			if other.Rank > 100 {
				return invalid("Filter rank exceeds the maximum")
			}
			if e := tx.PutFilter(other); e != nil {
				return e
			}
		}
	}
	return tx.PutFilter(f)
}

func filterOutputCriteria(in api.FindingCriteria) api.FindingCriteria {
	out := api.CloneFindingCriteria(in)
	for name, c := range out.Criterion {
		if c.Eq == nil && c.Equals != nil {
			c.Eq = api.Eq(slices.Clone(c.Equals))
		}
		if c.Equals == nil && c.Eq != nil {
			c.Equals = api.Equals(slices.Clone(c.Eq))
		}
		if c.Neq == nil && c.NotEquals != nil {
			c.Neq = api.Neq(slices.Clone(c.NotEquals))
		}
		if c.NotEquals == nil && c.Neq != nil {
			c.NotEquals = api.NotEquals(slices.Clone(c.Neq))
		}
		filterOutputBound(&c.Gt, &c.GreaterThan)
		filterOutputBound(&c.Gte, &c.GreaterThanOrEqual)
		filterOutputBound(&c.Lt, &c.LessThan)
		filterOutputBound(&c.Lte, &c.LessThanOrEqual)
		out.Criterion[name] = c
	}
	return out
}

func filterOutputBound(old **api.Integer, current **api.Long) {
	if *current == nil && *old != nil {
		*current = new(api.Long(**old))
	}
	if *old == nil && *current != nil && **current >= -1<<31 && **current <= 1<<31-1 {
		*old = new(api.Integer(**current))
	}
}
