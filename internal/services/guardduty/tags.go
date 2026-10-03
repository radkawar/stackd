package guardduty

import (
	"errors"
	"maps"
	"slices"
	"strings"

	api "stackd/internal/awsapi/guardduty"
)

type taggedResource struct {
	detector    *Detector
	filter      *Filter
	ipList      *IPList
	destination *PublishingDestination
}

func (v taggedResource) tags() map[string]string {
	if v.detector != nil {
		return v.detector.Tags
	}
	if v.destination != nil {
		return v.destination.Tags
	}
	if v.ipList != nil {
		return v.ipList.Tags
	}
	return v.filter.Tags
}
func (v taggedResource) put(tx Transaction, tags map[string]string) error {
	if v.detector != nil {
		v.detector.Tags = tags
		return tx.PutDetector(*v.detector)
	}
	if v.destination != nil {
		v.destination.Tags = tags
		return tx.PutPublishingDestination(*v.destination)
	}
	if v.ipList != nil {
		v.ipList.Tags = tags
		return tx.PutIPList(*v.ipList)
	}
	v.filter.Tags = tags
	return tx.PutFilter(*v.filter)
}
func (s *Service) taggedResource(tx Transaction, arn, action string, requested map[string]string, keys []string) (taggedResource, error) {
	sc := scopeFor(tx.Context())
	prefix := detectorARN(sc, "")
	var resource taggedResource
	var err error
	if strings.HasPrefix(arn, prefix) {
		parts := strings.Split(strings.TrimPrefix(arn, prefix), "/")
		switch {
		case len(parts) == 1 && parts[0] != "":
			var d Detector
			d, err = tx.Detector(sc, parts[0])
			resource.detector = &d
		case len(parts) == 3 && parts[0] != "" && parts[1] == "publishingdestination" && parts[2] != "":
			var v PublishingDestination
			v, err = tx.PublishingDestination(sc, parts[0], parts[2])
			resource.destination = &v
		case len(parts) == 3 && parts[0] != "" && parts[1] == "filter" && parts[2] != "":
			var f Filter
			f, err = tx.Filter(sc, parts[0], parts[2])
			resource.filter = &f
		case len(parts) == 3 && parts[0] != "" && (IPListKind(parts[1]) == TrustedIPList || IPListKind(parts[1]) == ThreatIPList) && parts[2] != "":
			var v IPList
			v, err = tx.IPList(sc, parts[0], IPListKind(parts[1]), parts[2])
			resource.ipList = &v
			if err == nil && v.Status == "DELETED" && action != "ListTagsForResource" {
				err = ErrNotFound
			}
		default:
			err = ErrNotFound
		}
	} else {
		err = ErrNotFound
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return resource, err
	}
	var tags map[string]string
	if resource.detector != nil || resource.filter != nil || resource.ipList != nil || resource.destination != nil {
		tags = resource.tags()
	}
	if e := s.authorize(tx.Context(), action, arn, tags, requested, keys); e != nil {
		return resource, e
	}
	if err != nil {
		return resource, invalid("The requested resource does not exist in this account and Region")
	}
	return resource, nil
}
func registerTags(s *Service) {
	register(s, "ListTagsForResource", func(tx Transaction, in *api.ListTagsForResourceRequest) (*api.ListTagsForResourceResponse, error) {
		v, e := s.taggedResource(tx, value(in.ResourceArn), "ListTagsForResource", nil, nil)
		if e != nil {
			return nil, e
		}
		return &api.ListTagsForResourceResponse{Tags: outputTags(v.tags())}, nil
	})
	register(s, "TagResource", func(tx Transaction, in *api.TagResourceRequest) (*api.TagResourceResponse, error) {
		requested := stringTags(in.Tags)
		keys := slices.Sorted(maps.Keys(requested))
		v, e := s.taggedResource(tx, value(in.ResourceArn), "TagResource", requested, keys)
		if e != nil {
			return nil, e
		}
		if e := validateTags(requested); e != nil {
			return nil, e
		}
		tags := maps.Clone(v.tags())
		if tags == nil {
			tags = map[string]string{}
		}
		maps.Copy(tags, requested)
		if e := validateTags(tags); e != nil {
			return nil, e
		}
		if e := v.put(tx, tags); e != nil {
			return nil, e
		}
		return &api.TagResourceResponse{}, nil
	})
	register(s, "UntagResource", func(tx Transaction, in *api.UntagResourceRequest) (*api.UntagResourceResponse, error) {
		keys := make([]string, len(in.TagKeys))
		for i, k := range in.TagKeys {
			keys[i] = string(k)
		}
		v, e := s.taggedResource(tx, value(in.ResourceArn), "UntagResource", nil, keys)
		if e != nil {
			return nil, e
		}
		validation := make(map[string]string, len(keys))
		for _, k := range keys {
			validation[k] = ""
		}
		if e := validateTags(validation); e != nil {
			return nil, e
		}
		tags := maps.Clone(v.tags())
		for _, k := range keys {
			delete(tags, k)
		}
		if e := v.put(tx, tags); e != nil {
			return nil, e
		}
		return &api.UntagResourceResponse{}, nil
	})
}
