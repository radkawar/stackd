package ssm

import (
	"errors"
	"slices"
	"strings"

	api "stackd/internal/awsapi/ssm"
)

func parameterLabels(labels []string) api.ParameterLabelList {
	out := make(api.ParameterLabelList, len(labels))
	for i, label := range labels {
		out[i] = api.ParameterLabel(label)
	}
	return out
}

func validParameterLabel(label string) bool {
	if len(label) == 0 || len(label) > 100 || label[0] >= '0' && label[0] <= '9' {
		return false
	}
	lower := strings.ToLower(label)
	if strings.HasPrefix(lower, "aws") || strings.HasPrefix(lower, "ssm") {
		return false
	}
	for _, c := range label {
		if c != '.' && c != '-' && c != '_' && !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func validateLabelRequest(labels api.ParameterLabelList) error {
	if len(labels) < 1 || len(labels) > 10 {
		return failure("ValidationException", "Labels must contain between 1 and 10 entries.")
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 100 {
			return failure("ValidationException", "Labels must contain between 1 and 100 characters.")
		}
	}
	return nil
}

func (s *Service) labelParameterVersion(tx Transaction, in *api.LabelParameterVersionRequest) (*api.LabelParameterVersionResult, error) {
	if err := validateLabelRequest(in.Labels); err != nil {
		return nil, err
	}
	p, err := s.readParameter(tx, value(in.Name), "LabelParameterVersion", false)
	if err != nil {
		return nil, err
	}
	version := p.CurrentVersion
	if in.ParameterVersion != nil {
		version = int64(*in.ParameterVersion)
	}
	if version < 1 || version > p.CurrentVersion {
		return nil, failure("ParameterVersionNotFound", "The specified parameter version was not found.")
	}
	versions, err := tx.Versions(p.Key)
	if err != nil {
		return nil, err
	}
	target := slices.IndexFunc(versions, func(v VersionRecord) bool { return v.Key.Version == version })
	if target < 0 {
		return nil, failure("ParameterVersionNotFound", "The specified parameter version was not found.")
	}
	out := &api.LabelParameterVersionResult{ParameterVersion: new(api.PSParameterVersion(version)), InvalidLabels: api.ParameterLabelList{}}
	additions := make([]string, 0, len(in.Labels))
	for _, label := range in.Labels {
		if !validParameterLabel(string(label)) {
			if !slices.Contains(out.InvalidLabels, label) {
				out.InvalidLabels = append(out.InvalidLabels, label)
			}
			continue
		}
		if !slices.Contains(additions, string(label)) {
			additions = append(additions, string(label))
		}
	}
	labels := slices.Clone(versions[target].Labels)
	for _, label := range additions {
		if !slices.Contains(labels, label) {
			labels = append(labels, label)
		}
	}
	// Check before moving anything: a full target must not steal labels from an
	// older version when this operation fails its per-version limit.
	if len(labels) > 10 {
		return nil, failure("ParameterVersionLabelLimitExceeded", "A parameter version can have a maximum of ten labels.")
	}
	for _, label := range additions {
		if slices.Contains(versions[target].Labels, label) {
			continue
		}
		var from int64
		for _, v := range versions {
			if slices.Contains(v.Labels, label) {
				from = v.Key.Version
				break
			}
		}
		if err := s.emitLabelChange(tx, p, label, from, version); err != nil {
			return nil, err
		}
	}
	for i, v := range versions {
		if i == target {
			continue
		}
		retained := slices.DeleteFunc(slices.Clone(v.Labels), func(label string) bool { return slices.Contains(additions, label) })
		if len(retained) != len(v.Labels) {
			v.Labels = retained
			if err := tx.PutVersion(v); err != nil {
				return nil, err
			}
		}
	}
	if !slices.Equal(labels, versions[target].Labels) {
		versions[target].Labels = labels
		if err := tx.PutVersion(versions[target]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Service) unlabelParameterVersion(tx Transaction, in *api.UnlabelParameterVersionRequest) (*api.UnlabelParameterVersionResult, error) {
	if err := validateLabelRequest(in.Labels); err != nil {
		return nil, err
	}
	if in.ParameterVersion == nil {
		return nil, failure("ValidationException", "ParameterVersion is required.")
	}
	p, err := s.readParameter(tx, value(in.Name), "UnlabelParameterVersion", false)
	if err != nil {
		return nil, err
	}
	version := int64(*in.ParameterVersion)
	if version < 1 || version > p.CurrentVersion {
		return nil, failure("ParameterVersionNotFound", "The specified parameter version was not found.")
	}
	v, err := tx.Version(VersionKey{Parameter: p.Key, Version: version})
	if errors.Is(err, ErrNotFound) {
		return nil, failure("ParameterVersionNotFound", "The specified parameter version was not found.")
	}
	if err != nil {
		return nil, err
	}
	out := &api.UnlabelParameterVersionResult{InvalidLabels: api.ParameterLabelList{}, RemovedLabels: api.ParameterLabelList{}}
	seen := make(map[api.ParameterLabel]bool, len(in.Labels))
	for _, label := range in.Labels {
		if seen[label] {
			continue
		}
		seen[label] = true
		if slices.Contains(v.Labels, string(label)) {
			out.RemovedLabels = append(out.RemovedLabels, label)
		} else {
			out.InvalidLabels = append(out.InvalidLabels, label)
		}
	}
	if len(out.RemovedLabels) > 0 {
		v.Labels = slices.DeleteFunc(slices.Clone(v.Labels), func(label string) bool { return slices.Contains(out.RemovedLabels, api.ParameterLabel(label)) })
		if err := tx.PutVersion(v); err != nil {
			return nil, err
		}
	}
	return out, nil
}
