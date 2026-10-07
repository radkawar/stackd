package ssm

import (
	"errors"
	"slices"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awswire"
)

func splitParameterSelector(input string) (string, string) {
	name := strings.TrimSpace(input)
	start := 0
	if strings.HasPrefix(name, "arn:") {
		// Colons in the ARN prefix are not version selectors.
		if i := strings.Index(name, ":parameter/"); i >= 0 {
			start = i + len(":parameter/")
		} else {
			return name, ""
		}
	}
	if i := strings.IndexByte(name[start:], ':'); i >= 0 {
		return name[:start+i], name[start+i:]
	}
	return name, ""
}

// Top-level names with and without a leading slash alias the same parameter.
// Keep the stored spelling in the record for metadata and version keys.
func resolveParameter(r Reader, key ParameterKey) (ParameterRecord, error) {
	p, err := r.Parameter(key)
	if errors.Is(err, ErrNotFound) && !strings.Contains(strings.TrimPrefix(key.Name, "/"), "/") {
		if strings.HasPrefix(key.Name, "/") {
			key.Name = strings.TrimPrefix(key.Name, "/")
		} else {
			key.Name = "/" + key.Name
		}
		return r.Parameter(key)
	}
	return p, err
}

func (s *Service) readParameter(r Reader, name, action string, allowARN bool) (ParameterRecord, error) {
	key, err := parameterKey(r.Context(), name, allowARN)
	if err != nil {
		return ParameterRecord{}, err
	}
	p, err := resolveParameter(r, key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return ParameterRecord{}, err
	}
	// Under a claim, an existing row is either this incarnation's parameter or
	// a conflict; a claimed pending first version is in progress, not absent.
	var claimed error
	if err == nil {
		if claimed = cloudFormationParameterConflict(r.Context(), p); claimed == nil && p.CurrentVersion == 0 {
			if _, bound := cloudFormationParameterOwner(r.Context()); bound {
				claimed = failure("TooManyUpdates", "An update to this parameter is already in progress.")
			}
		}
	}
	if err == nil && p.CurrentVersion == 0 {
		err = ErrNotFound
	}
	if errors.Is(err, ErrNotFound) {
		p = ParameterRecord{Key: key, ARN: parameterARN(key)}
	}
	if authErr := s.authorize(r, action, p, nil); authErr != nil {
		return ParameterRecord{}, authErr
	}
	if claimed != nil {
		return ParameterRecord{}, claimed
	}
	if errors.Is(err, ErrNotFound) {
		return ParameterRecord{}, failure("ParameterNotFound", "Parameter "+name+" not found.")
	}
	return p, nil
}

func selectedParameterVersion(r Reader, p ParameterRecord, selector string) (VersionRecord, error) {
	version := p.CurrentVersion
	if selector != "" {
		if selector == ":" || strings.Count(selector, ":") != 1 {
			return VersionRecord{}, failure("ValidationException", "A parameter selector must contain a single version or label.")
		}
		text := strings.TrimPrefix(selector, ":")
		numeric := text != ""
		for _, c := range text {
			if c < '0' || c > '9' {
				numeric = false
				break
			}
		}
		if numeric {
			var err error
			version, err = strconv.ParseInt(text, 10, 64)
			if err != nil || version < 1 || version > p.CurrentVersion {
				return VersionRecord{}, failure("ParameterVersionNotFound", "The specified parameter version was not found.")
			}
		} else {
			versions, err := r.Versions(p.Key)
			if err != nil {
				return VersionRecord{}, err
			}
			for _, v := range versions {
				if v.Key.Version <= p.CurrentVersion && slices.Contains(v.Labels, text) {
					return v, nil
				}
			}
			return VersionRecord{}, failure("ParameterVersionNotFound", "The parameter label was not found.")
		}
	}
	v, err := r.Version(VersionKey{Parameter: p.Key, Version: version})
	if errors.Is(err, ErrNotFound) {
		return VersionRecord{}, failure("ParameterVersionNotFound", "The specified parameter version was not found.")
	}
	return v, err
}

func (s *Service) parameterOutput(r Reader, p ParameterRecord, v VersionRecord, selector string, decrypt bool) (api.Parameter, error) {
	text, err := s.openVersion(r, p, v, decrypt)
	if err != nil {
		return api.Parameter{}, err
	}
	out := api.Parameter{ARN: new(api.String(p.ARN)), Name: new(api.PSParameterName(p.Key.Name)), Type: new(api.ParameterType(v.Type)), Value: new(api.PSParameterValue(text)), Version: new(api.PSParameterVersion(v.Key.Version)), LastModifiedDate: new(v.Modified), DataType: new(api.ParameterDataType(v.DataType))}
	if selector != "" {
		out.Selector = new(api.PSParameterSelector(selector))
	}
	return out, nil
}

func (s *Service) getParameter(tx Transaction, in *api.GetParameterRequest) (*api.GetParameterResult, error) {
	if isSecretReference(value(in.Name)) {
		out, _, err := s.secretReferenceParameter(tx, value(in.Name), "GetParameter", in.WithDecryption != nil && bool(*in.WithDecryption))
		if err != nil {
			return nil, err
		}
		return &api.GetParameterResult{Parameter: &out}, nil
	}
	name, selector := splitParameterSelector(value(in.Name))
	p, err := s.readParameter(tx, name, "GetParameter", true)
	if err != nil {
		return nil, err
	}
	v, err := selectedParameterVersion(tx, p, selector)
	if err != nil {
		return nil, err
	}
	out, err := s.parameterOutput(tx, p, v, selector, in.WithDecryption != nil && bool(*in.WithDecryption))
	if err != nil {
		return nil, err
	}
	if name != p.Key.Name && !strings.HasPrefix(name, "arn:") {
		out.Name = new(api.PSParameterName(name))
	}
	return &api.GetParameterResult{Parameter: &out}, nil
}

func (s *Service) getParameters(tx Transaction, in *api.GetParametersRequest) (*api.GetParametersResult, error) {
	if len(in.Names) < 1 || len(in.Names) > 10 {
		return nil, failure("ValidationException", "Names must contain between 1 and 10 entries.")
	}
	out := &api.GetParametersResult{Parameters: api.ParameterList{}, InvalidParameters: api.ParameterNameList{}}
	seen := make(map[string]bool, len(in.Names))
	for _, requested := range in.Names {
		raw := string(requested)
		if seen[raw] {
			continue
		}
		seen[raw] = true
		if isSecretReference(raw) {
			result, invalid, err := s.secretReferenceParameter(tx, raw, "GetParameters", in.WithDecryption != nil && bool(*in.WithDecryption))
			if err != nil {
				if invalid {
					out.InvalidParameters = append(out.InvalidParameters, requested)
					continue
				}
				return nil, err
			}
			out.Parameters = append(out.Parameters, result)
			continue
		}
		name, selector := splitParameterSelector(raw)
		p, err := s.readParameter(tx, name, "GetParameters", true)
		var v VersionRecord
		if err == nil {
			v, err = selectedParameterVersion(tx, p, selector)
		}
		if err != nil {
			var wire *awswire.Error
			if errors.As(err, &wire) && (wire.Code == "ParameterNotFound" || wire.Code == "ParameterVersionNotFound") {
				out.InvalidParameters = append(out.InvalidParameters, requested)
				continue
			}
			return nil, err
		}
		result, err := s.parameterOutput(tx, p, v, selector, in.WithDecryption != nil && bool(*in.WithDecryption))
		if err != nil {
			return nil, err
		}
		if name != p.Key.Name && !strings.HasPrefix(name, "arn:") {
			result.Name = new(api.PSParameterName(name))
		}
		out.Parameters = append(out.Parameters, result)
	}
	slices.SortStableFunc(out.Parameters, func(a, b api.Parameter) int { return strings.Compare(value(a.Name), value(b.Name)) })
	slices.Sort(out.InvalidParameters)
	return out, nil
}

type parameterVersionRow struct {
	Parameter ParameterRecord
	Version   VersionRecord
}

func (s *Service) getParametersByPath(tx Transaction, in *api.GetParametersByPathRequest) (*api.GetParametersByPathResult, error) {
	path, err := parameterPath(value(in.Path))
	if err != nil {
		return nil, err
	}
	filters, err := compileParameterFilters(in.ParameterFilters, true)
	if err != nil {
		return nil, err
	}
	recursive := in.Recursive != nil && bool(*in.Recursive)
	decrypt := in.WithDecryption != nil && bool(*in.WithDecryption)
	key := ParameterKey{Scope: scopeFor(tx.Context()), Name: path}
	// AWS authorizes the requested hierarchy, not each descendant. In particular,
	// an explicit deny on /a/b does not defeat an allowed recursive read of /a.
	if err := s.authorize(tx, "GetParametersByPath", ParameterRecord{Key: key, ARN: parameterARN(key)}, map[string][]string{"ssm:Recursive": {strconv.FormatBool(recursive)}}); err != nil {
		return nil, err
	}
	parameters, err := tx.Parameters(key.Scope)
	if err != nil {
		return nil, err
	}
	labeled := false
	for _, f := range filters {
		if f.Key == "Label" {
			labeled = true
			break
		}
	}
	rows := make([]parameterVersionRow, 0, len(parameters))
	for _, p := range parameters {
		if p.CurrentVersion == 0 || !parameterInPath(p.Key.Name, path, recursive) {
			continue
		}
		if labeled {
			versions, err := tx.Versions(p.Key)
			if err != nil {
				return nil, err
			}
			for _, v := range versions {
				if v.Key.Version <= p.CurrentVersion && matchesParameterFilters(p, v, filters) {
					rows = append(rows, parameterVersionRow{Parameter: p, Version: v})
					break
				}
			}
		} else {
			v, err := selectedParameterVersion(tx, p, "")
			if err != nil {
				return nil, err
			}
			if matchesParameterFilters(p, v, filters) {
				rows = append(rows, parameterVersionRow{Parameter: p, Version: v})
			}
		}
	}
	size := 10
	if in.MaxResults != nil {
		size = int(*in.MaxResults)
	}
	query := struct {
		Path               string
		Recursive, Decrypt bool
		Filters            []parameterFilter
	}{path, recursive, decrypt, filters}
	rows, next, err := parameterPage(s, tx, "GetParametersByPath", query, rows, func(row parameterVersionRow) string { return row.Parameter.Key.Name }, size, 10, in.NextToken)
	if err != nil {
		return nil, err
	}
	out := &api.GetParametersByPathResult{Parameters: make(api.ParameterList, 0, len(rows)), NextToken: next}
	for _, row := range rows {
		parameter, err := s.parameterOutput(tx, row.Parameter, row.Version, "", decrypt)
		if err != nil {
			return nil, err
		}
		out.Parameters = append(out.Parameters, parameter)
	}
	return out, nil
}

func (s *Service) getParameterHistory(tx Transaction, in *api.GetParameterHistoryRequest) (*api.GetParameterHistoryResult, error) {
	p, err := s.readParameter(tx, value(in.Name), "GetParameterHistory", true)
	if err != nil {
		return nil, err
	}
	versions, err := tx.Versions(p.Key)
	if err != nil {
		return nil, err
	}
	versions = slices.DeleteFunc(versions, func(v VersionRecord) bool { return v.Key.Version > p.CurrentVersion })
	decrypt := in.WithDecryption != nil && bool(*in.WithDecryption)
	query := struct {
		Key     ParameterKey
		Decrypt bool
	}{p.Key, decrypt}
	size := 50
	if in.MaxResults != nil {
		size = int(*in.MaxResults)
	}
	versions, next, err := parameterPage(s, tx, "GetParameterHistory", query, versions, func(v VersionRecord) int64 { return v.Key.Version }, size, 50, in.NextToken)
	if err != nil {
		return nil, err
	}
	out := &api.GetParameterHistoryResult{Parameters: make(api.ParameterHistoryList, 0, len(versions)), NextToken: next}
	for _, v := range versions {
		text, err := s.openVersion(tx, p, v, decrypt)
		if err != nil {
			return nil, err
		}
		row := api.ParameterHistory{Name: new(api.PSParameterName(p.Key.Name)), Type: new(api.ParameterType(v.Type)), Value: new(api.PSParameterValue(text)), Version: new(api.PSParameterVersion(v.Key.Version)), LastModifiedDate: new(v.Modified), LastModifiedUser: new(api.String(v.ModifiedUser)), Tier: new(api.ParameterTier(v.Tier)), DataType: new(api.ParameterDataType(v.DataType)), Policies: policyHistoryOutput(v.Policies), Labels: parameterLabels(v.Labels)}
		if v.KeyID != "" {
			row.KeyId = new(api.ParameterKeyId(v.KeyID))
		}
		if v.Description != "" {
			row.Description = new(api.ParameterDescription(v.Description))
		}
		if v.AllowedPattern != "" {
			row.AllowedPattern = new(api.AllowedPattern(v.AllowedPattern))
		}
		out.Parameters = append(out.Parameters, row)
	}
	return out, nil
}

func (s *Service) describeParameters(tx Transaction, in *api.DescribeParametersRequest) (*api.DescribeParametersResult, error) {
	if err := s.authorize(tx, "DescribeParameters", ParameterRecord{Key: ParameterKey{Scope: scopeFor(tx.Context())}, ARN: "*"}, nil); err != nil {
		return nil, err
	}
	filters, err := describeParameterFilters(in)
	if err != nil {
		return nil, err
	}
	shared := in.Shared != nil && bool(*in.Shared)
	var parameters []ParameterRecord
	if shared {
		parameters, err = s.sharedParameters(tx)
	} else {
		parameters, err = tx.Parameters(scopeFor(tx.Context()))
	}
	if err != nil {
		return nil, err
	}
	rows := make([]parameterVersionRow, 0, len(parameters))
	for _, p := range parameters {
		if p.CurrentVersion == 0 {
			continue
		}
		v, err := selectedParameterVersion(tx, p, "")
		if err != nil {
			return nil, err
		}
		if matchesParameterFilters(p, v, filters) {
			rows = append(rows, parameterVersionRow{Parameter: p, Version: v})
		}
	}
	size := 50
	if in.MaxResults != nil {
		size = int(*in.MaxResults)
	}
	query := struct {
		Filters []parameterFilter
		Shared  bool
	}{filters, shared}
	rows, next, err := parameterPage(s, tx, "DescribeParameters", query, rows, func(row parameterVersionRow) string { return row.Parameter.ARN }, size, 50, in.NextToken)
	if err != nil {
		return nil, err
	}
	out := &api.DescribeParametersResult{Parameters: make(api.ParameterMetadataList, 0, len(rows)), NextToken: next}
	for _, row := range rows {
		p, v := row.Parameter, row.Version
		metadata := api.ParameterMetadata{ARN: new(api.String(p.ARN)), Name: new(api.PSParameterName(p.Key.Name)), Type: new(api.ParameterType(p.Type)), Version: new(api.PSParameterVersion(v.Key.Version)), LastModifiedDate: new(v.Modified), LastModifiedUser: new(api.String(v.ModifiedUser)), Tier: new(api.ParameterTier(p.Tier)), DataType: new(api.ParameterDataType(p.DataType)), Policies: policyOutput(p.Policies)}
		if v.KeyID != "" {
			metadata.KeyId = new(api.ParameterKeyId(v.KeyID))
		}
		if p.Description != "" {
			metadata.Description = new(api.ParameterDescription(p.Description))
		}
		if p.AllowedPattern != "" {
			metadata.AllowedPattern = new(api.AllowedPattern(p.AllowedPattern))
		}
		out.Parameters = append(out.Parameters, metadata)
	}
	return out, nil
}
