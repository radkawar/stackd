package ssmdocuments

import (
	"bytes"
	"encoding/json"
	"maps"
	"slices"
	"strconv"

	"gopkg.in/yaml.v3"
	api "stackd/internal/awsapi/ssm"
)

func description(record Record, v Version) (*api.DocumentDescription, error) {
	doc := Document{Name: record.Key.Name, Owner: record.Key.AccountID, Version: strconv.FormatInt(v.Key.Version, 10)}
	platforms := api.PlatformTypeList{}
	if record.Type == "Command" {
		var err error
		doc, err = resolved(v)
		if err != nil {
			return nil, err
		}
		platforms = api.PlatformTypeList{"Linux", "MacOS"}
	}
	out := &api.DocumentDescription{Name: new(api.DocumentARN(doc.Name)), Owner: new(api.DocumentOwner(doc.Owner)), CreatedDate: new(api.DateTime(v.Created)), Status: new(api.DocumentStatus(v.Status)), DocumentVersion: new(api.DocumentVersion(doc.Version)), DefaultVersion: new(api.DocumentVersion(strconv.FormatInt(record.DefaultVersion, 10))), LatestVersion: new(api.DocumentVersion(strconv.FormatInt(record.LatestVersion, 10))), DocumentType: new(api.DocumentType(record.Type)), DocumentFormat: new(api.DocumentFormat(v.Format)), SchemaVersion: new(api.DocumentSchemaVersion(doc.SchemaVersion)), Description: optional[api.DescriptionInDocument](doc.Description), Hash: new(api.DocumentHash(v.Hash)), HashType: new(api.DocumentHashType("Sha256")), DisplayName: optional[api.DocumentDisplayName](v.DisplayName), VersionName: optional[api.DocumentVersionName](v.VersionName), TargetType: optional[api.TargetType](v.TargetType), PlatformTypes: platforms, Parameters: api.DocumentParameterList{}, Tags: api.TagList{}, Requires: documentRequires(record)}
	for _, name := range slices.Sorted(maps.Keys(doc.Parameters)) {
		p := doc.Parameters[name]
		row := api.DocumentParameter{Name: new(api.DocumentParameterName(name)), Type: new(api.DocumentParameterType(p.Type)), Description: optional[api.DocumentParameterDescrption](p.Description)}
		if p.Default != nil {
			var text string
			if p.Type == "String" {
				if err := json.Unmarshal(p.Default, &text); err != nil {
					return nil, err
				}
			} else {
				var compact bytes.Buffer
				if err := json.Compact(&compact, p.Default); err != nil {
					return nil, err
				}
				text = compact.String()
			}
			row.DefaultValue = new(api.DocumentParameterDefaultValue(text))
		}
		out.Parameters = append(out.Parameters, row)
	}
	for _, key := range slices.Sorted(maps.Keys(record.Tags)) {
		out.Tags = append(out.Tags, api.Tag{Key: new(api.TagKey(key)), Value: new(api.TagValue(record.Tags[key]))})
	}
	if record.Key.AccountID == "" {
		out.Category = api.CategoryList{"Script Execution"}
		out.CategoryEnum = api.CategoryEnumList{"ScriptExecution"}
	}
	return out, nil
}
func (s *Service) getDocument(tx Transaction, in *api.GetDocumentRequest) (*api.GetDocumentResult, error) {
	record, err := s.loadClaimed(tx, "GetDocument", value(in.Name))
	if err != nil {
		return nil, err
	}
	v, err := selectVersion(tx, record, value(in.DocumentVersion), value(in.VersionName))
	if err != nil {
		return nil, err
	}
	format := value(in.DocumentFormat)
	if format == "" {
		format = v.Format
	}
	content := v.Content
	if format != v.Format {
		if format != "JSON" && format != "YAML" {
			return nil, failure("InvalidDocumentContent", "Document conversion requires JSON or YAML.")
		}
		var data []byte
		if record.Type == "Command" {
			doc, err := resolved(v)
			if err != nil {
				return nil, err
			}
			data, err = JSONContent(doc)
			if err != nil {
				return nil, err
			}
		} else {
			tree, err := decodeConfiguration(v.Content, v.Format)
			if err != nil {
				return nil, err
			}
			data, err = json.Marshal(tree)
			if err != nil {
				return nil, err
			}
		}
		if format == "JSON" {
			content = string(data)
		} else {
			var tree any
			if record.Type == "Command" {
				if err = json.Unmarshal(data, &tree); err != nil {
					return nil, err
				}
			} else {
				var node yaml.Node
				if err = yaml.Unmarshal(data, &node); err != nil {
					return nil, err
				}
				tree = &node
			}
			data, err = yaml.Marshal(tree)
			if err != nil {
				return nil, err
			}
			content = string(data)
		}
	}
	return &api.GetDocumentResult{Name: new(api.DocumentARN(record.Key.Name)), Content: new(api.DocumentContent(content)), CreatedDate: new(api.DateTime(v.Created)), DocumentVersion: new(api.DocumentVersion(strconv.FormatInt(v.Key.Version, 10))), DocumentType: new(api.DocumentType(record.Type)), DocumentFormat: new(api.DocumentFormat(format)), Status: new(api.DocumentStatus(v.Status)), DisplayName: optional[api.DocumentDisplayName](v.DisplayName), VersionName: optional[api.DocumentVersionName](v.VersionName), Requires: documentRequires(record)}, nil
}
func (s *Service) describeDocument(tx Transaction, in *api.DescribeDocumentRequest) (*api.DescribeDocumentResult, error) {
	record, err := s.loadClaimed(tx, "DescribeDocument", value(in.Name))
	if err != nil {
		return nil, err
	}
	v, err := selectVersion(tx, record, value(in.DocumentVersion), value(in.VersionName))
	if err != nil {
		return nil, err
	}
	doc, err := description(record, v)
	if doc != nil && record.Type != "Command" {
		doc.SchemaVersion = nil
	}
	return &api.DescribeDocumentResult{Document: doc}, err
}
func (s *Service) listVersions(tx Transaction, in *api.ListDocumentVersionsRequest) (*api.ListDocumentVersionsResult, error) {
	record, err := s.loadClaimed(tx, "ListDocumentVersions", value(in.Name))
	if err != nil {
		return nil, err
	}
	versions, err := versionsFor(tx, record)
	if err != nil {
		return nil, err
	}
	versions = slices.DeleteFunc(versions, func(v Version) bool { return !sharedVersionAllowed(tx, record, v.Key.Version) })
	size := 50
	if in.MaxResults != nil {
		size = int(*in.MaxResults)
	}
	rows, next, err := documentPage(s, tx, "ListDocumentVersions", record.Key, versions, func(v Version) int64 { return -v.Key.Version }, size, in.NextToken)
	if err != nil {
		return nil, err
	}
	out := &api.ListDocumentVersionsResult{DocumentVersions: api.DocumentVersionList{}, NextToken: next}
	for _, v := range rows {
		out.DocumentVersions = append(out.DocumentVersions, api.DocumentVersionInfo{Name: new(api.DocumentName(record.Key.Name)), DocumentVersion: new(api.DocumentVersion(strconv.FormatInt(v.Key.Version, 10))), DocumentFormat: new(api.DocumentFormat(v.Format)), CreatedDate: new(api.DateTime(v.Created)), IsDefaultVersion: new(api.Boolean(v.Key.Version == record.DefaultVersion)), Status: new(api.DocumentStatus(v.Status)), DisplayName: optional[api.DocumentDisplayName](v.DisplayName), VersionName: optional[api.DocumentVersionName](v.VersionName)})
	}
	return out, nil
}
