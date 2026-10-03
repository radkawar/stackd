package glue

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/ohler55/ojg/jp"
	api "stackd/internal/awsapi/glue"
)

func registerClassifiers(s *Service) {
	registerControl(s, "CreateClassifier", s.createClassifier)
	registerControl(s, "GetClassifier", s.getClassifier)
	registerControl(s, "GetClassifiers", s.getClassifiers)
	registerControl(s, "UpdateClassifier", s.updateClassifier)
	registerControl(s, "DeleteClassifier", s.deleteClassifier)
}

func classifierName(v api.Classifier) string {
	switch {
	case v.CsvClassifier != nil:
		return value(v.CsvClassifier.Name)
	case v.JsonClassifier != nil:
		return value(v.JsonClassifier.Name)
	case v.XMLClassifier != nil:
		return value(v.XMLClassifier.Name)
	case v.GrokClassifier != nil:
		return value(v.GrokClassifier.Name)
	default:
		return ""
	}
}

func validateClassifier(v api.Classifier) error {
	count := 0
	if v.CsvClassifier != nil {
		count++
	}
	if v.JsonClassifier != nil {
		count++
	}
	if v.XMLClassifier != nil {
		count++
	}
	if v.GrokClassifier != nil {
		count++
	}
	if count != 1 || classifierName(v) == "" {
		return failure("InvalidInputException", "Specify exactly one named classifier.")
	}
	if c := v.CsvClassifier; c != nil {
		if c.Delimiter != nil && (utf8.RuneCountInString(value(c.Delimiter)) != 1 || strings.ContainsAny(value(c.Delimiter), "\r\n")) {
			return failure("InvalidInputException", "CSV delimiter must be one character.")
		}
		if c.QuoteSymbol != nil && utf8.RuneCountInString(value(c.QuoteSymbol)) != 1 {
			return failure("InvalidInputException", "CSV quote symbol must be one character.")
		}
		if c.ContainsHeader != nil && value(c.ContainsHeader) != "PRESENT" && value(c.ContainsHeader) != "ABSENT" && value(c.ContainsHeader) != "UNKNOWN" {
			return failure("InvalidInputException", "Invalid CSV header option.")
		}
	}
	if c := v.JsonClassifier; c != nil {
		if !strings.HasPrefix(value(c.JsonPath), "$") {
			return failure("InvalidInputException", "JSON path must start with $.")
		}
		if _, err := jp.ParseString(value(c.JsonPath)); err != nil {
			return failure("InvalidInputException", "Invalid JSON path.")
		}
	}
	if c := v.XMLClassifier; c != nil && (value(c.RowTag) == "" || strings.ContainsAny(value(c.RowTag), "<> \t\r\n")) {
		return failure("InvalidInputException", "An XML row tag is required.")
	}
	if c := v.GrokClassifier; c != nil && (value(c.GrokPattern) == "" || value(c.Classification) == "" || strings.ContainsAny(value(c.GrokPattern), "\r\n")) {
		return failure("InvalidInputException", "A single-line Grok pattern and classification are required.")
	}
	return nil
}

func (s *Service) createClassifier(ctx context.Context, tx Transaction, in *api.CreateClassifierInput) (*api.CreateClassifierOutput, error) {
	v := api.Classifier{}
	now := s.clock.Now().UTC()
	version := api.VersionId(1)
	if c := in.CsvClassifier; c != nil {
		v.CsvClassifier = &api.CsvClassifier{Name: c.Name, AllowSingleColumn: c.AllowSingleColumn, ContainsHeader: c.ContainsHeader, CustomDatatypeConfigured: c.CustomDatatypeConfigured, CustomDatatypes: c.CustomDatatypes, Delimiter: c.Delimiter, DisableValueTrimming: c.DisableValueTrimming, Header: c.Header, QuoteSymbol: c.QuoteSymbol, Serde: c.Serde, CreationTime: &now, LastUpdated: &now, Version: &version}
	}
	if c := in.JsonClassifier; c != nil {
		v.JsonClassifier = &api.JsonClassifier{Name: c.Name, JsonPath: c.JsonPath, CreationTime: &now, LastUpdated: &now, Version: &version}
	}
	if c := in.XMLClassifier; c != nil {
		v.XMLClassifier = &api.XMLClassifier{Name: c.Name, RowTag: c.RowTag, Classification: c.Classification, CreationTime: &now, LastUpdated: &now, Version: &version}
	}
	if c := in.GrokClassifier; c != nil {
		v.GrokClassifier = &api.GrokClassifier{Name: c.Name, GrokPattern: c.GrokPattern, CustomPatterns: c.CustomPatterns, Classification: c.Classification, CreationTime: &now, LastUpdated: &now, Version: &version}
	}
	if err := validateClassifier(v); err != nil {
		return nil, err
	}
	key := ResourceKey{Scope: scopeFor(ctx), Name: classifierName(v)}
	if err := s.authorize(ctx, tx, "CreateClassifier", key.Scope, "*", nil); err != nil {
		return nil, err
	}
	if _, err := tx.Classifier(key); err == nil {
		return nil, failure("AlreadyExistsException", "Classifier already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err := tx.PutClassifier(ClassifierRecord{Key: key, Classifier: v}); err != nil {
		return nil, err
	}
	return &api.CreateClassifierOutput{}, nil
}

func (s *Service) getClassifier(ctx context.Context, tx Transaction, in *api.GetClassifierInput) (*api.GetClassifierOutput, error) {
	key := ResourceKey{Scope: scopeFor(ctx), Name: value(in.Name)}
	if err := s.authorize(ctx, tx, "GetClassifier", key.Scope, "*", nil); err != nil {
		return nil, err
	}
	v, err := tx.Classifier(key)
	if err != nil {
		return nil, err
	}
	return &api.GetClassifierOutput{Classifier: &v.Classifier}, nil
}

func (s *Service) getClassifiers(ctx context.Context, tx Transaction, in *api.GetClassifiersInput) (*api.GetClassifiersOutput, error) {
	scope := scopeFor(ctx)
	if err := s.authorize(ctx, tx, "GetClassifiers", scope, "*", nil); err != nil {
		return nil, err
	}
	rows, err := tx.Classifiers(scope)
	if err != nil {
		return nil, err
	}
	start, end, next, err := crawlerPage(scope, "classifiers", "", in.NextToken, in.MaxResults, len(rows))
	if err != nil {
		return nil, err
	}
	out := &api.GetClassifiersOutput{Classifiers: api.ClassifierList{}, NextToken: next}
	for _, row := range rows[start:end] {
		out.Classifiers = append(out.Classifiers, row.Classifier)
	}
	return out, nil
}

func (s *Service) updateClassifier(ctx context.Context, tx Transaction, in *api.UpdateClassifierInput) (*api.UpdateClassifierOutput, error) {
	name, kind, count := "", "", 0
	if c := in.CsvClassifier; c != nil {
		name, kind, count = value(c.Name), "csv", count+1
	}
	if c := in.JsonClassifier; c != nil {
		name, kind, count = value(c.Name), "json", count+1
	}
	if c := in.XMLClassifier; c != nil {
		name, kind, count = value(c.Name), "xml", count+1
	}
	if c := in.GrokClassifier; c != nil {
		name, kind, count = value(c.Name), "grok", count+1
	}
	if count != 1 {
		return nil, failure("InvalidInputException", "Specify exactly one classifier.")
	}
	key := ResourceKey{Scope: scopeFor(ctx), Name: name}
	if err := s.authorize(ctx, tx, "UpdateClassifier", key.Scope, "*", nil); err != nil {
		return nil, err
	}
	row, err := tx.Classifier(key)
	if err != nil {
		return nil, err
	}
	v, now := &row.Classifier, s.clock.Now().UTC()
	switch {
	case kind == "csv" && v.CsvClassifier != nil:
		c, u := v.CsvClassifier, in.CsvClassifier
		c.AllowSingleColumn, c.ContainsHeader, c.CustomDatatypeConfigured, c.CustomDatatypes = u.AllowSingleColumn, u.ContainsHeader, u.CustomDatatypeConfigured, u.CustomDatatypes
		c.Delimiter, c.DisableValueTrimming, c.Header, c.QuoteSymbol, c.Serde = u.Delimiter, u.DisableValueTrimming, u.Header, u.QuoteSymbol, u.Serde
		c.LastUpdated, c.Version = &now, new(*c.Version+1)
	case kind == "json" && v.JsonClassifier != nil:
		c, u := v.JsonClassifier, in.JsonClassifier
		if u.JsonPath != nil {
			c.JsonPath = u.JsonPath
		}
		c.LastUpdated, c.Version = &now, new(*c.Version+1)
	case kind == "xml" && v.XMLClassifier != nil:
		c, u := v.XMLClassifier, in.XMLClassifier
		if u.RowTag != nil {
			c.RowTag = u.RowTag
		}
		if u.Classification != nil {
			c.Classification = u.Classification
		}
		c.LastUpdated, c.Version = &now, new(*c.Version+1)
	case kind == "grok" && v.GrokClassifier != nil:
		c, u := v.GrokClassifier, in.GrokClassifier
		if u.GrokPattern != nil {
			c.GrokPattern = u.GrokPattern
		}
		if u.CustomPatterns != nil {
			c.CustomPatterns = u.CustomPatterns
		}
		if u.Classification != nil {
			c.Classification = u.Classification
		}
		c.LastUpdated, c.Version = &now, new(*c.Version+1)
	default:
		return nil, failure("InvalidInputException", "Classifier type cannot be changed.")
	}
	if err := validateClassifier(*v); err != nil {
		return nil, err
	}
	if err := tx.PutClassifier(row); err != nil {
		return nil, err
	}
	return &api.UpdateClassifierOutput{}, nil
}

func (s *Service) deleteClassifier(ctx context.Context, tx Transaction, in *api.DeleteClassifierInput) (*api.DeleteClassifierOutput, error) {
	key := ResourceKey{Scope: scopeFor(ctx), Name: value(in.Name)}
	if err := s.authorize(ctx, tx, "DeleteClassifier", key.Scope, "*", nil); err != nil {
		return nil, err
	}
	if _, err := tx.Classifier(key); err != nil {
		return nil, err
	}
	if err := tx.DeleteClassifier(key); err != nil {
		return nil, err
	}
	return &api.DeleteClassifierOutput{}, nil
}
