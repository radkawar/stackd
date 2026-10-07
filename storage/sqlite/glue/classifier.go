package glue

import (
	"encoding/json"
	"fmt"
	"time"

	api "stackd/internal/awsapi/glue"
	domain "stackd/internal/services/glue"
	"stackd/storage/sqlite/glue/internal/sqlcgen"
)

func (r reader) Classifier(key domain.ResourceKey) (domain.ClassifierRecord, error) {
	v, err := r.q.GetGlueClassifier(r.ctx, sqlcgen.GetGlueClassifierParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Name: key.Name})
	if err != nil {
		return domain.ClassifierRecord{}, crawlerMissing(err)
	}
	return decodeClassifier(v)
}
func (r reader) Classifiers(scope domain.Scope) ([]domain.ClassifierRecord, error) {
	rows, err := r.q.ListGlueClassifiers(r.ctx, sqlcgen.ListGlueClassifiersParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ClassifierRecord, 0, len(rows))
	for _, v := range rows {
		row, err := decodeClassifier(v)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, nil
}
func decodeClassifier(v sqlcgen.GlueClassifier) (domain.ClassifierRecord, error) {
	row := domain.ClassifierRecord{Key: domain.ResourceKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name}}
	row.CFNOwner = v.CfnOwner
	created, updated := time.Unix(0, v.CreatedAt).UTC(), time.Unix(0, v.UpdatedAt).UTC()
	name, version := api.NameString(v.Name), api.VersionId(v.Version)
	switch v.Kind {
	case "json":
		row.Classifier.JsonClassifier = &api.JsonClassifier{Name: &name, Version: &version, CreationTime: &created, LastUpdated: &updated, JsonPath: crawlerPointer[api.JsonPath](v.JsonPath)}
	case "xml":
		row.Classifier.XMLClassifier = &api.XMLClassifier{Name: &name, Version: &version, CreationTime: &created, LastUpdated: &updated, RowTag: crawlerPointer[api.RowTag](v.RowTag), Classification: crawlerPointer[api.Classification](v.Classification)}
	case "grok":
		row.Classifier.GrokClassifier = &api.GrokClassifier{Name: &name, Version: &version, CreationTime: &created, LastUpdated: &updated, GrokPattern: crawlerPointer[api.GrokPattern](v.GrokPattern), CustomPatterns: crawlerPointer[api.CustomPatterns](v.CustomPatterns), Classification: crawlerPointer[api.Classification](v.Classification)}
	case "csv":
		c := &api.CsvClassifier{Name: &name, Version: &version, CreationTime: &created, LastUpdated: &updated, Delimiter: crawlerPointer[api.CsvColumnDelimiter](v.Delimiter), QuoteSymbol: crawlerPointer[api.CsvQuoteSymbol](v.QuoteSymbol), ContainsHeader: crawlerPointer[api.CsvHeaderOption](v.ContainsHeader), Serde: crawlerPointer[api.CsvSerdeOption](v.Serde), AllowSingleColumn: crawlerBoolPointer[api.NullableBoolean](v.AllowSingleColumn), DisableValueTrimming: crawlerBoolPointer[api.NullableBoolean](v.DisableValueTrimming), CustomDatatypeConfigured: crawlerBoolPointer[api.NullableBoolean](v.CustomDatatypeConfigured)}
		if err := json.Unmarshal([]byte(v.Header), &c.Header); err != nil {
			return domain.ClassifierRecord{}, err
		}
		if err := json.Unmarshal([]byte(v.CustomDatatypes), &c.CustomDatatypes); err != nil {
			return domain.ClassifierRecord{}, err
		}
		row.Classifier.CsvClassifier = c
	default:
		return domain.ClassifierRecord{}, fmt.Errorf("unknown retained Glue classifier type %q", v.Kind)
	}
	return row, nil
}
func (w writer) PutClassifier(row domain.ClassifierRecord) error {
	v := sqlcgen.PutGlueClassifierParams{Partition: row.Key.Partition, AccountID: row.Key.AccountID, Region: row.Key.Region, Name: row.Key.Name, Header: "null", CustomDatatypes: "null"}
	v.CfnOwner = row.CFNOwner
	switch c := row.Classifier; {
	case c.JsonClassifier != nil:
		x := c.JsonClassifier
		v.Kind = "json"
		v.JsonPath = crawlerString(x.JsonPath)
		v.Version = int64(*x.Version)
		v.CreatedAt = x.CreationTime.UnixNano()
		v.UpdatedAt = x.LastUpdated.UnixNano()
	case c.XMLClassifier != nil:
		x := c.XMLClassifier
		v.Kind = "xml"
		v.RowTag = crawlerString(x.RowTag)
		v.Classification = crawlerString(x.Classification)
		v.Version = int64(*x.Version)
		v.CreatedAt = x.CreationTime.UnixNano()
		v.UpdatedAt = x.LastUpdated.UnixNano()
	case c.GrokClassifier != nil:
		x := c.GrokClassifier
		v.Kind = "grok"
		v.GrokPattern = crawlerString(x.GrokPattern)
		v.CustomPatterns = crawlerString(x.CustomPatterns)
		v.Classification = crawlerString(x.Classification)
		v.Version = int64(*x.Version)
		v.CreatedAt = x.CreationTime.UnixNano()
		v.UpdatedAt = x.LastUpdated.UnixNano()
	case c.CsvClassifier != nil:
		x := c.CsvClassifier
		v.Kind = "csv"
		v.Delimiter = crawlerString(x.Delimiter)
		v.QuoteSymbol = crawlerString(x.QuoteSymbol)
		v.ContainsHeader = crawlerString(x.ContainsHeader)
		v.Serde = crawlerString(x.Serde)
		v.AllowSingleColumn = crawlerBool(x.AllowSingleColumn)
		v.DisableValueTrimming = crawlerBool(x.DisableValueTrimming)
		v.CustomDatatypeConfigured = crawlerBool(x.CustomDatatypeConfigured)
		v.Version = int64(*x.Version)
		v.CreatedAt = x.CreationTime.UnixNano()
		v.UpdatedAt = x.LastUpdated.UnixNano()
		var err error
		v.Header, err = crawlerJSON(x.Header)
		if err != nil {
			return err
		}
		v.CustomDatatypes, err = crawlerJSON(x.CustomDatatypes)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("empty Glue classifier")
	}
	return w.q.PutGlueClassifier(w.ctx, v)
}
func (w writer) DeleteClassifier(key domain.ResourceKey) error {
	return w.q.DeleteGlueClassifier(w.ctx, sqlcgen.DeleteGlueClassifierParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Name: key.Name})
}
