package glue

import (
	"context"
	"encoding/json"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	api "stackd/internal/awsapi/glue"
)

type crawlerDerivedTable struct {
	Table      api.TableInput
	Partitions []api.PartitionInput
}
type crawlerObjectGroup struct {
	location      string
	name          string
	schema        crawlerSchema
	partitionKeys api.ColumnList
	partitions    map[string]api.PartitionInput
}

func (s *Service) crawlerExecutionSupported(v api.Crawler) error {
	if s.crawlerSource == nil {
		return unsupported("Crawler S3/execution-role adapter is not configured.")
	}
	if value(v.DatabaseName) == "" {
		return failure("InvalidInputException", "A catalog database is required for these crawler targets.")
	}
	t := v.Targets
	// TODO: Comeback use the native DynamoDB/MongoDB/Iceberg/Delta/Hudi owners and catalog-target recrawl engines.
	if len(t.DynamoDBTargets)+len(t.MongoDBTargets)+len(t.CatalogTargets)+len(t.IcebergTargets)+len(t.DeltaTargets)+len(t.HudiTargets) != 0 {
		return unsupported("Crawler target requires a native discovery adapter that is not configured.")
	}
	if v.CrawlerSecurityConfiguration != nil && value(v.CrawlerSecurityConfiguration) != "" {
		return unsupported("Crawler security-configuration log encryption is not implemented.")
	}
	if v.LakeFormationConfiguration != nil && v.LakeFormationConfiguration.UseLakeFormationCredentials != nil && bool(*v.LakeFormationConfiguration.UseLakeFormationCredentials) {
		return unsupported("Lake Formation credential crawling is not implemented.")
	}
	if v.LineageConfiguration != nil && value(v.LineageConfiguration.CrawlerLineageSettings) == "ENABLE" {
		return unsupported("Crawler lineage publication is not implemented.")
	}
	if v.RecrawlPolicy != nil && value(v.RecrawlPolicy.RecrawlBehavior) != "CRAWL_EVERYTHING" {
		return unsupported("Incremental and event-driven recrawl modes are not implemented.")
	}
	if v.Configuration != nil && value(v.Configuration) != "" {
		var cfg map[string]json.RawMessage
		_ = json.Unmarshal([]byte(value(v.Configuration)), &cfg)
		for key := range cfg {
			if key != "Version" {
				return unsupported("This crawler configuration requires a grouping or sampling mode that is not implemented.")
			}
		}
	}
	for _, target := range t.S3Targets {
		if value(target.ConnectionName) != "" || value(target.EventQueueArn) != "" || value(target.DlqEventQueueArn) != "" {
			return unsupported("VPC and event-driven S3 crawler targets are not implemented.")
		}
	}
	return nil
}

func crawlerGlob(pattern string) (*regexp.Regexp, error) {
	var out strings.Builder
	out.WriteByte('^')
	inClass := false
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				i++
				if i+1 < len(pattern) && pattern[i+1] == '/' {
					i++
					out.WriteString("(?:.*/)?")
				} else {
					out.WriteString(".*")
				}
			} else {
				out.WriteString("[^/]*")
			}
		case '?':
			out.WriteString("[^/]")
		case '[':
			inClass = true
			out.WriteByte(c)
			if i+1 < len(pattern) && pattern[i+1] == '!' {
				i++
				out.WriteByte('^')
			}
		case ']':
			inClass = false
			out.WriteByte(c)
		case '{':
			out.WriteString("(?:")
		case '}':
			out.WriteByte(')')
		case ',':
			out.WriteByte('|')
		default:
			if inClass {
				out.WriteByte(c)
			} else {
				out.WriteString(regexp.QuoteMeta(string(c)))
			}
		}
	}
	out.WriteByte('$')
	compiled, err := regexp.Compile(out.String())
	if err != nil {
		return nil, failure("InvalidInputException", "Invalid crawler exclusion pattern.")
	}
	return compiled, nil
}
func mergeCrawlerColumns(a, b api.ColumnList) api.ColumnList {
	out := api.CloneColumnList(a)
	positions := make(map[string]int, len(out))
	for i, col := range out {
		positions[value(col.Name)] = i
	}
	for _, col := range b {
		if i, ok := positions[value(col.Name)]; ok {
			out[i].Type = new(api.ColumnTypeString(mergeColumnType(value(out[i].Type), value(col.Type))))
		} else {
			positions[value(col.Name)] = len(out)
			out = append(out, col)
		}
	}
	return out
}
func objectCrawlerLocation(bucket, key, prefix string) (string, string, api.ColumnList, api.ValueStringList) {
	directory := path.Dir(key)
	if directory == "." {
		directory = ""
	}
	parts := strings.Split(directory, "/")
	first := -1
	keys := api.ColumnList{}
	values := api.ValueStringList{}
	for i, segment := range parts {
		if name, val, ok := strings.Cut(segment, "="); ok && name != "" {
			if first < 0 {
				first = i
			}
			keys = append(keys, api.Column{Name: new(api.NameString(strings.ToLower(name))), Type: new(api.ColumnTypeString("string"))})
			values = append(values, api.ValueString(val))
		} else if first >= 0 {
			keys = nil
			values = nil
			first = -1
			break
		}
	}
	root := directory
	if first >= 0 {
		root = strings.Join(parts[:first], "/")
	}
	if prefix != "" && directory == strings.TrimSuffix(prefix, "/") {
		root = directory
	}
	name := path.Base(root)
	if name == "." || name == "" {
		name = bucket
	}
	location := "s3://" + bucket + "/"
	if root != "" {
		location += root + "/"
	}
	return location, name, keys, values
}
func descriptorForCrawler(schema crawlerSchema, location string) *api.StorageDescriptor {
	return &api.StorageDescriptor{Columns: api.CloneColumnList(schema.Columns), Location: new(api.LocationString(location)), InputFormat: new(api.FormatString(schema.InputFormat)), OutputFormat: new(api.FormatString(schema.OutputFormat)), SerdeInfo: &api.SerDeInfo{SerializationLibrary: new(api.NameString(schema.Serde)), Parameters: maps.Clone(schema.SerdeParameters)}}
}
func (s *Service) crawlS3(ctx context.Context, row CrawlerRecord, classifiers []ClassifierRecord) ([]crawlerDerivedTable, error) {
	groups := map[string]*crawlerObjectGroup{}
	for _, target := range row.Crawler.Targets.S3Targets {
		bucket, prefix, err := crawlerS3Path(value(target.Path))
		if err != nil {
			return nil, err
		}
		exclusions := make([]*regexp.Regexp, 0, len(target.Exclusions))
		for _, pattern := range target.Exclusions {
			compiled, err := crawlerGlob(string(pattern))
			if err != nil {
				return nil, err
			}
			exclusions = append(exclusions, compiled)
		}
		sampled := map[string]int{}
		token := ""
		for {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			page, err := s.crawlerSource.List(ctx, bucket, prefix, token)
			if err != nil {
				return nil, err
			}
			for _, object := range page.Objects {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if object.Size == 0 || strings.HasSuffix(object.Key, "/") {
					continue
				}
				base := path.Base(object.Key)
				if strings.HasPrefix(base, "_") || strings.HasPrefix(base, ".") {
					continue
				}
				relative := strings.TrimPrefix(strings.TrimPrefix(object.Key, prefix), "/")
				excluded := false
				for _, pattern := range exclusions {
					if pattern.MatchString(relative) {
						excluded = true
						break
					}
				}
				if excluded {
					continue
				}
				directory := path.Dir(object.Key)
				if target.SampleSize != nil && sampled[directory] >= int(*target.SampleSize) {
					continue
				}
				sampled[directory]++
				// TODO: Comeback add range-read sampling for objects above this explicit local memory bound.
				if object.Size > 64<<20 {
					return nil, unsupported("Crawler objects larger than 64 MiB require range sampling, which is not implemented.")
				}
				data, err := s.crawlerSource.Read(ctx, bucket, object.Key)
				if err != nil {
					return nil, err
				}
				schema, err := classifyCrawlerObject(data, classifiers)
				if err != nil {
					return nil, err
				}
				location, name, partitionKeys, values := objectCrawlerLocation(bucket, object.Key, prefix)
				group := groups[location]
				if group == nil {
					group = &crawlerObjectGroup{location: location, name: crawlerTableName(value(row.Crawler.TablePrefix) + name), schema: schema, partitionKeys: partitionKeys, partitions: map[string]api.PartitionInput{}}
					groups[location] = group
				} else {
					if group.schema.Classification != schema.Classification || len(group.partitionKeys) != len(partitionKeys) {
						return nil, unsupported("Mixed formats or incompatible partition layouts at one table location are not supported.")
					}
					for i, key := range partitionKeys {
						if value(group.partitionKeys[i].Name) != value(key.Name) {
							return nil, failure("InvalidInputException", "Conflicting partition key names at one table location.")
						}
					}
					group.schema.Columns = mergeCrawlerColumns(group.schema.Columns, schema.Columns)
				}
				if len(values) > 0 {
					encoded, _ := json.Marshal(values)
					partitionLocation := "s3://" + bucket + "/" + directory + "/"
					group.partitions[string(encoded)] = api.PartitionInput{Values: values, StorageDescriptor: descriptorForCrawler(schema, partitionLocation)}
				}
			}
			if page.NextToken == "" {
				break
			}
			if page.NextToken == token {
				return nil, failure("InternalServiceException", "S3 listing did not advance.", 500)
			}
			token = page.NextToken
		}
	}
	locations := make([]string, 0, len(groups))
	for location := range groups {
		locations = append(locations, location)
	}
	slices.Sort(locations)
	out := make([]crawlerDerivedTable, 0, len(locations))
	names := map[string]string{}
	for _, location := range locations {
		group := groups[location]
		if previous, ok := names[group.name]; ok && previous != location {
			return nil, unsupported("Target locations produce a colliding table name; use separate crawlers with table prefixes.")
		}
		names[group.name] = location
		columns := group.schema.Columns[:0]
		for _, column := range group.schema.Columns {
			partitionColumn := false
			for _, key := range group.partitionKeys {
				if value(key.Name) == value(column.Name) {
					partitionColumn = true
					break
				}
			}
			if !partitionColumn {
				columns = append(columns, column)
			}
		}
		group.schema.Columns = columns
		parameters := maps.Clone(group.schema.Parameters)
		parameters["classification"] = api.ParametersMapValue(group.schema.Classification)
		parameters["UPDATED_BY_CRAWLER"] = api.ParametersMapValue(row.Key.Name)
		parameters["typeOfData"] = "file"
		derived := crawlerDerivedTable{Table: api.TableInput{Name: new(api.NameString(group.name)), TableType: new(api.TableTypeString("EXTERNAL_TABLE")), StorageDescriptor: descriptorForCrawler(group.schema, location), PartitionKeys: group.partitionKeys, Parameters: parameters}}
		partitionIDs := make([]string, 0, len(group.partitions))
		for id := range group.partitions {
			partitionIDs = append(partitionIDs, id)
		}
		slices.Sort(partitionIDs)
		for _, id := range partitionIDs {
			partition := group.partitions[id]
			partition.StorageDescriptor.Columns = api.CloneColumnList(group.schema.Columns)
			derived.Partitions = append(derived.Partitions, partition)
		}
		out = append(out, derived)
	}
	return out, nil
}
