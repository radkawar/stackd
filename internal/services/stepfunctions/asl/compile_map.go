package asl

import (
	"fmt"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"
)

func (c *compiler) mapState(object map[string]any, ctx compileContext, location string, depth int, parameters *Template) *MapState {
	mapping := &MapState{ProcessorConfig: ProcessorConfig{Mode: "INLINE"}}
	c.exactlyOne(object, []string{"ItemProcessor", "Iterator"}, location)
	processorField := "ItemProcessor"
	if _, exists := object["ItemProcessor"]; !exists {
		processorField = "Iterator"
	}
	processor := c.object(object[processorField], location+"/"+processorField)
	if value, exists := processor["ProcessorConfig"]; exists {
		at := location + "/" + processorField + "/ProcessorConfig"
		config := c.object(value, at)
		c.fields(config, "Mode ExecutionType", at)
		mapping.ProcessorConfig.Mode = c.enum(config, "Mode", "INLINE", "INLINE DISTRIBUTED", at)
		mapping.ProcessorConfig.ExecutionType = c.enum(config, "ExecutionType", "", "STANDARD EXPRESS", at)
		if mapping.ProcessorConfig.Mode == "DISTRIBUTED" && mapping.ProcessorConfig.ExecutionType == "" {
			c.schema("Distributed Map requires ExecutionType", at+"/ExecutionType")
		}
		if mapping.ProcessorConfig.Mode == "INLINE" {
			if _, exists := config["ExecutionType"]; exists {
				c.schema("ExecutionType is only supported for distributed Map", at+"/ExecutionType")
			}
		}
	}
	distributed := mapping.ProcessorConfig.Mode == "DISTRIBUTED"
	mapping.Processor = c.definition(processor, location+"/"+processorField, ctx.scope, false, distributed, depth+1)
	if ctx.language == JSONPath {
		mapping.ItemsPath = c.path(object, "ItemsPath", true, false, true, ctx, location)
	} else {
		if value, exists := object["Items"]; exists {
			_, array := value.([]any)
			_, objectValue := value.(map[string]any)
			text, expression := value.(string)
			if !array && !objectValue && (!expression || !strings.HasPrefix(text, "{%")) {
				c.schema("Items must be an array, object, or JSONata expression", location+"/Items")
			}
		}
		mapping.Items = c.template(object, "Items", false, ctx, location)
	}
	if _, selector := object["ItemSelector"]; selector && parameters != nil {
		c.schema("ItemSelector and Parameters are mutually exclusive", location)
	}
	mapping.ItemSelector = c.template(object, "ItemSelector", ctx.language == JSONPath, ctx, location)
	if mapping.ItemSelector == nil {
		mapping.ItemSelector = parameters
	}
	maxConcurrency := int64(40)
	if distributed {
		maxConcurrency = 10000
	}
	mapping.MaxConcurrency = c.integer(object, "MaxConcurrency", "MaxConcurrencyPath", 0, maxConcurrency, ctx, location)
	mapping.ToleratedFailureCount = c.integer(object, "ToleratedFailureCount", "ToleratedFailureCountPath", 0, math.MaxInt32, ctx, location)
	mapping.ToleratedFailurePercentage = c.number(object, "ToleratedFailurePercentage", "ToleratedFailurePercentagePath", 0, 100, ctx, location)
	if !distributed {
		for _, field := range []string{"ItemReader", "ItemBatcher", "ResultWriter", "ToleratedFailureCount", "ToleratedFailureCountPath", "ToleratedFailurePercentage", "ToleratedFailurePercentagePath", "Label"} {
			if _, exists := object[field]; exists {
				c.schema(field+" is only supported for distributed Map", location+"/"+field)
			}
		}
	}
	if value, exists := object["ItemReader"]; exists {
		mapping.ItemReader = c.itemReader(c.object(value, location+"/ItemReader"), ctx, location+"/ItemReader")
	}
	if value, exists := object["ItemBatcher"]; exists {
		mapping.ItemBatcher = c.itemBatcher(c.object(value, location+"/ItemBatcher"), ctx, location+"/ItemBatcher")
	}
	if value, exists := object["ResultWriter"]; exists {
		mapping.ResultWriter = c.resultWriter(c.object(value, location+"/ResultWriter"), ctx, location+"/ResultWriter")
	}
	if _, exists := object["Label"]; exists {
		mapping.Label = c.optionalString(object, "Label", location)
		if !compilerLabel(mapping.Label) {
			c.error("INVALID_LABEL_NAME", "Map labels must contain 1 to 40 characters without reserved characters", location+"/Label")
		}
		if c.labels[mapping.Label] {
			c.error("DUPLICATE_LABEL_NAME", "Duplicate Map label: "+mapping.Label, location+"/Label")
		}
		c.labels[mapping.Label] = true
	}
	return mapping
}

func (c *compiler) itemReader(object map[string]any, ctx compileContext, location string) *ItemReader {
	fields := "Resource ReaderConfig"
	if ctx.language == JSONPath {
		fields += " Parameters"
	} else {
		fields += " Arguments"
	}
	c.fields(object, fields, location)
	reader := &ItemReader{Resource: c.resource(object, true, location)}
	if ctx.language == JSONPath {
		reader.Parameters = c.template(object, "Parameters", true, ctx, location)
	} else {
		reader.Arguments = c.template(object, "Arguments", true, ctx, location)
	}
	if value, exists := object["ReaderConfig"]; exists {
		at := location + "/ReaderConfig"
		config := c.object(value, at)
		fields := "InputType CSVHeaderLocation CSVHeaders CSVDelimiter MaxItems ManifestType ItemsPointer Transformation"
		if ctx.language == JSONPath {
			fields += " MaxItemsPath"
		}
		c.fields(config, fields, at)
		reader.ReaderConfig = &ReaderConfig{
			InputType:         c.enum(config, "InputType", "", "CSV JSON JSONL PARQUET MANIFEST", at),
			CSVHeaderLocation: c.enum(config, "CSVHeaderLocation", "", "FIRST_ROW GIVEN", at),
			CSVDelimiter:      c.enum(config, "CSVDelimiter", "COMMA", "COMMA PIPE SEMICOLON SPACE TAB", at),
			MaxItems:          c.integer(config, "MaxItems", "MaxItemsPath", 1, 100000000, ctx, at),
			ManifestType:      c.enum(config, "ManifestType", "", "ATHENA_DATA S3_INVENTORY", at),
			ItemsPointer:      c.optionalString(config, "ItemsPointer", at),
			Transformation:    c.enum(config, "Transformation", "NONE", "NONE LOAD_AND_FLATTEN", at),
		}
		r := reader.ReaderConfig
		if r.Transformation == "LOAD_AND_FLATTEN" && r.InputType == "" {
			c.schema("InputType is required with LOAD_AND_FLATTEN", at+"/InputType")
		}
		if r.ManifestType == "S3_INVENTORY" && r.InputType != "" {
			c.schema("InputType cannot be specified with an S3_INVENTORY manifest", at+"/InputType")
		}
		if value, exists := config["CSVHeaders"]; exists {
			entries := c.array(value, at+"/CSVHeaders", true)
			bytes := 0
			for i, entry := range entries {
				text, ok := entry.(string)
				if !ok {
					c.schema("CSVHeaders entries must be strings", fmt.Sprintf("%s/CSVHeaders[%d]", at, i))
					continue
				}
				r.CSVHeaders = append(r.CSVHeaders, text)
				bytes += len(text)
			}
			if bytes > 10240 {
				c.schema("CSV headers cannot exceed 10 KiB", at+"/CSVHeaders")
			}
			if r.CSVHeaderLocation != "GIVEN" {
				c.schema("CSVHeaders requires CSVHeaderLocation GIVEN", at+"/CSVHeaders")
			}
		}
		if r.CSVHeaderLocation == "GIVEN" && len(r.CSVHeaders) == 0 {
			c.schema("CSVHeaderLocation GIVEN requires CSVHeaders", at+"/CSVHeaders")
		}
		if r.InputType == "CSV" && r.CSVHeaderLocation == "" {
			c.schema("CSV input requires CSVHeaderLocation", at+"/CSVHeaderLocation")
		}
		for _, field := range []string{"CSVHeaderLocation", "CSVHeaders", "CSVDelimiter"} {
			if _, exists := config[field]; exists && r.InputType != "CSV" && r.InputType != "MANIFEST" && r.ManifestType != "S3_INVENTORY" {
				c.schema(field+" requires CSV or MANIFEST input", at+"/"+field)
			}
		}
		if _, exists := config["ItemsPointer"]; exists {
			if r.InputType != "JSON" {
				c.schema("ItemsPointer requires JSON input", at+"/ItemsPointer")
			}
			if !compilerJSONPointer(r.ItemsPointer) || utf8.RuneCountInString(r.ItemsPointer) >= 2000 {
				c.schema("ItemsPointer must be a JSON Pointer shorter than 2000 characters", at+"/ItemsPointer")
			}
		}
	}
	return reader
}

func (c *compiler) itemBatcher(object map[string]any, ctx compileContext, location string) *ItemBatcher {
	fields := "BatchInput MaxItemsPerBatch MaxInputBytesPerBatch"
	if ctx.language == JSONPath {
		fields += " MaxItemsPerBatchPath MaxInputBytesPerBatchPath"
	}
	c.fields(object, fields, location)
	batcher := &ItemBatcher{
		BatchInput:            c.template(object, "BatchInput", ctx.language == JSONPath, ctx, location),
		MaxItemsPerBatch:      c.integer(object, "MaxItemsPerBatch", "MaxItemsPerBatchPath", 1, math.MaxInt32, ctx, location),
		MaxInputBytesPerBatch: c.integer(object, "MaxInputBytesPerBatch", "MaxInputBytesPerBatchPath", 1, 262144, ctx, location),
	}
	if batcher.MaxItemsPerBatch == nil && batcher.MaxInputBytesPerBatch == nil {
		c.schema("ItemBatcher requires an item count or input size limit", location)
	}
	return batcher
}

func (c *compiler) resultWriter(object map[string]any, ctx compileContext, location string) *ResultWriter {
	fields := "Resource WriterConfig"
	if ctx.language == JSONPath {
		fields += " Parameters"
	} else {
		fields += " Arguments"
	}
	c.fields(object, fields, location)
	writer := &ResultWriter{Resource: c.resource(object, false, location)}
	if ctx.language == JSONPath {
		writer.Parameters = c.template(object, "Parameters", true, ctx, location)
	} else {
		writer.Arguments = c.template(object, "Arguments", true, ctx, location)
	}
	if value, exists := object["WriterConfig"]; exists {
		at := location + "/WriterConfig"
		config := c.object(value, at)
		c.fields(config, "Transformation OutputType", at)
		transformation := "COMPACT"
		if writer.Resource != "" {
			transformation = "NONE"
		}
		writer.WriterConfig = &WriterConfig{Transformation: c.enum(config, "Transformation", transformation, "NONE COMPACT FLATTEN", at), OutputType: c.enum(config, "OutputType", "JSON", "JSON JSONL", at)}
	}
	if writer.Resource == "" && writer.WriterConfig == nil {
		c.schema("ResultWriter requires WriterConfig or a Resource and parameters", location)
	}
	if writer.Resource != "" && writer.Parameters == nil && writer.Arguments == nil {
		c.schema("ResultWriter Resource requires Parameters or Arguments", location)
	}
	if writer.Resource == "" && (writer.Parameters != nil || writer.Arguments != nil) {
		c.schema("ResultWriter parameters require Resource", location)
	}
	return writer
}

func compilerLabel(label string) bool {
	if label == "" || utf8.RuneCountInString(label) > 40 {
		return false
	}
	for _, r := range label {
		if unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune(`?*<>{}[]:;,\|^~$#%&`+"`\"", r) {
			return false
		}
	}
	return true
}

func compilerJSONPointer(pointer string) bool {
	if pointer == "" {
		return true
	}
	if pointer[0] != '/' {
		return false
	}
	for i := 0; i < len(pointer); i++ {
		if pointer[i] == '~' {
			i++
			if i == len(pointer) || (pointer[i] != '0' && pointer[i] != '1') {
				return false
			}
		}
	}
	return true
}
