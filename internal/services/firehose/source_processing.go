package firehose

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"

	api "stackd/internal/awsapi/firehose"
)

// Source stages run once in their fixed order, independently of declaration order.
func sourceProcessing(destination api.ExtendedS3DestinationDescription) (decompress, extract bool) {
	processing := destination.ProcessingConfiguration
	if processing == nil || processing.Enabled == nil || !bool(*processing.Enabled) {
		return false, false
	}
	for _, processor := range processing.Processors {
		switch value(processor.Type) {
		case "Decompression":
			decompress = true
		case "CloudWatchLogProcessing":
			for _, parameter := range processor.Parameters {
				if value(parameter.ParameterName) == "DataMessageExtraction" && value(parameter.ParameterValue) == "true" {
					extract = true
				}
			}
		}
	}
	return decompress, extract
}

// Originals remain authoritative for backup and failures. Derived bytes live only
// for this processing attempt; the retained identity and original-byte accounting
// also survive extraction of an entire envelope into one record.
func prepareSourceRecords(destination api.ExtendedS3DestinationDescription, originals []RecordRecord) (ready []RecordRecord, failed []processingResult) {
	decompress, extract := sourceProcessing(destination)
	if !decompress {
		return originals, nil
	}
	ready = make([]RecordRecord, 0, len(originals))
	for _, original := range originals {
		data, ok := prepareSourceData(original.Data, extract)
		if !ok {
			failed = append(failed, processingResult{
				record: original,
				result: "ProcessingFailed",
				kind:   BufferDecompressionFailed,
				failure: &processingFailure{
					Code:    "Decompression failed.",
					Message: "Decompression failed because input data does not conform to cloudwatch log.",
				},
			})
			continue
		}
		original.Data = data
		ready = append(ready, original)
	}
	return ready, failed
}

func prepareSourceData(data []byte, extract bool) ([]byte, bool) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	decoded, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		return nil, false
	}
	if !extract {
		return decoded, json.Valid(decoded)
	}
	var envelope struct {
		MessageType string `json:"messageType"`
		LogEvents   []struct {
			Message *string `json:"message"`
		} `json:"logEvents"`
	}
	if err := json.Unmarshal(decoded, &envelope); err != nil {
		return nil, false
	}
	switch envelope.MessageType {
	case "CONTROL_MESSAGE":
		return []byte{}, true
	case "DATA_MESSAGE":
		if envelope.LogEvents == nil {
			return nil, false
		}
	default:
		return nil, false
	}
	size := len(envelope.LogEvents)
	for _, event := range envelope.LogEvents {
		if event.Message == nil {
			return nil, false
		}
		size += len(*event.Message)
	}
	out := make([]byte, 0, size)
	for _, event := range envelope.LogEvents {
		out = append(out, (*event.Message)...)
		out = append(out, '\n')
	}
	return out, true
}
