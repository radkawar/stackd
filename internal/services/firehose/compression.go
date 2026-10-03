package firehose

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/klauspost/compress/s2"
	api "stackd/internal/awsapi/firehose"
)

func deliveryBody(destination api.ExtendedS3DestinationDescription, records []RecordRecord, kind BufferKind) ([]byte, error) {
	delimiter := ""
	if kind == BufferFailed || kind == BufferDecompressionFailed {
		delimiter = "\n"
	}
	if processing := destination.ProcessingConfiguration; processing != nil && processing.Enabled != nil && bool(*processing.Enabled) {
		for _, processor := range processing.Processors {
			if value(processor.Type) == "AppendDelimiterToRecord" {
				delimiter = "\n"
				break
			}
		}
	}
	var body bytes.Buffer
	var writer io.Writer = &body
	var closer io.Closer
	format := value(destination.CompressionFormat)
	switch format {
	case "GZIP":
		compressed := gzip.NewWriter(&body)
		writer, closer = compressed, compressed
	case "ZIP":
		compressed := zip.NewWriter(&body)
		entry, err := compressed.CreateHeader(&zip.FileHeader{Name: "data", Method: zip.Deflate})
		if err != nil {
			return nil, err
		}
		writer, closer = entry, compressed
	case "", "UNCOMPRESSED", "Snappy", "HADOOP_SNAPPY":
		size := 0
		for _, record := range records {
			size += len(record.Data)
		}
		if len(records) > 1 {
			size += (len(records) - 1) * len(delimiter)
		}
		body.Grow(size)
	default:
		return nil, fmt.Errorf("unsupported Firehose compression format %q", format)
	}
	for i, record := range records {
		if i > 0 && delimiter != "" {
			if _, err := io.WriteString(writer, delimiter); err != nil {
				return nil, err
			}
		}
		if _, err := writer.Write(record.Data); err != nil {
			return nil, err
		}
	}
	if closer != nil {
		if err := closer.Close(); err != nil {
			return nil, err
		}
	}
	if format == "Snappy" || format == "HADOOP_SNAPPY" {
		return snappyDeliveryBody(body.Bytes(), format == "HADOOP_SNAPPY"), nil
	}
	return body.Bytes(), nil
}

// Xerial and Hadoop wrap ordinary Snappy blocks, not the Snappy framed stream
// format. Block boundaries are encoder choices, not Firehose record boundaries.
func snappyDeliveryBody(body []byte, hadoop bool) []byte {
	out := make([]byte, 0, len(body))
	if !hadoop {
		out = append(out, 0x82, 'S', 'N', 'A', 'P', 'P', 'Y', 0)
		out = binary.BigEndian.AppendUint32(out, 1)
		out = binary.BigEndian.AppendUint32(out, 1)
	}
	var compressed []byte
	for len(body) != 0 {
		size := min(len(body), 32*1024)
		compressed = s2.EncodeSnappy(compressed[:0], body[:size])
		if hadoop {
			out = binary.BigEndian.AppendUint32(out, uint32(size))
		}
		out = binary.BigEndian.AppendUint32(out, uint32(len(compressed)))
		out = append(out, compressed...)
		body = body[size:]
	}
	return out
}
