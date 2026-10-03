package kinesisaggregation

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
)

// KPL's public proto2 envelope is magic + AggregatedRecord + MD5. This bounded
// decoder only extracts its key tables and records; tags/unknown scalar fields
// are skipped. Invalid envelopes remain ordinary Kinesis data, as with KCL.
// https://github.com/awslabs/amazon-kinesis-producer/blob/master/aws/kinesis/protobuf/messages.proto
var kplMagic = []byte{0xf3, 0x89, 0x9a, 0xc2}

// Record is an inner KPL record. Data borrows the aggregate's backing bytes.
type Record struct {
	PartitionKey    string
	ExplicitHashKey string
	Data            []byte
}

type kplField struct {
	number, wire uint64
	integer      uint64
	data         []byte
}

func takeKPLField(payload []byte) (kplField, []byte, error) {
	var f kplField
	tag, n := binary.Uvarint(payload)
	if n <= 0 || tag>>3 == 0 {
		return f, nil, fmt.Errorf("invalid KPL field")
	}
	f.number, f.wire = tag>>3, tag&7
	payload = payload[n:]
	switch f.wire {
	case 0:
		f.integer, n = binary.Uvarint(payload)
		if n <= 0 {
			return f, nil, fmt.Errorf("invalid KPL varint")
		}
		payload = payload[n:]
	case 1:
		if len(payload) < 8 {
			return f, nil, fmt.Errorf("truncated KPL fixed64")
		}
		payload = payload[8:]
	case 2:
		size, count := binary.Uvarint(payload)
		if count <= 0 || size > uint64(len(payload)-count) {
			return f, nil, fmt.Errorf("truncated KPL bytes")
		}
		payload = payload[count:]
		f.data, payload = payload[:int(size)], payload[int(size):]
	case 5:
		if len(payload) < 4 {
			return f, nil, fmt.Errorf("truncated KPL fixed32")
		}
		payload = payload[4:]
	default:
		return f, nil, fmt.Errorf("unsupported KPL wire type")
	}
	return f, payload, nil
}

// Decode returns the aggregate's inner records. A false result means callers
// must treat data as an ordinary record, including malformed KPL envelopes.
func Decode(data []byte) ([]Record, bool) {
	if len(data) <= 20 || !bytes.Equal(data[:4], kplMagic) {
		return nil, false
	}
	body := data[4 : len(data)-md5.Size]
	digest := md5.Sum(body)
	if !bytes.Equal(digest[:], data[len(data)-md5.Size:]) {
		return nil, false
	}
	var keys, hashes []string
	var records [][]byte
	for rest := body; len(rest) > 0; {
		field, next, err := takeKPLField(rest)
		if err != nil {
			return nil, false
		}
		rest = next
		switch field.number {
		case 1, 2, 3:
			if field.wire != 2 {
				return nil, false
			}
			switch field.number {
			case 1:
				keys = append(keys, string(field.data))
			case 2:
				hashes = append(hashes, string(field.data))
			case 3:
				records = append(records, field.data)
			}
		}
	}
	out := make([]Record, 0, len(records))
	for _, encoded := range records {
		var key, hash uint64
		var haveKey, haveHash, haveData bool
		var payload []byte
		for len(encoded) > 0 {
			field, next, err := takeKPLField(encoded)
			if err != nil {
				return nil, false
			}
			encoded = next
			switch field.number {
			case 1:
				if field.wire != 0 {
					return nil, false
				}
				key, haveKey = field.integer, true
			case 2:
				if field.wire != 0 {
					return nil, false
				}
				hash, haveHash = field.integer, true
			case 3:
				if field.wire != 2 {
					return nil, false
				}
				payload, haveData = field.data, true
			}
		}
		if !haveKey || !haveData || key >= uint64(len(keys)) || haveHash && hash >= uint64(len(hashes)) {
			return nil, false
		}
		record := Record{PartitionKey: keys[key], Data: payload}
		if haveHash {
			record.ExplicitHashKey = hashes[hash]
		}
		out = append(out, record)
	}
	return out, true
}
