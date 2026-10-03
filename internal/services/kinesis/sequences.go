package kinesis

import (
	"crypto/sha256"
	"math"
	"math/big"

	api "stackd/internal/awsapi/kinesis"
)

// Sequence numbers are opaque decimal coordinates: an incarnation namespace,
// native partition, then alternating record and checkpoint words. A checkpoint
// lies between records so both AT and AFTER resume at the next unread offset.
func sequenceStart(streamID string, partition int32) api.SequenceNumber {
	namespace := sha256.Sum256([]byte(streamID))
	base := new(big.Int).SetBytes(namespace[:12])
	base.Lsh(base, 96)
	part := new(big.Int).Lsh(big.NewInt(int64(partition)), 64)
	return api.SequenceNumber(base.Or(base, part).String())
}

type shardSequence struct{ base *big.Int }

// The retained starting bound is produced only by the shard constructor. Parse
// it once per native batch, rather than hashing and parsing for every record.
func sequenceFor(shard ShardRecord) shardSequence {
	base, _ := new(big.Int).SetString(value(shard.Data.SequenceNumberRange.StartingSequenceNumber), 10)
	return shardSequence{base: base}
}

func (s shardSequence) number(offset int64) api.SequenceNumber {
	word := new(big.Int).SetUint64((uint64(offset) + 1) << 1)
	return api.SequenceNumber(word.Add(word, s.base).String())
}

func (s shardSequence) checkpoint(nextOffset int64) api.SequenceNumber {
	word := new(big.Int).SetUint64(uint64(nextOffset)<<1 | 1)
	return api.SequenceNumber(word.Add(word, s.base).String())
}

func (s shardSequence) end() api.SequenceNumber {
	word := new(big.Int).SetUint64(math.MaxUint64)
	return api.SequenceNumber(word.Add(word, s.base).String())
}

// position distinguishes records from checkpoints and the terminal boundary.
// The starting bound is a checkpoint at offset zero, including an empty shard.
func (s shardSequence) position(text string) (offset int64, terminal, checkpoint bool, err error) {
	coordinate, ok := new(big.Int).SetString(text, 10)
	if !ok || coordinate.Sign() < 0 {
		return 0, false, false, failure("InvalidArgumentException", "Invalid starting sequence number.")
	}
	word := coordinate.Sub(coordinate, s.base)
	if word.Sign() < 0 || word.BitLen() > 64 {
		return 0, false, false, failure("InvalidArgumentException", "Sequence number does not belong to the requested shard.")
	}
	if word.Uint64() == math.MaxUint64 {
		return 0, true, false, nil
	}
	value := word.Uint64()
	if value == 0 || value&1 != 0 {
		return int64(value >> 1), false, true, nil
	}
	return int64(value>>1) - 1, false, false, nil
}
