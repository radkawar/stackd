package lambda

import (
	"crypto/md5"
	"math/big"

	api "stackd/internal/awsapi/kinesis"
	"stackd/internal/kinesisaggregation"
)

func kinesisAggregateInShard(records []kinesisaggregation.Record, shard api.Shard) bool {
	if shard.HashKeyRange == nil {
		return false
	}
	start, ok := new(big.Int).SetString(value(shard.HashKeyRange.StartingHashKey), 10)
	if !ok {
		return false
	}
	end, ok := new(big.Int).SetString(value(shard.HashKeyRange.EndingHashKey), 10)
	if !ok {
		return false
	}
	var hash big.Int
	for _, record := range records {
		if record.ExplicitHashKey != "" {
			if _, ok := hash.SetString(record.ExplicitHashKey, 10); !ok {
				return false
			}
		} else {
			digest := md5.Sum([]byte(record.PartitionKey))
			hash.SetBytes(digest[:])
		}
		if hash.Cmp(start) < 0 || hash.Cmp(end) > 0 {
			return false
		}
	}
	return true
}
