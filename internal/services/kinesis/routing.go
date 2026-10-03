package kinesis

import (
	"crypto/md5"
	"math/big"

	api "stackd/internal/awsapi/kinesis"
)

func partitionHash(key string, explicit *api.HashKey) (*big.Int, error) {
	if explicit != nil {
		hash, ok := new(big.Int).SetString(value(explicit), 10)
		if !ok || hash.Sign() < 0 || hash.BitLen() > 128 {
			return nil, failure("InvalidArgumentException", "Invalid ExplicitHashKey. ExplicitHashKey must be in the range: [0, 2^128-1]. Specified value was "+value(explicit))
		}
		return hash, nil
	}
	hash := md5.Sum([]byte(key))
	return new(big.Int).SetBytes(hash[:]), nil
}

type shardRoute struct {
	shard      ShardRecord
	start, end *big.Int
}

// Parse the current topology once per request, not once per batch member.
func shardRoutes(shards []ShardRecord) ([]shardRoute, error) {
	routes := make([]shardRoute, 0, len(shards))
	for _, shard := range shards {
		if shard.State != ShardOpen {
			continue
		}
		route, err := parseShardRoute(shard)
		if err != nil {
			return nil, err
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func parseShardRoute(shard ShardRecord) (shardRoute, error) {
	if shard.Data.HashKeyRange == nil {
		return shardRoute{}, failure("InternalFailure", "Shard has no hash range.", 500)
	}
	start, startOK := new(big.Int).SetString(value(shard.Data.HashKeyRange.StartingHashKey), 10)
	end, endOK := new(big.Int).SetString(value(shard.Data.HashKeyRange.EndingHashKey), 10)
	if !startOK || !endOK || start.Sign() < 0 || end.BitLen() > 128 || end.Cmp(start) < 0 {
		return shardRoute{}, failure("InternalFailure", "Shard has an invalid hash range.", 500)
	}
	return shardRoute{shard: shard, start: start, end: end}, nil
}

func routeRecord(routes []shardRoute, key string, explicit *api.HashKey) (int, error) {
	hash, err := partitionHash(key, explicit)
	if err != nil {
		return 0, err
	}
	for i, route := range routes {
		if hash.Cmp(route.start) >= 0 && hash.Cmp(route.end) <= 0 {
			return i, nil
		}
	}
	return 0, failure("ResourceInUseException", "Stream has no writable shard for the partition key.")
}
