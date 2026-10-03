package dynamodb

import (
	"maps"
	"reflect"

	api "stackd/internal/awsapi/dynamodb"
)

type writeCharge struct {
	table, read   float64
	local, global map[api.IndexName]float64
}

func capacityProjection(tableKeys, indexKeys api.KeySchema, projection *api.Projection, item api.AttributeMap) api.AttributeMap {
	for _, member := range indexKeys {
		if _, exists := item[api.AttributeName(value(member.AttributeName))]; !exists {
			return nil
		}
	}
	if value(projection.ProjectionType) == "ALL" {
		return item
	}
	projected := make(api.AttributeMap, len(tableKeys)+len(indexKeys)+len(projection.NonKeyAttributes))
	add := func(name api.AttributeName) {
		if attribute, exists := item[name]; exists {
			projected[name] = attribute
		}
	}
	for _, member := range tableKeys {
		add(api.AttributeName(value(member.AttributeName)))
	}
	for _, member := range indexKeys {
		add(api.AttributeName(value(member.AttributeName)))
	}
	for _, name := range projection.NonKeyAttributes {
		add(api.AttributeName(name))
	}
	return projected
}

func indexProjectsAttributes(tableKeys, indexKeys api.KeySchema, projection *api.Projection, attributes []string) bool {
	if projection == nil || value(projection.ProjectionType) == "ALL" {
		return true
	}
	for _, attribute := range attributes {
		found := false
		for _, schema := range [2]api.KeySchema{tableKeys, indexKeys} {
			for _, member := range schema {
				if string(value(member.AttributeName)) == attribute {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			for _, name := range projection.NonKeyAttributes {
				if string(name) == attribute {
					found = true
					break
				}
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func indexWriteUnits(tableKeys, indexKeys api.KeySchema, projection *api.Projection, before, after api.AttributeMap) float64 {
	old := capacityProjection(tableKeys, indexKeys, projection, before)
	current := capacityProjection(tableKeys, indexKeys, projection, after)
	if maps.EqualFunc(old, current, AttributeValuesEqual) {
		return 0
	}
	if old == nil {
		return writeUnits(itemSize(current))
	}
	if current == nil {
		return writeUnits(itemSize(old))
	}
	if capacityKeyID("", indexKeys, api.Key(old)) != capacityKeyID("", indexKeys, api.Key(current)) {
		return writeUnits(itemSize(old)) + writeUnits(itemSize(current))
	}
	return writeUnits(max(itemSize(old), itemSize(current)))
}

func (c *writeCharge) add(write *capacityWrite, transaction bool) {
	size := max(itemSize(write.before), itemSize(write.after))
	units := writeUnits(size)
	if transaction {
		units *= 2
		c.read += float64(max(1, (size+4095)/4096) * 2)
	}
	c.table += units
	for _, index := range write.table.Data.LocalSecondaryIndexes {
		units := indexWriteUnits(write.table.Data.KeySchema, index.KeySchema, index.Projection, write.before, write.after)
		if units != 0 {
			if c.local == nil {
				c.local = make(map[api.IndexName]float64)
			}
			c.local[*index.IndexName] += units
		}
	}
	for _, index := range write.table.Data.GlobalSecondaryIndexes {
		units := indexWriteUnits(write.table.Data.KeySchema, index.KeySchema, index.Projection, write.before, write.after)
		if units != 0 {
			if c.global == nil {
				c.global = make(map[api.IndexName]float64)
			}
			c.global[*index.IndexName] += units
		}
	}
}

func (c *writeCharge) capacity(table string, transaction bool) api.ConsumedCapacity {
	part := func(units float64) api.Capacity {
		out := api.Capacity{CapacityUnits: new(api.ConsumedCapacityUnits(units))}
		if transaction {
			out.WriteCapacityUnits = new(api.ConsumedCapacityUnits(units))
		}
		return out
	}
	out := api.ConsumedCapacity{TableName: new(api.TableArn(table)), Table: new(part(c.table))}
	total := c.table
	if len(c.local) != 0 {
		out.LocalSecondaryIndexes = make(api.SecondaryIndexesCapacityMap, len(c.local))
		for name, units := range c.local {
			out.LocalSecondaryIndexes[name] = part(units)
			total += units
		}
	}
	if len(c.global) != 0 {
		out.GlobalSecondaryIndexes = make(api.SecondaryIndexesCapacityMap, len(c.global))
		for name, units := range c.global {
			out.GlobalSecondaryIndexes[name] = part(units)
			total += units
		}
	}
	out.CapacityUnits = new(api.ConsumedCapacityUnits(total))
	if transaction {
		out.WriteCapacityUnits = new(api.ConsumedCapacityUnits(total))
	}
	return out
}

type tableWriteCharge struct {
	table *TableRecord
	writeCharge
}

func aggregateWrites(writes []capacityWrite, transaction bool, excluded map[capacityItemID]bool) []tableWriteCharge {
	var charges []tableWriteCharge
	positions := make(map[string]int)
	for i := range writes {
		write := &writes[i]
		if excluded[write.id()] {
			continue
		}
		position, exists := positions[write.table.PhysicalName]
		if !exists {
			position = len(charges)
			positions[write.table.PhysicalName] = position
			charges = append(charges, tableWriteCharge{table: write.table})
		}
		charges[position].add(write, transaction)
	}
	return charges
}

// AttributeValuesEqual compares validated DynamoDB values using native number
// and unordered-set semantics. AppSync condition reconciliation shares this owner.
func AttributeValuesEqual(a, b api.AttributeValue) bool {
	if reflect.DeepEqual(a, b) {
		return true
	}
	if a.N != nil && b.N != nil {
		x, _ := dataCanonicalScalar(a)
		y, _ := dataCanonicalScalar(b)
		return x == y
	}
	if a.M != nil && b.M != nil {
		return maps.EqualFunc(a.M, b.M, AttributeValuesEqual)
	}
	if a.L != nil && b.L != nil {
		if len(a.L) != len(b.L) {
			return false
		}
		for i := range a.L {
			if !AttributeValuesEqual(a.L[i], b.L[i]) {
				return false
			}
		}
		return true
	}
	if a.SS != nil && b.SS != nil {
		return capacitySetEqual(a.SS, b.SS, func(v api.StringAttributeValue) string { return string(v) })
	}
	if a.NS != nil && b.NS != nil {
		return capacitySetEqual(a.NS, b.NS, func(v api.NumberAttributeValue) string {
			canonical, _ := dataCanonicalScalar(api.AttributeValue{N: &v})
			return canonical
		})
	}
	if a.BS != nil && b.BS != nil {
		return capacitySetEqual(a.BS, b.BS, func(v api.BinaryAttributeValue) string { return string(v) })
	}
	return false
}

func capacitySetEqual[S ~[]T, T any](a, b S, key func(T) string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, item := range a {
		seen[key(item)] = true
	}
	for _, item := range b {
		if !seen[key(item)] {
			return false
		}
	}
	return true
}
