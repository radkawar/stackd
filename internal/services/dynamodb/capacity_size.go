package dynamodb

import (
	"strings"

	api "stackd/internal/awsapi/dynamodb"
)

// Item size excludes the per-item storage billing overhead. The 1-KiB native
// crossover fixtures cover scalar, set, collection and decimal representation
// costs, including the extra negative-number byte and the one-byte zero.
func itemSize[M ~map[api.AttributeName]api.AttributeValue](item M) int {
	size := 0
	for name, attribute := range item {
		size += len(name) + attributeSize(attribute)
	}
	return size
}

func attributeSize(attribute api.AttributeValue) int {
	switch {
	case attribute.S != nil:
		return len(*attribute.S)
	case attribute.N != nil:
		return numberSize(string(*attribute.N))
	case attribute.B != nil:
		return len(attribute.B)
	case attribute.BOOL != nil, attribute.NULL != nil:
		return 1
	case attribute.M != nil:
		return 3 + len(attribute.M) + itemSize(attribute.M)
	case attribute.L != nil:
		size := 3 + len(attribute.L)
		for _, element := range attribute.L {
			size += attributeSize(element)
		}
		return size
	case attribute.SS != nil:
		size := 0
		for _, element := range attribute.SS {
			size += len(element)
		}
		return size
	case attribute.NS != nil:
		size := 0
		for _, element := range attribute.NS {
			size += numberSize(string(element))
		}
		return size
	case attribute.BS != nil:
		size := 0
		for _, element := range attribute.BS {
			size += len(element)
		}
		return size
	}
	return 0
}

// The native engine validates numbers. Count significant mantissa digits without
// allocating a normalized decimal string or including the exponent's digits.
func numberSize(number string) int {
	negative := strings.HasPrefix(number, "-")
	if exponent := strings.IndexAny(number, "eE"); exponent >= 0 {
		number = number[:exponent]
	}
	first, last, digits := -1, -1, 0
	for _, digit := range number {
		if digit < '0' || digit > '9' {
			continue
		}
		if digit != '0' {
			if first == -1 {
				first = digits
			}
			last = digits
		}
		digits++
	}
	if first == -1 {
		return 1
	}
	size := (last-first+2)/2 + 1
	if negative {
		size++
	}
	return size
}

func writeUnits(size int) float64 {
	return float64(max(1, (size+1023)/1024))
}
