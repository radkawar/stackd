package s3

import "context"

// InventoryORCEncoder runs Apache ORC outside the repository transaction. Schema
// uses native ORC struct syntax; rows are newline-delimited JSON with UTC
// millisecond timestamps. The result must be a complete ZLIB-compressed ORC file.
type InventoryORCEncoder interface {
	Encode(context.Context, string, []byte) ([]byte, error)
}

// inventoryColumn binds an AWS report name to its columnar field and physical
// value kind. Rows contain strings, bools, int64s, time.Time values or nil.
type inventoryColumn struct {
	Name, Field, Kind string
}
