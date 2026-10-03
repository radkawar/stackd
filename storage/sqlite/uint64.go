package sqlite

import (
	"database/sql/driver"
	"encoding/binary"
	"fmt"
)

// Uint64 stores the complete unsigned domain counter in an ordered eight-byte
// SQLite BLOB. Native INTEGER is signed and cannot hold every repository value.
type Uint64 uint64

func (u Uint64) Value() (driver.Value, error) {
	return binary.BigEndian.AppendUint64(nil, uint64(u)), nil
}

func (u *Uint64) Scan(value any) error {
	data, ok := value.([]byte)
	if !ok || len(data) != 8 {
		return fmt.Errorf("invalid SQLite unsigned counter")
	}
	*u = Uint64(binary.BigEndian.Uint64(data))
	return nil
}
