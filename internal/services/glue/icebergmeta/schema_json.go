package icebergmeta

// Schema and field extension members are retained along with the raw nested
// type unions so property-only commits do not strip metadata from other clients.
func (s Schema) MarshalJSON() ([]byte, error) {
	type plain Schema
	return marshalExtra(plain(s), s.Extra)
}

func (s *Schema) UnmarshalJSON(data []byte) error {
	type plain Schema
	var value plain
	extra, err := unmarshalExtra(data, &value)
	if err != nil {
		return err
	}
	*s = Schema(value)
	s.Extra = extra
	return nil
}

func (f Field) MarshalJSON() ([]byte, error) {
	type plain Field
	return marshalExtra(plain(f), f.Extra)
}

func (f *Field) UnmarshalJSON(data []byte) error {
	type plain Field
	var value plain
	extra, err := unmarshalExtra(data, &value)
	if err != nil {
		return err
	}
	*f = Field(value)
	f.Extra = extra
	return nil
}
