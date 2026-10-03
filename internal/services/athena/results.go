package athena

import (
	"fmt"
	"strings"

	api "stackd/internal/awsapi/athena"
)

// resultRows preserves an unquoted empty field as SQL NULL and a quoted empty
// field as an empty string. encoding/csv intentionally discards that distinction
// and skips single-column NULL rows, so it cannot represent Athena result rows.
func resultRows(data []byte, offset, limit int) (api.RowList, bool, error) {
	rows := api.RowList{}
	position, rowNumber := 0, 0
	for position < len(data) {
		if rowNumber >= offset+limit {
			return rows, true, nil
		}
		retain := rowNumber >= offset
		row := api.Row{}
		for {
			quoted := position < len(data) && data[position] == '"'
			start := position
			var text string
			if quoted {
				position++
				start = position
				var escaped strings.Builder
				segment := position
				closed := false
				for position < len(data) {
					if data[position] != '"' {
						position++
						continue
					}
					if position+1 < len(data) && data[position+1] == '"' {
						if retain {
							escaped.Write(data[segment:position])
							escaped.WriteByte('"')
						}
						position += 2
						segment = position
						continue
					}
					if retain {
						if segment == start {
							text = string(data[start:position])
						} else {
							escaped.Write(data[segment:position])
							text = escaped.String()
						}
					}
					position++
					closed = true
					break
				}
				if !closed {
					return nil, false, fmt.Errorf("unterminated quoted Athena result field")
				}
				if position < len(data) && data[position] != ',' && data[position] != '\r' && data[position] != '\n' {
					return nil, false, fmt.Errorf("invalid character after quoted Athena result field")
				}
			} else {
				for position < len(data) && data[position] != ',' && data[position] != '\r' && data[position] != '\n' {
					if data[position] == '"' {
						return nil, false, fmt.Errorf("invalid quote in Athena result field")
					}
					position++
				}
				if retain {
					text = string(data[start:position])
				}
			}
			if retain {
				datum := api.Datum{}
				if quoted || position > start {
					datum.VarCharValue = new(api.DatumString(text))
				}
				row.Data = append(row.Data, datum)
			}
			if position == len(data) {
				break
			}
			delimiter := data[position]
			position++
			if delimiter == ',' {
				continue
			}
			if delimiter == '\r' {
				if position == len(data) || data[position] != '\n' {
					return nil, false, fmt.Errorf("invalid CSV line ending in Athena result")
				}
				position++
			}
			break
		}
		if retain {
			rows = append(rows, row)
		}
		rowNumber++
	}
	if offset > rowNumber {
		return nil, false, invalidRequest("Invalid pagination token.")
	}
	return rows, false, nil
}
