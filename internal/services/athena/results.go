package athena

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/athena"
	"stackd/internal/awswire"
)

// manifestQuery changes only the object location; encryption, expected owner,
// ACL and requester-pays settings remain those selected for the query.
func manifestQuery(query QueryRecord, location string) QueryRecord {
	config := api.CloneResultConfiguration(*query.Data.ResultConfiguration)
	config.OutputLocation = new(api.ResultOutputLocation(location))
	query.Data.ResultConfiguration = &config
	return query
}

// resultRows preserves an unquoted empty field as SQL NULL and a quoted empty
// field as an empty string. encoding/csv intentionally discards that distinction
// and skips single-column NULL rows, so it cannot represent Athena result rows.
func resultRows(data []byte, offset, limit int) (api.RowList, bool, error) {
	rows, more, _, err := parseResultRows(data, offset, limit)
	return rows, more, err
}

// Result continuation is a byte position, as observed when native Athena
// accepts a SELECT token against a different writer's manifest.
func resultByteRows(data []byte, offset, limit int) (api.RowList, bool, int, error) {
	if offset >= len(data) {
		return api.RowList{}, false, offset, nil
	}
	rows, more, consumed, err := parseResultRows(data[offset:], 0, limit)
	return rows, more, offset + consumed, err
}

func parseResultRows(data []byte, offset, limit int) (api.RowList, bool, int, error) {
	rows := api.RowList{}
	position, rowNumber := 0, 0
	for position < len(data) {
		if rowNumber >= offset+limit {
			return rows, true, position, nil
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
					return nil, false, position, fmt.Errorf("unterminated quoted Athena result field")
				}
				if position < len(data) && data[position] != ',' && data[position] != '\r' && data[position] != '\n' {
					return nil, false, position, fmt.Errorf("invalid character after quoted Athena result field")
				}
			} else {
				for position < len(data) && data[position] != ',' && data[position] != '\r' && data[position] != '\n' {
					if data[position] == '"' {
						return nil, false, position, fmt.Errorf("invalid quote in Athena result field")
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
					return nil, false, position, fmt.Errorf("invalid CSV line ending in Athena result")
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
		return nil, false, position, invalidRequest("Invalid pagination token.")
	}
	return rows, false, position, nil
}

func manifestRows(data []byte, offset, limit int) (api.RowList, bool, int, error) {
	rows := api.RowList{}
	position := offset
	for position < len(data) && len(rows) < limit {
		end := bytes.IndexByte(data[position:], '\n')
		if end < 0 {
			end = len(data) - position
		}
		rows = append(rows, api.Row{Data: api.DatumList{{VarCharValue: new(api.DatumString(string(data[position : position+end])))}}})
		position += end
		if position < len(data) {
			position++
		}
	}
	return rows, position < len(data), position, nil
}

func queryResultError(message, code string) *awswire.Error {
	return &awswire.Error{Code: "InvalidRequestException", Message: message, StatusCode: 400,
		Details: map[string]json.RawMessage{"AthenaErrorCode": json.RawMessage(strconv.Quote(code))}}
}

func resultReadError(rejected *awswire.Error) *awswire.Error {
	switch rejected.Code {
	case "AccessDenied", "AccessDeniedException":
		return queryResultError("You do not seem to have access to the S3 location of your query results. Please confirm your account has access to the S3 location where your query results are saved and try again. If specifying an expected bucket owner, confirm the bucket is owned by the expected account. If you are using KMS to encrypt query results, please ensure you have permission to access your KMS key. If you continue to see this issue, please contact customer support.", "INSUFFICIENT_PERMISSIONS")
	case "NoSuchKey", "NoSuchBucket", "NotFound":
		return queryResultError("Could not find results", "RESULT_NOT_FOUND")
	default:
		return rejected
	}
}
