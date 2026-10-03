package evaluator

import (
	"encoding/json"
	"math"
	"strconv"
)

// formatJSONataNumber follows JSONata's JavaScript number stringification.
// Non-integers are first rounded to 15 significant digits, then encoded using
// the ECMAScript-compatible formatting rules used by encoding/json.
func formatJSONataNumber(number float64) string {
	if math.IsNaN(number) || math.IsInf(number, 0) {
		return strconv.FormatFloat(number, 'g', -1, 64)
	}
	if number == 0 {
		return "0"
	}
	if math.Trunc(number) != number {
		rounded, err := strconv.ParseFloat(strconv.FormatFloat(number, 'g', 15, 64), 64)
		if err == nil {
			number = rounded
		}
	}
	encoded, err := json.Marshal(number)
	if err != nil {
		return strconv.FormatFloat(number, 'g', -1, 64)
	}
	return string(encoded)
}
