package evaluator

import (
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/tiaanduplessis/jsonata-go/internal/value"
)

type integerPicture struct {
	digits       []rune
	zero         rune
	optional     int
	mandatory    int
	separators   []integerSeparator
	modifier     string
	ordinal      bool
	inputPattern string
}

type integerSeparator struct {
	char      rune
	fromRight int
}

func builtinFormatInteger(st state, args []any) (any, error) {
	if err := checkFormatRuntime(st); err != nil {
		return nil, err
	}
	if len(args) == 0 || value.IsUndefined(collapse(args[0])) {
		return value.Undefined, nil
	}
	if len(args) < 2 {
		return nil, functionArityError("$formatInteger", 2, len(args))
	}
	number, ok := strictNumeric(collapse(args[0]))
	if !ok {
		return nil, runtimeError{code: "T0410", msg: "expected a number"}
	}
	picture, ok := collapse(args[1]).(string)
	if !ok {
		return nil, runtimeError{code: "T0410", msg: "expected a string picture"}
	}
	parsed, err := parseIntegerPicture(picture)
	if err != nil {
		return nil, err
	}
	integer, ok := pictureNumberInteger(number)
	if !ok {
		return nil, runtimeError{code: "D1001", msg: "numeric result is not finite"}
	}
	if number < 0 {
		integer.Neg(integer)
	}
	if parsed.modifier == "w" || parsed.modifier == "W" || parsed.modifier == "Ww" {
		result := integerWords(integer, parsed.modifier, parsed.ordinal)
		return result, nil
	}
	if parsed.modifier == "I" || parsed.modifier == "i" {
		if integer.Sign() <= 0 {
			return "", nil
		}
		if integer.BitLen() > 24 {
			return nil, formatPictureError("D3130")
		}
		result := romanInteger(integer)
		if parsed.modifier == "i" {
			result = strings.ToLower(result)
		}
		return result, nil
	}
	if parsed.modifier == "A" || parsed.modifier == "a" {
		if integer.Sign() <= 0 {
			return "", nil
		}
		result := alphabeticInteger(integer)
		if parsed.modifier == "a" {
			result = strings.ToLower(result)
		}
		return result, nil
	}
	if integer.Sign() < 0 {
		integer.Abs(integer)
	}
	digits := integer.Text(10)
	for len([]rune(digits)) < parsed.mandatory {
		digits = "0" + digits
	}
	if integer.Sign() == 0 && parsed.mandatory == 0 {
		digits = ""
	}
	result := applyIntegerSeparators(digits, parsed)
	if number < 0 && result != "" {
		result = "-" + result
	}
	if parsed.modifier == "o" {
		result += ordinalSuffix(integer)
	}
	return mapIntegerDigits(result, parsed.zero), nil
}

func parseIntegerPicture(picture string) (integerPicture, error) {
	var parsed integerPicture
	parsed.inputPattern = picture
	parts := strings.Split(picture, ";")
	if len(parts) > 2 || len(parts) == 0 || parts[0] == "" {
		return parsed, formatPictureError("D3130")
	}
	if isIntegerWordPicture(parts[0]) {
		parsed.modifier = parts[0]
		if len(parts) == 2 {
			if parts[1] != "o" {
				return parsed, formatPictureError("D3130")
			}
			parsed.ordinal = true
		}
		return parsed, nil
	}
	digits := []rune(parts[0])
	if len(parts) == 2 {
		parsed.modifier = parts[1]
	}
	validModifier := parsed.modifier == "" || parsed.modifier == "c" || parsed.modifier == "o" || parsed.modifier == "w" || parsed.modifier == "W" || parsed.modifier == "Ww" || parsed.modifier == "I" || parsed.modifier == "i" || parsed.modifier == "A" || parsed.modifier == "a"
	if !validModifier {
		return parsed, formatPictureError("D3130")
	}
	if parsed.modifier == "w" || parsed.modifier == "W" || parsed.modifier == "Ww" || parsed.modifier == "I" || parsed.modifier == "i" || parsed.modifier == "A" || parsed.modifier == "a" {
		if len(digits) != 1 || digits[0] != []rune(parsed.modifier)[0] {
			return parsed, formatPictureError("D3130")
		}
		return parsed, nil
	}
	zeroFound := false
	for index, char := range digits {
		switch {
		case char == '0':
			if parsed.zero != 0 && parsed.zero != char {
				return parsed, formatPictureError("D3131")
			}
			parsed.zero = char
			parsed.mandatory++
			zeroFound = true
		case char == '#':
			parsed.optional++
		case unicode.IsDigit(char):
			value := integerPictureDigitValue(char)
			familyZero := char - rune(value)
			if !zeroFound {
				parsed.zero = familyZero
				zeroFound = true
			}
			if parsed.zero != familyZero {
				return parsed, formatPictureError("D3131")
			}
			parsed.mandatory++
		default:
			toRight := 0
			for _, right := range digits[index+1:] {
				if right == '0' || right == '#' || unicode.IsDigit(right) {
					toRight++
				}
			}
			parsed.separators = append(parsed.separators, integerSeparator{char: char, fromRight: toRight})
		}
	}
	if !zeroFound {
		return parsed, formatPictureError("D3130")
	}
	if parsed.zero == 0 {
		parsed.zero = '0'
	}
	return parsed, nil
}

func applyIntegerSeparators(digits string, picture integerPicture) string {
	if len(picture.separators) == 0 || digits == "" {
		return digits
	}
	runes := []rune(digits)
	insertions := make([]integerSeparator, len(picture.separators))
	copy(insertions, picture.separators)
	sort.Slice(insertions, func(i, j int) bool { return insertions[i].fromRight < insertions[j].fromRight })
	if len(insertions) > 0 {
		same := true
		step := insertions[0].fromRight
		for _, insertion := range insertions[1:] {
			if insertion.char != insertions[0].char || insertion.fromRight-insertions[0].fromRight != step {
				same = false
				break
			}
		}
		if same && step > 0 && (len(insertions) == 1 || insertions[0].fromRight == step) {
			for position := insertions[len(insertions)-1].fromRight + step; position < len(runes); position += step {
				insertions = append(insertions, integerSeparator{char: insertions[0].char, fromRight: position})
			}
		}
	}
	sort.Slice(insertions, func(i, j int) bool { return insertions[i].fromRight > insertions[j].fromRight })
	for i := range insertions {
		position := len(runes) - insertions[i].fromRight
		if position > 0 && position < len(runes) {
			runes = append(runes[:position], append([]rune{insertions[i].char}, runes[position:]...)...)
		}
	}
	return string(runes)
}

func isIntegerWordPicture(picture string) bool {
	return picture == "w" || picture == "W" || picture == "Ww" || picture == "I" || picture == "i" || picture == "A" || picture == "a"
}

func mapIntegerDigits(text string, zero rune) string {
	if zero == '0' {
		return text
	}
	var out strings.Builder
	for _, char := range text {
		if char >= '0' && char <= '9' {
			out.WriteRune(zero + (char - '0'))
		} else {
			out.WriteRune(char)
		}
	}
	return out.String()
}

func ordinalSuffix(n *big.Int) string {
	lastTwo := new(big.Int).Mod(new(big.Int).Abs(n), big.NewInt(100)).Int64()
	if lastTwo >= 11 && lastTwo <= 13 {
		return "th"
	}
	last := new(big.Int).Mod(new(big.Int).Abs(n), big.NewInt(10)).Int64()
	switch last {
	case 1:
		return "st"
	case 2:
		return "nd"
	case 3:
		return "rd"
	default:
		return "th"
	}
}

func romanInteger(number *big.Int) string {
	if number == nil || number.Sign() < 0 || number.BitLen() > 24 {
		return ""
	}
	values := []struct {
		value  int64
		symbol string
	}{
		{1000, "M"}, {900, "CM"}, {500, "D"}, {400, "CD"},
		{100, "C"}, {90, "XC"}, {50, "L"}, {40, "XL"},
		{10, "X"}, {9, "IX"}, {5, "V"}, {4, "IV"}, {1, "I"},
	}
	remaining := new(big.Int).Set(number)
	var out strings.Builder
	for _, item := range values {
		count := new(big.Int).Div(remaining, big.NewInt(item.value))
		remaining.Mod(remaining, big.NewInt(item.value))
		for count.Sign() > 0 {
			out.WriteString(item.symbol)
			count.Sub(count, big.NewInt(1))
		}
	}
	return out.String()
}

func alphabeticInteger(number *big.Int) string {
	remaining := new(big.Int).Set(number)
	var reversed []byte
	for remaining.Sign() > 0 {
		remaining.Sub(remaining, big.NewInt(1))
		rem := new(big.Int).Mod(remaining, big.NewInt(26)).Int64()
		reversed = append(reversed, byte('A'+rem))
		remaining.Div(remaining, big.NewInt(26))
	}
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	return string(reversed)
}

var integerWordsUnderTwenty = []string{"zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen"}
var integerWordsTens = []string{"", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"}

func integerWords(number *big.Int, modifier string, ordinal bool) string {
	negative := number.Sign() < 0
	absolute := new(big.Int).Abs(number)
	if absolute.Sign() == 0 {
		return "zero"
	}
	if absolute.Cmp(big.NewInt(1000000000000)) >= 0 {
		trillion := big.NewInt(1000000000000)
		high := new(big.Int)
		low := new(big.Int)
		high.QuoRem(absolute, trillion, low)
		highText := integerWordsCore(high, modifier, ordinal && low.Sign() == 0)
		highText += " trillion"
		result := highText
		if low.Sign() != 0 {
			lowText := integerWordsCore(low, modifier, ordinal)
			if low.Cmp(big.NewInt(100)) < 0 {
				result += " and " + lowText
			} else {
				result += ", " + lowText
			}
		}
		if negative {
			result = "minus " + result
		}
		if modifier == "W" {
			return strings.ToUpper(result)
		}
		if modifier == "Ww" {
			return titleIntegerWords(result)
		}
		return result
	}
	result := integerWordsCore(absolute, modifier, ordinal)
	if negative {
		result = "minus " + result
	}
	if modifier == "W" {
		result = strings.ToUpper(result)
	} else if modifier == "Ww" {
		result = titleIntegerWords(result)
	}
	return result
}

func integerWordsCore(absolute *big.Int, modifier string, ordinal bool) string {
	groups := make([]int, 0)
	thousand := big.NewInt(1000)
	remaining := new(big.Int).Set(absolute)
	for remaining.Sign() > 0 {
		part := new(big.Int).Mod(remaining, thousand).Int64()
		groups = append(groups, int(part))
		remaining.Div(remaining, thousand)
	}
	lastGroup := -1
	for i, group := range groups {
		if group != 0 {
			lastGroup = i
			break
		}
	}
	var parts []string
	for i := len(groups) - 1; i >= 0; i-- {
		if groups[i] == 0 {
			continue
		}
		partOrdinal := ordinal && i == lastGroup && i == 0
		part := wordsUnderThousand(groups[i], partOrdinal)
		scale := integerScaleName(i)
		if scale != "" {
			if ordinal && i == lastGroup {
				scale += "th"
			}
			part += " " + scale
		}
		parts = append(parts, part)
	}
	result := strings.Join(parts, ", ")
	if len(groups) > 0 && groups[0] > 0 && groups[0] < 100 && len(parts) > 1 {
		result = strings.TrimSuffix(result, ", ")
		lastComma := strings.LastIndex(result, ", ")
		if lastComma >= 0 {
			result = result[:lastComma] + " and " + result[lastComma+2:]
		}
	}
	return result
}

func integerScaleName(group int) string {
	if group == 0 {
		return ""
	}
	names := []string{"thousand", "million", "billion", "trillion"}
	if group < len(names)+1 {
		return names[group-1]
	}
	cycle := group / 4
	base := []string{"trillion", "thousand", "million", "billion"}[group%4]
	return base + strings.Repeat(" trillion", cycle)
}

func wordsUnderThousand(number int, ordinal bool) string {
	if number >= 100 {
		prefix := integerWordsUnderTwenty[number/100] + " hundred"
		if number%100 == 0 {
			if ordinal {
				return prefix + "th"
			}
			return prefix
		}
		return prefix + " and " + wordsUnderThousand(number%100, ordinal)
	}
	if number < 20 {
		if !ordinal {
			return integerWordsUnderTwenty[number]
		}
		return ordinalWord(integerWordsUnderTwenty[number])
	}
	if number%10 == 0 {
		word := integerWordsTens[number/10]
		if ordinal {
			return ordinalWord(word)
		}
		return word
	}
	result := integerWordsTens[number/10] + "-" + integerWordsUnderTwenty[number%10]
	if ordinal {
		result = integerWordsTens[number/10] + "-" + ordinalWord(integerWordsUnderTwenty[number%10])
	}
	return result
}

func ordinalWord(word string) string {
	mapWords := map[string]string{"one": "first", "two": "second", "three": "third", "four": "fourth", "five": "fifth", "six": "sixth", "seven": "seventh", "eight": "eighth", "nine": "ninth", "twelve": "twelfth", "thirteen": "thirteenth", "fourteen": "fourteenth", "fifteen": "fifteenth", "sixteen": "sixteenth", "seventeen": "seventeenth", "eighteen": "eighteenth", "nineteen": "nineteenth", "ten": "tenth", "eleven": "eleventh", "twenty": "twentieth", "thirty": "thirtieth", "forty": "fortieth", "fifty": "fiftieth", "sixty": "sixtieth", "seventy": "seventieth", "eighty": "eightieth", "ninety": "ninetieth"}
	if replacement, ok := mapWords[word]; ok {
		return replacement
	}
	return word + "th"
}

func titleIntegerWords(text string) string {
	words := strings.FieldsFunc(text, func(r rune) bool { return r == ' ' || r == '-' || r == ',' })
	for _, word := range words {
		_ = word
	}
	var out strings.Builder
	upperNext := true
	for _, char := range text {
		if upperNext && unicode.IsLetter(char) {
			out.WriteRune(unicode.ToUpper(char))
			upperNext = false
		} else {
			out.WriteRune(char)
		}
		if char == ' ' || char == '-' || char == ',' {
			upperNext = true
		}
	}
	return strings.ReplaceAll(out.String(), "And", "and")
}

func builtinParseInteger(st state, args []any) (any, error) {
	if err := checkFormatRuntime(st); err != nil {
		return nil, err
	}
	if len(args) == 0 || value.IsUndefined(collapse(args[0])) {
		return value.Undefined, nil
	}
	if len(args) < 2 {
		return nil, functionArityError("$parseInteger", 2, len(args))
	}
	text, ok := collapse(args[0]).(string)
	if !ok {
		return nil, runtimeError{code: "T0410", msg: "expected a string"}
	}
	picture, ok := collapse(args[1]).(string)
	if !ok {
		return nil, runtimeError{code: "T0410", msg: "expected a string picture"}
	}
	parsed, err := parseIntegerPicture(picture)
	if err != nil {
		return nil, err
	}
	modifier := parsed.modifier
	if modifier == "w" || modifier == "W" || modifier == "Ww" {
		return parseIntegerWords(st, text, modifier, parsed.ordinal)
	}
	if modifier == "I" || modifier == "i" {
		result, ok := parseRomanInteger(text)
		if !ok {
			return nil, formatPictureError("D3130")
		}
		return finiteBigFloat(result)
	}
	if modifier == "A" || modifier == "a" {
		result, ok := parseAlphabeticInteger(text)
		if !ok {
			return nil, formatPictureError("D3130")
		}
		return finiteBigFloat(result)
	}
	if modifier == "o" {
		suffix := "th"
		if strings.HasSuffix(text, "st") || strings.HasSuffix(text, "nd") || strings.HasSuffix(text, "rd") {
			suffix = text[len(text)-2:]
		}
		if !strings.HasSuffix(text, suffix) {
			return nil, formatPictureError("D3130")
		}
		text = text[:len(text)-len(suffix)]
	}
	text = strings.TrimSpace(text)
	negative := strings.HasPrefix(text, "-")
	if negative {
		text = text[1:]
	}
	var digits strings.Builder
	for _, char := range text {
		if parsed.zero == '0' && char >= '0' && char <= '9' {
			digits.WriteRune(char)
			continue
		}
		if mapped, ok := unicodeIntegerDigit(char, parsed.zero); ok {
			digits.WriteByte(byte('0' + mapped))
			continue
		}
		for _, separator := range parsed.separators {
			if char == separator.char {
				goto nextRune
			}
		}
		return nil, formatPictureError("D3130")
	nextRune:
	}
	if digits.Len() == 0 {
		return 0.0, nil
	}
	integer, ok := new(big.Int).SetString(digits.String(), 10)
	if !ok {
		return nil, formatPictureError("D3130")
	}
	if negative {
		integer.Neg(integer)
	}
	return finiteBigFloat(integer)
}

func unicodeIntegerDigit(char, zero rune) (int, bool) {
	if zero == 0 {
		return 0, false
	}
	for offset := 0; offset < 10; offset++ {
		if char == zero+rune(offset) {
			return offset, true
		}
	}
	return 0, false
}

func integerPictureDigitValue(char rune) int {
	if char >= '0' && char <= '9' {
		return int(char - '0')
	}
	for offset := 0; offset < 10; offset++ {
		start := char - rune(offset)
		if !unicode.IsDigit(start) {
			continue
		}
		valid := true
		for digit := 0; digit < 10; digit++ {
			if !unicode.IsDigit(start + rune(digit)) {
				valid = false
				break
			}
		}
		if valid {
			return offset
		}
	}
	return 0
}

func parseRomanInteger(text string) (*big.Int, bool) {
	if text == "" {
		return big.NewInt(0), true
	}
	if len(text) > 100000 {
		return nil, false
	}
	text = strings.ToUpper(text)
	values := map[byte]int64{'I': 1, 'V': 5, 'X': 10, 'L': 50, 'C': 100, 'D': 500, 'M': 1000}
	total := big.NewInt(0)
	previous := int64(0)
	for i := len(text) - 1; i >= 0; i-- {
		value, ok := values[text[i]]
		if !ok {
			return nil, false
		}
		if value < previous {
			total.Sub(total, big.NewInt(value))
		} else {
			total.Add(total, big.NewInt(value))
			previous = value
		}
	}
	if romanInteger(total) != text {
		return nil, false
	}
	return total, true
}

func parseAlphabeticInteger(text string) (*big.Int, bool) {
	text = strings.ToUpper(strings.TrimSpace(text))
	if text == "" {
		return nil, false
	}
	result := big.NewInt(0)
	for _, char := range text {
		if char < 'A' || char > 'Z' {
			return nil, false
		}
		result.Mul(result, big.NewInt(26))
		result.Add(result, big.NewInt(int64(char-'A'+1)))
	}
	return result, true
}

func finiteBigFloat(integer *big.Int) (any, error) {
	result, err := strconv.ParseFloat(integer.String(), 64)
	if err != nil || math.IsInf(result, 0) || math.IsNaN(result) {
		return nil, runtimeError{code: "D1001", msg: "numeric result is not finite"}
	}
	return result, nil
}

func parseIntegerWords(st state, text, modifier string, ordinal bool) (any, error) {
	text = strings.ToLower(strings.TrimSpace(text))
	if modifier == "W" {
		text = strings.ToUpper(text)
		text = strings.ToLower(text)
	}
	text = strings.ReplaceAll(text, "-", " ")
	text = strings.ReplaceAll(text, ",", " ")
	tokens := strings.Fields(text)
	if len(tokens) == 0 {
		return 0.0, nil
	}
	negative := tokens[0] == "minus"
	if negative {
		tokens = tokens[1:]
		if len(tokens) == 0 {
			return nil, formatPictureError("D3130")
		}
	}
	ordinalWords := map[string]string{"first": "one", "second": "two", "third": "three", "fourth": "four", "fifth": "five", "sixth": "six", "seventh": "seven", "eighth": "eight", "ninth": "nine", "tenth": "ten", "eleventh": "eleven", "twelfth": "twelve", "thirteenth": "thirteen", "fourteenth": "fourteen", "fifteenth": "fifteen", "sixteenth": "sixteen", "seventeenth": "seventeen", "eighteenth": "eighteen", "nineteenth": "nineteen", "twentieth": "twenty", "thirtieth": "thirty", "fortieth": "forty", "fiftieth": "fifty", "sixtieth": "sixty", "seventieth": "seventy", "eightieth": "eighty", "ninetieth": "ninety", "hundredth": "hundred", "thousandth": "thousand"}
	unitValues := make(map[string]int64, len(integerWordsUnderTwenty)+len(integerWordsTens))
	for i, word := range integerWordsUnderTwenty {
		unitValues[word] = int64(i)
	}
	for i, word := range integerWordsTens {
		if word != "" {
			unitValues[word] = int64(i * 10)
		}
	}
	if ordinal {
		for from, to := range ordinalWords {
			if value, ok := unitValues[to]; ok {
				unitValues[from] = value
			}
		}
	}
	scaleValues := map[string]*big.Int{"hundred": big.NewInt(100), "thousand": big.NewInt(1000), "million": big.NewInt(1000000), "billion": big.NewInt(1000000000), "trillion": big.NewInt(1000000000000)}
	total := new(big.Int)
	current := new(big.Int)
	for _, token := range tokens {
		if err := checkFormatRuntime(st); err != nil {
			return nil, err
		}
		if token == "and" {
			continue
		}
		if replacement, ok := ordinalWords[token]; ok {
			token = replacement
		}
		if unit, ok := unitValues[token]; ok {
			current.Add(current, big.NewInt(unit))
			continue
		}
		scale, ok := scaleValues[token]
		if !ok {
			return nil, formatPictureError("D3130")
		}
		if token == "hundred" {
			if current.Sign() == 0 {
				current.SetInt64(100)
			} else {
				current.Mul(current, scale)
			}
			continue
		}
		if current.Sign() > 0 {
			current.Mul(current, scale)
			total.Add(total, current)
			current.SetInt64(0)
		} else if total.Sign() > 0 {
			total.Mul(total, scale)
		} else {
			return nil, formatPictureError("D3130")
		}
	}
	total.Add(total, current)
	if negative {
		total.Neg(total)
	}
	return finiteBigFloat(total)
}
