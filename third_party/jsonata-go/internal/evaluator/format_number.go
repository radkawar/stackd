package evaluator

import (
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/tiaanduplessis/jsonata-go/internal/value"
)

type numberPictureProperties struct {
	decimal   string
	grouping  string
	exponent  string
	minus     string
	percent   string
	permille  string
	zero      string
	digit     string
	separator string
}

type numberPictureParts struct {
	prefix, suffix, active string
	mantissa, exponent     string
	integer, fractional    string
	picture                string
}

type analysedNumberPicture struct {
	groupingPositions         []int
	regularGrouping           int
	minimumIntegerPartSize    int
	scalingFactor             int
	fractionalGrouping        []int
	minimumFractionalPartSize int
	maximumFractionalPartSize int
	minimumExponentSize       int
	prefix, suffix, picture   string
}

func builtinFormatNumber(st state, args []any) (any, error) {
	if len(args) == 0 || value.IsUndefined(collapse(args[0])) {
		return value.Undefined, nil
	}
	if len(args) < 2 {
		return nil, functionArityError("$formatNumber", 2, len(args))
	}
	number, ok := strictNumeric(collapse(args[0]))
	if !ok {
		return nil, runtimeError{code: "T0410", msg: "expected a number"}
	}
	if math.IsNaN(number) || math.IsInf(number, 0) {
		return nil, runtimeError{code: "D1001", msg: "numeric result is not finite"}
	}
	picture, ok := collapse(args[1]).(string)
	if !ok {
		return nil, runtimeError{code: "T0410", msg: "expected a string picture"}
	}
	properties := numberPictureProperties{
		decimal: ".", grouping: ",", exponent: "e", minus: "-", percent: "%",
		permille: "‰", zero: "0", digit: "#", separator: ";",
	}
	options := formatOptions(args)
	properties.decimal = formatStringOption(options, "decimal-separator", properties.decimal)
	properties.grouping = formatStringOption(options, "grouping-separator", properties.grouping)
	properties.exponent = formatStringOption(options, "exponent-separator", properties.exponent)
	properties.minus = formatStringOption(options, "minus-sign", properties.minus)
	properties.percent = formatStringOption(options, "percent", properties.percent)
	properties.permille = formatStringOption(options, "per-mille", properties.permille)
	properties.zero = formatStringOption(options, "zero-digit", properties.zero)
	properties.digit = formatStringOption(options, "digit", properties.digit)
	properties.separator = formatStringOption(options, "pattern-separator", properties.separator)
	zeroFamily, ok := formatDigitsFamily(properties.zero)
	if !ok || properties.decimal == "" || properties.grouping == "" || properties.exponent == "" || properties.minus == "" || properties.digit == "" || properties.separator == "" {
		return nil, formatPictureError("D3086")
	}
	subPictures := strings.Split(picture, properties.separator)
	if len(subPictures) > 2 {
		return nil, formatPictureError("D3080")
	}
	parts := make([]numberPictureParts, len(subPictures))
	variables := make([]analysedNumberPicture, len(subPictures))
	for i, subpicture := range subPictures {
		part := splitNumberPicture(subpicture, properties, zeroFamily)
		if err := validateNumberPicture(part, properties, zeroFamily); err != nil {
			return nil, err
		}
		parts[i] = part
		variables[i] = analyseNumberPicture(part, properties, zeroFamily)
	}
	if len(variables) == 1 {
		negative := variables[0]
		negative.prefix = properties.minus + negative.prefix
		variables = append(variables, negative)
	}
	if err := checkFormatRuntime(st); err != nil {
		return nil, err
	}
	pic := variables[0]
	if number < 0 {
		pic = variables[1]
	}
	adjusted := number
	selectedIndex := 0
	if number < 0 {
		selectedIndex = 1
	}
	if selectedIndex >= len(parts) {
		selectedIndex = len(parts) - 1
	}
	if strings.Contains(parts[selectedIndex].picture, properties.percent) {
		adjusted *= 100
	} else if strings.Contains(parts[selectedIndex].picture, properties.permille) {
		adjusted *= 1000
	}
	var mantissa float64
	exponent := 0
	if pic.minimumExponentSize == 0 {
		mantissa = adjusted
	} else {
		mantissa = adjusted
		minMantissa := math.Pow10(pic.scalingFactor - 1)
		maxMantissa := math.Pow10(pic.scalingFactor)
		if mantissa != 0 {
			for math.Abs(mantissa) < minMantissa {
				if err := checkFormatRuntime(st); err != nil {
					return nil, err
				}
				mantissa *= 10
				exponent--
			}
			for math.Abs(mantissa) > maxMantissa {
				if err := checkFormatRuntime(st); err != nil {
					return nil, err
				}
				mantissa /= 10
				exponent++
			}
		}
	}
	rounded := roundNumberDecimals(mantissa, pic.maximumFractionalPartSize)
	stringValue := strconv.FormatFloat(math.Abs(rounded), 'f', pic.maximumFractionalPartSize, 64)
	decimalPosition := strings.IndexByte(stringValue, '.')
	if decimalPosition < 0 {
		stringValue += "."
		decimalPosition = len(stringValue) - 1
	}
	stringValue = mapPictureDigits(stringValue, zeroFamily)
	if properties.decimal != "." {
		stringValue = strings.Replace(stringValue, ".", properties.decimal, 1)
	}
	decimalPosition = runeSubstringIndex(stringValue, properties.decimal)
	if decimalPosition < 0 {
		decimalPosition = runeSubstringIndex(stringValue, ".")
	}
	for strings.HasPrefix(stringValue, string(zeroFamily[0])) {
		runes := []rune(stringValue)
		stringValue = string(runes[1:])
	}
	for strings.HasSuffix(stringValue, string(zeroFamily[0])) {
		runes := []rune(stringValue)
		stringValue = string(runes[:len(runes)-1])
	}
	if !strings.Contains(stringValue, properties.decimal) {
		stringValue += properties.decimal
	}
	decimalPosition = runeSubstringIndex(stringValue, properties.decimal)
	padLeft := pic.minimumIntegerPartSize - decimalPosition
	if padLeft > 0 {
		stringValue = strings.Repeat(string(zeroFamily[0]), padLeft) + stringValue
	}
	decimalPosition = runeSubstringIndex(stringValue, properties.decimal)
	decimalRunePosition := decimalPosition
	padRight := pic.minimumFractionalPartSize - (len([]rune(stringValue)) - decimalRunePosition - len([]rune(properties.decimal)))
	if padRight > 0 {
		stringValue += strings.Repeat(string(zeroFamily[0]), padRight)
	}
	decimalPosition = runeSubstringIndex(stringValue, properties.decimal)
	if pic.regularGrouping > 0 {
		groups := (decimalPosition - 1) / pic.regularGrouping
		for group := 1; group <= groups; group++ {
			position := decimalPosition - group*pic.regularGrouping
			stringValue = insertRuneString(stringValue, position, properties.grouping)
		}
	} else {
		for _, position := range pic.groupingPositions {
			positionAt := decimalPosition - position
			if positionAt > 0 {
				stringValue = insertRuneString(stringValue, positionAt, properties.grouping)
				decimalPosition += utf8.RuneCountInString(properties.grouping)
			}
		}
	}
	for _, position := range pic.fractionalGrouping {
		positionAt := position + runeSubstringIndex(stringValue, properties.decimal) + utf8.RuneCountInString(properties.decimal)
		if positionAt < utf8.RuneCountInString(stringValue) {
			stringValue = insertRuneString(stringValue, positionAt, properties.grouping)
		}
	}
	if !strings.Contains(pic.picture, properties.decimal) || strings.HasSuffix(stringValue, properties.decimal) {
		stringValue = strings.TrimSuffix(stringValue, properties.decimal)
	}
	if pic.minimumExponentSize > 0 {
		exponentText := mapPictureDigits(strconv.Itoa(absInt(exponent)), zeroFamily)
		if len([]rune(exponentText)) < pic.minimumExponentSize {
			exponentText = strings.Repeat(string(zeroFamily[0]), pic.minimumExponentSize-len([]rune(exponentText))) + exponentText
		}
		stringValue += properties.exponent
		if exponent < 0 {
			stringValue += properties.minus
		}
		stringValue += exponentText
	}
	stringValue = pic.prefix + stringValue + pic.suffix
	return stringValue, nil
}

func runeSubstringIndex(text, substring string) int {
	if substring == "" {
		return 0
	}
	byteIndex := strings.Index(text, substring)
	if byteIndex < 0 {
		return -1
	}
	return utf8.RuneCountInString(text[:byteIndex])
}

func insertRuneString(text string, position int, insertion string) string {
	runes := []rune(text)
	if position < 0 {
		position = 0
	}
	if position > len(runes) {
		position = len(runes)
	}
	result := make([]rune, 0, len(runes)+utf8.RuneCountInString(insertion))
	result = append(result, runes[:position]...)
	result = append(result, []rune(insertion)...)
	result = append(result, runes[position:]...)
	return string(result)
}

func splitNumberPicture(subpicture string, properties numberPictureProperties, zeroFamily []rune) numberPictureParts {
	active := func(char rune) bool {
		for _, digit := range zeroFamily {
			if char == digit {
				return true
			}
		}
		return char == []rune(properties.decimal)[0] || char == []rune(properties.grouping)[0] || char == []rune(properties.exponent)[0] || char == []rune(properties.digit)[0] || char == []rune(properties.separator)[0]
	}
	runes := []rune(subpicture)
	prefixEnd := len(runes)
	for i, char := range runes {
		if active(char) && string(char) != properties.exponent {
			prefixEnd = i
			break
		}
	}
	suffixStart := 0
	for i := len(runes) - 1; i >= 0; i-- {
		if active(runes[i]) && string(runes[i]) != properties.exponent {
			suffixStart = i + 1
			break
		}
	}
	if prefixEnd > suffixStart {
		prefixEnd = suffixStart
	}
	prefix := string(runes[:prefixEnd])
	suffix := string(runes[suffixStart:])
	activePart := string(runes[prefixEnd:suffixStart])
	exponentPosition := strings.Index(activePart, properties.exponent)
	mantissa := activePart
	exponentPart := ""
	if exponentPosition >= 0 {
		mantissa = activePart[:exponentPosition]
		exponentPart = activePart[exponentPosition+len([]rune(properties.exponent)):]
	}
	decimalPosition := strings.Index(mantissa, properties.decimal)
	integerPart := mantissa
	fractionalPart := suffix
	if decimalPosition >= 0 {
		integerPart = mantissa[:decimalPosition]
		fractionalPart = mantissa[decimalPosition+len([]rune(properties.decimal)):]
	}
	return numberPictureParts{prefix: prefix, suffix: suffix, active: activePart, mantissa: mantissa, exponent: exponentPart, integer: integerPart, fractional: fractionalPart, picture: subpicture}
}

func validateNumberPicture(parts numberPictureParts, properties numberPictureProperties, zeroFamily []rune) error {
	hasDigit := false
	for _, char := range parts.mantissa {
		if numberPictureDigit(char, zeroFamily) || string(char) == properties.digit {
			hasDigit = true
		}
	}
	if !hasDigit {
		if strings.Contains(parts.picture, properties.exponent) {
			return formatPictureError("D3085")
		}
		return formatPictureError("D3086")
	}
	if countSubstring(parts.picture, properties.decimal) > 1 {
		return formatPictureError("D3081")
	}
	if countSubstring(parts.picture, properties.percent) > 1 {
		return formatPictureError("D3082")
	}
	if countSubstring(parts.picture, properties.permille) > 1 {
		return formatPictureError("D3083")
	}
	if strings.Contains(parts.picture, properties.percent) && strings.Contains(parts.picture, properties.permille) {
		return formatPictureError("D3084")
	}
	for _, char := range parts.active {
		if !numberPictureActiveChar(char, properties, zeroFamily) && !strings.ContainsRune(parts.prefix+parts.suffix, char) {
			return formatPictureError("D3086")
		}
	}
	decimalPosition := runeSubstringIndex(parts.picture, properties.decimal)
	if decimalPosition >= 0 {
		pictureRunes := []rune(parts.picture)
		before, after := "", ""
		if decimalPosition > 0 {
			before = string(pictureRunes[decimalPosition-1])
		}
		if decimalPosition+1 < len(pictureRunes) {
			after = string(pictureRunes[decimalPosition+1])
		}
		if before == properties.grouping || after == properties.grouping {
			return formatPictureError("D3087")
		}
	} else if strings.HasSuffix(parts.integer, properties.grouping) {
		return formatPictureError("D3088")
	}
	if strings.Contains(parts.integer, properties.grouping+properties.grouping) {
		return formatPictureError("D3089")
	}
	if optionalBeforeMandatory(parts.integer, properties.digit, zeroFamily) {
		return formatPictureError("D3090")
	}
	if optionalAfterMandatory(parts.fractional, properties.digit, zeroFamily) {
		return formatPictureError("D3091")
	}
	if parts.exponent != "" && (strings.Contains(parts.picture, properties.percent) || strings.Contains(parts.picture, properties.permille)) {
		return formatPictureError("D3092")
	}
	if strings.Contains(parts.active, properties.exponent) && (parts.exponent == "" || !allPictureDigits(parts.exponent, zeroFamily)) {
		return formatPictureError("D3093")
	}
	return nil
}

func analyseNumberPicture(parts numberPictureParts, properties numberPictureProperties, zeroFamily []rune) analysedNumberPicture {
	integerPositions := numberGroupingPositions(parts.integer, properties.grouping, zeroFamily, false)
	regular := regularPictureGrouping(integerPositions)
	scalingFactor := countPictureMandatory(parts.integer, zeroFamily)
	minimumInteger := scalingFactor
	minimumFractional := countPictureMandatory(parts.fractional, zeroFamily)
	maximumFractional := minimumFractional + strings.Count(parts.fractional, properties.digit)
	minimumExponent := countPictureMandatory(parts.exponent, zeroFamily)
	if minimumInteger == 0 && maximumFractional == 0 {
		if parts.exponent != "" {
			minimumFractional, maximumFractional = 1, 1
		} else {
			minimumInteger = 1
		}
	}
	if parts.exponent != "" && minimumInteger == 0 && strings.Contains(parts.integer, properties.digit) {
		minimumInteger = 1
	}
	if minimumInteger == 0 && minimumFractional == 0 {
		minimumFractional = 1
	}
	return analysedNumberPicture{
		groupingPositions: integerPositions, regularGrouping: regular,
		minimumIntegerPartSize: minimumInteger, scalingFactor: scalingFactor,
		fractionalGrouping:        numberGroupingPositions(parts.fractional, properties.grouping, zeroFamily, true),
		minimumFractionalPartSize: minimumFractional, maximumFractionalPartSize: maximumFractional,
		minimumExponentSize: minimumExponent, prefix: parts.prefix, suffix: parts.suffix, picture: parts.picture,
	}
}

func numberPictureDigit(char rune, family []rune) bool {
	return digitIndex(char, family) >= 0
}

func digitIndex(char rune, family []rune) int {
	for i, digit := range family {
		if char == digit {
			return i
		}
	}
	return -1
}

func numberPictureActiveChar(char rune, properties numberPictureProperties, family []rune) bool {
	return numberPictureDigit(char, family) || string(char) == properties.decimal || string(char) == properties.grouping || string(char) == properties.exponent || string(char) == properties.digit || string(char) == properties.separator
}

func allPictureDigits(text string, family []rune) bool {
	if text == "" {
		return false
	}
	for _, char := range text {
		if !numberPictureDigit(char, family) {
			return false
		}
	}
	return true
}

func countPictureMandatory(text string, family []rune) int {
	count := 0
	for _, char := range text {
		if numberPictureDigit(char, family) {
			count++
		}
	}
	return count
}

func numberGroupingPositions(part, separator string, family []rune, toLeft bool) []int {
	positions := []int{}
	for index := strings.Index(part, separator); index >= 0; {
		var text string
		if toLeft {
			text = part[:index]
		} else {
			text = part[index:]
		}
		positions = append(positions, countPictureMandatory(text, family)+strings.Count(text, "#"))
		next := index + len(separator)
		if next >= len(part) {
			break
		}
		rest := part[next:]
		nextIndex := strings.Index(rest, separator)
		if nextIndex < 0 {
			break
		}
		index = next + nextIndex
	}
	return positions
}

func regularPictureGrouping(positions []int) int {
	if len(positions) == 0 {
		return 0
	}
	factor := positions[0]
	for _, position := range positions[1:] {
		factor = gcdPicture(factor, position)
	}
	for i := 1; i <= len(positions); i++ {
		found := false
		for _, position := range positions {
			if position == i*factor {
				found = true
			}
		}
		if !found {
			return 0
		}
	}
	return factor
}

func gcdPicture(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func optionalBeforeMandatory(text, optional string, family []rune) bool {
	index := strings.Index(text, optional)
	if index < 0 {
		return false
	}
	return countPictureMandatory(text[:index], family) > 0
}

func optionalAfterMandatory(text, optional string, family []rune) bool {
	index := strings.LastIndex(text, optional)
	if index < 0 {
		return false
	}
	return countPictureMandatory(text[index:], family) > 0
}

func countSubstring(text, target string) int {
	if target == "" {
		return 0
	}
	return strings.Count(text, target)
}

func roundNumberDecimals(number float64, places int) float64 {
	if places < 0 || places > 300 {
		return number
	}
	pow := math.Pow10(places)
	if math.IsInf(pow, 0) {
		return number
	}
	return math.Round(number*pow) / pow
}

func absInt(number int) int {
	if number < 0 {
		return -number
	}
	return number
}

func checkFormatRuntime(st state) error {
	if st.runtime == nil {
		return nil
	}
	return st.runtime.check()
}
