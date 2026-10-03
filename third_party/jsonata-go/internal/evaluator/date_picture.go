package evaluator

import (
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type datePicturePart struct {
	literal string
	marker  *dateMarker
}

type dateMarker struct {
	component     byte
	presentation  string
	presentation2 byte
	names         dateNameCase
	ordinal       bool
	widthMin      int
	widthMax      int
	yearDigits    int
	integer       *dateIntegerPicture
}

type dateNameCase uint8

const (
	dateNamesNone dateNameCase = iota
	dateNamesLower
	dateNamesUpper
	dateNamesTitle
)

type dateIntegerKind uint8

const (
	dateIntegerDecimal dateIntegerKind = iota
	dateIntegerLetters
	dateIntegerRoman
	dateIntegerWords
	dateIntegerSequence
)

type dateIntegerPicture struct {
	kind         dateIntegerKind
	presentation string
	nameCase     dateNameCase
	ordinal      bool
	mandatory    int
	optional     int
	parseWidth   int
	regular      bool
	regularSep   rune
	regularEvery int
	separators   []dateIntegerSeparator
}

type dateIntegerSeparator struct {
	char      rune
	fromRight int
}

var dateDefaultPresentation = map[byte]string{
	'Y': "1", 'M': "1", 'D': "1", 'd': "1", 'F': "n", 'W': "1", 'w': "1",
	'X': "1", 'x': "1", 'H': "1", 'h': "1", 'P': "n", 'm': "01", 's': "01",
	'f': "1", 'Z': "01:01", 'z': "01:01", 'C': "n", 'E': "n",
}

var dateDayNames = []string{"", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"}
var dateMonthNames = []string{"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"}

func analyseDateTimePicture(st state, picture string) ([]datePicturePart, error) {
	parts := make([]datePicturePart, 0, 8)
	addLiteral := func(raw string) {
		if raw != "" {
			parts = append(parts, datePicturePart{literal: strings.ReplaceAll(raw, "]]", "]")})
		}
	}
	start := 0
	for position := 0; position < len(picture); {
		if err := dateCheck(st); err != nil {
			return nil, err
		}
		if picture[position] != '[' {
			position++
			continue
		}
		if position+1 < len(picture) && picture[position+1] == '[' {
			addLiteral(picture[start:position])
			parts = append(parts, datePicturePart{literal: "["})
			position += 2
			start = position
			continue
		}
		addLiteral(picture[start:position])
		end := strings.IndexByte(picture[position+1:], ']')
		if end < 0 {
			return nil, dateError("D3135", "date/time picture has no closing bracket")
		}
		end += position + 1
		marker, err := analyseDateMarker(st, picture[position+1:end])
		if err != nil {
			return nil, err
		}
		if len(parts) > 0 && parts[len(parts)-1].marker != nil && parts[len(parts)-1].marker.integer != nil {
			parts[len(parts)-1].marker.integer.parseWidth = parts[len(parts)-1].marker.integer.mandatory
		}
		parts = append(parts, datePicturePart{marker: marker})
		position = end + 1
		start = position
	}
	addLiteral(picture[start:])
	return parts, nil
}

func analyseDateMarker(st state, raw string) (*dateMarker, error) {
	var compact strings.Builder
	for _, char := range raw {
		if err := dateCheck(st); err != nil {
			return nil, err
		}
		if !unicode.IsSpace(char) {
			compact.WriteRune(char)
		}
	}
	text := compact.String()
	if text == "" {
		return nil, dateError("D3132", "unknown date/time component")
	}
	marker := &dateMarker{component: text[0]}
	presentation := text[1:]
	if comma := strings.LastIndexByte(presentation, ','); comma >= 0 {
		width := presentation[comma+1:]
		presentation = presentation[:comma]
		if dash := strings.IndexByte(width, '-'); dash >= 0 {
			marker.widthMin = dateParseWidth(width[:dash])
			marker.widthMax = dateParseWidth(width[dash+1:])
		} else {
			marker.widthMin = dateParseWidth(width)
		}
	}
	if presentation == "" {
		var ok bool
		presentation, ok = dateDefaultPresentation[marker.component]
		if !ok {
			return nil, dateError("D3132", "unknown date/time component")
		}
	}
	if len(presentation) > 1 {
		last := presentation[len(presentation)-1]
		if strings.ContainsRune("atco", rune(last)) {
			marker.presentation2 = last
			marker.ordinal = last == 'o'
			presentation = presentation[:len(presentation)-1]
		}
	}
	marker.presentation = presentation
	if presentation == "" {
		return nil, dateError("D3130", "invalid date/time presentation")
	}
	switch presentation[0] {
	case 'n':
		marker.names = dateNamesLower
	case 'N':
		if len(presentation) > 1 && presentation[1] == 'n' {
			marker.names = dateNamesTitle
		} else {
			marker.names = dateNamesUpper
		}
	default:
		if strings.ContainsRune("YMDdFWwXxHhmsf", rune(marker.component)) {
			integer, err := analyseDateIntegerPicture(presentation, marker.ordinal)
			if err != nil {
				return nil, err
			}
			if marker.widthMin > integer.mandatory {
				integer.mandatory = marker.widthMin
			}
			marker.integer = integer
			if marker.component == 'Y' {
				marker.yearDigits = -1
				if marker.widthMax > 0 {
					marker.yearDigits = marker.widthMax
					integer.mandatory = marker.widthMax
				} else if integer.mandatory+integer.optional >= 2 {
					marker.yearDigits = integer.mandatory + integer.optional
				}
			}
		}
	}
	if marker.component == 'Z' || marker.component == 'z' {
		integer, err := analyseDateIntegerPicture(presentation, false)
		if err != nil {
			return nil, err
		}
		marker.integer = integer
	}
	if _, ok := dateDefaultPresentation[marker.component]; !ok {
		return nil, dateError("D3132", "unknown date/time component")
	}
	return marker, nil
}

func dateParseWidth(text string) int {
	if text == "" || text == "*" {
		return 0
	}
	width, err := strconv.Atoi(text)
	if err != nil || width < 0 {
		return 0
	}
	return width
}

func analyseDateIntegerPicture(presentation string, ordinal bool) (*dateIntegerPicture, error) {
	format := &dateIntegerPicture{presentation: presentation, ordinal: ordinal}
	switch presentation {
	case "A":
		format.kind, format.nameCase = dateIntegerLetters, dateNamesUpper
		return format, nil
	case "a":
		format.kind, format.nameCase = dateIntegerLetters, dateNamesLower
		return format, nil
	case "I":
		format.kind, format.nameCase = dateIntegerRoman, dateNamesUpper
		return format, nil
	case "i":
		format.kind, format.nameCase = dateIntegerRoman, dateNamesLower
		return format, nil
	case "W":
		format.kind, format.nameCase = dateIntegerWords, dateNamesUpper
		return format, nil
	case "Ww":
		format.kind, format.nameCase = dateIntegerWords, dateNamesTitle
		return format, nil
	case "w":
		format.kind, format.nameCase = dateIntegerWords, dateNamesLower
		return format, nil
	}
	format.kind = dateIntegerDecimal
	position := 0
	for index := len(presentation) - 1; index >= 0; index-- {
		char := rune(presentation[index])
		switch {
		case char >= '0' && char <= '9':
			format.mandatory++
			position++
		case char == '#':
			format.optional++
			position++
		default:
			format.separators = append(format.separators, dateIntegerSeparator{char: char, fromRight: position})
		}
	}
	if format.mandatory == 0 {
		format.kind = dateIntegerSequence
		return format, dateError("D3130", "unsupported numbering sequence")
	}
	if len(format.separators) > 0 {
		same := true
		for _, separator := range format.separators[1:] {
			if separator.char != format.separators[0].char {
				same = false
			}
		}
		factor := format.separators[0].fromRight
		for _, separator := range format.separators[1:] {
			factor = dateGCD(factor, separator.fromRight)
		}
		if same && factor > 0 {
			seen := make(map[int]bool, len(format.separators))
			for _, separator := range format.separators {
				seen[separator.fromRight] = true
			}
			regular := true
			for index := 1; index <= len(format.separators); index++ {
				regular = regular && seen[index*factor]
			}
			if regular {
				format.regular = true
				format.regularSep = format.separators[0].char
				format.regularEvery = factor
			}
		}
	}
	return format, nil
}

func dateGCD(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func formatDateTime(st state, millis int64, picture, timezone *string) (string, error) {
	if err := dateCheck(st); err != nil {
		return "", err
	}
	offsetMinutes := 0
	if timezone != nil {
		var ok bool
		offsetMinutes, ok = parseDateTimezone(*timezone)
		if !ok {
			return "", dateError("D3134", "invalid timezone")
		}
	}
	pictureText := "[Y0001]-[M01]-[D01]T[H01]:[m01]:[s01].[f001][Z01:01t]"
	if picture != nil {
		pictureText = *picture
	}
	parts, err := analyseDateTimePicture(st, pictureText)
	if err != nil {
		return "", err
	}
	date := time.UnixMilli(millis).UTC().Add(time.Duration(offsetMinutes) * time.Minute)
	var result strings.Builder
	for _, part := range parts {
		if err := dateCheck(st); err != nil {
			return "", err
		}
		if part.marker == nil {
			result.WriteString(part.literal)
			continue
		}
		formatted, err := formatDateMarker(date, part.marker, offsetMinutes)
		if err != nil {
			return "", err
		}
		result.WriteString(formatted)
	}
	return result.String(), nil
}

func formatDateMarker(date time.Time, marker *dateMarker, offsetMinutes int) (string, error) {
	if marker.component == 'Z' || marker.component == 'z' {
		return formatDateTimezone(marker, offsetMinutes)
	}
	if marker.component == 'C' || marker.component == 'E' {
		return "ISO", nil
	}
	if marker.component == 'P' {
		value := "am"
		if date.Hour() >= 12 {
			value = "pm"
		}
		if marker.names == dateNamesUpper {
			value = strings.ToUpper(value)
		}
		return value, nil
	}
	value := dateFragment(date, marker.component)
	if marker.names != dateNamesNone {
		var name string
		switch marker.component {
		case 'M', 'x':
			if value >= 1 && value <= 12 {
				name = dateMonthNames[value-1]
			}
		case 'F':
			if value >= 1 && value <= 7 {
				name = dateDayNames[value]
			}
		default:
			return "", dateError("D3133", "component does not support names")
		}
		switch marker.names {
		case dateNamesLower:
			name = strings.ToLower(name)
		case dateNamesUpper:
			name = strings.ToUpper(name)
		}
		if marker.widthMax > 0 && len(name) > marker.widthMax {
			name = name[:marker.widthMax]
		}
		return name, nil
	}
	if marker.component == 'Y' && marker.yearDigits > 0 {
		value %= int(math.Pow10(marker.yearDigits))
	}
	return formatDateInteger(value, marker.integer)
}

func formatDateInteger(value int, picture *dateIntegerPicture) (string, error) {
	if picture == nil {
		return strconv.Itoa(value), nil
	}
	switch picture.kind {
	case dateIntegerLetters:
		result := alphabeticInteger(big.NewInt(int64(value)))
		if picture.nameCase == dateNamesLower {
			result = strings.ToLower(result)
		}
		return result, nil
	case dateIntegerRoman:
		result := romanInteger(big.NewInt(int64(value)))
		if picture.nameCase == dateNamesLower {
			result = strings.ToLower(result)
		}
		return result, nil
	case dateIntegerWords:
		modifier := "w"
		if picture.nameCase == dateNamesUpper {
			modifier = "W"
		} else if picture.nameCase == dateNamesTitle {
			modifier = "Ww"
		}
		return integerWords(big.NewInt(int64(value)), modifier, picture.ordinal), nil
	case dateIntegerSequence:
		return "", dateError("D3130", "unsupported numbering sequence")
	}
	negative := value < 0
	if negative {
		value = -value
	}
	result := strconv.Itoa(value)
	if len(result) < picture.mandatory {
		result = strings.Repeat("0", picture.mandatory-len(result)) + result
	}
	if picture.regular {
		for position := len(result) - picture.regularEvery; position > 0; position -= picture.regularEvery {
			result = result[:position] + string(picture.regularSep) + result[position:]
		}
	} else {
		for _, separator := range picture.separators {
			position := len(result) - separator.fromRight
			if position > 0 && position < len(result) {
				result = result[:position] + string(separator.char) + result[position:]
			}
		}
	}
	if picture.ordinal {
		result += ordinalSuffix(big.NewInt(int64(value)))
	}
	if negative {
		result = "-" + result
	}
	return result, nil
}

func formatDateTimezone(marker *dateMarker, offsetMinutes int) (string, error) {
	sign := "+"
	absolute := offsetMinutes
	if absolute < 0 {
		sign = "-"
		absolute = -absolute
	}
	hours, minutes := absolute/60, absolute%60
	picture := marker.integer
	if picture == nil {
		return "", dateError("D3134", "invalid timezone presentation")
	}
	var value string
	if picture.regular {
		formatted, err := formatDateInteger(hours*100+minutes, picture)
		if err != nil {
			return "", err
		}
		value = formatted
	} else {
		switch picture.mandatory {
		case 1, 2:
			formatted, err := formatDateInteger(hours, picture)
			if err != nil {
				return "", err
			}
			value = formatted
			if minutes != 0 {
				value += ":" + leftPadDateNumber(minutes, 2)
			}
		case 3, 4:
			formatted, err := formatDateInteger(hours*100+minutes, picture)
			if err != nil {
				return "", err
			}
			value = formatted
		default:
			return "", dateError("D3134", "timezone picture must contain one to four digits")
		}
	}
	value = sign + value
	if marker.component == 'z' {
		value = "GMT" + value
	}
	if offsetMinutes == 0 && marker.presentation2 == 't' {
		return "Z", nil
	}
	return value, nil
}

func leftPadDateNumber(value, width int) string {
	result := strconv.Itoa(value)
	if len(result) < width {
		result = strings.Repeat("0", width-len(result)) + result
	}
	return result
}

func parseDateTimezone(text string) (int, bool) {
	if text == "" {
		return 0, false
	}
	sign := 1
	if text[0] == '-' {
		sign = -1
		text = text[1:]
	} else if text[0] == '+' {
		text = text[1:]
	}
	text = strings.ReplaceAll(text, ":", "")
	if len(text) == 0 || len(text) > 4 {
		return 0, false
	}
	number, err := strconv.Atoi(text)
	if err != nil {
		return 0, false
	}
	hours, minutes := number, 0
	if len(text) > 2 {
		hours, minutes = number/100, number%100
	}
	if hours > 23 || minutes > 59 {
		return 0, false
	}
	return sign * (hours*60 + minutes), true
}

func dateFragment(date time.Time, component byte) int {
	switch component {
	case 'Y':
		return date.Year()
	case 'M':
		return int(date.Month())
	case 'D':
		return date.Day()
	case 'd':
		return date.YearDay()
	case 'F':
		weekday := int(date.Weekday())
		if weekday == 0 {
			return 7
		}
		return weekday
	case 'W':
		_, week := date.ISOWeek()
		return week
	case 'w':
		return dateWeekInMonth(date)
	case 'X':
		year, _ := date.ISOWeek()
		return year
	case 'x':
		return dateWeekMonth(date)
	case 'H':
		return date.Hour()
	case 'h':
		hour := date.Hour() % 12
		if hour == 0 {
			return 12
		}
		return hour
	case 'm':
		return date.Minute()
	case 's':
		return date.Second()
	case 'f':
		return date.Nanosecond() / int(time.Millisecond)
	}
	return 0
}

func dateWeekInMonth(date time.Time) int {
	start := startOfFirstDateWeek(date.Year(), date.Month())
	today := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, time.UTC)
	week := int(math.Floor(float64(today.Sub(start))/float64(7*24*time.Hour))) + 1
	if week > 4 {
		nextMonth := time.Date(date.Year(), date.Month()+1, 1, 0, 0, 0, 0, time.UTC)
		next := startOfFirstDateWeek(nextMonth.Year(), nextMonth.Month())
		if !today.Before(next) {
			return 1
		}
	} else if week < 1 {
		previous := time.Date(date.Year(), date.Month()-1, 1, 0, 0, 0, 0, time.UTC)
		startPrevious := startOfFirstDateWeek(previous.Year(), previous.Month())
		week = int(math.Floor(float64(today.Sub(startPrevious))/float64(7*24*time.Hour))) + 1
	}
	return week
}

func dateWeekMonth(date time.Time) int {
	start := startOfFirstDateWeek(date.Year(), date.Month())
	nextDate := time.Date(date.Year(), date.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	end := startOfFirstDateWeek(nextDate.Year(), nextDate.Month())
	today := time.Date(date.Year(), date.Month(), date.Day(), date.Hour(), date.Minute(), date.Second(), date.Nanosecond(), time.UTC)
	if today.Before(start) {
		previous := time.Date(date.Year(), date.Month()-1, 1, 0, 0, 0, 0, time.UTC)
		return int(previous.Month())
	}
	if !today.Before(end) {
		return int(nextDate.Month())
	}
	return int(date.Month())
}

func startOfFirstDateWeek(year int, month time.Month) time.Time {
	first := time.Date(year, month, 1, 0, 0, 0, 0, time.UTC)
	weekday := int(first.Weekday())
	if weekday == 0 {
		weekday = 7
	}
	if weekday > 4 {
		return first.AddDate(0, 0, 8-weekday)
	}
	return first.AddDate(0, 0, -(weekday - 1))
}
