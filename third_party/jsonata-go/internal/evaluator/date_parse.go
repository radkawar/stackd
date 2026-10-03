package evaluator

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var isoDateTimePattern = regexp.MustCompile(`^([0-9]{4})(?:-([01][0-9]))?(?:-([0-3][0-9]))?(?:T([0-2][0-9]):([0-5][0-9]):([0-5][0-9]))?(?:\.([0-9]+))?(?:([+-][0-2][0-9]:?[0-5][0-9]|Z))?$`)

func parseISODateTime(st state, timestamp string) (int64, bool, error) {
	if err := consumeDateBudget(st, len(timestamp)+1); err != nil {
		return 0, false, err
	}
	match := isoDateTimePattern.FindStringSubmatch(timestamp)
	if match == nil {
		return 0, false, nil
	}
	year, _ := strconv.Atoi(match[1])
	month, day := 1, 1
	if match[2] != "" {
		month, _ = strconv.Atoi(match[2])
		if month < 1 || month > 12 {
			return 0, false, nil
		}
	}
	if match[3] != "" {
		day, _ = strconv.Atoi(match[3])
		if day < 1 || day > daysInDateMonth(year, time.Month(month)) {
			return 0, false, nil
		}
	}
	hour, minute, second, millis := 0, 0, 0, 0
	if match[4] != "" {
		hour, _ = strconv.Atoi(match[4])
		minute, _ = strconv.Atoi(match[5])
		second, _ = strconv.Atoi(match[6])
		if hour > 23 {
			return 0, false, nil
		}
	}
	if match[7] != "" {
		millis = parseDateFraction(match[7])
	}
	offset := 0
	if match[8] != "" && match[8] != "Z" {
		var ok bool
		offset, ok = parseDateTimezone(match[8])
		if !ok {
			return 0, false, nil
		}
	}
	parsed := time.Date(year, time.Month(month), day, hour, minute, second, millis*int(time.Millisecond), time.UTC)
	return parsed.Add(-time.Duration(offset) * time.Minute).UnixMilli(), true, nil
}

func parseDateTime(st state, timestamp, picture string) (int64, bool, error) {
	parts, err := analyseDateTimePicture(st, picture)
	if err != nil {
		return 0, false, err
	}
	var expression strings.Builder
	expression.WriteString("(?i)^")
	captures := make([]*dateMarker, 0, len(parts))
	for _, part := range parts {
		if err := dateCheck(st); err != nil {
			return 0, false, err
		}
		if part.marker == nil {
			expression.WriteString(regexp.QuoteMeta(part.literal))
			continue
		}
		pattern, err := dateMarkerPattern(part.marker)
		if err != nil {
			return 0, false, err
		}
		expression.WriteByte('(')
		expression.WriteString(pattern)
		expression.WriteByte(')')
		captures = append(captures, part.marker)
	}
	expression.WriteByte('$')
	if err := consumeDateBudget(st, len(timestamp)+expression.Len()); err != nil {
		return 0, false, err
	}
	matcher, compileErr := regexp.Compile(expression.String())
	if compileErr != nil {
		return 0, false, dateError("D3136", "date/time picture cannot parse the timestamp")
	}
	match := matcher.FindStringSubmatch(timestamp)
	if match == nil {
		return 0, false, nil
	}
	components := make(map[byte]int, len(captures))
	for index, marker := range captures {
		value, err := parseDateMarkerValue(marker, match[index+1])
		if err != nil {
			return 0, false, err
		}
		components[marker.component] = value
	}
	if len(components) == 0 {
		return 0, false, nil
	}
	return buildParsedDateTime(st, components)
}

func dateMarkerPattern(marker *dateMarker) (string, error) {
	if marker.component == 'Z' || marker.component == 'z' {
		prefix := ""
		if marker.component == 'z' {
			prefix = "GMT"
		}
		if marker.integer != nil && marker.integer.regular {
			return prefix + `[-+][0-9]+` + regexp.QuoteMeta(string(marker.integer.regularSep)) + `[0-9]+`, nil
		}
		return prefix + `[-+][0-9]+`, nil
	}
	if marker.component == 'f' {
		return `[0-9]+`, nil
	}
	if marker.names != dateNamesNone {
		switch marker.component {
		case 'M', 'x', 'F', 'P':
			return `[a-z]+`, nil
		default:
			return "", dateError("D3133", "component does not support names")
		}
	}
	if marker.integer == nil {
		return "", dateError("D3136", "date/time marker cannot be parsed")
	}
	switch marker.integer.kind {
	case dateIntegerLetters:
		return `[a-z]+`, nil
	case dateIntegerRoman:
		return `[mdclxvi]+`, nil
	case dateIntegerWords:
		return dateWordsRegex, nil
	case dateIntegerDecimal:
		pattern := `[0-9]`
		if marker.integer.parseWidth > 0 {
			pattern += `{` + strconv.Itoa(marker.integer.parseWidth) + `}`
		} else {
			pattern += `+`
		}
		if marker.integer.ordinal {
			pattern += `(?:th|st|nd|rd)`
		}
		return pattern, nil
	default:
		return "", dateError("D3130", "unsupported numbering sequence")
	}
}

func parseDateMarkerValue(marker *dateMarker, text string) (int, error) {
	if marker.component == 'Z' || marker.component == 'z' {
		if marker.component == 'z' {
			text = strings.TrimPrefix(strings.ToUpper(text), "GMT")
		}
		value, ok := parseDateTimezone(text)
		if !ok {
			return 0, dateError("D3136", "invalid timezone")
		}
		return value, nil
	}
	if marker.component == 'f' {
		return parseDateFraction(text), nil
	}
	if marker.names != dateNamesNone {
		switch marker.component {
		case 'M', 'x':
			for index, name := range dateMonthNames {
				if marker.widthMax > 0 && len(name) > marker.widthMax {
					name = name[:marker.widthMax]
				}
				if strings.EqualFold(name, text) {
					return index + 1, nil
				}
			}
		case 'F':
			for index := 1; index < len(dateDayNames); index++ {
				name := dateDayNames[index]
				if marker.widthMax > 0 && len(name) > marker.widthMax {
					name = name[:marker.widthMax]
				}
				if strings.EqualFold(name, text) {
					return index, nil
				}
			}
		case 'P':
			if strings.EqualFold(text, "pm") {
				return 1, nil
			}
			if strings.EqualFold(text, "am") {
				return 0, nil
			}
		}
		return 0, dateError("D3136", "date/time name is invalid")
	}
	if marker.integer == nil {
		return 0, dateError("D3136", "date/time marker cannot be parsed")
	}
	switch marker.integer.kind {
	case dateIntegerLetters:
		return dateLettersToDecimal(text), nil
	case dateIntegerRoman:
		return dateRomanToDecimal(strings.ToUpper(text)), nil
	case dateIntegerWords:
		value, ok := dateWordsToNumber(strings.ToLower(text))
		if !ok {
			return 0, dateError("D3136", "date/time word is invalid")
		}
		return value, nil
	case dateIntegerDecimal:
		if marker.integer.ordinal {
			if len(text) < 2 {
				return 0, dateError("D3136", "ordinal date/time value is invalid")
			}
			text = text[:len(text)-2]
		}
		var digits strings.Builder
		for _, char := range text {
			if char >= '0' && char <= '9' {
				digits.WriteRune(char)
			}
		}
		value, err := strconv.Atoi(digits.String())
		if err != nil {
			return 0, dateError("D3136", "numeric date/time value is invalid")
		}
		return value, nil
	default:
		return 0, dateError("D3130", "unsupported numbering sequence")
	}
}

func buildParsedDateTime(st state, components map[byte]int) (int64, bool, error) {
	dateA := dateComponentsFit(components, "YMD", "YXMxWwdD")
	dateB := !dateA && dateComponentsFit(components, "Yd", "YXMxWwdD")
	dateC := dateComponentsFit(components, "Xxw", "YXMxWwdD")
	dateD := !dateC && dateComponentsFit(components, "XW", "YXMxWwdD")
	timeA := dateComponentsFit(components, "Hmsf", "PHhmsf")
	timeB := !timeA && dateComponentsFit(components, "Phmsf", "PHhmsf")

	dateOrder := "YMD"
	if dateB {
		dateOrder = "YD"
	} else if dateC {
		dateOrder = "XxwF"
	} else if dateD {
		dateOrder = "XWF"
	}
	timeOrder := "Hmsf"
	if timeB {
		timeOrder = "Phmsf"
	}
	order := dateOrder + timeOrder
	now := dateEvaluationTime(st)
	started, ended := false, false
	for index := 0; index < len(order); index++ {
		component := order[index]
		if _, exists := components[component]; exists {
			started = true
			if ended {
				return 0, false, dateError("D3136", "date/time picture is missing required specifiers")
			}
			continue
		}
		if started {
			if strings.ContainsRune("MDd", rune(component)) {
				components[component] = 1
			} else {
				components[component] = 0
			}
			ended = true
		} else {
			components[component] = dateFragment(now, component)
		}
	}
	if dateC || dateD {
		return 0, false, dateError("D3136", "ISO week date parsing is unsupported")
	}
	year, month, day := components['Y'], components['M'], components['D']
	if month > 0 {
		// time.Month is one-indexed, so no conversion is required here.
	} else {
		month = 1
	}
	if dateB {
		derived := time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, components['d']-1)
		month, day = int(derived.Month()), derived.Day()
	}
	hour := components['H']
	if timeB {
		hour = components['h']
		if hour == 12 {
			hour = 0
		}
		if components['P'] == 1 {
			hour += 12
		}
	}
	parsed := time.Date(year, time.Month(month), day, hour, components['m'], components['s'], components['f']*int(time.Millisecond), time.UTC)
	offset := components['Z']
	if value, exists := components['z']; exists {
		offset = value
	}
	return parsed.Add(-time.Duration(offset) * time.Minute).UnixMilli(), true, nil
}

func dateComponentsFit(components map[byte]int, allowed, family string) bool {
	found := false
	for component := range components {
		if strings.ContainsRune(family, rune(component)) {
			if !strings.ContainsRune(allowed, rune(component)) {
				return false
			}
			found = true
		}
	}
	return found
}

func consumeDateBudget(st state, units int) error {
	for index := 0; index < units; index++ {
		if err := dateCheck(st); err != nil {
			return err
		}
	}
	return nil
}

func parseDateFraction(text string) int {
	if len(text) > 3 {
		text = text[:3]
	}
	for len(text) < 3 {
		text += "0"
	}
	value, _ := strconv.Atoi(text)
	return value
}

func daysInDateMonth(year int, month time.Month) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

func dateLettersToDecimal(text string) int {
	value := 0
	for _, char := range strings.ToUpper(text) {
		value = value*26 + int(char-'A'+1)
	}
	return value
}

func dateRomanToDecimal(text string) int {
	values := map[byte]int{'M': 1000, 'D': 500, 'C': 100, 'L': 50, 'X': 10, 'V': 5, 'I': 1}
	result, maximum := 0, 1
	for index := len(text) - 1; index >= 0; index-- {
		value := values[text[index]]
		if value < maximum {
			result -= value
		} else {
			maximum = value
			result += value
		}
	}
	return result
}

var dateWordValues = func() map[string]int {
	values := make(map[string]int)
	cardinals := []string{"zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen"}
	ordinals := []string{"zeroth", "first", "second", "third", "fourth", "fifth", "sixth", "seventh", "eighth", "ninth", "tenth", "eleventh", "twelfth", "thirteenth", "fourteenth", "fifteenth", "sixteenth", "seventeenth", "eighteenth", "nineteenth"}
	for index, word := range cardinals {
		values[word] = index
		values[ordinals[index]] = index
	}
	tens := []string{"twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"}
	for index, word := range tens {
		value := (index + 2) * 10
		values[word] = value
		values[strings.TrimSuffix(word, "y")+"ieth"] = value
	}
	values["hundred"], values["hundredth"] = 100, 100
	for word, value := range map[string]int{"thousand": 1000, "million": 1000000, "billion": 1000000000} {
		values[word] = value
		values[word+"th"] = value
	}
	return values
}()

var dateWordsRegex = func() string {
	words := make([]string, 0, len(dateWordValues)+1)
	for word := range dateWordValues {
		words = append(words, regexp.QuoteMeta(word))
	}
	words = append(words, "and")
	sort.Slice(words, func(left, right int) bool {
		return len(words[left]) > len(words[right])
	})
	return `(?:` + strings.Join(words, "|") + `|[ ,\-])+`
}()

func dateWordsToNumber(text string) (int, bool) {
	replacer := strings.NewReplacer(", ", " ", ",", " ", " and ", " ", "-", " ")
	parts := strings.Fields(replacer.Replace(text))
	segments := []int{0}
	for _, part := range parts {
		value, ok := dateWordValues[part]
		if !ok {
			return 0, false
		}
		if value < 100 {
			top := segments[len(segments)-1]
			segments = segments[:len(segments)-1]
			if top >= 1000 {
				segments = append(segments, top)
				top = 0
			}
			segments = append(segments, top+value)
		} else {
			segments[len(segments)-1] *= value
		}
	}
	result := 0
	for _, segment := range segments {
		result += segment
	}
	return result, true
}
