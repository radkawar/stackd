package firehose

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Patterns follow Java DateTimeFormatter's English text and Sunday-first week
// fields, as observed in Firehose. Unsupported fields fail rather than leaking
// pattern letters into delivered object keys.
func formatS3Timestamp(pattern string, instant time.Time) (string, error) {
	if pattern == "" {
		return "", fmt.Errorf("empty Firehose timestamp expression")
	}
	var out strings.Builder
	depth, pad := 0, 0
	for i := 0; i < len(pattern); {
		c := pattern[i]
		if c == '[' {
			if pad != 0 {
				return "", fmt.Errorf("padding requires a timestamp field")
			}
			depth++
			i++
			continue
		}
		if c == ']' {
			if depth == 0 {
				return "", fmt.Errorf("unmatched timestamp optional section")
			}
			depth--
			i++
			continue
		}
		var text string
		if c == '\'' {
			i++
			var literal strings.Builder
			closed := false
			if i < len(pattern) && pattern[i] == '\'' {
				literal.WriteByte('\'')
				i++
				closed = true
			} else {
				for i < len(pattern) {
					if pattern[i] != '\'' {
						literal.WriteByte(pattern[i])
						i++
						continue
					}
					i++
					if i < len(pattern) && pattern[i] == '\'' {
						literal.WriteByte('\'')
						i++
						continue
					}
					closed = true
					break
				}
			}
			if !closed {
				return "", fmt.Errorf("unclosed quoted literal in Firehose timestamp prefix")
			}
			text = literal.String()
		} else if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' {
			end := i + 1
			for end < len(pattern) && pattern[end] == c {
				end++
			}
			width := end - i
			i = end
			if c == 'p' {
				if i == len(pattern) || !(pattern[i] >= 'A' && pattern[i] <= 'Z' || pattern[i] >= 'a' && pattern[i] <= 'z') {
					return "", fmt.Errorf("padding requires a timestamp field")
				}
				pad = width
				continue
			}
			var err error
			text, err = s3TimestampField(c, width, instant)
			if err != nil {
				return "", err
			}
		} else {
			if c == '{' || c == '}' || c == '#' {
				return "", fmt.Errorf("reserved Firehose timestamp character %c", c)
			}
			text = string(c)
			i++
		}
		if pad != 0 {
			if len(text) > pad {
				return "", fmt.Errorf("timestamp field exceeds padding width")
			}
			out.WriteString(strings.Repeat(" ", pad-len(text)))
			pad = 0
		}
		out.WriteString(text)
	}
	// Java automatically closes optional sections at the end of a pattern.
	return out.String(), nil
}

func s3TimestampField(c byte, width int, t time.Time) (string, error) {
	invalid := func() (string, error) {
		return "", fmt.Errorf("invalid or unsupported Firehose timestamp token: %s", strings.Repeat(string(c), width))
	}
	number := func(v, maxWidth int) (string, error) {
		if width > maxWidth {
			return invalid()
		}
		return fmt.Sprintf("%0*d", width, v), nil
	}
	text := func(short, full, narrow string) (string, error) {
		switch {
		case width < 4:
			return short, nil
		case width == 4:
			return full, nil
		case width == 5:
			return narrow, nil
		default:
			return invalid()
		}
	}
	switch c {
	case 'y', 'u', 'Y':
		year := t.Year()
		if c == 'Y' {
			year, _ = s3Week(t)
		}
		if c == 'y' && year <= 0 {
			year = 1 - year
		}
		if width == 2 {
			return fmt.Sprintf("%02d", year%100), nil
		}
		if width > 19 {
			return invalid()
		}
		result := fmt.Sprintf("%0*d", width, year)
		if width >= 4 && year > 0 && len(result) > width {
			result = "+" + result
		}
		return result, nil
	case 'M', 'L':
		if width < 3 {
			return number(int(t.Month()), 2)
		}
		month := t.Month().String()
		return text(month[:3], month, month[:1])
	case 'E', 'e', 'c':
		if c != 'E' && width < 3 {
			if c == 'c' && width == 2 {
				return invalid()
			}
			return number(int(t.Weekday())+1, 2)
		}
		day := t.Weekday().String()
		return text(day[:3], day, day[:1])
	case 'Q', 'q':
		quarter := (int(t.Month())-1)/3 + 1
		if width < 3 {
			return number(quarter, 2)
		}
		return text("Q"+strconv.Itoa(quarter), []string{"1st quarter", "2nd quarter", "3rd quarter", "4th quarter"}[quarter-1], strconv.Itoa(quarter))
	case 'G':
		if t.Year() <= 0 {
			return text("BC", "Before Christ", "B")
		}
		return text("AD", "Anno Domini", "A")
	case 'd':
		return number(t.Day(), 2)
	case 'D':
		return number(t.YearDay(), 3)
	case 'w':
		_, week := s3Week(t)
		return number(week, 2)
	case 'W':
		first := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, t.Location())
		return number((t.Day()-1+int(first.Weekday()))/7+1, 1)
	case 'F':
		return number((t.Day()-1)%7+1, 1)
	case 'H':
		return number(t.Hour(), 2)
	case 'h':
		return number((t.Hour()+11)%12+1, 2)
	case 'K':
		return number(t.Hour()%12, 2)
	case 'k':
		return number((t.Hour()+23)%24+1, 2)
	case 'm':
		return number(t.Minute(), 2)
	case 's':
		return number(t.Second(), 2)
	case 'a':
		if width != 1 {
			return invalid()
		}
		if t.Hour() < 12 {
			return "AM", nil
		}
		return "PM", nil
	case 'S':
		if width > 9 {
			return invalid()
		}
		return fmt.Sprintf("%09d", t.Nanosecond())[:width], nil
	case 'n':
		return number(t.Nanosecond(), 19)
	case 'A':
		return number(((t.Hour()*60+t.Minute())*60+t.Second())*1000+t.Nanosecond()/1000000, 19)
	case 'N':
		return number(((t.Hour()*60+t.Minute())*60+t.Second())*1000000000+t.Nanosecond(), 19)
	case 'V':
		if width != 2 {
			return invalid()
		}
		return t.Location().String(), nil
	case 'z':
		if width > 4 {
			return invalid()
		}
		zone, _ := t.Zone()
		if width < 4 {
			return zone, nil
		}
		// Go's tzdata has abbreviations, not Java's localized long names.
		// TODO: Comeback — supply CLDR zone names for long-name patterns outside UTC.
		if t.Location() == time.UTC {
			return "Coordinated Universal Time", nil
		}
		return "", fmt.Errorf("long Firehose timestamp zone names outside UTC are not implemented")
	case 'X', 'x', 'Z', 'O':
		if width > 5 || c == 'O' && width != 1 && width != 4 {
			return invalid()
		}
		_, offset := t.Zone()
		if offset == 0 && (c == 'X' || c == 'Z' && width == 5) {
			return "Z", nil
		}
		localized := c == 'O' || c == 'Z' && width == 4
		if localized && offset == 0 {
			return "GMT", nil
		}
		sign := "+"
		if offset < 0 {
			sign = "-"
			offset = -offset
		}
		h, m, s := offset/3600, offset/60%60, offset%60
		if localized {
			if width == 1 {
				result := "GMT" + sign + strconv.Itoa(h)
				if m != 0 || s != 0 {
					result += fmt.Sprintf(":%02d", m)
				}
				if s != 0 {
					result += fmt.Sprintf(":%02d", s)
				}
				return result, nil
			}
			result := fmt.Sprintf("GMT%s%02d:%02d", sign, h, m)
			if s != 0 {
				result += fmt.Sprintf(":%02d", s)
			}
			return result, nil
		}
		if c == 'Z' && width < 4 {
			return fmt.Sprintf("%s%02d%02d", sign, h, m), nil
		}
		if width == 1 && m == 0 {
			return fmt.Sprintf("%s%02d", sign, h), nil
		}
		separator := ""
		if width == 3 || width == 5 {
			separator = ":"
		}
		result := fmt.Sprintf("%s%02d%s%02d", sign, h, separator, m)
		if width >= 4 && s != 0 {
			result += separator + fmt.Sprintf("%02d", s)
		}
		return result, nil
	default:
		return invalid()
	}
}

// Native English week fields start on Sunday; the week containing January 1 is
// week one. Calendar arithmetic avoids DST-length assumptions at year boundaries.
func s3Week(t time.Time) (int, int) {
	year := t.Year()
	first := time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
	next := time.Date(year+1, 1, 1, 0, 0, 0, 0, time.UTC)
	day := time.Date(year, t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	if !day.Before(next.AddDate(0, 0, -int(next.Weekday()))) {
		return year + 1, 1
	}
	return year, (t.YearDay()-1+int(first.Weekday()))/7 + 1
}
