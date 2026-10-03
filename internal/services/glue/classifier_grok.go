package glue

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	api "stackd/internal/awsapi/glue"
)

var crawlerGrokReference = regexp.MustCompile(`%\{([A-Za-z0-9_]+)(?::([A-Za-z0-9_]+))?(?::([A-Za-z0-9_]+))?\}`)

// The native recognizer uses regexp2 rather than rewriting Java-style lookbehind
// into RE2. Unknown built-ins fail explicitly instead of inventing a schema.
// TODO: Comeback complete Glue's remaining built-in Grok vocabulary and SerDe interoperability.
var crawlerGrokPatterns = map[string]string{
	"USERNAME": `[a-zA-Z0-9._-]+`, "USER": `%{USERNAME}`, "INT": `[+-]?[0-9]+`,
	"BASE10NUM": `(?<![0-9.+-])(?>[+-]?(?:(?:[0-9]+(?:\.[0-9]+)?)|(?:\.[0-9]+)))`, "NUMBER": `%{BASE10NUM}`,
	"BOOLEAN": `(?i:true|false)`, "POSINT": `\b[1-9][0-9]*\b`, "NONNEGINT": `\b[0-9]+\b`,
	"WORD": `\b\w+\b`, "NOTSPACE": `\S+`, "SPACE": `\s*`, "DATA": `.*?`, "GREEDYDATA": `.*`,
	"QUOTEDSTRING": `(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')`, "QS": `%{QUOTEDSTRING}`,
	"UUID":     `[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}`,
	"IPV4":     `(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})(?![0-9])`,
	"HOSTNAME": `\b(?:[0-9A-Za-z][0-9A-Za-z_-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z_-]{0,62}))*\.?\b`,
	"IPORHOST": `(?:%{IPV4}|%{HOSTNAME})`, "HOST": `%{HOSTNAME}`,
	"YEAR": `[0-9]{4}`, "MONTHNUM": `(?:0?[1-9]|1[0-2])`, "MONTHDAY": `(?:0?[1-9]|[12][0-9]|3[01])`,
	"HOUR": `(?:2[0-3]|[01]?[0-9])`, "MINUTE": `[0-5][0-9]`, "SECOND": `(?:[0-5]?[0-9]|60)(?:[.,][0-9]+)?`,
	"TIME": `%{HOUR}:%{MINUTE}:%{SECOND}`, "ISO8601_TIMEZONE": `(?:Z|[+-]%{HOUR}(?::?%{MINUTE})?)`,
	"TIMESTAMP_ISO8601": `%{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND})?%{ISO8601_TIMEZONE}?`,
	"LOGLEVEL":          `(?i:trace|debug|info|warn|warning|error|critical|fatal|severe|emergency)`,
}

func classifyGrok(data []byte, c *api.GrokClassifier) (crawlerSchema, bool, error) {
	patterns := make(map[string]string, len(crawlerGrokPatterns))
	for name, pattern := range crawlerGrokPatterns {
		patterns[name] = pattern
	}
	scanner := bufio.NewScanner(strings.NewReader(value(c.CustomPatterns)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, pattern, ok := strings.Cut(line, " ")
		if !ok {
			return crawlerSchema{}, false, failure("InvalidInputException", "Invalid custom Grok pattern definition.")
		}
		patterns[name] = strings.TrimSpace(pattern)
	}
	columns := api.ColumnList{}
	seen := map[string]bool{}
	var expand func(string, int) (string, error)
	expand = func(pattern string, depth int) (string, error) {
		if depth > 32 {
			return "", failure("InvalidInputException", "Cyclic or too deeply nested Grok patterns.")
		}
		var result strings.Builder
		position := 0
		for _, indices := range crawlerGrokReference.FindAllStringSubmatchIndex(pattern, -1) {
			result.WriteString(pattern[position:indices[0]])
			name := pattern[indices[2]:indices[3]]
			body, ok := patterns[name]
			if !ok {
				return "", unsupported("Grok built-in pattern is not supported: " + name)
			}
			expanded, err := expand(body, depth+1)
			if err != nil {
				return "", err
			}
			field := ""
			if indices[4] >= 0 {
				field = pattern[indices[4]:indices[5]]
			}
			kind := "string"
			if indices[6] >= 0 {
				kind = pattern[indices[6]:indices[7]]
				switch kind {
				case "byte":
					kind = "tinyint"
				case "short":
					kind = "smallint"
				case "long":
					kind = "bigint"
				case "int", "float", "double", "boolean", "string":
				default:
					return "", failure("InvalidInputException", "Unsupported Grok field datatype.")
				}
			}
			if field != "" && field != "UNWANTED" {
				if seen[field] {
					return "", failure("InvalidInputException", "Duplicate Grok field name.")
				}
				seen[field] = true
				columns = append(columns, api.Column{Name: new(api.NameString(strings.ToLower(field))), Type: new(api.ColumnTypeString(kind))})
			}
			fmt.Fprintf(&result, "(?:%s)", expanded)
			position = indices[1]
		}
		result.WriteString(pattern[position:])
		return result.String(), nil
	}
	pattern, err := expand(value(c.GrokPattern), 0)
	if err != nil {
		return crawlerSchema{}, false, err
	}
	compiled, err := regexp2.Compile("^(?:"+pattern+")$", 0)
	if err != nil {
		return crawlerSchema{}, false, failure("InvalidInputException", "Invalid Grok regular expression.")
	}
	compiled.MatchTimeout = 100 * time.Millisecond
	lines := bufio.NewScanner(bytes.NewReader(data))
	lines.Buffer(make([]byte, 4096), 4<<20)
	matched := false
	for lines.Scan() {
		if len(bytes.TrimSpace(lines.Bytes())) == 0 {
			continue
		}
		ok, err := compiled.MatchString(lines.Text())
		if err != nil {
			return crawlerSchema{}, false, failure("InvalidInputException", "Grok classifier match limit exceeded.")
		}
		if !ok {
			return crawlerSchema{}, false, nil
		}
		matched = true
	}
	if lines.Err() != nil {
		return crawlerSchema{}, false, failure("InvalidInputException", "Grok input line exceeds supported bound.")
	}
	if !matched || len(columns) == 0 {
		return crawlerSchema{}, false, nil
	}
	schema := textCrawlerSchema(columns, value(c.Classification), "com.amazonaws.glue.serde.GrokSerDe")
	schema.SerdeParameters["input.format"] = api.ParametersMapValue(value(c.GrokPattern))
	return schema, true, nil
}
