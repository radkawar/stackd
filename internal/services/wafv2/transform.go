package wafv2

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"slices"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/wafv2"
)

// transform applies text transformations in ascending priority, as documented
// at https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-transformation.html.
func transform(in []byte, list api.TextTransformations) []byte {
	ordered := slices.Clone(list)
	slices.SortFunc(ordered, func(a, b api.TextTransformation) int { return int(*a.Priority) - int(*b.Priority) })
	out := in
	for _, t := range ordered {
		out = transformOne(out, *t.Type)
	}
	return out
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

// mapBytes rewrites or drops individual bytes; inputs may be binary.
func mapBytes(in []byte, f func(byte) (byte, bool)) []byte {
	out := make([]byte, 0, len(in))
	for _, c := range in {
		if v, keep := f(c); keep {
			out = append(out, v)
		}
	}
	return out
}

func transformOne(in []byte, kind api.TextTransformationType) []byte {
	switch kind {
	case "LOWERCASE":
		return mapBytes(in, func(c byte) (byte, bool) {
			if c >= 'A' && c <= 'Z' {
				return c + 32, true
			}
			return c, true
		})
	case "UPPERCASE":
		return mapBytes(in, func(c byte) (byte, bool) {
			if c >= 'a' && c <= 'z' {
				return c - 32, true
			}
			return c, true
		})
	case "URL_DECODE":
		return urlDecode(in, false)
	case "URL_DECODE_UNI":
		return urlDecode(in, true)
	case "BASE64_DECODE":
		text := strings.TrimSpace(string(in))
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if out, err := enc.DecodeString(text); err == nil {
				return out
			}
		}
		return in
	case "BASE64_DECODE_EXT":
		clean := bytes.Map(func(r rune) rune {
			if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '+' || r == '/' {
				return r
			}
			if r == '-' {
				return '+'
			}
			if r == '_' {
				return '/'
			}
			return -1
		}, in)
		if len(clean)%4 == 1 {
			clean = clean[:len(clean)-1]
		}
		out, err := base64.RawStdEncoding.DecodeString(string(clean))
		if err != nil {
			return in
		}
		return out
	case "HEX_DECODE":
		out := make([]byte, 0, len(in)/2)
		for i := 0; i+1 < len(in); i += 2 {
			b, err := strconv.ParseUint(string(in[i:i+2]), 16, 8)
			if err != nil {
				return in
			}
			out = append(out, byte(b))
		}
		return out
	case "MD5":
		sum := md5.Sum(in)
		return sum[:]
	case "SHA256":
		sum := sha256.Sum256(in)
		return sum[:]
	case "CMD_LINE":
		return cmdLine(in)
	case "CMD_LINE_UNIX":
		return cmdLineUnix(in)
	case "CMD_LINE_WIN":
		return cmdLineWin(in)
	case "COMPRESS_WHITE_SPACE":
		var out []byte
		space := false
		for _, c := range in {
			if isSpace(c) || c == 0xa0 {
				if !space {
					out = append(out, ' ')
				}
				space = true
				continue
			}
			space = false
			out = append(out, c)
		}
		return out
	case "HTML_ENTITY_DECODE":
		return htmlEntityDecode(in)
	case "NORMALIZE_PATH":
		return normalizePath(in)
	case "NORMALIZE_PATH_WIN":
		return normalizePath(bytes.ReplaceAll(in, []byte{'\\'}, []byte{'/'}))
	case "REMOVE_COMMENTS_CHAR":
		out := in
		for _, token := range []string{"/*", "*/", "--", "#"} {
			out = bytes.ReplaceAll(out, []byte(token), nil)
		}
		return out
	case "REMOVE_NULLS":
		return bytes.ReplaceAll(in, []byte{0}, nil)
	case "REPLACE_NULLS":
		return bytes.ReplaceAll(in, []byte{0}, []byte{' '})
	case "REMOVE_WHITESPACE":
		return mapBytes(in, func(c byte) (byte, bool) { return c, !isSpace(c) })
	case "REPLACE_COMMENTS":
		var out []byte
		for i := 0; i < len(in); {
			if i+1 < len(in) && in[i] == '/' && in[i+1] == '*' {
				end := bytes.Index(in[i+2:], []byte("*/"))
				out = append(out, ' ')
				if end < 0 {
					return out
				}
				i += end + 4
				continue
			}
			out = append(out, in[i])
			i++
		}
		return out
	case "SQL_HEX_DECODE":
		return sqlHexDecode(in)
	case "TRIM":
		return bytes.TrimFunc(in, func(r rune) bool { return r < 0x80 && isSpace(byte(r)) })
	case "TRIM_LEFT":
		return bytes.TrimLeftFunc(in, func(r rune) bool { return r < 0x80 && isSpace(byte(r)) })
	case "TRIM_RIGHT":
		return bytes.TrimRightFunc(in, func(r rune) bool { return r < 0x80 && isSpace(byte(r)) })
	case "ESCAPE_SEQ_DECODE":
		return escapeSeqDecode(in)
	default: // NONE
		return in
	}
}

func hexValue(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func urlDecode(in []byte, unicode bool) []byte {
	out := make([]byte, 0, len(in))
	for i := 0; i < len(in); i++ {
		c := in[i]
		if c == '+' {
			out = append(out, ' ')
			continue
		}
		if c != '%' {
			out = append(out, c)
			continue
		}
		if unicode && i+5 < len(in) && (in[i+1] == 'u' || in[i+1] == 'U') {
			var code uint16
			valid := true
			for _, h := range in[i+2 : i+6] {
				v, ok := hexValue(h)
				valid = valid && ok
				code = code<<4 | uint16(v)
			}
			if valid {
				low := byte(code)
				if code >= 0xff01 && code <= 0xff5e {
					low += 0x20
				}
				out = append(out, low)
				i += 5
				continue
			}
		}
		if i+2 < len(in) {
			hi, ok1 := hexValue(in[i+1])
			lo, ok2 := hexValue(in[i+2])
			if ok1 && ok2 {
				out = append(out, hi<<4|lo)
				i += 2
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

func collapseSpaces(in []byte) []byte {
	var out []byte
	for i, c := range in {
		if c == ' ' && i > 0 && in[i-1] == ' ' {
			continue
		}
		out = append(out, c)
	}
	return out
}

func lowerASCII(in []byte) []byte { return transformOne(in, "LOWERCASE") }

func cmdLine(in []byte) []byte {
	var out []byte
	for _, c := range in {
		switch c {
		case '\\', '"', '\'', '^':
			continue
		case ',', ';':
			c = ' '
		case '/', '(':
			for len(out) > 0 && out[len(out)-1] == ' ' {
				out = out[:len(out)-1]
			}
		}
		out = append(out, c)
	}
	return lowerASCII(collapseSpaces(out))
}

func cmdLineUnix(in []byte) []byte {
	var out []byte
	for _, c := range in {
		switch c {
		case '\\', '"', '\'':
			continue
		case '\t', '\n', '\r', '\v', '\f':
			c = ' '
		}
		out = append(out, c)
	}
	return lowerASCII(bytes.Trim(collapseSpaces(out), " "))
}

func cmdLineWin(in []byte) []byte {
	var out []byte
	for i := 0; i < len(in); i++ {
		c := in[i]
		if c == '^' {
			if i+1 < len(in) && in[i+1] == '\n' {
				i++
				continue
			}
			if i+2 < len(in) && in[i+1] == '\r' && in[i+2] == '\n' {
				i += 2
				continue
			}
			continue
		}
		switch c {
		case '"', '\'', '`':
			continue
		case '\t', '\n', '\r', '\v', '\f':
			c = ' '
		case '\\':
			if len(out) > 0 && out[len(out)-1] == '\\' {
				continue
			}
		}
		out = append(out, c)
	}
	return lowerASCII(bytes.Trim(collapseSpaces(out), " "))
}

var htmlEntities = map[string]string{
	"quot": "\"", "amp": "&", "lt": "<", "gt": ">", "nbsp": "\xa0", "nonbreakingspace": "\xa0", "newline": "\n", "tab": "\t",
	"lcub": "{", "lbrace": "{", "verbar": "|", "vert": "|", "verticalline": "|", "rcub": "}", "rbrace": "}", "excl": "!",
	"num": "#", "dollar": "$", "percent": "%", "percnt": "%", "apos": "'", "lpar": "(", "rpar": ")", "ast": "*", "midast": "*",
	"plus": "+", "comma": ",", "period": ".", "sol": "/", "colon": ":", "semi": ";", "equals": "=", "quest": "?",
	"tilde": "~", "diacriticaltilde": "~", "minus": "-", "lsqb": "[", "lbrack": "[", "bsol": "\\", "rsqb": "]", "rbrack": "]",
	"hat": "^", "lowbar": "_", "underbar": "_", "grave": "`", "diacriticalgrave": "`",
}

func htmlEntityDecode(in []byte) []byte {
	var out []byte
	for i := 0; i < len(in); i++ {
		if in[i] != '&' {
			out = append(out, in[i])
			continue
		}
		end := bytes.IndexByte(in[i:], ';')
		if end < 2 || end > 32 {
			out = append(out, in[i])
			continue
		}
		entity := string(in[i+1 : i+end])
		if strings.HasPrefix(entity, "#") {
			base, digits := 10, entity[1:]
			if strings.HasPrefix(digits, "x") || strings.HasPrefix(digits, "X") {
				base, digits = 16, digits[1:]
			}
			if n, err := strconv.ParseUint(digits, base, 32); err == nil && digits != "" {
				out = append(out, byte(n))
				i += end
				continue
			}
		} else if v, ok := htmlEntities[strings.ToLower(entity)]; ok {
			out = append(out, v...)
			i += end
			continue
		}
		out = append(out, in[i])
	}
	return out
}

// normalizePath removes repeated slashes, self references and back references
// that are not at the beginning of the input.
func normalizePath(in []byte) []byte {
	if len(in) == 0 {
		return in
	}
	absolute := in[0] == '/'
	trailing := in[len(in)-1] == '/'
	var parts []string
	for _, part := range strings.Split(string(in), "/") {
		switch part {
		case "", ".":
		case "..":
			if len(parts) > 0 && parts[len(parts)-1] != ".." {
				parts = parts[:len(parts)-1]
			} else if !absolute {
				parts = append(parts, part)
			}
		default:
			parts = append(parts, part)
		}
	}
	out := strings.Join(parts, "/")
	if absolute {
		out = "/" + out
	}
	if trailing && !strings.HasSuffix(out, "/") {
		out += "/"
	}
	return []byte(out)
}

func sqlHexDecode(in []byte) []byte {
	var out []byte
	for i := 0; i < len(in); i++ {
		if in[i] == '0' && i+3 < len(in) && (in[i+1] == 'x' || in[i+1] == 'X') {
			j := i + 2
			var decoded []byte
			for j+1 < len(in) {
				hi, ok1 := hexValue(in[j])
				lo, ok2 := hexValue(in[j+1])
				if !ok1 || !ok2 {
					break
				}
				decoded = append(decoded, hi<<4|lo)
				j += 2
			}
			if len(decoded) > 0 {
				out = append(out, decoded...)
				i = j - 1
				continue
			}
		}
		out = append(out, in[i])
	}
	return out
}

func escapeSeqDecode(in []byte) []byte {
	simple := map[byte]byte{'a': '\a', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t', 'v': '\v', '\\': '\\', '?': '?', '\'': '\'', '"': '"'}
	var out []byte
	for i := 0; i < len(in); i++ {
		if in[i] != '\\' || i+1 >= len(in) {
			out = append(out, in[i])
			continue
		}
		next := in[i+1]
		if v, ok := simple[next]; ok {
			out = append(out, v)
			i++
			continue
		}
		if (next == 'x' || next == 'X') && i+3 < len(in) {
			hi, ok1 := hexValue(in[i+2])
			lo, ok2 := hexValue(in[i+3])
			if ok1 && ok2 {
				out = append(out, hi<<4|lo)
				i += 3
				continue
			}
		}
		if next == '0' {
			j, n := i+2, 0
			for j < len(in) && j < i+5 && in[j] >= '0' && in[j] <= '7' {
				n = n*8 + int(in[j]-'0')
				j++
			}
			out = append(out, byte(n))
			i = j - 1
			continue
		}
		out = append(out, in[i])
	}
	return out
}
