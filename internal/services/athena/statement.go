package athena

import "strings"

// statementClass identifies the AWS control-plane class before publishing the
// queued event. It does not validate SQL, bind parameters or execute expressions;
// the native parser/engine is authoritative for syntax, types and query results.
// CTAS is DML, whereas CREATE TABLE definitions and CREATE VIEW remain DDL.
func statementClass(first string, tokens *statementTokens) string {
	switch {
	case keyword(first, "SELECT"), keyword(first, "WITH"), keyword(first, "VALUES"), keyword(first, "INSERT"), keyword(first, "UPDATE"), keyword(first, "DELETE"), keyword(first, "MERGE"), keyword(first, "UNLOAD"), keyword(first, "EXECUTE"):
		return "DML"
	case keyword(first, "EXPLAIN"), keyword(first, "DESCRIBE"), keyword(first, "DESC"), keyword(first, "SHOW"), keyword(first, "USE"), keyword(first, "PREPARE"), keyword(first, "DEALLOCATE"):
		return "UTILITY"
	case keyword(first, "ALTER"), keyword(first, "DROP"), keyword(first, "MSCK"), keyword(first, "TRUNCATE"), keyword(first, "GRANT"), keyword(first, "REVOKE"):
		return "DDL"
	case !keyword(first, "CREATE"):
		return ""
	}
	kind, _ := tokens.next()
	if keyword(kind, "OR") {
		replace, _ := tokens.next()
		if !keyword(replace, "REPLACE") {
			return "DDL"
		}
		kind, _ = tokens.next()
	}
	if keyword(kind, "EXTERNAL") {
		kind, _ = tokens.next()
	}
	if !keyword(kind, "TABLE") {
		return "DDL"
	}
	for {
		token, depth := tokens.next()
		if token == "" {
			return "DDL"
		}
		if depth == 0 && keyword(token, "AS") {
			return "DML"
		}
	}
}

func keyword(token, want string) bool { return strings.EqualFold(token, want) }

type statementTokens struct {
	sql           string
	offset, depth int
}

// next skips comments and quoted literals/identifiers without allocating. Depth
// keeps column expressions and WITH/TBLPROPERTIES values out of CTAS detection.
func (s *statementTokens) next() (string, int) {
	for s.offset < len(s.sql) {
		c := s.sql[s.offset]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v' {
			s.offset++
			continue
		}
		if c == '-' && s.offset+1 < len(s.sql) && s.sql[s.offset+1] == '-' {
			s.offset += 2
			for s.offset < len(s.sql) && s.sql[s.offset] != '\n' {
				s.offset++
			}
			continue
		}
		if c == '/' && s.offset+1 < len(s.sql) && s.sql[s.offset+1] == '*' {
			s.offset += 2
			nested := 1
			for s.offset < len(s.sql) && nested > 0 {
				if s.offset+1 < len(s.sql) && s.sql[s.offset] == '/' && s.sql[s.offset+1] == '*' {
					nested++
					s.offset += 2
					continue
				}
				if s.offset+1 < len(s.sql) && s.sql[s.offset] == '*' && s.sql[s.offset+1] == '/' {
					nested--
					s.offset += 2
					continue
				}
				s.offset++
			}
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			quote := c
			s.offset++
			for s.offset < len(s.sql) {
				if s.sql[s.offset] != quote {
					s.offset++
					continue
				}
				s.offset++
				if s.offset < len(s.sql) && s.sql[s.offset] == quote {
					s.offset++
					continue
				}
				break
			}
			// A quoted AS identifier is a token, but never the AS keyword.
			return "<quoted>", s.depth
		}
		depth := s.depth
		s.offset++
		if c == '(' {
			s.depth++
			return "(", depth
		}
		if c == ')' {
			if s.depth > 0 {
				s.depth--
			}
			return ")", s.depth
		}
		if c == ';' {
			return "", depth
		}
		start := s.offset - 1
		if statementWordByte(c) {
			for s.offset < len(s.sql) {
				c = s.sql[s.offset]
				if !statementWordByte(c) {
					break
				}
				s.offset++
			}
		}
		return s.sql[start:s.offset], depth
	}
	return "", s.depth
}

func statementWordByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '$' || c == '@' || c == ':' || c >= 0x80
}
