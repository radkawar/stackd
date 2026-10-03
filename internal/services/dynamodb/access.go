package dynamodb

import (
	"context"
	"encoding/base64"
	"sort"
	"strings"

	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/messageattribute"
)

// dataAccess contains attributes named by the request, not attributes returned
// by the engine. Select and ReturnValues independently describe response access.
type dataAccess struct {
	keys        []api.Key
	attributes  []string
	names       api.ExpressionAttributeNameMap
	expressions []string
	projection  string
	selectMode  string
	returns     string
	enclosing   string
}

func dataMapAttributes[M ~map[api.AttributeName]V, V any](m M) []string {
	out := make([]string, 0, len(m))
	for name := range m {
		out = append(out, string(name))
	}
	return out
}
func dataKeySchema(table *TableRecord, index string) api.KeySchema {
	if index == "" {
		return table.Data.KeySchema
	}
	for _, candidate := range table.Data.GlobalSecondaryIndexes {
		if value(candidate.IndexName) == index {
			return candidate.KeySchema
		}
	}
	for _, candidate := range table.Data.LocalSecondaryIndexes {
		if value(candidate.IndexName) == index {
			return candidate.KeySchema
		}
	}
	return nil
}
func dataPartitionKey(table *TableRecord, index string) string {
	for _, k := range dataKeySchema(table, index) {
		if value(k.KeyType) == "HASH" {
			return value(k.AttributeName)
		}
	}
	return ""
}
func dataScalar(v api.AttributeValue) (string, bool) {
	kinds := 0
	if v.S != nil {
		kinds++
	}
	if v.N != nil {
		kinds++
	}
	if v.B != nil {
		kinds++
	}
	if v.BOOL != nil {
		kinds++
	}
	if v.NULL != nil {
		kinds++
	}
	if v.M != nil {
		kinds++
	}
	if v.L != nil {
		kinds++
	}
	if v.SS != nil {
		kinds++
	}
	if v.NS != nil {
		kinds++
	}
	if v.BS != nil {
		kinds++
	}
	if kinds != 1 {
		return "", false
	}
	if v.S != nil {
		return string(*v.S), true
	}
	if v.N != nil {
		return string(*v.N), true
	}
	if v.B != nil {
		return base64.StdEncoding.EncodeToString(v.B), true
	}
	return "", false
}

func dataCanonicalScalar(value api.AttributeValue) (string, bool) {
	scalar, ok := dataScalar(value)
	if ok && value.N != nil {
		if number, err := messageattribute.ParseNumber(scalar, -130); err == nil {
			scalar = number.String()
		}
	}
	return scalar, ok
}

// DynamoDB expressions have no inline literals. Tokenizing identifiers and
// placeholders suffices to discover top-level paths without executing them.
// Unknown lexical constructs produce unbounded access, leaving validation to
// the native engine rather than guessing an attribute or partition key.
func dataTokens(expression string) ([]string, bool) {
	var out []string
	for i := 0; i < len(expression); {
		c := expression[i]
		if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
			i++
			continue
		}
		start := i
		if dataWord(c) || c == '#' || c == ':' {
			i++
			for i < len(expression) && dataWord(expression[i]) {
				i++
			}
		} else if strings.ContainsRune(".,[]()+-=<>!", rune(c)) {
			i++
		} else {
			return nil, false
		}
		out = append(out, expression[start:i])
	}
	return out, true
}
func dataWord(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}
func dataExpressionAttributes(expression string, names api.ExpressionAttributeNameMap) ([]string, bool) {
	tokens, ok := dataTokens(expression)
	if !ok {
		return nil, false
	}
	var attributes []string
	for i, t := range tokens {
		if t == "" || t[0] == ':' || t[0] >= '0' && t[0] <= '9' || !dataWord(t[0]) && t[0] != '#' {
			continue
		}
		if i > 0 && tokens[i-1] == "." {
			continue
		}
		if i+1 < len(tokens) && tokens[i+1] == "(" {
			continue
		}
		if t[0] == '#' {
			name, ok := names[api.ExpressionAttributeNameVariable(t)]
			if !ok {
				return nil, false
			}
			attributes = append(attributes, string(name))
			continue
		}
		switch strings.ToUpper(t) {
		case "AND", "OR", "NOT", "BETWEEN", "IN", "SET", "REMOVE", "ADD", "DELETE":
			continue
		}
		attributes = append(attributes, t)
	}
	return attributes, true
}
func dataUnique(values []string) []string {
	sort.Strings(values)
	out := values[:0]
	for _, v := range values {
		if len(out) == 0 || out[len(out)-1] != v {
			out = append(out, v)
		}
	}
	return out
}
func (a dataAccess) conditions(table *TableRecord, index string) map[string][]string {
	conditions := map[string][]string{}
	pk := dataPartitionKey(table, index)
	leading := make([]string, 0, len(a.keys))
	bounded := len(a.keys) > 0 && pk != ""
	for _, key := range a.keys {
		v, ok := dataScalar(key[api.AttributeName(pk)])
		if !ok {
			bounded = false
			break
		}
		leading = append(leading, v)
	}
	if bounded {
		conditions["dynamodb:LeadingKeys"] = dataUnique(leading)
	}
	attributes := append([]string{}, a.attributes...)
	bounded = true
	for _, expression := range append(a.expressions, a.projection) {
		refs, ok := dataExpressionAttributes(expression, a.names)
		if !ok {
			bounded = false
		}
		attributes = append(attributes, refs...)
	}
	if bounded && len(attributes) > 0 {
		conditions["dynamodb:Attributes"] = dataUnique(attributes)
	}
	if a.selectMode != "" {
		conditions["dynamodb:Select"] = []string{a.selectMode}
	}
	if a.returns != "" {
		conditions["dynamodb:ReturnValues"] = []string{a.returns}
	}
	if a.enclosing != "" {
		conditions["dynamodb:EnclosingOperation"] = []string{a.enclosing}
	}
	return conditions
}
func dataSelect(mode, projection string, attributes api.AttributeNameList, index string) string {
	if mode != "" {
		return mode
	}
	if projection != "" || len(attributes) > 0 {
		return "SPECIFIC_ATTRIBUTES"
	}
	if index != "" {
		return "ALL_PROJECTED_ATTRIBUTES"
	}
	return "ALL_ATTRIBUTES"
}
func dataAttributeList(names api.AttributeNameList) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = string(n)
	}
	return out
}
func dataReturn(mode string) string {
	if mode == "" {
		return "NONE"
	}
	return mode
}
func (s *Service) dataTable(ctx context.Context, r Reader, selector string) (*TableRecord, error) {
	key, err := parseTableKey(ctx, selector)
	if err != nil {
		return nil, err
	}
	table, err := r.Table(key)
	if err != nil {
		return nil, err
	}
	rememberAuditTable(ctx, &table)
	if status := value(table.Data.TableStatus); status != "ACTIVE" && status != "UPDATING" {
		return nil, ErrNotFound
	}
	return &table, nil
}
func (s *Service) dataAuthorize(ctx context.Context, r Reader, table *TableRecord, action, index string, a dataAccess) error {
	return s.authorizeTable(ctx, r, table.Key, action, index, a.conditions(table, index))
}
func (s *Service) prepareData(ctx context.Context, selector, action, index string, a dataAccess) (*TableRecord, error) {
	var table *TableRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		table, err = s.dataTable(r.Context(), r, selector)
		if err != nil {
			return err
		}
		return s.dataAuthorize(r.Context(), r, table, action, index, a)
	})
	return table, err
}
func dataPhysical(table *TableRecord) *api.TableArn {
	name := api.TableArn(table.PhysicalName)
	return &name
}
func dataCapacity(capacity *api.ConsumedCapacity, table *TableRecord) {
	if capacity != nil && capacity.TableName != nil {
		name := api.TableArn(table.Key.Name)
		capacity.TableName = &name
	}
}

// A plan routes one regional database. Transactions use exactly one plan;
// batches may contain several, all authorized before the first engine call.
type dataPlan struct {
	table      *TableRecord
	additional []*TableRecord
	names      map[string]string
	tables     map[string]*TableRecord
}

// add gives every consumer the representative refreshed under the data gate.
func (p *dataPlan) add(owner **TableRecord, selector string) error {
	table := *owner
	if p.table == nil {
		p.table = table
		p.names = make(map[string]string)
		p.tables = make(map[string]*TableRecord)
	} else if p.table.DatabaseID != table.DatabaseID || p.table.Key.Scope != table.Key.Scope {
		return failure("ValidationException", "All tables in the transaction must belong to the same account and region database.")
	}
	if canonical, known := p.tables[table.PhysicalName]; known {
		*owner = canonical
	} else {
		p.tables[table.PhysicalName] = table
		if table != p.table {
			p.additional = append(p.additional, table)
		}
	}
	p.names[table.PhysicalName] = selector
	return nil
}
func (p *dataPlan) ready() error {
	if p.table == nil {
		return failure("ValidationException", "The request must contain at least one operation.")
	}
	return nil
}
func (p *dataPlan) capacities(capacities api.ConsumedCapacityMultiple) {
	for i := range capacities {
		if table, ok := p.tables[value(capacities[i].TableName)]; ok {
			n := api.TableArn(table.Key.Name)
			capacities[i].TableName = &n
		}
	}
}
func dataRemap[M ~map[api.TableArn]V, V any](m M, p *dataPlan) M {
	if m == nil {
		return nil
	}
	out := make(M, len(m))
	for key, v := range m {
		name, ok := p.names[string(key)]
		if ok {
			key = api.TableArn(name)
		}
		out[key] = v
	}
	return out
}
func dataMergeMaps[M ~map[api.TableArn]V, V any](into M, from M) M {
	if from == nil {
		return into
	}
	if into == nil {
		into = make(M, len(from))
	}
	for k, v := range from {
		into[k] = v
	}
	return into
}

// A valid Query key condition requires a partition-key equality joined only by
// AND. We extract that proven scalar bound; all validation remains native.
func dataQueryKeys(expression string, names api.ExpressionAttributeNameMap, values api.ExpressionAttributeValueMap, pk string) []api.Key {
	tokens, ok := dataTokens(expression)
	if !ok || pk == "" {
		return nil
	}
	for _, t := range tokens {
		if strings.EqualFold(t, "OR") || strings.EqualFold(t, "NOT") {
			return nil
		}
	}
	for i := 0; i+2 < len(tokens); i++ {
		if tokens[i+1] != "=" {
			continue
		}
		name, parameter := tokens[i], tokens[i+2]
		if strings.HasPrefix(name, ":") {
			name, parameter = parameter, name
		}
		if strings.HasPrefix(name, "#") {
			name = string(names[api.ExpressionAttributeNameVariable(name)])
		}
		if name != pk || !strings.HasPrefix(parameter, ":") {
			continue
		}
		if i > 0 && (tokens[i-1] == "." || tokens[i-1] == "<" || tokens[i-1] == ">" || tokens[i-1] == "!") {
			continue
		}
		if i+3 < len(tokens) && (tokens[i+3] == "." || tokens[i+3] == "[") {
			continue
		}
		v, ok := values[api.ExpressionAttributeValueVariable(parameter)]
		if !ok {
			return nil
		}
		return []api.Key{{api.AttributeName(pk): v}}
	}
	return nil
}
