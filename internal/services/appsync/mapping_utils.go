package appsync

// Helpers run inside the same interruptible VM as customer code. Unknown helpers
// fail explicitly instead of returning placeholders. The supported expression
// forms follow https://docs.aws.amazon.com/appsync/latest/devguide/built-in-modules-js.html.
// TODO: Comeback: remaining util families, DynamoDB sync/transaction helpers and
// the RDS SQL-builder module need their actual native contracts before admission.
const mappingUtilities = `
var __utils, __dynamodb, util, runtime, extensions;
(function() {
  function fail(message, type, data) { return __fail(String(message), type || 'MappingTemplate', data === undefined ? null : data); }
  function unsupported(name) { return fail('Unsupported AppSync utility: ' + name, 'UnsupportedOperation'); }
  function boundary(name, members) {
    return new Proxy(members, {get: function(target, key) {
      if (key === '__esModule') return false;
      if (typeof key === 'symbol' || key in target) return target[key];
      return unsupported(name + '.' + key);
    }});
  }
  function object(v) { if (!v || typeof v !== 'object' || Array.isArray(v)) fail('Expected an object'); return v; }
  function typed(v) {
    if (v === null) return {NULL: true};
    if (typeof v === 'string') return {S: v};
    if (typeof v === 'boolean') return {BOOL: v};
    if (typeof v === 'number') { if (!Number.isFinite(v)) fail('DynamoDB numbers must be finite'); return {N: String(v)}; }
    if (Array.isArray(v)) return {L: v.map(typed)};
    if (typeof v === 'object') return {M: mapValues(v)};
    return fail('Cannot convert value to DynamoDB');
  }
  function mapValues(v) { const out = {}; Object.keys(object(v)).forEach(k => { out[k] = typed(v[k]); }); return out; }
  function setValue(type, values) {
    if (!Array.isArray(values) || values.length === 0) fail('DynamoDB sets require a nonempty array');
    const out = {}; out[type] = [...new Set(values.map(v => type === 'NS' ? String(v) : v))]; return out;
  }
  const dynamodb = boundary('util.dynamodb', {
    toDynamoDB: typed, toDynamoDBJson: v => JSON.stringify(typed(v)),
    toMapValues: mapValues, toMapValuesJson: v => JSON.stringify(mapValues(v)),
    toMap: v => ({M: mapValues(v)}), toMapJson: v => JSON.stringify({M: mapValues(v)}),
    toList: v => ({L: v.map(typed)}), toListJson: v => JSON.stringify({L: v.map(typed)}),
    toString: v => ({S: String(v)}), toStringJson: v => JSON.stringify({S: String(v)}),
    toNumber: v => typed(Number(v)), toNumberJson: v => JSON.stringify(typed(Number(v))),
    toBoolean: v => ({BOOL: Boolean(v)}), toBooleanJson: v => JSON.stringify({BOOL: Boolean(v)}),
    toNull: () => ({NULL: true}), toNullJson: () => '{"NULL":true}',
    toBinary: v => ({B: v}), toBinaryJson: v => JSON.stringify({B: v}),
    toStringSet: v => setValue('SS', v), toStringSetJson: v => JSON.stringify(setValue('SS', v)),
    toNumberSet: v => setValue('NS', v), toNumberSetJson: v => JSON.stringify(setValue('NS', v)),
    toBinarySet: v => setValue('BS', v), toBinarySetJson: v => JSON.stringify(setValue('BS', v))
  });
  function expression(input, prefix) {
    const names = {}, values = {}; let ni = 0, vi = 0;
    function name(key) { const n = '#' + prefix + ni++; names[n] = key; return n; }
    function value(v) { const n = ':' + prefix + vi++; values[n] = typed(v); return n; }
    function walk(node) {
      const parts = [];
      Object.keys(object(node)).forEach(key => {
        const v = node[key];
        if (key === 'and' || key === 'or') {
          if (!Array.isArray(v) || !v.length) fail('Logical conditions require a nonempty array');
          parts.push('(' + v.map(walk).join(key === 'and' ? ' AND ' : ' OR ') + ')'); return;
        }
        if (key === 'not') { parts.push('(NOT ' + walk(v) + ')'); return; }
        const n = name(key);
        Object.keys(object(v)).forEach(op => {
          const arg = v[op], operators = {eq: '=', ne: '<>', lt: '<', le: '<=', gt: '>', ge: '>='};
          if (operators[op]) parts.push(n + ' ' + operators[op] + ' ' + value(arg));
          else if (op === 'attributeExists') parts.push((arg ? 'attribute_exists(' : 'attribute_not_exists(') + n + ')');
          else if (op === 'beginsWith' || op === 'contains' || op === 'notContains') parts.push((op === 'notContains' ? 'NOT ' : '') + (op === 'beginsWith' ? 'begins_with' : 'contains') + '(' + n + ', ' + value(arg) + ')');
          else if (op === 'between') { if (!Array.isArray(arg) || arg.length !== 2) fail('between requires two values'); parts.push(n + ' BETWEEN ' + value(arg[0]) + ' AND ' + value(arg[1])); }
          else if (op === 'in') { if (!Array.isArray(arg) || !arg.length) fail('in requires values'); parts.push(n + ' IN (' + arg.map(value).join(', ') + ')'); }
          else if (op === 'attributeType') parts.push('attribute_type(' + n + ', ' + value(arg) + ')');
          else unsupported('DynamoDB condition.' + op);
        });
      });
      if (!parts.length) fail('Empty DynamoDB condition');
      return '(' + parts.join(' AND ') + ')';
    }
    const result = {expression: walk(input)};
    if (Object.keys(names).length) result.expressionNames = names;
    if (Object.keys(values).length) result.expressionValues = values;
    return result;
  }
  const marker = Symbol('DynamoDB update operation');
  function operation(kind, value) { const v = {value: value}; v[marker] = kind; return v; }
  const operations = boundary('dynamodb.operations', {
    replace: v => operation('replace', v), remove: () => operation('remove'),
    increment: (v = 1) => operation('increment', v), decrement: (v = 1) => operation('decrement', v),
    append: v => operation('append', v), prepend: v => operation('prepend', v)
  });
  function updateExpression(input) {
    const names = {}, values = {}, sets = [], removes = []; let ni = 0, vi = 0;
    function name(k) { const n = '#u' + ni++; names[n] = k; return n; }
    function value(v) { const n = ':u' + vi++; values[n] = typed(v); return n; }
    function walk(node, path) {
      Object.keys(object(node)).forEach(k => {
        const p = path ? path + '.' + name(k) : name(k), v = node[k];
        const kind = v && v[marker];
        if (kind === 'remove' || v === null) { removes.push(p); return; }
        if (kind === 'increment' || kind === 'decrement') { sets.push(p + ' = ' + p + (kind === 'increment' ? ' + ' : ' - ') + value(v.value)); return; }
        if (kind === 'append' || kind === 'prepend') { const a = value(v.value); sets.push(p + ' = list_append(' + (kind === 'append' ? p + ', ' + a : a + ', ' + p) + ')'); return; }
        if (kind === 'replace') { sets.push(p + ' = ' + value(v.value)); return; }
        if (v && typeof v === 'object' && !Array.isArray(v)) { walk(v, p); return; }
        sets.push(p + ' = ' + value(v));
      });
    }
    walk(input, '');
    const parts = []; if (sets.length) parts.push('SET ' + sets.join(', ')); if (removes.length) parts.push('REMOVE ' + removes.join(', '));
    if (!parts.length) fail('Empty DynamoDB update');
    const result = {expression: parts.join(' '), expressionNames: names};
    if (Object.keys(values).length) result.expressionValues = values;
    return result;
  }
  function request(op, input) {
    input = object(input); const out = {operation: op};
    Object.keys(input).forEach(k => {
      if (k === '_version' || k === 'customPartitionKey' || k === 'populateIndexFields') unsupported('dynamodb.' + k);
      if (k === 'key') out.key = mapValues(input.key);
      else if (k === 'item') out.attributeValues = mapValues(input.item);
      else if (k === 'condition') { if (input[k] != null) out.condition = expression(input[k], 'c'); }
      else if (k === 'filter') { if (input[k] != null) out.filter = expression(input[k], 'f'); }
      else if (k === 'query') out.query = expression(input[k], 'q');
      else if (k === 'update') out.update = updateExpression(input[k]);
      else out[k] = input[k];
    });
    return out;
  }
  __dynamodb = boundary('dynamodb', {
    get: v => request('GetItem', v), put: v => request('PutItem', v), remove: v => request('DeleteItem', v),
    update: v => request('UpdateItem', v), query: v => request('Query', v), scan: v => request('Scan', v), operations: operations
  });
  util = boundary('util', {
    error: (message, type, data) => fail(message, type || 'CustomTemplateException', data),
    appendError: (message, type, data) => { __appendError(String(message), type || 'CustomTemplateException', data === undefined ? null : data); },
    unauthorized: () => fail('Unauthorized', 'Unauthorized'),
    validate: (condition, message, type, data) => { if (!condition) fail(message, type || 'CustomTemplateException', data); },
    autoId: __uuid, base64Encode: __base64Encode, base64Decode: __base64Decode, urlEncode: __urlEncode, urlDecode: __urlDecode,
    toJson: JSON.stringify, parseJson: JSON.parse,
    isNull: v => v == null, isNullOrEmpty: v => v == null || v === '', isNullOrBlank: v => v == null || String(v).trim() === '',
    defaultIfNull: (v, d) => v == null ? d : v, defaultIfNullOrEmpty: (v, d) => v == null || v === '' ? d : v,
    defaultIfNullOrBlank: (v, d) => v == null || String(v).trim() === '' ? d : v,
    isString: v => typeof v === 'string', isNumber: v => typeof v === 'number', isBoolean: v => typeof v === 'boolean',
    isList: Array.isArray, isMap: v => v !== null && typeof v === 'object' && !Array.isArray(v),
    dynamodb: dynamodb,
    time: boundary('util.time', {nowISO8601: () => __now('iso'), nowEpochSeconds: () => __now('seconds'), nowEpochMilliSeconds: () => __now('milliseconds')}),
    transform: boundary('util.transform', {toDynamoDBFilterExpression: v => JSON.stringify(expression(v, 'f')), toDynamoDBConditionExpression: v => JSON.stringify(expression(v, 'c'))})
  });
  runtime = boundary('runtime', {earlyReturn: (value, options) => {
    const skip = options && options.skipTo || 'NEXT';
    if (skip !== 'END' && skip !== 'NEXT') fail('runtime.earlyReturn skipTo must be END or NEXT');
    return __earlyReturn(value === undefined ? null : value, skip);
  }});
  extensions = boundary('extensions', {});
  __utils = boundary('@aws-appsync/utils', {util: util, runtime: runtime, extensions: extensions});
})();
`
