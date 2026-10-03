package awsapi

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"time"

	"stackd/internal/awscatalog"
)

// encodeQueryResponse returns the fields of the operation's Result element.
// The transport supplies its Response envelope and authenticated request ID.
func encodeQueryResponse(service awscatalog.Service, operation awscatalog.Operation, output any) ([]byte, error) {
	var body bytes.Buffer
	encoder := xml.NewEncoder(&body)
	if err := encodeXMLFields(encoder, service, operation.Output, reflect.ValueOf(output)); err != nil {
		return nil, err
	}
	if service.Protocol == awscatalog.EC2Query && operation.Output == "smithy.api#Unit" {
		if err := encoder.EncodeElement(true, xml.StartElement{Name: xml.Name{Local: "return"}}); err != nil {
			return nil, err
		}
	}
	if err := encoder.Flush(); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

func encodeXMLFields(e *xml.Encoder, service awscatalog.Service, id awscatalog.ShapeID, value reflect.Value) error {
	return encodeXMLBoundFields(e, service, id, value, false)
}

func encodeXMLBoundFields(e *xml.Encoder, service awscatalog.Service, id awscatalog.ShapeID, value reflect.Value, root bool) error {
	shape, ok := service.Shape(id)
	if !ok {
		return fmt.Errorf("missing generated shape %s", id)
	}
	for value.IsValid() && (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) {
		if value.IsNil() {
			return fmt.Errorf("nil output for %s", id)
		}
		value = value.Elem()
	}
	if !value.IsValid() {
		return fmt.Errorf("nil output for %s", id)
	}
	switch shape.Kind {
	case "structure", "union":
		if value.Kind() != reflect.Struct {
			return outputTypeError(id, value)
		}
		fields := make(map[string]reflect.Value, value.NumField())
		for i := 0; i < value.NumField(); i++ {
			fields[value.Type().Field(i).Tag.Get("smithy")] = value.Field(i)
		}
		present := 0
		for _, m := range shape.Members {
			if root && !documentMember(m, true) {
				continue
			}
			field, exists := fields[m.Name]
			if !exists {
				return fmt.Errorf("output %s missing generated member %s", id, m.Name)
			}
			if nilValue(field) {
				continue
			}
			present++
			if m.XMLAttribute {
				continue
			}
			if err := encodeXMLMember(e, service, m, field); err != nil {
				return err
			}
		}
		if shape.Kind == "union" && present != 1 {
			return fmt.Errorf("output union %s must have one member", id)
		}
		return nil
	case "list", "set":
		if value.Kind() != reflect.Slice {
			return outputTypeError(id, value)
		}
		for i := 0; i < value.Len(); i++ {
			if err := encodeXMLMember(e, service, shape.Member, value.Index(i)); err != nil {
				return err
			}
		}
		return nil
	case "map":
		if value.Kind() != reflect.Map || value.Type().Key().Kind() != reflect.String {
			return outputTypeError(id, value)
		}
		keys := value.MapKeys()
		slices.SortFunc(keys, func(a, b reflect.Value) int {
			if a.String() < b.String() {
				return -1
			}
			if a.String() > b.String() {
				return 1
			}
			return 0
		})
		for _, key := range keys {
			start := xml.StartElement{Name: xml.Name{Local: "entry"}}
			if err := e.EncodeToken(start); err != nil {
				return err
			}
			if err := encodeXMLElement(e, service, xmlName(shape.Key, "key"), shape.Key.Target, key); err != nil {
				return err
			}
			if err := encodeXMLElement(e, service, xmlName(shape.Value, "value"), shape.Value.Target, value.MapIndex(key)); err != nil {
				return err
			}
			if err := e.EncodeToken(start.End()); err != nil {
				return err
			}
		}
		return nil
	default:
		text, err := xmlScalar(shape, value)
		if err != nil {
			return err
		}
		return e.EncodeToken(xml.CharData(text))
	}
}

func encodeXMLMember(e *xml.Encoder, service awscatalog.Service, m awscatalog.Member, value reflect.Value) error {
	shape, ok := service.Shape(m.Target)
	if !ok {
		return fmt.Errorf("missing generated shape %s", m.Target)
	}
	name := xmlName(m, m.Name)
	if m.XMLFlattened || shape.XMLFlattened {
		for value.Kind() == reflect.Pointer {
			value = value.Elem()
		}
		if shape.Kind != "list" && shape.Kind != "set" {
			return fmt.Errorf("unsupported flattened output %s", m.Target)
		}
		if value.Kind() != reflect.Slice {
			return outputTypeError(m.Target, value)
		}
		for i := 0; i < value.Len(); i++ {
			element := shape.Member
			element.Name, element.XMLName = name, name
			element.XMLNamespace, element.XMLNamespacePrefix = m.XMLNamespace, m.XMLNamespacePrefix
			if m.TimestampFormat != "" {
				element.TimestampFormat = m.TimestampFormat
			}
			if err := encodeXMLMember(e, service, element, value.Index(i)); err != nil {
				return err
			}
		}
		return nil
	}
	return encodeXMLBoundElement(e, service, m, value, false)
}

func encodeXMLElement(e *xml.Encoder, service awscatalog.Service, name string, id awscatalog.ShapeID, value reflect.Value) error {
	return encodeXMLBoundElement(e, service, awscatalog.Member{Name: name, Target: id}, value, false)
}

func encodeXMLBoundElement(e *xml.Encoder, service awscatalog.Service, member awscatalog.Member, value reflect.Value, root bool) error {
	shape, ok := service.Shape(member.Target)
	if !ok {
		return fmt.Errorf("missing generated shape %s", member.Target)
	}
	value = indirectHTTPValue(value)
	start := xml.StartElement{Name: xml.Name{Local: xmlName(member, member.Name)}}
	namespace, prefix := member.XMLNamespace, member.XMLNamespacePrefix
	if namespace == "" {
		namespace, prefix = shape.XMLNamespace, shape.XMLNamespacePrefix
	}
	if namespace == "" && root {
		namespace = service.XMLNamespace
	}
	if namespace != "" {
		name := "xmlns"
		if prefix != "" {
			name += ":" + prefix
		}
		start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: name}, Value: namespace})
	}
	if shape.Kind == "structure" || shape.Kind == "union" {
		fields, err := smithyFields(value, shape.ID)
		if err != nil {
			return err
		}
		for _, attribute := range shape.Members {
			if !attribute.XMLAttribute || (root && !documentMember(attribute, true)) {
				continue
			}
			field, ok := fields[attribute.Name]
			if !ok {
				return fmt.Errorf("output %s missing generated member %s", shape.ID, attribute.Name)
			}
			if nilValue(field) {
				continue
			}
			target, _ := service.Shape(attribute.Target)
			text, err := xmlScalar(target, indirectHTTPValue(field))
			if err != nil {
				return err
			}
			start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: xmlName(attribute, attribute.Name)}, Value: text})
		}
	}
	if err := e.EncodeToken(start); err != nil {
		return err
	}
	if shape.Kind == "timestamp" && (member.TimestampFormat != "" || shape.TimestampFormat != "") {
		format := member.TimestampFormat
		if format == "" {
			format = shape.TimestampFormat
		}
		var text string
		if format == "http-date" {
			stamp, ok := value.Interface().(time.Time)
			if !ok {
				return outputTypeError(shape.ID, value)
			}
			text = stamp.UTC().Format(http.TimeFormat)
		} else if format == "epoch-seconds" {
			raw, err := encodeValue(service, shape.ID, value, format, documentPosition{})
			if err != nil {
				return err
			}
			text = string(raw)
		} else if format == "date-time" {
			var err error
			text, err = xmlScalar(shape, value)
			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("%w: XML timestamp format %s", ErrUnsupportedBinding, format)
		}
		if err := e.EncodeToken(xml.CharData(text)); err != nil {
			return err
		}
	} else if err := encodeXMLBoundFields(e, service, shape.ID, value, root); err != nil {
		return err
	}
	return e.EncodeToken(start.End())
}

func xmlName(m awscatalog.Member, fallback string) string {
	if m.XMLName != "" {
		return m.XMLName
	}
	return fallback
}

func xmlScalar(shape awscatalog.Shape, value reflect.Value) (string, error) {
	switch shape.Kind {
	case "string", "enum":
		if value.Kind() == reflect.String {
			return value.String(), nil
		}
	case "boolean":
		if value.Kind() == reflect.Bool {
			return strconv.FormatBool(value.Bool()), nil
		}
	case "byte", "short", "integer", "long", "intEnum":
		if value.CanInt() {
			return strconv.FormatInt(value.Int(), 10), nil
		}
	case "float", "double":
		if value.Kind() == reflect.Float32 || value.Kind() == reflect.Float64 {
			return strconv.FormatFloat(value.Float(), 'g', -1, value.Type().Bits()), nil
		}
	case "blob":
		if value.Kind() == reflect.Slice && value.Type().Elem().Kind() == reflect.Uint8 {
			return base64.StdEncoding.EncodeToString(value.Bytes()), nil
		}
	case "timestamp":
		if stamp, ok := value.Interface().(time.Time); ok {
			return stamp.UTC().Format(time.RFC3339Nano), nil
		}
	}
	return "", outputTypeError(shape.ID, value)
}
