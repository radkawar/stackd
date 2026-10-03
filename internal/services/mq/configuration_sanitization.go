package mq

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	api "stackd/internal/awsapi/mq"
)

// Schema membership is separate from implemented native capabilities. A valid
// AWS setting that we cannot apply must fail validation, not silently disappear.
type activeMQSchemaElement struct {
	attributes map[string]bool
	children   map[string]string
}

func sanitizeConfiguration(engine, data string) (string, []api.SanitizationWarning, error) {
	if engine != "ACTIVEMQ" {
		return data, nil, ValidateConfiguration(engine, data)
	}
	if strings.TrimSpace(data) == "" || len(data) > 1<<20 {
		return "", nil, errors.New("configuration must contain between 1 and 1048576 bytes")
	}
	decoder := xml.NewDecoder(strings.NewReader(data))
	var output bytes.Buffer
	encoder := xml.NewEncoder(&output)
	var stack []string
	var warnings []api.SanitizationWarning
	seenAttributes := make(map[xml.Name]bool)
	rootSeen, depth, skipped := false, 0, 0
	warn := func(element, attribute string, reason api.SanitizationWarningReason) {
		w := api.SanitizationWarning{Reason: &reason}
		text(&w.ElementName, element)
		if attribute != "" {
			text(&w.AttributeName, attribute)
		}
		warnings = append(warnings, w)
	}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil, fmt.Errorf("invalid ActiveMQ XML: %w", err)
		}
		switch t := token.(type) {
		case xml.StartElement:
			depth++
			if depth > 64 {
				return "", nil, errors.New("configuration XML nesting exceeds limit")
			}
			// Even discarded subtrees must be well-formed XML. Go's decoder
			// does not reject duplicate attributes, so check them explicitly.
			clear(seenAttributes)
			for _, a := range t.Attr {
				if seenAttributes[a.Name] {
					return "", nil, errors.New("duplicate configuration attribute")
				}
				seenAttributes[a.Name] = true
			}
			if skipped != 0 {
				continue
			}
			id := "broker"
			if len(stack) == 0 {
				if rootSeen || t.Name.Space != activeMQNamespace || t.Name.Local != "broker" {
					return "", nil, errors.New("configuration requires one ActiveMQ broker root")
				}
				rootSeen = true
			} else {
				id = activeMQSchemaElements[stack[len(stack)-1]].children[t.Name.Local]
				if t.Name.Space != activeMQNamespace || id == "" {
					warn(t.Name.Local, "", api.SanitizationWarningReasonDISALLOWED_ELEMENT_REMOVED)
					skipped = depth
					continue
				}
			}
			schema := activeMQSchemaElements[id]
			start := xml.StartElement{Name: xml.Name{Local: t.Name.Local}}
			if len(stack) == 0 {
				start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "xmlns"}, Value: activeMQNamespace})
			}
			// Native warnings visit attributes in lexical order, not input order.
			slices.SortFunc(t.Attr, func(a, b xml.Attr) int { return strings.Compare(a.Name.Local, b.Name.Local) })
			for _, a := range t.Attr {
				if a.Name.Local == "xmlns" && a.Name.Space == "" || a.Name.Space == "xmlns" {
					if a.Value != activeMQNamespace && a.Value != "http://www.w3.org/2001/XMLSchema-instance" {
						return "", nil, errors.New("unsupported XML namespace declaration")
					}
					continue
				}
				if a.Name.Space == "http://www.w3.org/2001/XMLSchema-instance" && a.Name.Local == "schemaLocation" && t.Name.Local == "broker" {
					start.Attr = append(start.Attr, a)
					continue
				}
				if a.Name.Space != "" {
					return "", nil, errors.New("namespaced configuration attributes are unsupported")
				}
				if !schema.attributes[a.Name.Local] {
					warn(t.Name.Local, a.Name.Local, api.SanitizationWarningReasonDISALLOWED_ATTRIBUTE_REMOVED)
				} else if strings.Contains(a.Value, "${") || strings.Contains(a.Value, "#{") {
					warn(t.Name.Local, a.Name.Local, api.SanitizationWarningReasonINVALID_ATTRIBUTE_VALUE_REMOVED)
				} else {
					start.Attr = append(start.Attr, a)
				}
			}
			stack = append(stack, id)
			token = start
		case xml.EndElement:
			if skipped != 0 {
				if depth == skipped {
					skipped = 0
				}
				depth--
				continue
			}
			depth--
			stack = stack[:len(stack)-1]
			token = xml.EndElement{Name: xml.Name{Local: t.Name.Local}}
		case xml.Directive:
			return "", nil, errors.New("XML directives and entities are unsupported")
		case xml.ProcInst:
			if t.Target != "xml" || rootSeen {
				return "", nil, errors.New("XML processing instructions are unsupported")
			}
			continue
		default:
			if skipped != 0 {
				continue
			}
		}
		if err := encoder.EncodeToken(token); err != nil {
			return "", nil, err
		}
	}
	if !rootSeen || depth != 0 {
		return "", nil, errors.New("configuration requires one broker element")
	}
	if err := encoder.Flush(); err != nil {
		return "", nil, err
	}
	if len(warnings) != 0 {
		data = output.String()
	}
	// This is the native object-instantiation boundary, not an XSD substitute.
	// TODO: Comeback implement remaining schema-permitted native settings and
	// calibrate primitive value coercion, references and XML serialization parity.
	if err := ValidateConfiguration(engine, data); err != nil {
		return "", nil, err
	}
	return data, warnings, nil
}
