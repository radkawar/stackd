package awsapi

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"stackd/internal/awscatalog"
)

// XML is translated to the same presence-preserving values as the JSON and
// Query binders. Only normalizeMember applies modeled constraints afterwards.
type xmlNode struct {
	Attributes []xml.Attr `xml:",any,attr"`
	Children   []xmlNode  `xml:",any"`
	Text       string     `xml:",chardata"`
	XMLName    xml.Name
}

func parseXMLDocument(body []byte) (*xmlNode, error) {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	var node xmlNode
	if err := decoder.Decode(&node); err != nil {
		return nil, &ValidationError{Reason: "expected an XML document"}
	}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return &node, nil
		}
		if err != nil {
			return nil, &ValidationError{Reason: "invalid XML document"}
		}
		switch value := token.(type) {
		case xml.CharData:
			if len(bytes.TrimSpace(value)) == 0 {
				continue
			}
		case xml.Comment, xml.ProcInst:
			continue
		}
		return nil, &ValidationError{Reason: "unexpected content after XML document"}
	}
}

func xmlShapeName(shape awscatalog.Shape) string {
	if shape.XMLName != "" {
		return shape.XMLName
	}
	_, name, _ := strings.Cut(string(shape.ID), "#")
	return name
}

func xmlPayloadName(service awscatalog.Service, member awscatalog.Member) string {
	shape, _ := service.Shape(member.Target)
	return xmlName(member, xmlShapeName(shape))
}

func xmlLocalName(name string) string {
	if _, local, ok := strings.Cut(name, ":"); ok {
		return local
	}
	return name
}

func decodeXMLDocument(service awscatalog.Service, shape awscatalog.Shape, body []byte) (map[string]json.RawMessage, error) {
	node, err := parseXMLDocument(body)
	if err != nil {
		return nil, err
	}
	if service.Name != "s3" && node.XMLName.Local != xmlLocalName(xmlShapeName(shape)) {
		return nil, &ValidationError{Reason: "unexpected XML document root"}
	}
	return xmlStructure(service, shape, node, true)
}

func decodeXMLPayload(service awscatalog.Service, member awscatalog.Member, body []byte) (json.RawMessage, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, nil
	}
	node, err := parseXMLDocument(body)
	if err != nil {
		return nil, err
	}
	// Modern S3 configuration roots are strict, unlike legacy controls such
	// as RequestPayment whose children are accepted under another wrapper.
	strictRoot := service.Name != "s3"
	switch member.Target {
	case "com.amazonaws.s3#MetricsConfiguration", "com.amazonaws.s3#InventoryConfiguration", "com.amazonaws.s3#AnalyticsConfiguration":
		strictRoot = true
	}
	if strictRoot && node.XMLName.Local != xmlLocalName(xmlPayloadName(service, member)) {
		return nil, &ValidationError{Path: member.Name, Reason: "unexpected XML payload root"}
	}
	raw, err := xmlValue(service, member, node)
	var validation *ValidationError
	if errors.As(err, &validation) {
		validation.Path = joinPath(member.Name, validation.Path)
	}
	return raw, err
}

func xmlStructure(service awscatalog.Service, shape awscatalog.Shape, node *xmlNode, root bool) (map[string]json.RawMessage, error) {
	result := make(map[string]json.RawMessage)
	matchedChildren := 0
	for _, member := range shape.Members {
		if root && !documentMember(member, false) {
			continue
		}
		name := xmlLocalName(xmlName(member, member.Name))
		var nodes []*xmlNode
		if member.XMLAttribute {
			for _, attribute := range node.Attributes {
				if attribute.Name.Local == name && attribute.Name.Space != "xmlns" {
					nodes = append(nodes, &xmlNode{Text: attribute.Value})
				}
			}
		} else {
			for i := range node.Children {
				if node.Children[i].XMLName.Local == name {
					nodes = append(nodes, &node.Children[i])
				}
			}
			matchedChildren += len(nodes)
		}
		if len(nodes) == 0 {
			continue
		}
		target, _ := service.Shape(member.Target)
		var raw json.RawMessage
		var err error
		if member.XMLFlattened || target.XMLFlattened {
			raw, err = xmlCollection(service, target, nodes)
		} else if len(nodes) != 1 {
			return nil, &ValidationError{Path: member.Name, Reason: "XML member must occur once"}
		} else {
			raw, err = xmlValue(service, member, nodes[0])
		}
		if err != nil {
			return nil, err
		}
		result[memberJSONName(member)] = raw
	}
	if service.Name == "s3" && matchedChildren != len(node.Children) {
		return nil, &ValidationError{Reason: "unexpected XML structure member"}
	}
	return result, nil
}

func xmlValue(service awscatalog.Service, member awscatalog.Member, node *xmlNode) (json.RawMessage, error) {
	shape, ok := service.Shape(member.Target)
	if !ok {
		return nil, fmt.Errorf("missing generated shape %s", member.Target)
	}
	if shape.Streaming {
		return nil, fmt.Errorf("%w: XML streaming shape %s", ErrUnsupportedBinding, member.Target)
	}
	switch shape.Kind {
	case "structure", "union":
		object, err := xmlStructure(service, shape, node, false)
		if err != nil {
			return nil, err
		}
		return json.Marshal(object)
	case "list", "set", "map":
		name := "entry"
		if shape.Kind != "map" {
			name = xmlName(shape.Member, "member")
		}
		var nodes []*xmlNode
		for i := range node.Children {
			if node.Children[i].XMLName.Local == xmlLocalName(name) {
				nodes = append(nodes, &node.Children[i])
			} else if service.Name == "s3" {
				return nil, &ValidationError{Path: member.Name, Reason: "unexpected XML collection member"}
			}
		}
		return xmlCollection(service, shape, nodes)
	case "blob":
		if !xmlScalarContent(service, node) {
			return nil, &ValidationError{Path: member.Name, Reason: "expected XML scalar"}
		}
		return json.Marshal(node.Text)
	case "document":
		return nil, fmt.Errorf("%w: XML document shape %s", ErrUnsupportedBinding, member.Target)
	default:
		if !xmlScalarContent(service, node) {
			return nil, &ValidationError{Path: member.Name, Reason: "expected XML scalar"}
		}
		text := node.Text
		if shape.Kind != "string" && shape.Kind != "enum" {
			text = strings.TrimSpace(text)
		}
		// S3 document booleans differ from HTTP header/query booleans. Native
		// PAB and encryption documents treat every other lexical value as false.
		if service.Name == "s3" && shape.Kind == "boolean" {
			if shape.ID == "com.amazonaws.s3#IsEnabled" && text != "true" && text != "false" && text != "1" && text != "0" {
				return nil, &ValidationError{Path: member.Name, Reason: "expected an XML boolean"}
			}
			return json.Marshal(strings.EqualFold(text, "true") || text == "1")
		}
		return decodeHTTPValues(service, member, []string{text}, false)
	}
}

// S3 ignores empty elements inside scalar content, but rejects nested text.
// Direct character data is already concatenated by encoding/xml.
func xmlScalarContent(service awscatalog.Service, node *xmlNode) bool {
	if service.Name != "s3" {
		return len(node.Children) == 0
	}
	for i := range node.Children {
		child := &node.Children[i]
		if child.Text != "" || !xmlScalarContent(service, child) {
			return false
		}
	}
	return true
}

func xmlCollection(service awscatalog.Service, shape awscatalog.Shape, nodes []*xmlNode) (json.RawMessage, error) {
	switch shape.Kind {
	case "list", "set":
		items := make([]json.RawMessage, len(nodes))
		for i, node := range nodes {
			var err error
			items[i], err = xmlValue(service, shape.Member, node)
			if err != nil {
				return nil, err
			}
		}
		return json.Marshal(items)
	case "map":
		items := make(map[string]json.RawMessage, len(nodes))
		for _, node := range nodes {
			var key, value *xmlNode
			for i := range node.Children {
				child := &node.Children[i]
				switch child.XMLName.Local {
				case xmlLocalName(xmlName(shape.Key, "key")):
					if key != nil {
						return nil, &ValidationError{Reason: "duplicate XML map key element"}
					}
					key = child
				case xmlLocalName(xmlName(shape.Value, "value")):
					if value != nil {
						return nil, &ValidationError{Reason: "duplicate XML map value element"}
					}
					value = child
				}
			}
			if key == nil || value == nil || len(key.Children) != 0 {
				return nil, &ValidationError{Reason: "XML map entry requires a scalar key and a value"}
			}
			raw, err := xmlValue(service, shape.Value, value)
			if err != nil {
				return nil, err
			}
			items[key.Text] = raw
		}
		return json.Marshal(items)
	default:
		return nil, fmt.Errorf("%w: flattened XML shape %s", ErrUnsupportedBinding, shape.ID)
	}
}
