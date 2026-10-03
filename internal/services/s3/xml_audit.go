package s3

import (
	"encoding/json"
	"encoding/xml"
	"maps"
	"strings"
)

// XML observations preserve the submitted wrapper and namespace declarations,
// including accepted non-model wrapper names. They never validate commands.
type xmlAuditNode struct {
	XMLName    xml.Name
	Attributes []xml.Attr     `xml:",any,attr"`
	Children   []xmlAuditNode `xml:",any"`
	Text       string         `xml:",chardata"`
}

func xmlAuditParameters(c *apiCall, body []byte) {
	var root xmlAuditNode
	if err := xml.Unmarshal(body, &root); err != nil {
		return
	}
	c.params[root.XMLName.Local] = root.project(nil)
}

func (node xmlAuditNode) project(inherited map[string]string) any {
	if len(node.Attributes) == 0 && len(node.Children) == 0 {
		return xmlAuditScalar(strings.TrimSpace(node.Text))
	}
	namespaces := inherited
	copied := false
	for _, attribute := range node.Attributes {
		if attribute.Name.Space != "xmlns" {
			continue
		}
		if !copied {
			namespaces = maps.Clone(inherited)
			if namespaces == nil {
				namespaces = make(map[string]string)
			}
			copied = true
		}
		namespaces[attribute.Value] = attribute.Name.Local
	}
	fields := make(map[string]any, len(node.Attributes)+len(node.Children))
	for _, attribute := range node.Attributes {
		name := attribute.Name.Local
		prefix := namespaces[attribute.Name.Space]
		if attribute.Name.Space == "xmlns" {
			prefix = "xmlns"
		}
		if prefix != "" {
			name = prefix + ":" + name
		}
		fields[name] = attribute.Value
	}
	for _, child := range node.Children {
		if value := child.project(namespaces); value != nil {
			appendNotificationElement(fields, child.XMLName.Local, value)
		}
	}
	if text := strings.TrimSpace(node.Text); text != "" {
		fields["content"] = xmlAuditScalar(text)
	}
	return fields
}

// Audit XML coercion is lexical, including rejected boolean spellings; it is
// independent of generated shape admission and retained configuration strings.
func xmlAuditScalar(text string) any {
	if text == "null" {
		return nil
	}
	if strings.EqualFold(text, "true") {
		return true
	}
	if strings.EqualFold(text, "false") {
		return false
	}
	if len(text) > 0 && (text[0] == '-' || text[0] >= '0' && text[0] <= '9') && json.Valid([]byte(text)) {
		return json.Number(text)
	}
	return text
}
