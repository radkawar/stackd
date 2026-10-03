package sts

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"strings"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"
)

const (
	samlAssertionNS     = "urn:oasis:names:tc:SAML:2.0:assertion"
	samlProtocolNS      = "urn:oasis:names:tc:SAML:2.0:protocol"
	samlSignatureNS     = "http://www.w3.org/2000/09/xmldsig#"
	samlEncryptionNS    = "http://www.w3.org/2001/04/xmlenc#"
	samlEncryption11NS  = "http://www.w3.org/2009/xmlenc11#"
	samlAttributePrefix = "https://aws.amazon.com/SAML/Attributes/"
	samlMaxXML          = 100000
)

var errSAMLXML = errors.New("invalid SAML XML document")

// parseSAMLXML rejects ambiguous parser inputs before signature processing. No
// external entity, schema, retrieval method or URL is ever resolved.
func parseSAMLXML(raw []byte) (*etree.Element, error) {
	if len(raw) == 0 || len(raw) > samlMaxXML {
		return nil, errSAMLXML
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	depth, roots, count := 0, 0, 0
	ids := make(map[string]bool)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errSAMLXML
		}
		switch token := token.(type) {
		case xml.StartElement:
			depth++
			count++
			if depth == 1 {
				roots++
			}
			if depth > 64 || count > 12000 {
				return nil, errSAMLXML
			}
			attrs := make(map[xml.Name]bool)
			for _, attr := range token.Attr {
				if attrs[attr.Name] {
					return nil, errSAMLXML
				}
				attrs[attr.Name] = true
				if strings.EqualFold(attr.Name.Local, "id") {
					if attr.Value == "" || ids[attr.Value] {
						return nil, errSAMLXML
					}
					ids[attr.Value] = true
				}
			}
		case xml.EndElement:
			depth--
		case xml.Directive:
			return nil, errSAMLXML
		case xml.ProcInst:
			if token.Target != "xml" || roots != 0 {
				return nil, errSAMLXML
			}
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(token)) != "" {
				return nil, errSAMLXML
			}
		}
	}
	if roots != 1 || depth != 0 || xrv.Validate(bytes.NewReader(raw)) != nil {
		return nil, errSAMLXML
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil || doc.Root() == nil {
		return nil, errSAMLXML
	}
	return doc.Root(), nil
}

func samlChildren(parent *etree.Element, namespace, name string) []*etree.Element {
	var result []*etree.Element
	if parent == nil {
		return result
	}
	for _, child := range parent.ChildElements() {
		if child.NamespaceURI() == namespace && child.Tag == name {
			result = append(result, child)
		}
	}
	return result
}

func samlOne(parent *etree.Element, namespace, name string) (*etree.Element, error) {
	children := samlChildren(parent, namespace, name)
	if len(children) != 1 {
		return nil, errSAMLXML
	}
	return children[0], nil
}

func samlText(el *etree.Element) (string, error) {
	if el == nil || len(el.ChildElements()) != 0 {
		return "", errSAMLXML
	}
	return el.Text(), nil
}

func samlBase64(text string) ([]byte, error) {
	text = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, text)
	return base64.StdEncoding.Strict().DecodeString(text)
}

func samlCount(root *etree.Element, namespace, name string) int {
	n := 0
	if root.NamespaceURI() == namespace && root.Tag == name {
		n++
	}
	for _, child := range root.ChildElements() {
		n += samlCount(child, namespace, name)
	}
	return n
}
