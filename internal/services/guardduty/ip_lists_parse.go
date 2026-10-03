package guardduty

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
)

const ipListMaxBytes = 35 * 1024 * 1024

// parseIPList counts source entries before coalescing, so duplicate indicators
// cannot bypass the quota. Each populated CSV IP column is a separate entry.
func parseIPList(format string, content []byte, maxEntries int) ([]IPRange, error) {
	if len(content) > ipListMaxBytes {
		return nil, fmt.Errorf("IP list exceeds the 35 MB size limit")
	}
	if maxEntries <= 0 {
		return nil, fmt.Errorf("IP list entry limit must be positive")
	}
	p := ipListParser{limit: maxEntries}
	var err error
	switch format {
	case "TXT", "ALIEN_VAULT":
		err = p.lines(content, format)
	case "OTX_CSV", "PROOF_POINT", "FIRE_EYE":
		err = p.csv(content, format)
	case "STIX":
		err = p.stix(content)
	default:
		err = fmt.Errorf("unsupported IP list format %q", format)
	}
	if err != nil {
		return nil, err
	}
	if len(p.ranges) == 0 {
		return nil, fmt.Errorf("IP list contains no IPv4 entries")
	}
	slices.SortFunc(p.ranges, func(a, b IPRange) int {
		if a.First < b.First {
			return -1
		}
		if a.First > b.First {
			return 1
		}
		return 0
	})
	n := 0
	for _, next := range p.ranges[1:] {
		last := &p.ranges[n]
		if next.First <= last.Last || (last.Last != ^uint32(0) && next.First == last.Last+1) {
			last.Last = max(last.Last, next.Last)
		} else {
			n++
			p.ranges[n] = next
		}
	}
	return p.ranges[:n+1], nil
}

type ipListParser struct {
	ranges  []IPRange
	entries int
	limit   int
}

func (p *ipListParser) entry() error {
	p.entries++
	if p.entries > p.limit {
		return fmt.Errorf("IP list exceeds the %d entry limit", p.limit)
	}
	return nil
}

func ipListAddress(value string) (uint32, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil || !addr.Is4() {
		return 0, fmt.Errorf("invalid IPv4 address %q; IPv6 is not supported", value)
	}
	b := addr.As4()
	return binary.BigEndian.Uint32(b[:]), nil
}

func ipListRange(value string) (IPRange, error) {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() {
			return IPRange{}, fmt.Errorf("invalid IPv4 CIDR %q; IPv6 is not supported", value)
		}
		b := prefix.Masked().Addr().As4()
		first := binary.BigEndian.Uint32(b[:])
		return IPRange{First: first, Last: first | (^uint32(0) >> prefix.Bits())}, nil
	}
	addr, err := ipListAddress(value)
	return IPRange{First: addr, Last: addr}, err
}

func (p *ipListParser) lines(content []byte, format string) error {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(nil, ipListMaxBytes+1)
	line := 0
	for scanner.Scan() {
		line++
		value := strings.TrimSpace(scanner.Text())
		if value == "" {
			continue
		}
		if format == "ALIEN_VAULT" {
			var found bool
			value, _, found = strings.Cut(value, "#")
			if !found {
				return fmt.Errorf("ALIEN_VAULT line %d has no # field separator", line)
			}
			value = strings.TrimSpace(value)
			if ipListNonIPIndicator(value) {
				continue
			}
		}
		r, err := ipListRange(value)
		if err != nil {
			return fmt.Errorf("%s line %d: %w", format, line, err)
		}
		if err := p.entry(); err != nil {
			return err
		}
		p.ranges = append(p.ranges, r)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading %s list: %w", format, err)
	}
	return nil
}

// AlienVault can mix domains and hashes into its untyped indicator column.
// Numeric dotted values are never domains: malformed IPv4 must fail the feed.
func ipListNonIPIndicator(value string) bool {
	if len(value) == 64 {
		var hash [32]byte
		if _, err := hex.Decode(hash[:], []byte(value)); err == nil {
			return true
		}
	}
	if len(value) > 253 || !strings.Contains(value, ".") {
		return false
	}
	letters := false
	for label := range strings.SplitSeq(strings.TrimSuffix(value, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
				letters = true
			case c >= '0' && c <= '9', c == '-':
			default:
				return false
			}
		}
	}
	return letters
}

func (p *ipListParser) csv(content []byte, format string) error {
	r := csv.NewReader(bytes.NewReader(content))
	r.TrimLeadingSpace = true
	r.ReuseRecord = true
	header, err := r.Read()
	if err != nil {
		return fmt.Errorf("reading %s CSV header: %w", format, err)
	}
	columns := make(map[string]int, len(header))
	for i, field := range header {
		name := strings.ToLower(strings.TrimSpace(field))
		if name == "indicator type" {
			name = "indicatortype"
		}
		if _, exists := columns[name]; exists {
			return fmt.Errorf("%s CSV has duplicate header %q", format, field)
		}
		columns[name] = i
	}
	var selected []int
	typeColumn := -1
	switch format {
	case "OTX_CSV":
		indicator, ok := columns["indicator"]
		kind, hasKind := columns["indicatortype"]
		if !ok || !hasKind {
			return fmt.Errorf("OTX_CSV requires IndicatorType and Indicator headers")
		}
		selected, typeColumn = []int{indicator}, kind
	case "PROOF_POINT":
		ip, ok := columns["ip"]
		if !ok {
			return fmt.Errorf("PROOF_POINT requires an ip header")
		}
		selected = []int{ip}
	case "FIRE_EYE":
		for _, name := range []string{"sourceip", "ip", "cidr"} {
			if i, ok := columns[name]; ok {
				selected = append(selected, i)
			}
		}
		if len(selected) == 0 {
			return fmt.Errorf("FIRE_EYE requires a sourceIp, ip, or cidr header")
		}
	}
	for row := 2; ; row++ {
		record, err := r.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s CSV row %d: %w", format, row, err)
		}
		if typeColumn >= 0 {
			kind := strings.ToLower(strings.TrimSpace(record[typeColumn]))
			switch kind {
			case "ipv4", "cidr":
			case "ipv6":
				return fmt.Errorf("OTX_CSV row %d: IPv6 is not supported", row)
			case "":
				return fmt.Errorf("OTX_CSV row %d has an empty indicator type", row)
			default:
				continue
			}
		}
		for _, column := range selected {
			value := strings.TrimSpace(record[column])
			if value == "" && format == "FIRE_EYE" {
				continue
			}
			ip, err := ipListRange(value)
			if err != nil {
				return fmt.Errorf("%s CSV row %d: %w", format, row, err)
			}
			if err := p.entry(); err != nil {
				return err
			}
			p.ranges = append(p.ranges, ip)
		}
	}
}

const (
	ipListSTIXNamespace    = "http://stix.mitre.org/stix-1"
	ipListCyboxNamespace   = "http://cybox.mitre.org/cybox-2"
	ipListAddressNamespace = "http://cybox.mitre.org/objects#AddressObject-2"
)

type ipListXMLFrame struct {
	name     xml.Name
	category string
}

func (p *ipListParser) stix(content []byte) error {
	d := xml.NewDecoder(bytes.NewReader(content))
	var stack []ipListXMLFrame
	rootSeen := false
	for {
		token, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("invalid STIX XML: %w", err)
		}
		switch t := token.(type) {
		case xml.Directive:
			return fmt.Errorf("STIX XML directives and DTDs are not supported")
		case xml.CharData:
			if len(stack) == 0 && len(bytes.TrimSpace(t)) != 0 {
				return fmt.Errorf("STIX XML contains text outside its package")
			}
		case xml.StartElement:
			if len(stack) == 0 {
				if rootSeen || t.Name.Space != ipListSTIXNamespace || t.Name.Local != "STIX_Package" {
					return fmt.Errorf("STIX XML requires one STIX_Package in the STIX namespace")
				}
				rootSeen = true
			}
			if t.Name.Local == "Address_Value" {
				if t.Name.Space != ipListAddressNamespace || len(stack) == 0 || stack[len(stack)-1].name != (xml.Name{Space: ipListCyboxNamespace, Local: "Properties"}) {
					return fmt.Errorf("STIX Address_Value requires the AddressObject namespace and cybox Properties parent")
				}
				category := stack[len(stack)-1].category
				if category != "" && category != "ipv4-addr" && category != "ipv4-net" {
					return fmt.Errorf("STIX Address_Value category %q is not IPv4", category)
				}
				condition := ""
				for _, attr := range t.Attr {
					if attr.Name.Local == "condition" {
						if attr.Name.Space != "" {
							return fmt.Errorf("STIX condition attribute must be unqualified")
						}
						condition = attr.Value
					}
				}
				value, err := ipListXMLValue(d)
				if err != nil {
					return err
				}
				ip, err := ipListSTIXRange(value, condition)
				if err != nil {
					return err
				}
				if err := p.entry(); err != nil {
					return err
				}
				p.ranges = append(p.ranges, ip)
				continue
			}
			if len(stack) >= 256 {
				return fmt.Errorf("STIX XML nesting exceeds 256 elements")
			}
			frame := ipListXMLFrame{name: t.Name}
			for _, attr := range t.Attr {
				if attr.Name.Local == "category" && attr.Name.Space == "" {
					frame.category = attr.Value
				}
			}
			stack = append(stack, frame)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		}
	}
}

func ipListXMLValue(d *xml.Decoder) (string, error) {
	var value strings.Builder
	for {
		token, err := d.Token()
		if err != nil {
			return "", fmt.Errorf("invalid STIX Address_Value: %w", err)
		}
		switch t := token.(type) {
		case xml.CharData:
			if value.Len()+len(t) > 256 {
				return "", fmt.Errorf("STIX Address_Value exceeds 256 bytes")
			}
			value.Write(t)
		case xml.EndElement:
			return strings.TrimSpace(value.String()), nil
		case xml.Comment:
		default:
			return "", fmt.Errorf("STIX Address_Value must contain only address text")
		}
	}
}

func ipListSTIXRange(value, condition string) (IPRange, error) {
	switch condition {
	case "", "Equals":
		return ipListRange(value)
	case "InclusiveBetween":
		separator := ","
		if strings.Contains(value, "##comma##") {
			separator = "##comma##"
		}
		first, last, ok := strings.Cut(value, separator)
		if !ok {
			return IPRange{}, fmt.Errorf("STIX InclusiveBetween requires two IPv4 endpoints")
		}
		low, err := ipListAddress(strings.TrimSpace(first))
		if err != nil {
			return IPRange{}, err
		}
		high, err := ipListAddress(strings.TrimSpace(last))
		if err != nil {
			return IPRange{}, err
		}
		if low > high {
			return IPRange{}, fmt.Errorf("STIX InclusiveBetween endpoints are reversed")
		}
		return IPRange{First: low, Last: high}, nil
	default:
		return IPRange{}, fmt.Errorf("unsupported STIX Address_Value condition %q", condition)
	}
}
