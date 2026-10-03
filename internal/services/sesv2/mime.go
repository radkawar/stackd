package sesv2

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"slices"
	api "stackd/internal/awsapi/sesv2"
	"strings"
	"time"
	"unicode/utf8"
)

const maxMessageBytes = 40 * 1024 * 1024

func parseAddress(raw string) (*mail.Address, error) {
	if strings.ContainsAny(raw, "\r\n\x00") {
		return nil, bad("Invalid email address.")
	}
	a, e := mail.ParseAddress(raw)
	if e != nil {
		return nil, bad("Invalid email address.")
	}
	for _, r := range a.Address {
		if r > 127 {
			return nil, bad("Email addresses must use ASCII; encode domains with Punycode.")
		}
	}
	local, domain, ok := strings.Cut(a.Address, "@")
	if !ok || local == "" || domain == "" {
		return nil, bad("Invalid email address.")
	}
	return a, nil
}
func addressList(values api.EmailAddressList) ([]string, error) {
	out := make([]string, 0, len(values))
	for _, v := range values {
		a, e := parseAddress(string(v))
		if e != nil {
			return nil, e
		}
		out = append(out, a.String())
	}
	return out, nil
}
func contentText(v *api.Content) (string, error) {
	if v == nil || v.Data == nil {
		return "", bad("Message content Data is required.")
	}
	charset := strings.ToLower(value(v.Charset))
	if charset != "" && charset != "utf-8" && charset != "us-ascii" {
		return "", unsupported("Only UTF-8 and US-ASCII formatted content charsets are implemented; raw MIME retains other charsets.")
	}
	text := value(v.Data)
	if !utf8.ValidString(text) {
		return "", bad("Invalid UTF-8 content.")
	}
	if charset == "us-ascii" {
		for _, r := range text {
			if r > 127 {
				return "", bad("Non-ASCII content with US-ASCII charset.")
			}
		}
	}
	return text, nil
}
func normalizeCRLF(v string) string {
	return strings.ReplaceAll(strings.ReplaceAll(v, "\r\n", "\n"), "\n", "\r\n")
}
func writeHeaders(w io.Writer, h textproto.MIMEHeader) error {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			if strings.ContainsAny(v, "\r\n\x00") {
				return bad("Invalid message header.")
			}
			if len(k)+len(v)+2 > 998 {
				return bad("Message header exceeds RFC 5321 line limit.")
			}
			if _, e := fmt.Fprintf(w, "%s: %s\r\n", k, v); e != nil {
				return e
			}
		}
	}
	_, e := io.WriteString(w, "\r\n")
	return e
}
func addCustomHeaders(h textproto.MIMEHeader, headers api.MessageHeaderList) error {
	for _, v := range headers {
		k := value(v.Name)
		value := value(v.Value)
		if k == "" || strings.ContainsAny(value, "\r\n\x00") {
			return bad("Invalid message header.")
		}
		for _, r := range k {
			if r < 33 || r > 126 || r == ':' {
				return bad("Invalid message header name.")
			}
		}
		switch strings.ToLower(k) {
		case "from", "to", "cc", "bcc", "subject", "date", "message-id", "mime-version", "content-type", "content-transfer-encoding", "return-path", "reply-to":
			return bad("Reserved message header: " + k)
		}
		h.Add(k, value)
	}
	return nil
}
func textPart(kind, text string) (textproto.MIMEHeader, []byte, error) {
	h := textproto.MIMEHeader{"Content-Type": {kind + "; charset=UTF-8"}, "Content-Transfer-Encoding": {"quoted-printable"}}
	var b bytes.Buffer
	q := quotedprintable.NewWriter(&b)
	if _, e := q.Write([]byte(normalizeCRLF(text))); e != nil {
		return nil, nil, e
	}
	if e := q.Close(); e != nil {
		return nil, nil, e
	}
	return h, b.Bytes(), nil
}
func bodyParts(m Message) (textproto.MIMEHeader, []byte, error) {
	if m.Text != "" && m.HTML != "" {
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		for _, p := range []struct{ kind, text string }{{"text/plain", m.Text}, {"text/html", m.HTML}} {
			h, data, e := textPart(p.kind, p.text)
			if e != nil {
				return nil, nil, e
			}
			part, e := w.CreatePart(h)
			if e != nil {
				return nil, nil, e
			}
			if _, e = part.Write(data); e != nil {
				return nil, nil, e
			}
		}
		if e := w.Close(); e != nil {
			return nil, nil, e
		}
		return textproto.MIMEHeader{"Content-Type": {mime.FormatMediaType("multipart/alternative", map[string]string{"boundary": w.Boundary()})}}, b.Bytes(), nil
	}
	kind, text := "text/plain", m.Text
	if m.HTML != "" {
		kind, text = "text/html", m.HTML
	}
	return textPart(kind, text)
}
func renderMIME(m Message, simple *api.Message) ([]byte, error) {
	if strings.ContainsAny(m.Subject, "\r\n\x00") {
		return nil, bad("Invalid subject.")
	}
	h := textproto.MIMEHeader{"MIME-Version": {"1.0"}, "Date": {m.Accepted.UTC().Format(time.RFC1123Z)}, "Subject": {mime.QEncoding.Encode("UTF-8", m.Subject)}}
	if m.Key.Name != "" {
		h.Set("Message-ID", "<"+m.Key.Name+"@"+m.Key.Region+".amazonses.com>")
	}
	if m.From != "" {
		h.Set("From", m.From)
	}
	if len(m.To) > 0 {
		h.Set("To", strings.Join(m.To, ", "))
	}
	if len(m.CC) > 0 {
		h.Set("Cc", strings.Join(m.CC, ", "))
	}
	if len(m.ReplyTo) > 0 {
		h.Set("Reply-To", strings.Join(m.ReplyTo, ", "))
	}
	if simple != nil {
		if e := addCustomHeaders(h, simple.Headers); e != nil {
			return nil, e
		}
	}
	bodyHeader, body, e := bodyParts(m)
	if e != nil {
		return nil, e
	}
	if simple != nil && len(simple.Attachments) > 0 {
		return nil, unsupported("Formatted attachments are not implemented; use a valid multipart raw MIME message.")
	}
	for k, v := range bodyHeader {
		h[k] = v
	}
	var b bytes.Buffer
	if e = writeHeaders(&b, h); e != nil {
		return nil, e
	}
	b.Write(body)
	if b.Len() > maxMessageBytes {
		return nil, bad("Message exceeds 40 MB.")
	}
	return b.Bytes(), nil
}
func validateMIMEPart(h textproto.MIMEHeader, body io.Reader, parts *int) error {
	*parts++
	if *parts > 500 {
		return bad("MIME message exceeds 500 parts.")
	}
	kind, params, e := mime.ParseMediaType(h.Get("Content-Type"))
	if h.Get("Content-Type") == "" {
		kind = "text/plain"
		e = nil
	}
	if e != nil {
		return bad("Malformed MIME Content-Type.")
	}
	if strings.HasPrefix(kind, "multipart/") {
		if params["boundary"] == "" {
			return bad("Missing MIME boundary.")
		}
		r := multipart.NewReader(body, params["boundary"])
		count := 0
		for {
			p, e := r.NextRawPart()
			if e == io.EOF {
				break
			}
			if e != nil {
				return bad("Malformed MIME multipart body.")
			}
			count++
			if e = validateMIMEPart(p.Header, p, parts); e != nil {
				return e
			}
		}
		if count == 0 {
			return bad("Empty MIME multipart body.")
		}
		return nil
	}
	switch strings.ToLower(h.Get("Content-Transfer-Encoding")) {
	case "base64":
		body = base64.NewDecoder(base64.StdEncoding, body)
	case "quoted-printable":
		body = quotedprintable.NewReader(body)
	case "", "7bit", "8bit", "binary":
	default:
		return bad("Invalid MIME transfer encoding.")
	}
	if _, e = io.Copy(io.Discard, body); e != nil {
		return bad("Malformed MIME transfer encoding.")
	}
	return nil
}
func parseRaw(m *Message, raw []byte) (mail.Header, []byte, error) {
	if len(raw) == 0 || len(raw) > maxMessageBytes {
		return nil, nil, bad("Raw message must be between 1 byte and 40 MB.")
	}
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		if len(bytes.TrimSuffix(line, []byte{'\r'})) > 998 {
			return nil, nil, bad("Raw message line exceeds RFC 5321 limit.")
		}
	}
	if !bytes.Contains(raw, []byte("\r\n\r\n")) && !bytes.Contains(raw, []byte("\n\n")) {
		return nil, nil, bad("Raw message requires headers and a body separated by a blank line.")
	}
	r, e := mail.ReadMessage(bytes.NewReader(raw))
	if e != nil {
		return nil, nil, bad("Malformed MIME message.")
	}
	body, e := io.ReadAll(r.Body)
	if e != nil {
		return nil, nil, e
	}
	if r.Header.Get("From") == "" || r.Header.Get("Subject") == "" {
		return nil, nil, bad("Raw message requires From and Subject headers.")
	}
	if _, e = parseAddress(r.Header.Get("From")); e != nil {
		return nil, nil, e
	}
	if m.From == "" {
		m.From = r.Header.Get("From")
	}
	if len(m.To)+len(m.CC)+len(m.BCC) == 0 {
		for _, field := range []struct {
			name   string
			target *[]string
		}{{"To", &m.To}, {"Cc", &m.CC}, {"Bcc", &m.BCC}} {
			if r.Header.Get(field.name) == "" {
				continue
			}
			list, e := r.Header.AddressList(field.name)
			if e != nil {
				return nil, nil, bad("Invalid raw recipient header.")
			}
			for _, a := range list {
				if _, e = parseAddress(a.String()); e != nil {
					return nil, nil, e
				}
				*field.target = append(*field.target, a.String())
			}
		}
	}
	parts := 0
	if e = validateMIMEPart(textproto.MIMEHeader(r.Header), bytes.NewReader(body), &parts); e != nil {
		return nil, nil, e
	}
	m.Subject = r.Header.Get("Subject")
	return r.Header, body, nil
}
func finalizeRaw(m Message, h mail.Header, body []byte) ([]byte, error) {
	out := textproto.MIMEHeader(h)
	out.Del("Bcc")
	out.Del("X-SES-SOURCE-ARN")
	out.Del("X-SES-FROM-ARN")
	out.Del("X-SES-RETURN-PATH-ARN")
	out.Set("Message-ID", "<"+m.Key.Name+"@"+m.Key.Region+".amazonses.com>")
	out.Set("Date", m.Accepted.UTC().Format(time.RFC1123Z))
	var b bytes.Buffer
	if e := writeHeaders(&b, out); e != nil {
		return nil, e
	}
	b.Write(body)
	if b.Len() > maxMessageBytes {
		return nil, bad("Message exceeds 40 MB.")
	}
	return b.Bytes(), nil
}
