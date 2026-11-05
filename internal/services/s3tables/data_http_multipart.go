package s3tables

import (
	"bytes"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const dataXMLNamespace = "http://s3.amazonaws.com/doc/2006-03-01/"

type initiateMultipartResult struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	XMLNS    string   `xml:"xmlns,attr"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
}
type completeMultipartResult struct {
	XMLName           xml.Name `xml:"CompleteMultipartUploadResult"`
	XMLNS             string   `xml:"xmlns,attr"`
	Location          string   `xml:"Location"`
	Bucket            string   `xml:"Bucket"`
	Key               string   `xml:"Key"`
	ETag              string   `xml:"ETag"`
	ChecksumCRC32     string   `xml:"ChecksumCRC32,omitempty"`
	ChecksumCRC32C    string   `xml:"ChecksumCRC32C,omitempty"`
	ChecksumCRC64NVME string   `xml:"ChecksumCRC64NVME,omitempty"`
	ChecksumSHA1      string   `xml:"ChecksumSHA1,omitempty"`
	ChecksumSHA256    string   `xml:"ChecksumSHA256,omitempty"`
	ChecksumType      string   `xml:"ChecksumType,omitempty"`
}
type multipartHTTPPart struct {
	Number            int    `xml:"PartNumber"`
	Modified          string `xml:"LastModified"`
	ETag              string `xml:"ETag"`
	Size              int64  `xml:"Size"`
	ChecksumCRC32     string `xml:"ChecksumCRC32,omitempty"`
	ChecksumCRC32C    string `xml:"ChecksumCRC32C,omitempty"`
	ChecksumCRC64NVME string `xml:"ChecksumCRC64NVME,omitempty"`
	ChecksumSHA1      string `xml:"ChecksumSHA1,omitempty"`
	ChecksumSHA256    string `xml:"ChecksumSHA256,omitempty"`
}
type listMultipartResult struct {
	XMLName              xml.Name            `xml:"ListPartsResult"`
	XMLNS                string              `xml:"xmlns,attr"`
	Bucket               string              `xml:"Bucket"`
	Key                  string              `xml:"Key"`
	UploadID             string              `xml:"UploadId"`
	PartNumberMarker     int                 `xml:"PartNumberMarker"`
	NextPartNumberMarker int                 `xml:"NextPartNumberMarker,omitempty"`
	MaxParts             int                 `xml:"MaxParts"`
	IsTruncated          bool                `xml:"IsTruncated"`
	StorageClass         string              `xml:"StorageClass"`
	ChecksumAlgorithm    string              `xml:"ChecksumAlgorithm,omitempty"`
	ChecksumType         string              `xml:"ChecksumType,omitempty"`
	Parts                []multipartHTTPPart `xml:"Part"`
}

func (s *Service) listMultipartHTTP(w http.ResponseWriter, r *http.Request, location, bucket, key string, q url.Values) error {
	marker, max := 0, 1000
	var err error
	if q.Has("part-number-marker") {
		marker, err = dataInteger(q.Get("part-number-marker"), 0, 10000)
		if err != nil {
			return invalid("Invalid part-number-marker")
		}
	}
	if q.Has("max-parts") {
		max, err = dataInteger(q.Get("max-parts"), 0, 1000)
		if err != nil {
			return invalid("Invalid max-parts")
		}
	}
	upload, parts, err := s.ListMultipartParts(r.Context(), location, q.Get("uploadId"))
	if err != nil {
		return err
	}
	out := listMultipartResult{XMLNS: dataXMLNamespace, Bucket: bucket, Key: key, UploadID: upload.ID, PartNumberMarker: marker, MaxParts: max, StorageClass: "STANDARD", ChecksumAlgorithm: upload.Attributes.ChecksumAlgorithm}
	out.ChecksumType = dataMultipartChecksumType(out.ChecksumAlgorithm)
	for _, part := range parts {
		if part.Number <= marker {
			continue
		}
		if len(out.Parts) == max {
			out.IsTruncated = true
			break
		}
		out.NextPartNumberMarker = part.Number
		out.Parts = append(out.Parts, multipartHTTPPart{Number: part.Number, Modified: part.Modified.UTC().Format("2006-01-02T15:04:05.000Z"), ETag: part.ETag, Size: part.Size, ChecksumCRC32: part.Checksums.CRC32, ChecksumCRC32C: part.Checksums.CRC32C, ChecksumCRC64NVME: part.Checksums.CRC64NVME, ChecksumSHA1: part.Checksums.SHA1, ChecksumSHA256: part.Checksums.SHA256})
	}
	if !out.IsTruncated {
		out.NextPartNumberMarker = 0
	}
	writeXML(w, out)
	return nil
}

// Decode the small completion manifest strictly: encoding/xml's default struct
// decoder silently accepts duplicate scalar fields and unknown elements.
func decodeCompletedParts(r *http.Request) ([]CompletedPart, error) {
	if strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]), "application/x-www-form-urlencoded") {
		return nil, failure("InvalidRequest", "CompleteMultipartUpload does not accept form encoding", 400)
	}
	data, err := readDataBody(r)
	if err != nil {
		return nil, err
	}
	malformed := failure("MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema", 400)
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var parts []CompletedPart
	var part CompletedPart
	var text strings.Builder
	var field string
	var seen uint8
	depth, roots := 0, 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, malformed
		}
		switch token := token.(type) {
		case xml.StartElement:
			if token.Name.Space != "" && token.Name.Space != dataXMLNamespace {
				return nil, malformed
			}
			for _, attr := range token.Attr {
				if attr.Name.Local != "xmlns" && attr.Name.Space != "xmlns" {
					return nil, malformed
				}
			}
			switch depth {
			case 0:
				if roots != 0 || token.Name.Local != "CompleteMultipartUpload" {
					return nil, malformed
				}
				roots++
			case 1:
				if token.Name.Local != "Part" || len(parts) == 10000 {
					return nil, malformed
				}
				part = CompletedPart{}
				seen = 0
			case 2:
				field = token.Name.Local
				var bit uint8
				switch field {
				case "PartNumber":
					bit = 1
				case "ETag":
					bit = 2
				case "ChecksumCRC32":
					bit = 4
				case "ChecksumCRC32C":
					bit = 8
				case "ChecksumSHA1":
					bit = 16
				case "ChecksumSHA256":
					bit = 32
				case "ChecksumCRC64NVME":
					bit = 64
				default:
					return nil, malformed
				}
				if seen&bit != 0 {
					return nil, malformed
				}
				seen |= bit
				text.Reset()
			default:
				return nil, malformed
			}
			depth++
		case xml.CharData:
			if depth == 3 {
				text.Write(token)
			} else if len(bytes.TrimSpace(token)) != 0 {
				return nil, malformed
			}
		case xml.EndElement:
			depth--
			if depth == 2 {
				value := strings.TrimSpace(text.String())
				switch field {
				case "PartNumber":
					part.Number, err = dataInteger(value, 1, 10000)
					if err != nil {
						return nil, malformed
					}
				case "ETag":
					part.ETag = value
				case "ChecksumCRC32":
					part.Checksums.CRC32 = value
				case "ChecksumCRC32C":
					part.Checksums.CRC32C = value
				case "ChecksumSHA1":
					part.Checksums.SHA1 = value
				case "ChecksumSHA256":
					part.Checksums.SHA256 = value
				case "ChecksumCRC64NVME":
					part.Checksums.CRC64NVME = value
				}
			}
			if depth == 1 {
				if part.Number == 0 || part.ETag == "" {
					return nil, malformed
				}
				if len(parts) > 0 && part.Number <= parts[len(parts)-1].Number {
					return nil, failure("InvalidPartOrder", "Parts must be in ascending part number order", 400)
				}
				parts = append(parts, part)
			}
		case xml.Directive:
			return nil, malformed
		}
	}
	if depth != 0 || roots != 1 || len(parts) == 0 {
		return nil, malformed
	}
	return parts, nil
}

func dataObjectURL(r *http.Request, bucket, key string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	path := "/" + bucket + "/" + key
	if hostBucket, _, _ := strings.Cut(strings.Split(r.Host, ":")[0], "."); hostBucket == bucket {
		path = "/" + key
	}
	return (&url.URL{Scheme: scheme, Host: r.Host, Path: path}).String()
}
