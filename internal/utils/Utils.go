package utils

import (
	"errors"
	"strings"
)

// DNS Limitations (RFC 1035)
const (
	// MaxLabelLength is the maximum length of a single label (63 octets)
	MaxLabelLength = 63
	// MaxDomainNameLength is the maximum length of a domain name (255 octets)
	MaxDomainNameLength = 255
)

var (
	ErrLabelTooLong      = errors.New("label exceeds maximum length of 63 bytes")
	ErrDomainNameTooLong = errors.New("domain name exceeds maximum length of 255 bytes")
	ErrEmptyDomainName   = errors.New("domain name cannot be empty")
)

// EncodeDomainNameToLabel encodes names to a Label.
func EncodeDomainNameToLabel(name string) ([]byte, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}

	var buf []byte

	labels := strings.Split(strings.TrimSpace(name), ".")

	for _, label := range labels {
		trimmedLabel := strings.TrimSpace(label)
		if len(trimmedLabel) > 0 {

			buf = append(buf, uint8(len(trimmedLabel)))

			buf = append(buf, []byte(trimmedLabel)...)
		}
	}

	buf = append(buf, 0)

	return buf, nil
}

// ValidateName validates that names are valid Labels.
func ValidateName(name string) error {
	if len(name) == 0 {
		return ErrEmptyDomainName
	}

	if len(name) > MaxDomainNameLength {
		return ErrDomainNameTooLong
	}

	labels := strings.Split(name, ".")
	for _, label := range labels {
		trimmedLabel := strings.TrimSpace(label)
		if len(trimmedLabel) > MaxLabelLength {
			return ErrLabelTooLong
		}
	}

	return nil
}

// UnmarshalName decodes a domain name from DNS packet format
// Returns the domain name, number of bytes read, and any error
func UnmarshalName(data []byte) (string, int, error) {
	if len(data) == 0 {
		return "", 0, errors.New("empty data")
	}

	var (
		labels    []string
		bytesRead int
	)

	for {
		if bytesRead >= len(data) {
			return "", 0, errors.New("malformed domain name: no terminating zero byte")
		}

		labelLength := int(data[bytesRead])
		bytesRead++

		if labelLength == 0 {
			break
		}

		if labelLength > MaxLabelLength {
			return "", 0, ErrLabelTooLong
		}

		if bytesRead+labelLength > len(data) {
			return "", 0, errors.New("malformed domain name: label exceeds packet bounds")
		}

		label := string(data[bytesRead : bytesRead+labelLength])
		labels = append(labels, label)
		bytesRead += labelLength
	}

	// Combine labels into a domain name
	domainName := strings.Join(labels, ".")

	// Validate the domain name length
	if len(domainName) > MaxDomainNameLength {
		return "", 0, ErrDomainNameTooLong
	}

	return domainName, bytesRead, nil
}

// SplitStringIntoChunks is a helper function to split a string into chunks
func SplitStringIntoChunks(s string, chunkSize int) []string {
	var chunks []string
	for i := 0; i < len(s); i += chunkSize {
		end := i + chunkSize
		if end > len(s) {
			end = len(s)
		}
		chunks = append(chunks, s[i:end])
	}
	return chunks
}

// AppendUint32 is a helper function to append a uint32 in network byte order
func AppendUint32(data []byte, value uint32) []byte {
	return append(data,
		byte(value>>24),
		byte(value>>16),
		byte(value>>8),
		byte(value))
}
