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
	const (
		pointerMarker byte   = 0b11000000 // First two bits set indicate a compression pointer per the RFC 1035 section 4.1.4
		pointerMask   uint16 = 0b00111111 // Removes the first two bits, which again indicate following is a pointer and not a normal label
		maxPointers          = 100        // Maximum number of pointers to follow to prevent infinite loops in malformed data
	)

	if len(data) == 0 {
		return "", 0, errors.New("empty data for domain name")
	}

	var name strings.Builder
	var bytesRead int
	var pointerCount int
	followedPointer := false
	originalOffset := 0

	for offset := 0; offset < len(data); {
		if bytesRead == 0 { // Keep track of where we started in the original data
			originalOffset = offset
		}

		currentByte := data[offset] // Get the current byte (either a length byte or start of a pointer)

		if (currentByte & pointerMarker) == pointerMarker {
			if offset+1 >= len(data) {
				return "", 0, errors.New("incomplete pointer in domain name")
			}

			pointerCount++
			if pointerCount > maxPointers {
				return "", 0, errors.New("too many compression pointers: possible loop detected")
			}

			// Calculate the 14-bit offset where the actual data is located:
			// 1. Take the first byte, remove the pointer marker bits, and shift left 8 bits
			// 2. Combine with the second byte to get the full 14-bit offset
			firstByteBits := (uint16(currentByte) & pointerMask) << 8
			secondByteBits := uint16(data[offset+1])
			pointerOffset := int(firstByteBits | secondByteBits)

			// First time we encounter a pointer, record the bytes read from original data
			if !followedPointer {
				bytesRead = offset - originalOffset + 2
				followedPointer = true
			}

			// Jump to the location specified by the pointer
			offset = pointerOffset
			continue
		}

		labelLength := currentByte // Get the length of the current label

		if labelLength == 0 { // Zero-length label marks the end of the domain name

			if !followedPointer { // If we never followed a pointer, calculate total bytes read
				bytesRead = offset - originalOffset + 1 // +1 for the terminating zero byte
			}
			break
		}

		if offset+int(labelLength)+1 > len(data) {
			return "", 0, errors.New("domain name label exceeds data length")
		}

		if name.Len() > 0 {
			name.WriteByte('.')
		}

		name.Write(data[offset+1 : offset+1+int(labelLength)]) // Extract the label text (the bytes immediately following the length byte)

		offset += int(labelLength) + 1 // Move offset to the next label

		if !followedPointer { // If we haven't followed a pointer yet, update bytesRead
			bytesRead = offset - originalOffset
		}
	}

	return name.String(), bytesRead, nil
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
