package utils

import (
	"bytes"
	"errors"
	"fmt"
	"math"
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

// MarshalName marshals a domain name with compression, using pointers to previously seen names
func MarshalName(name string, fullPacket []byte, offset int) ([]byte, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}

	if name == "" || name == "." {
		return []byte{0}, nil
	}

	labels := strings.Split(strings.TrimSpace(name), ".")
	var result []byte
	currentOffset := offset

	for i, label := range labels {
		trimmedLabel := strings.TrimSpace(label)
		if len(trimmedLabel) == 0 {
			continue
		}

		remainingName := strings.Join(labels[i:], ".")
		if matchOffset := findNameMatch(remainingName, fullPacket); matchOffset != -1 {
			pointer := createPointer(matchOffset)
			result = append(result, pointer...)
			return result, nil
		}

		result = append(result, byte(len(trimmedLabel)))
		result = append(result, []byte(trimmedLabel)...)
		currentOffset += 1 + len(trimmedLabel)
	}

	result = append(result, 0)
	return result, nil
}

// findNameMatch looks for a match of the given name in the full packet
func findNameMatch(name string, fullPacket []byte) int {
	if len(name) == 0 {
		return -1
	}

	nameBytes, err := EncodeDomainNameToLabel(name)
	if err != nil {
		return -1
	}

	for i := 0; i < len(fullPacket)-len(nameBytes); i++ {
		if bytes.Equal(fullPacket[i:i+len(nameBytes)], nameBytes) {
			return i
		}
	}

	return -1
}

// createPointer creates a DNS pointer (2 bytes) pointing to the given offset
func createPointer(offset int) []byte {
	if offset > 0b0011111111111111 { // 14-bit max
		return nil
	}

	// First byte: 11000000 (pointer marker) | (offset >> 8)
	// Second byte: offset & 0xFF
	pointer := make([]byte, 2)
	pointer[0] = 0b11000000 | byte(offset>>8)
	pointer[1] = byte(offset & 0xFF)
	return pointer
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

// UnmarshalName unmarshal Names/labels with pointer compression.
func UnmarshalName(buffer []byte, offset int, fullPacket []byte) (string, int, error) {
	const (
		pointerMarker byte   = 0b11000000
		pointerMask   uint16 = 0b00111111
		maxPointers          = 10
	)

	if offset < 0 || offset >= len(buffer) {
		return "", 0, fmt.Errorf("initial offset %d out of bounds for buffer length %d", offset, len(buffer))
	}

	var name strings.Builder
	startOffset := offset
	bytesConsumed := 0
	pointersFollowed := 0   // Count pointers followed from the initial offset to detect loops
	jumped := false         // Tracks if we have jumped using a pointer
	currentBuffer := buffer // Keep track of which buffer we're currently working with

	for {
		if offset < 0 || offset >= len(currentBuffer) {
			return "", 0, fmt.Errorf("offset %d out of bounds during parsing (buffer length %d)", offset, len(currentBuffer))
		}

		currentByte := currentBuffer[offset]

		if (currentByte & pointerMarker) == pointerMarker { // Pointer (2 most significant bits are set)
			if offset+1 >= len(currentBuffer) {
				return "", 0, errors.New("incomplete pointer at end of buffer")
			}

			if !jumped {
				bytesConsumed = offset - startOffset + 2
				jumped = true
			}

			// Calculate the 14-bit offset from the start of the full packet
			// The offset is the lower 6 bits of the first byte (cleared of pointer bits)
			// followed by the entire second byte
			pointerOffset := int(((uint16(currentByte) & pointerMask) << 8) | uint16(currentBuffer[offset+1]))

			if pointerOffset < 0 || pointerOffset >= len(fullPacket) {
				return "", 0, fmt.Errorf("pointer offset %d out of bounds (full packet length %d)", pointerOffset, len(fullPacket))
			}

			// Follow the pointer by updating the buffer and offset
			currentBuffer = fullPacket // Always use the full packet when following pointers
			offset = pointerOffset
			pointersFollowed++
			if pointersFollowed > maxPointers {
				return "", 0, errors.New("too many pointers followed, potential loop detected")
			}
			continue

		} else {
			labelLength := int(currentByte)

			if labelLength > MaxLabelLength {
				return "", 0, ErrLabelTooLong
			}

			offset++

			if labelLength == 0 {
				if !jumped {
					bytesConsumed = offset - startOffset
				}
				break
			}

			if offset+labelLength > len(currentBuffer) {
				return "", 0, fmt.Errorf("label length %d exceeds buffer bounds at offset %d (buffer length %d)", labelLength, offset, len(currentBuffer))
			}

			if name.Len() > 0 {
				name.WriteByte('.')
			}
			name.Write(currentBuffer[offset : offset+labelLength])
			offset += labelLength

			if !jumped {
				bytesConsumed = offset - startOffset
			}
		}
	}

	// Handle root domain (.) which is a single 0 byte
	if name.Len() == 0 && bytesConsumed == 1 && buffer[startOffset] == 0 {
		return ".", 1, nil
	}

	// Return the assembled name and the number of bytes consumed from the startOffset
	return name.String(), bytesConsumed, nil
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

// WouldOverflowUint32 checks that the value of type int is within bounds for uint32 and will not over or underflow.
func WouldOverflowUint32(value int) bool {
	return value < 0 || value > math.MaxUint32
}

// WouldOverflowUint8 checks that the value of type int is within bounds for uint8 and will not over or underflow.
func WouldOverflowUint8(value int) bool {
	return value < 0 || value > math.MaxUint8
}

// WouldOverflowUint16 checks that the value of type int is within bounds for uint16 and will not over or underflow.
func WouldOverflowUint16(value int) bool {
	return value < 0 || value > math.MaxUint16
}
