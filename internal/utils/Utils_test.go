package utils

import (
	"bytes"
	"reflect"
	"slices"

	"strings"
	"testing"
)

func TestValidateName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"Valid simple domain", "example.com", false},
		{"Valid domain with subdomain", "sub.example.com", false},
		{"Valid domain with multiple subdomains", "a.b.c.d.example.com", false},
		{"Valid domain with max label length", strings.Repeat("a", 63) + ".com", false},
		{"Empty domain", "", true},
		{"Label too long", strings.Repeat("a", 64) + ".com", true},
		{"Domain too long", strings.Repeat("a.", 130), true},
		{"Valid with trailing dot", "example.com.", false},
		{"Valid with leading spaces", "  example.com", false},
		{"Valid with trailing spaces", "example.com  ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEncodeDomainNameToLabel(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
		wantErr  bool
	}{
		{
			name:     "Simple domain",
			input:    "example.com",
			expected: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			wantErr:  false,
		},
		{
			name:     "Domain with subdomain",
			input:    "sub.example.com",
			expected: []byte{3, 's', 'u', 'b', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			wantErr:  false,
		},
		{
			name:     "Root domain",
			input:    ".",
			expected: []byte{0},
			wantErr:  false,
		},
		{
			name:    "Empty domain",
			input:   "",
			wantErr: true,
		},
		{
			name:     "Domain with trailing dot",
			input:    "example.com.",
			expected: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			wantErr:  false,
		},
		{
			name:     "Domain with empty labels",
			input:    "example..com",
			expected: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeDomainNameToLabel(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EncodeDomainNameToLabel() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !bytes.Equal(got, tt.expected) {
				t.Fatalf("EncodeDomainNameToLabel() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMarshalNameWithoutCompression(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
		wantErr  bool
	}{
		{
			name:     "Simple domain without compression",
			input:    "example.com",
			expected: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			wantErr:  false,
		},
		{
			name:     "Domain with subdomain without compression",
			input:    "sub.example.com",
			expected: []byte{3, 's', 'u', 'b', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			wantErr:  false,
		},
		{
			name:     "Root domain",
			input:    ".",
			expected: []byte{0},
			wantErr:  false,
		},
		{
			name:     "Empty string",
			input:    "",
			expected: []byte{0},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MarshalName(tt.input, []byte{}, 0)
			if (err != nil) != tt.wantErr {
				t.Fatalf("MarshalName(without compression) error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !bytes.Equal(got, tt.expected) {
				t.Fatalf("MarshalName(without compression) = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestUnmarshalName(t *testing.T) {
	simplePacket := []byte{
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		// Other data follows
		1, 2, 3, 4,
	}

	compressedPacket := []byte{
		// Offset 0: "example.com" encoded
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		// Offset 13: "sub" + pointer to "example.com"
		3, 's', 'u', 'b', 0xC0, 0, // Pointer to offset 0
		// Offset 19: "other.sub" + pointer to "example.com"
		5, 'o', 't', 'h', 'e', 'r', 0xC0, 13, // Pointer to "sub.example.com"
	}

	tests := []struct {
		name           string
		expectedName   string
		buffer         []byte
		fullPacket     []byte
		offset         int
		expectedOffset int
		wantErr        bool
	}{
		{
			name:           "Simple domain",
			buffer:         simplePacket,
			offset:         0,
			fullPacket:     simplePacket,
			expectedName:   "example.com",
			expectedOffset: 13,
			wantErr:        false,
		},
		{
			name:           "Root domain",
			buffer:         []byte{0, 1, 2, 3},
			offset:         0,
			fullPacket:     []byte{0, 1, 2, 3},
			expectedName:   ".",
			expectedOffset: 1,
			wantErr:        false,
		},
		{
			name:           "Domain with pointer",
			buffer:         compressedPacket,
			offset:         13, // Start at "sub.example.com"
			fullPacket:     compressedPacket,
			expectedName:   "sub.example.com",
			expectedOffset: 6, // Consumed 6 bytes (3,"sub",0xC0,0)
			wantErr:        false,
		},
		{
			name:           "Domain with nested pointer",
			buffer:         compressedPacket,
			offset:         19, // Start at "other.sub.example.com"
			fullPacket:     compressedPacket,
			expectedName:   "other.sub.example.com",
			expectedOffset: 8, // Consumed 8 bytes (5,"other",0xC0,13)
			wantErr:        false,
		},
		{
			name:           "Invalid offset",
			buffer:         simplePacket,
			offset:         100, // Out of bounds
			fullPacket:     simplePacket,
			expectedName:   "",
			expectedOffset: 0,
			wantErr:        true,
		},
		{
			name:           "Incomplete pointer",
			buffer:         []byte{0xC0}, // Pointer without second byte
			offset:         0,
			fullPacket:     []byte{0xC0},
			expectedName:   "",
			expectedOffset: 0,
			wantErr:        true,
		},
		{
			name:           "Invalid pointer offset",
			buffer:         []byte{0xC0, 0xFF}, // Points to offset 255, out of bounds
			offset:         0,
			fullPacket:     []byte{0xC0, 0xFF},
			expectedName:   "",
			expectedOffset: 0,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotOffset, err := UnmarshalName(tt.buffer, tt.offset, tt.fullPacket)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if gotName != tt.expectedName {
					t.Fatalf("UnmarshalName() name = %v, want %v", gotName, tt.expectedName)
				}
				if gotOffset != tt.expectedOffset {
					t.Fatalf("UnmarshalName() offset = %v, want %v", gotOffset, tt.expectedOffset)
				}
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"example.com"},
		{"sub.example.com"},
		{"a.b.c.d.example.com"},
		{"very-long-label-close-to-the-maximum-length-allowed-by-dns.example.com"},
		{"."},
		{"com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := EncodeDomainNameToLabel(tt.name)
			if err != nil {
				t.Fatalf("EncodeDomainNameToLabel() error = %v", err)
			}

			decoded, _, err := UnmarshalName(encoded, 0, encoded)
			if err != nil {
				t.Fatalf("UnmarshalName() error = %v", err)
			}

			expectedName := tt.name
			if expectedName == "." {
			} else if strings.HasSuffix(expectedName, ".") {
				expectedName = expectedName[:len(expectedName)-1]
			}

			if decoded != expectedName {
				t.Fatalf("Round trip failed: got %v, want %v", decoded, expectedName)
			}
		})
	}
}

func TestCreatePointer(t *testing.T) {
	tests := []struct {
		name     string
		expected []byte
		offset   int
	}{
		{"Offset 0", []byte{0xC0, 0x00}, 0},
		{"Offset 10", []byte{0xC0, 0x0A}, 10},
		{"Offset 255", []byte{0xC0, 0xFF}, 255},
		{"Offset 1000", []byte{0xC3, 0xE8}, 1000},
		{"Offset 16383", []byte{0xFF, 0xFF}, 16383}, // Maximum valid offset (14 bits)
		{"Offset too large", nil, 16384},            // Should return nil as it's out of range
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := createPointer(tt.offset)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Fatalf("CreatePointer(%d) = %v, want %v", tt.offset, got, tt.expected)
			}
		})
	}
}

func TestFindNameMatch(t *testing.T) {
	// Create a packet with "example.com" at offset 10 and "sub.example.com" at offset 30
	exampleEncoded := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	subExampleEncoded := []byte{3, 's', 'u', 'b', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}

	packet := make([]byte, 50)
	copy(packet[10:], exampleEncoded)
	copy(packet[30:], subExampleEncoded)

	tests := []struct {
		name        string
		searchName  string
		packet      []byte
		expectedPos int
	}{
		{"Find example.com", "example.com", packet, 10},
		{"Find sub.example.com", "sub.example.com", packet, 30},
		{"No match", "nonexistent.com", packet, -1},
		{"Empty name", "", packet, -1},
		{"Invalid name", strings.Repeat("x", 300), packet, -1}, // Too long to be valid
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pos := findNameMatch(tt.searchName, tt.packet)
			if pos != tt.expectedPos {
				t.Fatalf("FindNameMatch(%s) = %d, want %d", tt.searchName, pos, tt.expectedPos)
			}
		})
	}
}

func TestSplitStringIntoChunks(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  []string
		chunkSize int
	}{
		{"Empty string", "", []string{}, 5},
		{"String smaller than chunk", "hello", []string{"hello"}, 10},
		{"String exactly chunk size", "hello", []string{"hello"}, 5},
		{"String larger than chunk", "hello world", []string{"hello", " worl", "d"}, 5},
		{"Multiple full chunks", "abcdefghijklmno", []string{"abcde", "fghij", "klmno"}, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitStringIntoChunks(tt.input, tt.chunkSize)
			if !slices.Equal(got, tt.expected) {
				t.Fatalf("SplitStringIntoChunks() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAppendUint32(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected []byte
		value    uint32
	}{
		{"Append to empty", []byte{}, []byte{0x01, 0x02, 0x03, 0x04}, 0x01020304},
		{"Append to existing", []byte{0xFF}, []byte{0xFF, 0x01, 0x02, 0x03, 0x04}, 0x01020304},
		{"Append zero", []byte{}, []byte{0x00, 0x00, 0x00, 0x00}, 0},
		{"Append max", []byte{}, []byte{0xFF, 0xFF, 0xFF, 0xFF}, 0xFFFFFFFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AppendUint32(tt.data, tt.value)
			if !bytes.Equal(got, tt.expected) {
				t.Fatalf("AppendUint32() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestOverflowChecks(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(int) bool
		values   []int
		expected []bool
	}{
		{
			"WouldOverflowUint8",
			WouldOverflowUint8,
			[]int{-1, 0, 255, 256, 1000},
			[]bool{true, false, false, true, true},
		},
		{
			"WouldOverflowUint16",
			WouldOverflowUint16,
			[]int{-1, 0, 65535, 65536, 100000},
			[]bool{true, false, false, true, true},
		},
		{
			"WouldOverflowUint32",
			WouldOverflowUint32,
			[]int{-1, 0, 4294967295, 4294967296, 5000000000},
			[]bool{true, false, false, true, true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i, val := range tt.values {
				got := tt.testFunc(val)
				if got != tt.expected[i] {
					t.Fatalf("%s(%d) = %v, want %v", tt.name, val, got, tt.expected[i])
				}
			}
		})
	}
}
