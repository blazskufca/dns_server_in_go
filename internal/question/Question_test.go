package question

import (
	"bytes"
	"github.com/blazskufca/dns_server_in_go/internal/DNS_Class"
	"github.com/blazskufca/dns_server_in_go/internal/DNS_Type"
	"testing"
)

func TestQuestion_SetName(t *testing.T) {
	q := Question{}
	q.SetName("example.com")
	if q.Name != "example.com" {
		t.Fatalf("Expected Name to be 'example.com', got '%s'", q.Name)
	}
}

func TestQuestion_SetType(t *testing.T) {
	q := Question{}
	q.SetType(DNS_Type.A)
	if q.Type != DNS_Type.A {
		t.Fatalf("Expected Type to be A (%d), got %d", DNS_Type.A, q.Type)
	}
}

func TestQuestion_SetClass(t *testing.T) {
	q := Question{}
	q.SetClass(DNS_Class.IN)
	if q.Class != DNS_Class.IN {
		t.Fatalf("Expected Class to be IN (%d), got %d", DNS_Class.IN, q.Class)
	}
}

func TestQuestion_MarshalBinary(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected []byte
		qType    DNS_Type.Type
		qClass   DNS_Class.Class
	}{
		{
			name:   "simple domain",
			domain: "example.com",
			qType:  DNS_Type.A,
			qClass: DNS_Class.IN,
			// \x07example\x03com\x00 + Type (0x0001) + Class (0x0001)
			expected: []byte{
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
				0x00, 0x01, // Type A
				0x00, 0x01, // Class IN
			},
		},
		{
			name:   "subdomain",
			domain: "sub.example.com",
			qType:  DNS_Type.AAAA,
			qClass: DNS_Class.IN,
			// \x03sub\x07example\x03com\x00 + Type (0x001c) + Class (0x0001)
			expected: []byte{
				0x03, 's', 'u', 'b',
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
				0x00, 0x1c, // Type AAAA
				0x00, 0x01, // Class IN
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := Question{}
			q.SetName(tc.domain)
			q.SetType(tc.qType)
			q.SetClass(tc.qClass)

			data, err := q.MarshalBinary()
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if !bytes.Equal(data, tc.expected) {
				t.Fatalf("Expected %v, got %v", tc.expected, data)
			}
		})
	}
}

func TestUnmarshal(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		expected   Question
		bytesRead  int
		shouldFail bool
	}{
		{
			name: "simple question",
			data: []byte{
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
				0x00, 0x01, // Type A
				0x00, 0x01, // Class IN
			},
			expected: Question{
				Name:  "example.com",
				Type:  DNS_Type.A,
				Class: DNS_Class.IN,
			},
			bytesRead:  17,
			shouldFail: false,
		},
		{
			name: "incomplete data for type and class",
			data: []byte{
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
				0x00, // Only 1 byte, should expect 4 more
			},
			expected:   Question{},
			bytesRead:  0,
			shouldFail: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q, bytesRead, err := Unmarshal(tc.data, tc.data)

			if tc.shouldFail {
				if err == nil {
					t.Fatalf("Expected an error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if bytesRead != tc.bytesRead {
				t.Fatalf("Expected bytesRead to be %d, got %d", tc.bytesRead, bytesRead)
			}

			if q.Name != tc.expected.Name {
				t.Fatalf("Expected Name to be '%s', got '%s'", tc.expected.Name, q.Name)
			}

			if q.Type != tc.expected.Type {
				t.Fatalf("Expected Type to be %d, got %d", tc.expected.Type, q.Type)
			}

			if q.Class != tc.expected.Class {
				t.Fatalf("Expected Class to be %d, got %d", tc.expected.Class, q.Class)
			}
		})
	}
}

func TestUnmarshal_WithCompression(t *testing.T) {
	fullPacket := []byte{
		// First part of packet (simulating header etc)
		0x00, 0x00,

		// First question - example.com
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01, // Type
		0x00, 0x01, // Class

		// Second question with compression - sub.(pointer to offset 2)
		0x03, 's', 'u', 'b',
		0xc0, 0x02, // Pointer to offset 2 (start of example.com)
		0x00, 0x01, // Type
		0x00, 0x01, // Class
	}

	secondQuestionData := fullPacket[19:]
	q, bytesRead, err := Unmarshal(secondQuestionData, fullPacket)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expected := Question{
		Name:  "sub.example.com",
		Type:  DNS_Type.A,
		Class: DNS_Class.IN,
	}

	if q.Name != expected.Name {
		t.Fatalf("Expected Name to be '%s', got '%s'", expected.Name, q.Name)
	}
	if q.Type != expected.Type {
		t.Fatalf("Expected Type to be %d, got %d", expected.Type, q.Type)
	}
	if q.Class != expected.Class {
		t.Fatalf("Expected Class to be %d, got %d", expected.Class, q.Class)
	}

	if bytesRead != len(fullPacket[19:]) {
		t.Fatalf("Expected bytesRead to be 10, got %d", bytesRead)
	}
}

func TestQuestion_RoundTrip(t *testing.T) {
	domains := []string{
		"example.com",
		"sub.example.com",
		"a.very.long.subdomain.example.com",
	}

	for _, domain := range domains {
		original := Question{
			Name:  domain,
			Type:  DNS_Type.A,
			Class: DNS_Class.IN,
		}

		data, err := original.MarshalBinary()
		if err != nil {
			t.Fatalf("Marshaling error for %s: %v", domain, err)
		}

		parsed, _, err := Unmarshal(data, data)
		if err != nil {
			t.Fatalf("Unmarshaling error for %s: %v", domain, err)
		}

		if parsed.Name != original.Name {
			t.Fatalf("Expected Name to be '%s', got '%s'", original.Name, parsed.Name)
		}

		if parsed.Type != original.Type {
			t.Fatalf("Expected Type to be %d, got %d", original.Type, parsed.Type)
		}

		if parsed.Class != original.Class {
			t.Fatalf("Expected Class to be %d, got %d", original.Class, parsed.Class)
		}
	}
}
