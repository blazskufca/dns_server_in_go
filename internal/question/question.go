package question

import (
	"encoding/binary"
	"errors"
	"strings"
)

/*
Each question has the following structure:

    Name: A domain name, represented as a sequence of "labels" (more on this below)
    Type: 2-byte int; the type of record (1 for an A record, 5 for a CNAME record etc., full list -> https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2)
    Class: 2-byte int; usually set to 1 (full list -> https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4)

Section 4.1.2 of the RFC covers the question section format in detail. Section 3.2 has more details on Type and class.

Domain names in DNS packets are encoded as a sequence of labels.

Labels are encoded as <length><content>, where <length> is a single byte that specifies the length of the label, and
<content> is the actual content of the label. The sequence of labels is terminated by a null byte (\x00).

For example:

    google.com is encoded as \x06google\x03com\x00 (in hex: 06 67 6f 6f 67 6c 65 03 63 6f 6d 00)
        \x06google is the first label
            \x06 is a single byte, which is the length of the label
            google is the content of the label
        \x03com is the second label
            \x03 is a single byte, which is the length of the label
            com is the content of the label
        \x00 is the null byte that terminates the domain name
*/

// DNS Limitations (RFC 1035)
const (
	// MaxLabelLength is the maximum length of a single label (63 octets)
	MaxLabelLength = 63
	// MaxDomainNameLength is the maximum length of a domain name (255 octets)
	MaxDomainNameLength = 255
)

// Common errors
var (
	ErrLabelTooLong      = errors.New("label exceeds maximum length of 63 bytes")
	ErrDomainNameTooLong = errors.New("domain name exceeds maximum length of 255 bytes")
	ErrEmptyDomainName   = errors.New("domain name cannot be empty")
)

type Type uint16

const (
	// A represents a host address query
	A Type = 1
	// NS represents an authoritative name server
	NS Type = 2
	// MD represents a mail destination (Obsolete - use MX)
	MD Type = 3
	// MF represents a mail forwarder (Obsolete - use MX)
	MF Type = 4
	// CNAME represents the canonical name for an alias
	CNAME Type = 5
	// SOA represents the start of a zone of authority
	SOA Type = 6
	// MB represents a mailbox domain
	MB Type = 7
	// MG represents a mail group member
	MG Type = 8
	//MR represents a mail rename domain name
	MR Type = 9
	// NULL represents a Null RR
	NULL Type = 10
	// WKS represents a well known service descriptor
	WKS Type = 11
	// PTR represents a domain name pointer
	PTR Type = 12
	// HINFO represents a host information
	HINFO Type = 13
	// MINFO represents a mailbox or mail list information
	MINFO Type = 14
	// MX represents a mail exchange
	MX Type = 15
	// TXT represents a text strings
	TXT Type = 16
)

func (t Type) String() string {
	switch t {
	case A:
		return "A - Host address query"
	case NS:
		return "NS - authoritative name server"
	case MD:
		return "MD - Mail destination"
	case MF:
		return "MF - Mail forwarder"
	case CNAME:
		return "CNAME - Canonical name for an alias"
	case SOA:
		return "SOA - Start of zone of authority"
	case MB:
		return "MB - Mailbox domain"
	case MG:
		return "MG - Mail group domain"
	case MR:
		return "MR - Mail rename domain"
	case NULL:
		return "NULL - NULL RR"
	case WKS:
		return "WKS - Well known service"
	case PTR:
		return "PTR - Domain name pointer"
	case HINFO:
		return "HINFO - Host information"
	case MINFO:
		return "MINFO - Mailbox or mail list information"
	case MX:
		return "MX - Mail exchange domain"
	case TXT:
		return "TXT - Text strings"
	default:
		return "Unknown"
	}
}

type Class uint16

const (
	// IN class represents the internet
	IN Class = 1
	// CS represents the CSNET class
	CS Class = 2
	// CH represents the CHAOS class
	CH Class = 3
	// HS represents the Hesiod [Dyer 87]
	HS Class = 4
)

func (c Class) String() string {
	switch c {
	case IN:
		return "IN - Internet class"
	case CS:
		return "CS - CSNET class"
	case CH:
		return "CH - CHAOS class"
	case HS:
		return "HS - Hesiod class"
	default:
		return "Unknown class"
	}
}

type Question struct {
	// Name is a single domain name
	Name  string
	Type  Type
	Class Class
}

// SetName sets the Question's Name to the given domain name
func (q *Question) SetName(name string) {
	q.Name = name
}

// SetType sets the Question.Type to the given Type
func (q *Question) SetType(t Type) {
	q.Type = t
}

// SetClass sets the Question.Class to the given class
func (q *Question) SetClass(class Class) {
	q.Class = class
}

// ValidateName validates that the domain name meets RFC 1035 specifications
func (q *Question) ValidateName() error {
	if len(q.Name) == 0 {
		return ErrEmptyDomainName
	}

	if len(q.Name) > MaxDomainNameLength {
		return ErrDomainNameTooLong
	}

	labels := strings.Split(q.Name, ".")
	for _, label := range labels {
		trimmedLabel := strings.TrimSpace(label)
		if len(trimmedLabel) > MaxLabelLength {
			return ErrLabelTooLong
		}
	}

	return nil
}

// Marshal the Question into a byte slice.
func (q *Question) Marshal() ([]byte, error) {
	if err := q.ValidateName(); err != nil {
		return nil, err
	}

	nameBytes, err := q.MarshalName()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, len(nameBytes)+4)

	copy(buf, nameBytes)

	nbl := len(nameBytes)

	binary.BigEndian.PutUint16(buf[nbl:nbl+2], uint16(q.Type))
	binary.BigEndian.PutUint16(buf[nbl+2:nbl+4], uint16(q.Class))

	return buf, nil
}

// MarshalName marshal the Question.Name into a byte slice
func (q *Question) MarshalName() ([]byte, error) {
	if err := q.ValidateName(); err != nil {
		return nil, err
	}

	var buf []byte

	labels := strings.Split(strings.TrimSpace(q.Name), ".")

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

// Unmarshal parses a DNS question from raw binary data
func Unmarshal(data []byte) (Question, int, error) {
	const typeAndClassBytes int = 4
	const uintSixteenBytes int = 2
	q := Question{}

	name, bytesRead, err := unmarshalName(data)
	if err != nil {
		return Question{}, 0, err
	}
	q.Name = name

	if len(data) < bytesRead+typeAndClassBytes {
		return Question{}, 0, errors.New("incomplete question: not enough bytes for type and class")
	}

	q.Type = Type(binary.BigEndian.Uint16(data[bytesRead : bytesRead+uintSixteenBytes]))
	bytesRead += uintSixteenBytes

	q.Class = Class(binary.BigEndian.Uint16(data[bytesRead : bytesRead+uintSixteenBytes]))
	bytesRead += uintSixteenBytes

	return q, bytesRead, nil
}

// unmarshalName decodes a domain name from DNS packet format
// Returns the domain name, number of bytes read, and any error
func unmarshalName(data []byte) (string, int, error) {
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

// UnmarshalFromReader reads and parses a Question from a binary reader
func (q *Question) UnmarshalFromReader(data []byte) (int, error) {
	question, bytesRead, err := Unmarshal(data)
	if err != nil {
		return 0, err
	}

	*q = question
	return bytesRead, nil
}
