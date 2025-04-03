package question

import (
	"encoding/binary"
	"errors"
	"github.com/codecrafters-io/dns-server-starter-go/internal/DNS_Class"
	"github.com/codecrafters-io/dns-server-starter-go/internal/DNS_Type"
	"github.com/codecrafters-io/dns-server-starter-go/internal/utils"
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

type Question struct {
	// Name is a single domain name
	Name  string
	Type  DNS_Type.Type
	Class DNS_Class.Class
}

// SetName sets the Question's Name to the given domain name
func (q *Question) SetName(name string) {
	q.Name = name
}

// SetType sets the Question.Type to the given Type
func (q *Question) SetType(t DNS_Type.Type) {
	q.Type = t
}

// SetClass sets the Question.Class to the given class
func (q *Question) SetClass(class DNS_Class.Class) {
	q.Class = class
}

// Marshal the Question into a byte slice.
func (q *Question) Marshal() ([]byte, error) {

	nameBytes, err := utils.EncodeDomainNameToLabel(q.Name)
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

// Unmarshal parses a DNS question from raw binary data
func Unmarshal(data []byte) (Question, int, error) {
	const typeAndClassBytes int = 4
	const uintSixteenBytes int = 2
	q := Question{}

	name, bytesRead, err := utils.UnmarshalName(data)
	if err != nil {
		return Question{}, 0, err
	}
	q.Name = name

	if len(data) < bytesRead+typeAndClassBytes {
		return Question{}, 0, errors.New("incomplete question: not enough bytes for type and class")
	}

	q.Type = DNS_Type.Type(binary.BigEndian.Uint16(data[bytesRead : bytesRead+uintSixteenBytes]))
	bytesRead += uintSixteenBytes

	q.Class = DNS_Class.Class(binary.BigEndian.Uint16(data[bytesRead : bytesRead+uintSixteenBytes]))
	bytesRead += uintSixteenBytes

	return q, bytesRead, nil
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
