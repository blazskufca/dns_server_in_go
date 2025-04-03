package header

import (
	"encoding/binary"
	"fmt"
)

/*
DNS packets are sent using UDP transport and are limited to 512 bytes.

DNS is quite convenient in the sense that queries and responses use the same format.

On a high level, a DNS packet looks as follows:


| Section            | Size     | Type              | Purpose                                                                                                |
| ------------------ | -------- | ----------------- | ------------------------------------------------------------------------------------------------------ |
| Header             | 12 Bytes | Header            | Information about the query/response.                                                                  |
| Question Section   | Variable | List of Questions | In practice only a single question indicating the query name (domain) and the record type of interest. |
| Answer Section     | Variable | List of Records   | The relevant records of the requested type.                                                            |
| Authority Section  | Variable | List of Records   | An list of name servers (NS records), used for resolving queries recursively.                          |
| Additional Section | Variable | List of Records   | Additional records, that might be useful. For instance, the corresponding A records for NS records.    |

Essentially, we have to support three different objects: Header, Question and Record. Conveniently, the lists of
records and questions are simply individual instances appended in a row, with no extras.

The number of records in each section is provided by the header.

The header structure looks as follows:

| RFC Name | Descriptive Name     | Length             | Description                                                                                                                                                                         |
| -------- | -------------------- | ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID       | Packet Identifier    | 16 bits            | A random identifier is assigned to query packets. Response packets must reply with the same id. This is needed to differentiate responses due to the stateless nature of UDP.       |
| QR       | Query Response       | 1 bit              | 0 for queries, 1 for responses.                                                                                                                                                     |
| OPCODE   | Operation Code       | 4 bits             | Typically always 0, see RFC1035 for details.                                                                                                                                        |
| AA       | Authoritative Answer | 1 bit              | Set to 1 if the responding server is authoritative - that is, it "owns" - the domain queried.                                                                                       |
| TC       | Truncated Message    | 1 bit              | Set to 1 if the message length exceeds 512 bytes. Traditionally a hint that the query can be reissued using TCP, for which the length limitation doesn't apply.                     |
| RD       | Recursion Desired    | 1 bit              | Set by the sender of the request if the server should attempt to resolve the query recursively if it does not have an answer readily available.                                     |
| RA       | Recursion Available  | 1 bit              | Set by the server to indicate whether or not recursive queries are allowed.                                                                                                         |
| Z        | Reserved             | 3 bits             | Originally reserved for later use, but now used for DNSSEC queries.                                                                                                                 |
| RCODE    | Response Code        | 4 bits             | Set by the server to indicate the status of the response, i.e. whether or not it was successful or failed, and in the latter case providing details about the cause of the failure. |
| QDCOUNT  | Question Count       | 16 bits            | The number of entries in the Question Section                                                                                                                                       |
| ANCOUNT  | Answer Count         | 16 bits            | The number of entries in the Answer Section                                                                                                                                         |
| NSCOUNT  | Authority Count      | 16 bits            | The number of entries in the Authority Section                                                                                                                                      |
| ARCOUNT  | Additional Count     | 16 bits            | The number of entries in the Additional Section                                                                                                                                     |

The header section is always 12 bytes long. Integers are encoded in big-endian format.

https://datatracker.ietf.org/doc/html/rfc1035#section-4.1

*/

// Header structure follows the following pattern
/*
The header structure looks as follows:

| RFC Name | Descriptive Name     | Length             | Description                                                                                                                                                                         |
| -------- | -------------------- | ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID       | Packet Identifier    | 16 bits            | A random identifier is assigned to query packets. Response packets must reply with the same id. This is needed to differentiate responses due to the stateless nature of UDP.       |
| QR       | Query Response       | 1 bit              | 0 for queries, 1 for responses.                                                                                                                                                     |
| OPCODE   | Operation Code       | 4 bits             | Typically always 0, see RFC1035 for details.                                                                                                                                        |
| AA       | Authoritative Answer | 1 bit              | Set to 1 if the responding server is authoritative - that is, it "owns" - the domain queried.                                                                                       |
| TC       | Truncated Message    | 1 bit              | Set to 1 if the message length exceeds 512 bytes. Traditionally a hint that the query can be reissued using TCP, for which the length limitation doesn't apply.                     |
| RD       | Recursion Desired    | 1 bit              | Set by the sender of the request if the server should attempt to resolve the query recursively if it does not have an answer readily available.                                     |
| RA       | Recursion Available  | 1 bit              | Set by the server to indicate whether or not recursive queries are allowed.                                                                                                         |
| Z        | Reserved             | 3 bits             | Originally reserved for later use, but now used for DNSSEC queries.                                                                                                                 |
| RCODE    | Response Code        | 4 bits             | Set by the server to indicate the status of the response, i.e. whether or not it was successful or failed, and in the latter case providing details about the cause of the failure. |
| QDCOUNT  | Question Count       | 16 bits            | The number of entries in the Question Section                                                                                                                                       |
| ANCOUNT  | Answer Count         | 16 bits            | The number of entries in the Answer Section                                                                                                                                         |
| NSCOUNT  | Authority Count      | 16 bits            | The number of entries in the Authority Section                                                                                                                                      |
| ARCOUNT  | Additional Count     | 16 bits            | The number of entries in the Additional Section
*/
// Header structure represents a DNS packet header (12 bytes total)
type Header struct {
	// ID is a 16-bit identifier assigned by the program that generates any kind of query
	ID [2]byte

	// Flags contains various 1-bit and multi-bit fields
	Flags [2]byte

	// QDCOUNT specifies the number of entries in the question section
	QDCOUNT [2]byte

	// ANCOUNT specifies the number of resource records in the answer section
	ANCOUNT [2]byte

	// NSCOUNT specifies the number of name server resource records in the authority section
	NSCOUNT [2]byte

	// ARCOUNT specifies the number of resource records in the additional records section
	ARCOUNT [2]byte
}

type flagByte int

const (
	firstFlagByte flagByte = iota
	secondFlagByte
)

const (
	QR_Mask          byte = 0b10000000 // Mask for the QR bit
	QR_ClearMask     byte = 0b01111111 // Mask to clear QR bit
	Opcode_ClearMask byte = 0b00001111 // Mask to extract Opcode
)

// Opcode represents a DNS header opcode (4 bits)
type Opcode int

const (
	Query  Opcode = iota // Standard query (QUERY)
	IQuery               // Inverse query (IQUERY)
	Status               // Server status request (STATUS)
	// 3-15 reserved for future use
)

// ResponseCode represents a DNS response code (4 bits)
type ResponseCode int

const (
	NoError        ResponseCode = iota // No error condition
	FormatError                        // Format error
	ServerFailure                      // Server failure
	NameError                          // Name error (domain doesn't exist)
	NotImplemented                     // Not implemented
	Refused                            // Operation refused
	// 6-15 reserved for future use
)

func (code ResponseCode) String() string {
	switch code {
	case NoError:
		return "NoError"
	case FormatError:
		return "FormatError"
	case ServerFailure:
		return "ServerFailure"
	case NameError:
		return "NameError"
	case NotImplemented:
		return "NotImplemented"
	case Refused:
		return "Refused"
	case 6, 7, 8, 9, 10, 11, 12, 13, 14, 15:
		return "ReservedForFutureUse"
	default:
		return "Unknown"
	}
}

// IsQuery returns true if the header represents a query
func (h *Header) IsQuery() bool {
	return h.Flags[firstFlagByte]&QR_Mask == 0
}

// IsResponse returns true if the header represents a response
func (h *Header) IsResponse() bool {
	return h.Flags[firstFlagByte]&QR_Mask != 0
}

// SetQRFlag sets the Query/Response flag (QR)
func (h *Header) SetQRFlag(isResponse bool) {
	if isResponse {
		h.Flags[firstFlagByte] |= QR_Mask
	} else {
		h.Flags[firstFlagByte] &= QR_ClearMask
	}
}

// GetOpcode extracts the Opcode from the header flags
func (h *Header) GetOpcode() Opcode {
	return Opcode((h.Flags[firstFlagByte] >> 3) & Opcode_ClearMask)
}

// SetOpcode sets the Opcode in the header flags
func (h *Header) SetOpcode(opcode Opcode) {
	const clearOpcodeMask byte = 0b10000111 // Clear bits 3-6
	const opcodeMask byte = 0b00001111      // Mask for 4-bit opcode
	h.Flags[firstFlagByte] = (h.Flags[firstFlagByte] & clearOpcodeMask) |
		((byte(opcode) & opcodeMask) << 3)
}

// IsAA returns whether the Authoritative Answer flag is set
func (h *Header) IsAA() bool {
	const aaMask byte = 0b00000100
	return h.Flags[firstFlagByte]&aaMask != 0
}

// SetAA sets the Authoritative Answer flag
func (h *Header) SetAA(isAA bool) {
	const setAA byte = 0b00000100
	const clearAA byte = 0b11111011
	if isAA {
		h.Flags[firstFlagByte] |= setAA
	} else {
		h.Flags[firstFlagByte] &= clearAA
	}
}

// IsTC returns whether the Truncation flag is set
func (h *Header) IsTC() bool {
	const tcMask byte = 0b00000010
	return h.Flags[firstFlagByte]&tcMask != 0
}

// SetTC sets the Truncation flag
func (h *Header) SetTC(isTruncated bool) {
	const setTC byte = 0b00000010
	const clearTC byte = 0b11111101
	if isTruncated {
		h.Flags[firstFlagByte] |= setTC
	} else {
		h.Flags[firstFlagByte] &= clearTC
	}
}

// IsRD returns whether the Recursion Desired flag is set
func (h *Header) IsRD() bool {
	const rdMask byte = 0b00000001
	return h.Flags[firstFlagByte]&rdMask != 0
}

// SetRD sets the Recursion Desired flag
func (h *Header) SetRD(recursionDesired bool) {
	const setRD byte = 0b00000001
	const clearRD byte = 0b11111110
	if recursionDesired {
		h.Flags[firstFlagByte] |= setRD
	} else {
		h.Flags[firstFlagByte] &= clearRD
	}
}

// IsRA returns whether the Recursion Available flag is set
func (h *Header) IsRA() bool {
	const raMask byte = 0b10000000
	return h.Flags[secondFlagByte]&raMask != 0
}

// SetRA sets the Recursion Available flag
func (h *Header) SetRA(recursionAvailable bool) {
	const setRA byte = 0b10000000
	const clearRA byte = 0b01111111
	if recursionAvailable {
		h.Flags[secondFlagByte] |= setRA
	} else {
		h.Flags[secondFlagByte] &= clearRA
	}
}

// GetZ returns the Z (DNSSEC) field value
func (h *Header) GetZ() uint8 {
	const zMask byte = 0b00000111
	return (h.Flags[secondFlagByte] >> 4) & zMask
}

// SetZ sets the Z (DNSSEC) field value
func (h *Header) SetZ(z uint8) {
	const clearZ byte = 0b10001111
	const zMask byte = 0b00000111
	h.Flags[secondFlagByte] = (h.Flags[secondFlagByte] & clearZ) | ((z & zMask) << 4)
}

// GetRCODE returns the Response Code
func (h *Header) GetRCODE() ResponseCode {
	const rcodeMask byte = 0b00001111
	return ResponseCode(h.Flags[secondFlagByte] & rcodeMask)
}

// SetRCODE sets the Response Code
func (h *Header) SetRCODE(rcode ResponseCode) {
	const clearRCODE byte = 0b11110000
	const rcodeMask byte = 0b00001111
	h.Flags[secondFlagByte] = (h.Flags[secondFlagByte] & clearRCODE) | (byte(rcode) & rcodeMask)
}

// GetQDCOUNT returns the Question Count
func (h *Header) GetQDCOUNT() uint16 {
	return binary.BigEndian.Uint16(h.QDCOUNT[:])
}

// SetQDCOUNT sets the Question Count
func (h *Header) SetQDCOUNT(qdcount uint16) {
	binary.BigEndian.PutUint16(h.QDCOUNT[:], qdcount)
}

// GetANCOUNT returns the Answer Count
func (h *Header) GetANCOUNT() uint16 {
	return binary.BigEndian.Uint16(h.ANCOUNT[:])
}

// SetANCOUNT sets the Answer Count
func (h *Header) SetANCOUNT(ancount uint16) {
	binary.BigEndian.PutUint16(h.ANCOUNT[:], ancount)
}

// GetNSCOUNT returns the Authority Record Count
func (h *Header) GetNSCOUNT() uint16 {
	return binary.BigEndian.Uint16(h.NSCOUNT[:])
}

// SetNSCOUNT sets the Authority Record Count
func (h *Header) SetNSCOUNT(nscount uint16) {
	binary.BigEndian.PutUint16(h.NSCOUNT[:], nscount) // Fixed: now uses NSCOUNT
}

// GetARCOUNT returns the Additional Record Count
func (h *Header) GetARCOUNT() uint16 {
	return binary.BigEndian.Uint16(h.ARCOUNT[:])
}

// SetARCOUNT sets the Additional Record Count
func (h *Header) SetARCOUNT(arcount uint16) { // Fixed: parameter name corrected
	binary.BigEndian.PutUint16(h.ARCOUNT[:], arcount)
}

// Marshal marshals a DNS Header into a 12-byte slice
func (h *Header) Marshal() ([]byte, error) {
	buf := make([]byte, 12)

	copy(buf[0:2], h.ID[:])

	copy(buf[2:4], h.Flags[:])

	binary.BigEndian.PutUint16(buf[4:6], h.GetQDCOUNT())
	binary.BigEndian.PutUint16(buf[6:8], h.GetANCOUNT())
	binary.BigEndian.PutUint16(buf[8:10], h.GetNSCOUNT())
	binary.BigEndian.PutUint16(buf[10:12], h.GetARCOUNT())

	return buf, nil
}

// Unmarshal deserializes a 12-byte slice into a Header
func Unmarshal(data []byte) (*Header, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("DNS header must be at least 12 bytes, got %d", len(data))
	}

	h := &Header{}

	copy(h.ID[:], data[0:2])

	copy(h.Flags[:], data[2:4])

	h.SetQDCOUNT(binary.BigEndian.Uint16(data[4:6]))
	h.SetANCOUNT(binary.BigEndian.Uint16(data[6:8]))
	h.SetNSCOUNT(binary.BigEndian.Uint16(data[8:10]))
	h.SetARCOUNT(binary.BigEndian.Uint16(data[10:12]))

	return h, nil
}
