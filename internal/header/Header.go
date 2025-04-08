package header

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/blazskufca/dns_server_in_go/internal/utils"
	"math"
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
*/

// Header structure follows the following pattern
/*
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

The header section is always 12 bytes long. Integers are encoded in big-endian format. https://datatracker.ietf.org/doc/html/rfc1035#section-4.1

Interesting tidbits from RFCs:
- Section 5. Transport Protocol Selection of RFC 7766 https://datatracker.ietf.org/doc/html/rfc7766.txt:
	- "Recursive server (or forwarder) implementations MUST support TCP so that they do not prevent large responses from
		a TCP-capable server from reaching its TCP-capable clients" - Relating to TC flag in Header.Flags.
*/
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

// SetRandomID sets a random Header.ID which used by the DNS programs to track transactions.
// Per the RFC 1035 this MUST be unique and unpredictable so it's generated via calls to crypto/rand.
func (h *Header) SetRandomID() error {
	n, err := rand.Read(h.ID[:])
	if err != nil {
		return err
	}
	if n != len(h.ID) {
		return fmt.Errorf("random id in header does not match the expected length, expected %d, got %d", len(h.ID), n)
	}
	return nil
}

// GetMessageID gets the Header.ID which uniquely identifies this DNS Message.
func (h *Header) GetMessageID() uint16 {
	return binary.BigEndian.Uint16(h.ID[:])
}

// IsQuery returns true if the header represents a query
func (h *Header) IsQuery() bool {
	const QR_Mask byte = 0b10000000 // Mask for the QR bit
	return h.Flags[firstFlagByte]&QR_Mask == 0
}

// IsResponse returns true if the header represents a response
func (h *Header) IsResponse() bool {
	const QR_Mask byte = 0b10000000 // Mask for the QR bit
	return h.Flags[firstFlagByte]&QR_Mask != 0
}

// SetQRFlag sets the Query/Response flag (QR)
func (h *Header) SetQRFlag(isResponse bool) {
	const QR_Mask byte = 0b10000000      // Mask for the QR bit
	const QR_ClearMask byte = 0b01111111 // Mask to clear QR bit
	if isResponse {
		h.Flags[firstFlagByte] |= QR_Mask
	} else {
		h.Flags[firstFlagByte] &= QR_ClearMask
	}
}

// GetOpcode extracts the Opcode from the header flags
func (h *Header) GetOpcode() Opcode {
	const Opcode_ClearMask byte = 0b00001111 // Mask to extract Opcode
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
func (h *Header) SetZ(z int) error {
	if utils.WouldOverflowUint8(z) {
		return fmt.Errorf("z with value %d would overflow uint8 with max range %d", z, math.MaxInt8)
	}
	const clearZ byte = 0b10001111
	const zMask byte = 0b00000111
	h.Flags[secondFlagByte] = (h.Flags[secondFlagByte] & clearZ) | ((uint8(z) & zMask) << 4)
	return nil
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
func (h *Header) SetQDCOUNT(qdcount int) error {
	if utils.WouldOverflowUint16(qdcount) {
		return fmt.Errorf("qdcount with value %d would overflow uint16 with max range %d", qdcount, math.MaxUint16)
	}
	binary.BigEndian.PutUint16(h.QDCOUNT[:], uint16(qdcount))
	return nil
}

// GetANCOUNT returns the Answer Count
func (h *Header) GetANCOUNT() uint16 {
	return binary.BigEndian.Uint16(h.ANCOUNT[:])
}

// SetANCOUNT sets the Answer Count
func (h *Header) SetANCOUNT(ancount int) error {
	if utils.WouldOverflowUint16(ancount) {
		return fmt.Errorf("ancount with value %d would overflow uint16 with max range %d", ancount, math.MaxUint16)
	}
	binary.BigEndian.PutUint16(h.ANCOUNT[:], uint16(ancount))
	return nil
}

// GetNSCOUNT returns the Authority Record Count
func (h *Header) GetNSCOUNT() uint16 {
	return binary.BigEndian.Uint16(h.NSCOUNT[:])
}

// SetNSCOUNT sets the Authority Record Count
func (h *Header) SetNSCOUNT(nscount int) error {
	if utils.WouldOverflowUint16(nscount) {
		return fmt.Errorf("nscount with value %d would overflow uint16 with max range %d", nscount, math.MaxUint16)
	}
	binary.BigEndian.PutUint16(h.NSCOUNT[:], uint16(nscount))
	return nil
}

// GetARCOUNT returns the Additional Record Count
func (h *Header) GetARCOUNT() uint16 {
	return binary.BigEndian.Uint16(h.ARCOUNT[:])
}

// SetARCOUNT sets the Additional Record Count
func (h *Header) SetARCOUNT(arcount int) error { // Fixed: parameter name corrected
	if utils.WouldOverflowUint16(arcount) {
		return fmt.Errorf("arcount with value %d would overflow uint16 with max range %d", arcount, math.MaxUint16)
	}
	binary.BigEndian.PutUint16(h.ARCOUNT[:], uint16(arcount))
	return nil
}

// MarshalBinary marshals a DNS Header into a 12-byte slice
func (h *Header) MarshalBinary() ([]byte, error) {
	const headerBytes uint8 = 12
	const firstByte uint8 = 0
	const uintSixteenSize uint8 = 2

	buf := make([]byte, headerBytes, headerBytes) //nolint:gosimple

	copy(buf[firstByte:uintSixteenSize], h.ID[:])

	copy(buf[uintSixteenSize:2*uintSixteenSize], h.Flags[:])

	binary.BigEndian.PutUint16(buf[2*uintSixteenSize:3*uintSixteenSize], h.GetQDCOUNT())
	binary.BigEndian.PutUint16(buf[3*uintSixteenSize:4*uintSixteenSize], h.GetANCOUNT())
	binary.BigEndian.PutUint16(buf[4*uintSixteenSize:5*uintSixteenSize], h.GetNSCOUNT())
	binary.BigEndian.PutUint16(buf[5*uintSixteenSize:6*uintSixteenSize], h.GetARCOUNT())

	return buf, nil
}

// Unmarshal deserializes a 12-byte slice into a Header
func Unmarshal(data []byte) (*Header, error) {
	const maxHeaderBytes int = 12
	const firstByte uint8 = 0
	const uintSixteenSize uint8 = 2

	if len(data) < maxHeaderBytes {
		return nil, fmt.Errorf("DNS header must be at least 12 bytes, got %d", len(data))
	}

	h := &Header{}

	copy(h.ID[:], data[firstByte:uintSixteenSize])

	copy(h.Flags[:], data[uintSixteenSize:2*uintSixteenSize])

	err := h.SetQDCOUNT(int(binary.BigEndian.Uint16(data[2*uintSixteenSize : 3*uintSixteenSize])))
	if err != nil {
		return nil, err
	}
	err = h.SetANCOUNT(int(binary.BigEndian.Uint16(data[3*uintSixteenSize : 4*uintSixteenSize])))
	if err != nil {
		return nil, err
	}
	err = h.SetNSCOUNT(int(binary.BigEndian.Uint16(data[4*uintSixteenSize : 5*uintSixteenSize])))
	if err != nil {
		return nil, err
	}
	err = h.SetARCOUNT(int(binary.BigEndian.Uint16(data[5*uintSixteenSize : 6*uintSixteenSize])))
	if err != nil {
		return nil, err
	}

	return h, nil
}
