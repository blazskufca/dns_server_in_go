package answer

import (
	"encoding/binary"
	"errors"
	"github.com/codecrafters-io/dns-server-starter-go/internal/DNS_Class"
	"github.com/codecrafters-io/dns-server-starter-go/internal/DNS_Type"
	"github.com/codecrafters-io/dns-server-starter-go/internal/utils"
	"net"
)

// Answer structure represents a structure of a DNS answer section
/*
The answer section contains a list of RRs (Resource Records), which are answers to the questions asked in the question section.

Each RR has the following structure:

Field					Type							Description
Name				Label Sequence		The domain name encoded as a sequence of labels.
Type 				2-byte Integer 		1 for an A record, 5 for a CNAME record etc., full list https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2
Class				2-byte Integer		Usually set to 1 (full list https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4)
TTL (Time-To-Live) 	4-byte Integer 		The duration in seconds a record can be cached before retrying.
Length (RDLENGTH) 	2-byte Integer 		Length of the RDATA field in bytes.
Data (RDATA)			Variable 		Data specific to the record type.

https://www.rfc-editor.org/rfc/rfc1035#section-3.2.1
*/
type Answer struct {
	Name     string
	Type     DNS_Type.Type
	Class    DNS_Class.Class
	TTL      uint32
	RDLENGTH uint16
	RDATA    []byte
}

// SetName sets the Answer.Name which is the set of labels.
func (a *Answer) SetName(name string) {
	a.Name = name
}

// SetType sets the Answer.Type which represents type.
func (a *Answer) SetType(t DNS_Type.Type) {
	a.Type = t
}

// SetClass sets the Answer.Class which represents the class.
func (a *Answer) SetClass(c DNS_Class.Class) {
	a.Class = c
}

// SetTTL sets the Answer.TTL which is the duration in seconds a record can be cached before re-querying
func (a *Answer) SetTTL(ttl uint32) {
	a.TTL = ttl
}

func (a *Answer) SetRDATA(data []byte) {
	a.RDATA = data
	a.RDLENGTH = uint16(len(a.RDATA))
}

// SetRDATAToARecord sets the Answer.RDATA to 4-byte integer which represents the net.IP address (IPv4 address).
// It also sets the Answer.Type to DNS_Type.A and sets the Answer.RDLEGNTH to appropriate value.
func (a *Answer) SetRDATAToARecord(ip net.IP) {
	a.Type = DNS_Type.A
	a.SetRDATA(ip.To4())
}

// SetRDATAToMXRecord sets the Answer.RDATA for an MX record with preference and exchange server
func (a *Answer) SetRDATAToMXRecord(preference uint16, exchange string) error {
	a.Type = DNS_Type.MX

	// Create data with 2-byte preference followed by domain name
	data := make([]byte, 2)
	data[0] = byte(preference >> 8)
	data[1] = byte(preference & 0xFF)

	// Append encoded domain name
	encodedExchange, err := utils.EncodeDomainNameToLabel(exchange)
	if err != nil {
		return err
	}
	data = append(data, encodedExchange...)

	a.SetRDATA(data)
	return nil
}

// SetRDATAToCNAMERecord sets the Answer.RDATA to contain a canonical name
func (a *Answer) SetRDATAToCNAMERecord(canonicalName string) error {
	a.Type = DNS_Type.CNAME
	encodedName, err := utils.EncodeDomainNameToLabel(canonicalName)
	if err != nil {
		return err
	}
	a.SetRDATA(encodedName)
	return nil
}

// SetRDATAToNSRecord sets the Answer.RDATA to contain a name server domain
func (a *Answer) SetRDATAToNSRecord(nameServer string) error {
	a.Type = DNS_Type.NS
	encodedNS, err := utils.EncodeDomainNameToLabel(nameServer)
	if err != nil {
		return err
	}
	a.SetRDATA(encodedNS)
	return nil
}

// SetRDATAToTXTRecord sets the Answer.RDATA to contain text strings
func (a *Answer) SetRDATAToTXTRecord(text string) {
	a.Type = DNS_Type.TXT

	// TXT records consist of one or more character strings
	// Each string is prefixed with a length byte
	if len(text) > 255 {
		// Split into multiple strings if longer than 255 bytes
		chunks := utils.SplitStringIntoChunks(text, 255)
		var data []byte
		for _, chunk := range chunks {
			data = append(data, byte(len(chunk)))
			data = append(data, []byte(chunk)...)
		}
		a.SetRDATA(data)
	} else {
		data := make([]byte, 1+len(text))
		data[0] = byte(len(text))
		copy(data[1:], []byte(text))
		a.SetRDATA(data)
	}
}

// SetRDATAToPTRRecord sets the Answer.RDATA to contain a pointer domain name
func (a *Answer) SetRDATAToPTRRecord(ptrDomain string) error {
	a.Type = DNS_Type.PTR
	encodedPtr, err := utils.EncodeDomainNameToLabel(ptrDomain)
	if err != nil {
		return err
	}
	a.SetRDATA(encodedPtr)
	return nil
}

// SetRDATAToSOARecord sets the Answer.RDATA for an SOA record
func (a *Answer) SetRDATAToSOARecord(
	mname string, // Primary name server
	rname string, // Responsible authority's mailbox
	serial uint32, // Version number of the zone file
	refresh uint32, // Time interval before zone should be refreshed
	retry uint32, // Time interval before failed refresh should be retried
	expire uint32, // Time when zone is no longer authoritative
	minimum uint32) error { // Minimum TTL field for zone

	a.Type = DNS_Type.SOA

	// Encode the two domain names
	encodedMName, err := utils.EncodeDomainNameToLabel(mname)
	if err != nil {
		return err
	}
	encodedRName, err := utils.EncodeDomainNameToLabel(rname)
	if err != nil {
		return err
	}
	// Calculate total size
	totalSize := len(encodedMName) + len(encodedRName) + 20 // 20 bytes for the 5 uint32 values

	// Create data buffer
	data := make([]byte, 0, totalSize)

	// Append the domain names
	data = append(data, encodedMName...)
	data = append(data, encodedRName...)

	// Append the 5 uint32 values
	data = utils.AppendUint32(data, serial)
	data = utils.AppendUint32(data, refresh)
	data = utils.AppendUint32(data, retry)
	data = utils.AppendUint32(data, expire)
	data = utils.AppendUint32(data, minimum)

	a.SetRDATA(data)
	return nil
}

// Marshal serializes an Answer into a byte slice according to DNS protocol
func (a *Answer) Marshal() ([]byte, error) {
	nameBytes, err := utils.EncodeDomainNameToLabel(a.Name)
	if err != nil {
		return nil, err
	}

	// Name + Type(2) + Class(2) + TTL(4) + RDLENGTH(2) + RDATA
	totalSize := len(nameBytes) + 10 + len(a.RDATA)
	buf := make([]byte, totalSize)

	offset := 0
	copy(buf[offset:], nameBytes)
	offset += len(nameBytes)

	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(a.Type))
	offset += 2

	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(a.Class))
	offset += 2

	binary.BigEndian.PutUint32(buf[offset:offset+4], a.TTL)
	offset += 4

	binary.BigEndian.PutUint16(buf[offset:offset+2], a.RDLENGTH)
	offset += 2

	copy(buf[offset:], a.RDATA)

	return buf, nil
}

// Unmarshal parses a DNS answer from raw binary data
func Unmarshal(data []byte) (Answer, int, error) {
	if len(data) < 12 { // Minimum size: name(1) + type(2) + class(2) + ttl(4) + rdlength(2) + terminator(1)
		return Answer{}, 0, errors.New("incomplete answer: data too short")
	}

	a := Answer{}

	name, bytesRead, err := utils.UnmarshalName(data)
	if err != nil {
		return Answer{}, 0, err
	}
	a.Name = name

	if len(data) < bytesRead+10 { // type(2) + class(2) + ttl(4) + rdlength(2)
		return Answer{}, 0, errors.New("incomplete answer: not enough bytes for fixed fields")
	}

	a.Type = DNS_Type.Type(binary.BigEndian.Uint16(data[bytesRead : bytesRead+2]))
	bytesRead += 2

	a.Class = DNS_Class.Class(binary.BigEndian.Uint16(data[bytesRead : bytesRead+2]))
	bytesRead += 2

	a.TTL = binary.BigEndian.Uint32(data[bytesRead : bytesRead+4])
	bytesRead += 4

	a.RDLENGTH = binary.BigEndian.Uint16(data[bytesRead : bytesRead+2])
	bytesRead += 2

	if len(data) < bytesRead+int(a.RDLENGTH) {
		return Answer{}, 0, errors.New("incomplete answer: not enough bytes for RDATA")
	}

	a.RDATA = make([]byte, a.RDLENGTH)
	copy(a.RDATA, data[bytesRead:bytesRead+int(a.RDLENGTH)])
	bytesRead += int(a.RDLENGTH)

	return a, bytesRead, nil
}
