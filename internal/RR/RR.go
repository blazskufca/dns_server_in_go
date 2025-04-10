package RR

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/blazskufca/dns_server_in_go/internal/DNS_Class"
	"github.com/blazskufca/dns_server_in_go/internal/DNS_Type"
	"github.com/blazskufca/dns_server_in_go/internal/utils"
	"math"
	"net"
	"strings"
)

// RR structure represents a structure of a DNS Resource Record
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
type RR struct {
	Name       string
	fullPacket []byte
	RDATA      []byte
	Type       DNS_Type.Type
	Class      DNS_Class.Class
	TTL        uint32
	RDLENGTH   uint16
}

// SetName sets the RR.Name which is the set of labels.
func (rr *RR) SetName(name string) {
	rr.Name = name
}

// GetName get the RR.Name and returns it to the caller.
func (rr *RR) GetName() string {
	return rr.Name
}

// SetType sets the RR.Type which represents type.
func (rr *RR) SetType(t DNS_Type.Type) {
	rr.Type = t
}

// SetClass sets the RR.Class which represents the class.
func (rr *RR) SetClass(c DNS_Class.Class) {
	rr.Class = c
}

// SetTTL sets the RR.TTL which is the duration in seconds a record can be cached before re-querying
func (rr *RR) SetTTL(ttl int) error {
	if utils.WouldOverflowUint32(ttl) {
		return fmt.Errorf("ttl with value %d overflows uint32 with max range %d", ttl, math.MaxUint32)
	}
	rr.TTL = uint32(ttl)
	return nil
}

// GetTTL gets the RR.TTL value.
func (rr *RR) GetTTL() uint32 {
	return rr.TTL
}

func (rr *RR) SetRDATA(data []byte) {
	rr.RDATA = data
	rr.RDLENGTH = uint16(len(rr.RDATA))
}

// SetRDATAToARecord sets the RR.RDATA to 4-byte integer which represents the net.IP address (IPv4 address).
// It also sets the RR.Type to DNS_Type.A and sets the RR.RDLEGNTH to appropriate value.
func (rr *RR) SetRDATAToARecord(ip net.IP) {
	rr.Type = DNS_Type.A
	rr.SetRDATA(ip.To4())
}

// GetRDATAAsARecord tries to interpret RR.RDATA byte slice as an A resource record.
func (rr *RR) GetRDATAAsARecord() (net.IP, error) {
	const IPv4ByteSize int = 4

	if rr.Type != DNS_Type.A {
		return nil, fmt.Errorf("record type is %s, not A type", rr.Type)
	}
	if len(rr.RDATA) != int(rr.RDLENGTH) {
		return nil, fmt.Errorf("invalid A record data length: got %d bytes, expected %d", len(rr.RDATA), rr.RDLENGTH)
	}
	if len(rr.RDATA) != IPv4ByteSize {
		return nil, fmt.Errorf("invalid A record data length: got %d bytes, expected 4", len(rr.RDATA))
	}
	return net.IPv4(rr.RDATA[0], rr.RDATA[1], rr.RDATA[2], rr.RDATA[3]), nil
}

// SetRDATAToMXRecord sets the RR.RDATA to contain a mail exchange domain
func (rr *RR) SetRDATAToMXRecord(preference uint16, exchange string) error {
	const firstByteIndex int = 0
	const secondByteIndex int = 1
	const twoBytePreference int = 2
	const oneByteShift int = 8
	const maskedByte = 0b11111111

	rr.Type = DNS_Type.MX

	// Create data with 2-byte preference followed by domain name
	data := make([]byte, twoBytePreference)
	data[firstByteIndex] = byte(preference >> oneByteShift)
	data[secondByteIndex] = byte(preference & maskedByte)

	encodedExchange, err := utils.MarshalName(exchange, data, len(data))
	if err != nil {
		return err
	}
	data = append(data, encodedExchange...)

	rr.SetRDATA(data)
	return nil
}

// GetRDATAAsMXRecord tries to interpret RR.RDATA byte slice as an MX resource record.
func (rr *RR) GetRDATAAsMXRecord() (preference uint16, exchange string, err error) {
	const minimumMXLength int = 3
	const uint16ByteSize int = 2
	var offset int

	if rr.Type != DNS_Type.MX {
		return 0, "", fmt.Errorf("record type is %d, not MX type", rr.Type)
	}
	if len(rr.RDATA) != int(rr.RDLENGTH) {
		return 0, "", fmt.Errorf("invalid MX record data length: got %d bytes, expected %d",
			len(rr.RDATA), rr.RDLENGTH)
	}
	if len(rr.RDATA) < minimumMXLength {
		return 0, "", fmt.Errorf("MX record data too short: %d bytes", len(rr.RDATA))
	}

	preference = binary.BigEndian.Uint16(rr.RDATA[offset : offset+uint16ByteSize])
	offset += uint16ByteSize

	exchange, _, err = utils.UnmarshalName(rr.RDATA[offset:], 0, rr.fullPacket)

	if err != nil {
		return 0, "", fmt.Errorf("failed to unmarshal MX exchange: %w", err)
	}

	return preference, exchange, nil
}

// SetRDATAToCNAMERecord sets the RR.RDATA to contain a canonical name
func (rr *RR) SetRDATAToCNAMERecord(canonicalName string) error {
	rr.Type = DNS_Type.CNAME
	encodedName, err := utils.MarshalName(canonicalName, nil, 0)
	if err != nil {
		return err
	}
	rr.SetRDATA(encodedName)
	return nil
}

// GetRDATAAsCNAMERecord tries to interpret RR.RDATA byte slice as an CNAME resource record.
func (rr *RR) GetRDATAAsCNAMERecord() (string, error) {
	if rr.Type != DNS_Type.CNAME {
		return "", fmt.Errorf("record type is %d, not CNAME type", rr.Type)
	}
	if len(rr.RDATA) != int(rr.RDLENGTH) {
		return "", fmt.Errorf("invalid CNAME record data length: got %d bytes, expected %d", len(rr.RDATA),
			rr.RDLENGTH)
	}

	cname, _, err := utils.UnmarshalName(rr.RDATA, 0, rr.fullPacket)

	if err != nil {
		return "", fmt.Errorf("failed to unmarshal CNAME: %w", err)
	}

	return cname, nil
}

// SetRDATAToNSRecord sets the RR.RDATA to contain a name server domain
func (rr *RR) SetRDATAToNSRecord(nameServer string) error {
	rr.Type = DNS_Type.NS
	encodedNS, err := utils.MarshalName(nameServer, nil, 0)
	if err != nil {
		return err
	}
	rr.SetRDATA(encodedNS)
	return nil
}

// GetRDATAAsNSRecord tries to interpret RR.RDATA byte slice as an NS resource record.
func (rr *RR) GetRDATAAsNSRecord() (string, error) {
	if rr.Type != DNS_Type.NS {
		return "", fmt.Errorf("record type is %d, not NS type", rr.Type)
	}
	if len(rr.RDATA) != int(rr.RDLENGTH) {
		return "", fmt.Errorf("invalid NS record data length: got %d bytes, expected %d", len(rr.RDATA),
			rr.RDLENGTH)
	}

	ns, _, err := utils.UnmarshalName(rr.RDATA, 0, rr.fullPacket)

	if err != nil {
		return "", fmt.Errorf("failed to unmarshal NS: %w", err)
	}

	return ns, nil
}

// SetRDATAToTXTRecord sets the RR.RDATA to contain text strings
func (rr *RR) SetRDATAToTXTRecord(text string) {
	rr.Type = DNS_Type.TXT

	// TXT records consist of one or more character strings
	// Each string is prefixed with a length byte
	if len(text) > math.MaxUint8 {
		// Split into multiple strings if longer than 255 bytes
		chunks := utils.SplitStringIntoChunks(text, math.MaxUint8)
		var data []byte
		for _, chunk := range chunks {
			data = append(data, byte(len(chunk)))
			data = append(data, []byte(chunk)...)
		}
		rr.SetRDATA(data)
	} else {
		data := make([]byte, 1+len(text))
		data[0] = byte(len(text))
		copy(data[1:], []byte(text))
		rr.SetRDATA(data)
	}
}

// GetRDATAAsTXTRecord tries to interpret RR.RDATA byte slice as TXT resource record.
func (rr *RR) GetRDATAAsTXTRecord() (string, error) {
	if rr.Type != DNS_Type.TXT {
		return "", fmt.Errorf("record type is %d, not TXT type", rr.Type)
	}
	if len(rr.RDATA) != int(rr.RDLENGTH) {
		return "", fmt.Errorf("invalid TXT record data length: got %d bytes, expected %d", len(rr.RDATA),
			rr.RDLENGTH)
	}

	var result []string
	var offset int

	for offset < len(rr.RDATA) {
		if offset >= len(rr.RDATA) {
			break
		}

		strLen := int(rr.RDATA[offset])
		offset++

		if offset+strLen > len(rr.RDATA) {
			return "", fmt.Errorf("TXT string length exceeds available data")
		}

		str := string(rr.RDATA[offset : offset+strLen])
		result = append(result, str)
		offset += strLen
	}

	return strings.Join(result, ""), nil
}

// SetRDATAToPTRRecord sets the RR.RDATA to contain a pointer domain name
func (rr *RR) SetRDATAToPTRRecord(ptrDomain string) error {
	rr.Type = DNS_Type.PTR
	encodedPtr, err := utils.MarshalName(ptrDomain, nil, 0)
	if err != nil {
		return err
	}
	rr.SetRDATA(encodedPtr)
	return nil
}

// GetRDATAAsPTRRecord tries to interpret RR.RDATA byte slice as PTR resource record.
func (rr *RR) GetRDATAAsPTRRecord() (string, error) {
	if rr.Type != DNS_Type.PTR {
		return "", fmt.Errorf("record type is %d, not PTR type", rr.Type)
	}
	if len(rr.RDATA) != int(rr.RDLENGTH) {
		return "", fmt.Errorf("invalid PTR record data length: got %d bytes, expected %d", len(rr.RDATA),
			rr.RDLENGTH)
	}

	ptr, _, err := utils.UnmarshalName(rr.RDATA, 0, rr.fullPacket)

	if err != nil {
		return "", fmt.Errorf("failed to unmarshal PTR: %w", err)
	}

	return ptr, nil
}

// SetRDATAToSOARecord sets the RR.RDATA for an SOA record
func (rr *RR) SetRDATAToSOARecord(
	mname string,   // Primary name server
	rname string,   // Responsible authority's mailbox
	serial uint32,  // Version number of the zone file
	refresh uint32, // Time interval before zone should be refreshed
	retry uint32,   // Time interval before failed refresh should be retried
	expire uint32,  // Time when zone is no longer authoritative
	minimum uint32) error {

	rr.Type = DNS_Type.SOA

	buf := make([]byte, 0)

	encodedMName, err := utils.MarshalName(mname, buf, 0)
	if err != nil {
		return err
	}
	buf = append(buf, encodedMName...)

	encodedRName, err := utils.MarshalName(rname, buf, len(buf))
	if err != nil {
		return err
	}
	buf = append(buf, encodedRName...)

	// Append the 5 uint32 values
	buf = utils.AppendUint32(buf, serial)
	buf = utils.AppendUint32(buf, refresh)
	buf = utils.AppendUint32(buf, retry)
	buf = utils.AppendUint32(buf, expire)
	buf = utils.AppendUint32(buf, minimum)

	rr.SetRDATA(buf)
	return nil
}

// GetRDATAAsSOARecord tries to interpret RR.RDATA as a SOA resource record.
func (rr *RR) GetRDATAAsSOARecord() (mname string, rname string, serial uint32, refresh uint32, retry uint32, expire uint32, minimum uint32, err error) {
	const uint32ByteLength int = 4
	const fiveUint32s int = uint32ByteLength * 5

	if rr.Type != DNS_Type.SOA {
		return "", "", 0, 0, 0, 0, 0, fmt.Errorf("record type is %d, not SOA type", rr.Type)
	}
	if len(rr.RDATA) != int(rr.RDLENGTH) {
		return "", "", 0, 0, 0, 0, 0,
			fmt.Errorf("invalid SOA record data length: got %d bytes, expected %d", len(rr.RDATA),
				rr.RDLENGTH)
	}

	mname, bytesRead, err := utils.UnmarshalName(rr.RDATA, 0, rr.fullPacket)

	if err != nil {
		return "", "", 0, 0, 0, 0, 0, fmt.Errorf("failed to unmarshal SOA MNAME: %w", err)
	}

	if bytesRead >= len(rr.RDATA) {
		return "", "", 0, 0, 0, 0, 0, fmt.Errorf("unexpected end of SOA record data")
	}

	rname, bytesRead2, err := utils.UnmarshalName(rr.RDATA[bytesRead:], 0, rr.fullPacket)

	if err != nil {
		return "", "", 0, 0, 0, 0, 0, fmt.Errorf("failed to unmarshal SOA RNAME: %w", err)
	}

	bytesRead += bytesRead2
	remainingLength := len(rr.RDATA) - bytesRead

	if remainingLength < fiveUint32s { // Ensure we have enough bytes for the 5 uint32 values
		return "", "", 0, 0, 0, 0, 0, fmt.Errorf("SOA record data too short: missing uint32 fields")
	}

	// Extract the 5 uint32 values
	serial = binary.BigEndian.Uint32(rr.RDATA[bytesRead : bytesRead+uint32ByteLength])
	bytesRead += uint32ByteLength

	refresh = binary.BigEndian.Uint32(rr.RDATA[bytesRead : bytesRead+uint32ByteLength])
	bytesRead += uint32ByteLength

	retry = binary.BigEndian.Uint32(rr.RDATA[bytesRead : bytesRead+uint32ByteLength])
	bytesRead += uint32ByteLength

	expire = binary.BigEndian.Uint32(rr.RDATA[bytesRead : bytesRead+uint32ByteLength])
	bytesRead += uint32ByteLength

	minimum = binary.BigEndian.Uint32(rr.RDATA[bytesRead : bytesRead+uint32ByteLength])

	return mname, rname, serial, refresh, retry, expire, minimum, nil
}

// GetRDATA just returns a raw (byte slice) RR.RDATA to the caller.
func (rr *RR) GetRDATA() []byte {
	return rr.RDATA
}

// MarshalBinary serializes an RR into a byte slice according to DNS protocol
func (rr *RR) MarshalBinary() ([]byte, error) {
	const uint16ByteLength int = 2
	const uint32ByteLength int = 4
	const TypeClassTTLRDLENGTHSize int = 3*uint16ByteLength + uint32ByteLength

	buf := make([]byte, 0)

	nameBytes, err := utils.MarshalName(rr.Name, buf, 0)
	if err != nil {
		return nil, err
	}
	buf = append(buf, nameBytes...)

	buf = append(buf, make([]byte, TypeClassTTLRDLENGTHSize)...)
	offset := len(nameBytes)

	binary.BigEndian.PutUint16(buf[offset:offset+uint16ByteLength], uint16(rr.Type))
	offset += uint16ByteLength

	binary.BigEndian.PutUint16(buf[offset:offset+uint16ByteLength], uint16(rr.Class))
	offset += uint16ByteLength

	binary.BigEndian.PutUint32(buf[offset:offset+uint32ByteLength], rr.TTL)
	offset += uint32ByteLength

	binary.BigEndian.PutUint16(buf[offset:offset+uint16ByteLength], rr.RDLENGTH)

	buf = append(buf, rr.RDATA...)

	return buf, nil
}

// Unmarshal parses a DNS RR from binary data.
func Unmarshal(data []byte, fullPacket []byte) (RR, int, error) {
	const uint16ByteLength int = 2
	const uint32ByteLength int = 4
	const TypeClassTTLRDLENGTHSize int = 3*uint16ByteLength + uint32ByteLength

	if len(data) < 1 { // Need at least 1 byte for the name
		return RR{}, 0, errors.New("incomplete answer: data too short")
	}

	a := RR{}
	bytesRead := 0
	a.fullPacket = fullPacket

	name, nameBytes, err := utils.UnmarshalName(data, 0, fullPacket)
	if err != nil {
		return RR{}, 0, err
	}
	a.Name = name
	bytesRead += nameBytes

	if len(data) < bytesRead+TypeClassTTLRDLENGTHSize { // type(2) + class(2) + ttl(4) + rdlength(2)
		return RR{}, 0, errors.New("incomplete answer: not enough bytes for fixed fields")
	}

	a.Type = DNS_Type.Type(binary.BigEndian.Uint16(data[bytesRead : bytesRead+uint16ByteLength]))
	bytesRead += uint16ByteLength

	a.Class = DNS_Class.Class(binary.BigEndian.Uint16(data[bytesRead : bytesRead+uint16ByteLength]))
	bytesRead += uint16ByteLength

	a.TTL = binary.BigEndian.Uint32(data[bytesRead : bytesRead+uint32ByteLength])
	bytesRead += uint32ByteLength

	a.RDLENGTH = binary.BigEndian.Uint16(data[bytesRead : bytesRead+uint16ByteLength])
	bytesRead += uint16ByteLength

	if len(data) < bytesRead+int(a.RDLENGTH) {
		return RR{}, 0, errors.New("incomplete answer: not enough bytes for RDATA")
	}

	a.RDATA = make([]byte, a.RDLENGTH)
	copy(a.RDATA, data[bytesRead:bytesRead+int(a.RDLENGTH)])
	bytesRead += int(a.RDLENGTH)

	return a, bytesRead, nil
}

// CopyRR creates a deep copy of a resource record, handling all supported DNS types
func CopyRR(old RR) (RR, error) {
	newCopy := RR{}
	newCopy.SetName(old.GetName())
	newCopy.SetClass(old.Class)
	if err := newCopy.SetTTL(int(old.GetTTL())); err != nil {
		return RR{}, fmt.Errorf("failed to set TTL: %w", err)
	}

	switch old.Type {
	case DNS_Type.A:
		ip, err := old.GetRDATAAsARecord()
		if err != nil {
			return RR{}, fmt.Errorf("failed to get A record: %w", err)
		}
		newCopy.SetRDATAToARecord(ip)

	case DNS_Type.NS:
		ns, err := old.GetRDATAAsNSRecord()
		if err != nil {
			return RR{}, fmt.Errorf("failed to get NS record: %w", err)
		}
		err = newCopy.SetRDATAToNSRecord(ns)
		if err != nil {
			return RR{}, fmt.Errorf("failed to set NS record: %w", err)
		}

	case DNS_Type.CNAME:
		cname, err := old.GetRDATAAsCNAMERecord()
		if err != nil {
			return RR{}, fmt.Errorf("failed to get CNAME record: %w", err)
		}
		err = newCopy.SetRDATAToCNAMERecord(cname)
		if err != nil {
			return RR{}, fmt.Errorf("failed to set CNAME record: %w", err)
		}

	case DNS_Type.SOA:
		mname, rname, serial, refresh, retry, expire, minimum, err := old.GetRDATAAsSOARecord()
		if err != nil {
			return RR{}, fmt.Errorf("failed to get SOA record: %w", err)
		}
		err = newCopy.SetRDATAToSOARecord(mname, rname, serial, refresh, retry, expire, minimum)
		if err != nil {
			return RR{}, fmt.Errorf("failed to set SOA record: %w", err)
		}

	case DNS_Type.MX:
		preference, exchange, err := old.GetRDATAAsMXRecord()
		if err != nil {
			return RR{}, fmt.Errorf("failed to get MX record: %w", err)
		}
		err = newCopy.SetRDATAToMXRecord(preference, exchange)
		if err != nil {
			return RR{}, fmt.Errorf("failed to set MX record: %w", err)
		}

	case DNS_Type.TXT:
		text, err := old.GetRDATAAsTXTRecord()
		if err != nil {
			return RR{}, fmt.Errorf("failed to get TXT record: %w", err)
		}
		newCopy.SetRDATAToTXTRecord(text)

	case DNS_Type.PTR:
		ptr, err := old.GetRDATAAsPTRRecord()
		if err != nil {
			return RR{}, fmt.Errorf("failed to get PTR record: %w", err)
		}
		err = newCopy.SetRDATAToPTRRecord(ptr)
		if err != nil {
			return RR{}, fmt.Errorf("failed to set PTR record: %w", err)
		}

	// For types without specific setters/getters (MD, MF, MB, MG, MR, NULL, WKS, HINFO, MINFO),
	// we'll just copy the raw RDATA
	case DNS_Type.MD, DNS_Type.MF, DNS_Type.MB, DNS_Type.MG, DNS_Type.MR,
		DNS_Type.NULL, DNS_Type.WKS, DNS_Type.HINFO, DNS_Type.MINFO:
		newCopy.SetType(old.Type)
		newCopy.SetRDATA(old.GetRDATA())

	default:
		newCopy.SetType(old.Type)
		newCopy.SetRDATA(old.GetRDATA())
	}

	return newCopy, nil
}
