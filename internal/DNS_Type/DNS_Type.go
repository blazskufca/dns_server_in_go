package DNS_Type

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
