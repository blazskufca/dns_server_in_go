package DNS_Class

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
