package main

import (
	"errors"
	"fmt"
	"github.com/blazskufca/dns_server_in_go/internal/DNS_Class"
	"github.com/blazskufca/dns_server_in_go/internal/DNS_Type"
	"github.com/blazskufca/dns_server_in_go/internal/RR"

	"github.com/blazskufca/dns_server_in_go/internal/header"
	"github.com/blazskufca/dns_server_in_go/internal/question"
)

// Message represents a DNS message.
type Message struct {
	Header     header.Header
	Questions  []question.Question
	Answers    []RR.RR
	Authority  []RR.RR
	Additional []RR.RR
}

// UnmarshalBinary unmarshalls the Message from binary format which was sent across the wire.
// It fulfills the encoding.BinaryUnmarshaler interface.
func (msg *Message) UnmarshalBinary(buf []byte) error {
	curOffset := 12

	unmarshalledHeader, err := header.Unmarshal(buf[:curOffset])
	if err != nil {
		return err
	}
	if unmarshalledHeader == nil {
		return errors.New("unmarshalled nil header")
	}
	msg.Header = *unmarshalledHeader

	msg.Questions = make([]question.Question, msg.Header.GetQDCOUNT())
	for i := 0; i < int(msg.Header.GetQDCOUNT()); i++ {
		q, bytesRead, err := question.Unmarshal(buf[curOffset:], buf)
		if err != nil {
			fmt.Println("Failed to unmarshal question:", err)
			continue
		}
		msg.Questions[i] = q
		curOffset += bytesRead
	}

	msg.Answers = make([]RR.RR, 0, msg.Header.GetANCOUNT())
	for i := 0; i < int(msg.Header.GetANCOUNT()); i++ {
		if curOffset >= len(buf) {
			break
		}
		ans, bytesRead, err := RR.Unmarshal(buf[curOffset:], buf)
		if err != nil {
			fmt.Println("Failed to unmarshal answer:", err)
			break
		}
		msg.Answers = append(msg.Answers, ans)
		curOffset += bytesRead
	}

	msg.Authority = make([]RR.RR, 0, msg.Header.GetNSCOUNT())
	for i := 0; i < int(msg.Header.GetNSCOUNT()); i++ {
		if curOffset >= len(buf) {
			break
		}
		auth, bytesRead, err := RR.Unmarshal(buf[curOffset:], buf)
		if err != nil {
			fmt.Println("Failed to unmarshal authority:", err)
			break
		}
		msg.Authority = append(msg.Authority, auth)
		curOffset += bytesRead
	}

	msg.Additional = make([]RR.RR, 0, msg.Header.GetARCOUNT())
	for i := 0; i < int(msg.Header.GetARCOUNT()); i++ {
		if curOffset >= len(buf) {
			break
		}
		add, bytesRead, err := RR.Unmarshal(buf[curOffset:], buf)
		if err != nil {
			fmt.Println("Failed to unmarshal additional:", err)
			break
		}
		msg.Additional = append(msg.Additional, add)
		curOffset += bytesRead
	}

	return nil
}

// MarshalBinary marshals the Message into binary format which will be sent across the wire.
// It fulfills the encoding.BinaryMarshaler interface.
func (msg *Message) MarshalBinary() ([]byte, error) {
	headerBytes, err := msg.Header.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header: %w", err)
	}

	result := headerBytes

	for _, q := range msg.Questions {
		qBytes, err := q.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal question: %w", err)
		}
		result = append(result, qBytes...)
	}

	for _, a := range msg.Answers {
		aBytes, err := a.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal answer: %w", err)
		}
		result = append(result, aBytes...)
	}

	for _, auth := range msg.Authority {
		authBytes, err := auth.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal authority: %w", err)
		}
		result = append(result, authBytes...)
	}

	for _, add := range msg.Additional {
		addBytes, err := add.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal additional: %w", err)
		}
		result = append(result, addBytes...)
	}

	return result, nil
}

func (msg *Message) Copy(source *Message) error {
	if msg == nil {
		return errors.New("copy got nil message")
	}
	msg.Header = source.Header
	msg.Questions = source.Questions
	msg.Answers = make([]RR.RR, len(source.Answers), len(source.Answers))
	msg.Authority = make([]RR.RR, len(source.Authority), len(source.Authority))
	msg.Additional = make([]RR.RR, len(source.Additional), len(source.Additional))

	for i, a := range source.Answers {
		newA := RR.RR{}
		newA.Class = a.Class
		newA.TTL = a.TTL
		newA.Name = a.Name

		switch a.Type {
		case DNS_Type.A:
			ip, err := a.GetRDATAAsARecord()
			if err != nil {
				return err
			}
			newA.SetRDATAToARecord(ip)

		case DNS_Type.NS:
			ns, err := a.GetRDATAAsNSRecord()
			if err != nil {
				return err
			}
			err = newA.SetRDATAToNSRecord(ns)
			if err != nil {
				return err
			}

		case DNS_Type.CNAME:
			cname, err := a.GetRDATAAsCNAMERecord()
			if err != nil {
				return err
			}
			err = newA.SetRDATAToCNAMERecord(cname)
			if err != nil {
				return err
			}

		case DNS_Type.SOA:
			mname, rname, serial, refresh, retry, expire, minimum, err := a.GetRDATAAsSOARecord()
			if err != nil {
				return err
			}
			err = newA.SetRDATAToSOARecord(mname, rname, serial, refresh, retry, expire, minimum)
			if err != nil {
				return err
			}

		case DNS_Type.MX:
			preference, exchange, err := a.GetRDATAAsMXRecord()
			if err != nil {
				return err
			}
			err = newA.SetRDATAToMXRecord(preference, exchange)
			if err != nil {
				return err
			}

		case DNS_Type.TXT:
			text, err := a.GetRDATAAsTXTRecord()
			if err != nil {
				return err
			}
			newA.SetRDATAToTXTRecord(text)

		case DNS_Type.PTR:
			ptr, err := a.GetRDATAAsPTRRecord()
			if err != nil {
				return err
			}
			err = newA.SetRDATAToPTRRecord(ptr)
			if err != nil {
				return err
			}

		// For types without specific setters/getters (MD, MF, MB, MG, MR, NULL, WKS, HINFO, MINFO),
		// we'll just copy the raw RDATA
		case DNS_Type.MD, DNS_Type.MF, DNS_Type.MB, DNS_Type.MG, DNS_Type.MR,
			DNS_Type.NULL, DNS_Type.WKS, DNS_Type.HINFO, DNS_Type.MINFO:
			newA.Type = a.Type
			newA.SetRDATA(a.GetRDATA())

		default:
			// For any unhandled types, copy the raw RDATA and type
			newA.Type = a.Type
			newA.SetRDATA(a.GetRDATA())
		}
		msg.Answers[i] = newA
	}
	for i, a := range source.Authority {
		newA := RR.RR{}
		newA.Class = a.Class
		newA.TTL = a.TTL
		newA.Name = a.Name

		switch a.Type {
		case DNS_Type.A:
			ip, err := a.GetRDATAAsARecord()
			if err != nil {
				return err
			}
			newA.SetRDATAToARecord(ip)

		case DNS_Type.NS:
			ns, err := a.GetRDATAAsNSRecord()
			if err != nil {
				return err
			}
			err = newA.SetRDATAToNSRecord(ns)
			if err != nil {
				return err
			}

		case DNS_Type.CNAME:
			cname, err := a.GetRDATAAsCNAMERecord()
			if err != nil {
				return err
			}
			err = newA.SetRDATAToCNAMERecord(cname)
			if err != nil {
				return err
			}

		case DNS_Type.SOA:
			mname, rname, serial, refresh, retry, expire, minimum, err := a.GetRDATAAsSOARecord()
			if err != nil {
				return err
			}
			err = newA.SetRDATAToSOARecord(mname, rname, serial, refresh, retry, expire, minimum)
			if err != nil {
				return err
			}

		case DNS_Type.MX:
			preference, exchange, err := a.GetRDATAAsMXRecord()
			if err != nil {
				return err
			}
			err = newA.SetRDATAToMXRecord(preference, exchange)
			if err != nil {
				return err
			}

		case DNS_Type.TXT:
			text, err := a.GetRDATAAsTXTRecord()
			if err != nil {
				return err
			}
			newA.SetRDATAToTXTRecord(text)

		case DNS_Type.PTR:
			ptr, err := a.GetRDATAAsPTRRecord()
			if err != nil {
				return err
			}
			err = newA.SetRDATAToPTRRecord(ptr)
			if err != nil {
				return err
			}

		// For types without specific setters/getters (MD, MF, MB, MG, MR, NULL, WKS, HINFO, MINFO),
		// we'll just copy the raw RDATA
		case DNS_Type.MD, DNS_Type.MF, DNS_Type.MB, DNS_Type.MG, DNS_Type.MR,
			DNS_Type.NULL, DNS_Type.WKS, DNS_Type.HINFO, DNS_Type.MINFO:
			newA.Type = a.Type
			newA.SetRDATA(a.GetRDATA())

		default:
			// For any unhandled types, copy the raw RDATA and type
			newA.Type = a.Type
			newA.SetRDATA(a.GetRDATA())
		}
		msg.Authority[i] = newA
	}
	for i, a := range source.Additional {
		newA := RR.RR{}
		newA.Class = a.Class
		newA.TTL = a.TTL
		newA.Name = a.Name

		switch a.Type {
		case DNS_Type.A:
			ip, err := a.GetRDATAAsARecord()
			if err != nil {
				return err
			}
			newA.SetRDATAToARecord(ip)

		case DNS_Type.NS:
			ns, err := a.GetRDATAAsNSRecord()
			if err != nil {
				return err
			}
			err = newA.SetRDATAToNSRecord(ns)
			if err != nil {
				return err
			}

		case DNS_Type.CNAME:
			cname, err := a.GetRDATAAsCNAMERecord()
			if err != nil {
				return err
			}
			err = newA.SetRDATAToCNAMERecord(cname)
			if err != nil {
				return err
			}

		case DNS_Type.SOA:
			mname, rname, serial, refresh, retry, expire, minimum, err := a.GetRDATAAsSOARecord()
			if err != nil {
				return err
			}
			err = newA.SetRDATAToSOARecord(mname, rname, serial, refresh, retry, expire, minimum)
			if err != nil {
				return err
			}

		case DNS_Type.MX:
			preference, exchange, err := a.GetRDATAAsMXRecord()
			if err != nil {
				return err
			}
			err = newA.SetRDATAToMXRecord(preference, exchange)
			if err != nil {
				return err
			}

		case DNS_Type.TXT:
			text, err := a.GetRDATAAsTXTRecord()
			if err != nil {
				return err
			}
			newA.SetRDATAToTXTRecord(text)

		case DNS_Type.PTR:
			ptr, err := a.GetRDATAAsPTRRecord()
			if err != nil {
				return err
			}
			err = newA.SetRDATAToPTRRecord(ptr)
			if err != nil {
				return err
			}

		// For types without specific setters/getters (MD, MF, MB, MG, MR, NULL, WKS, HINFO, MINFO),
		// we'll just copy the raw RDATA
		case DNS_Type.MD, DNS_Type.MF, DNS_Type.MB, DNS_Type.MG, DNS_Type.MR,
			DNS_Type.NULL, DNS_Type.WKS, DNS_Type.HINFO, DNS_Type.MINFO:
			newA.Type = a.Type
			newA.SetRDATA(a.GetRDATA())

		default:
			// For any unhandled types, copy the raw RDATA and type
			newA.Type = a.Type
			newA.SetRDATA(a.GetRDATA())
		}
		msg.Additional[i] = newA
	}
	err := msg.Header.SetANCOUNT(len(msg.Answers))
	if err != nil {
		return err
	}
	err = msg.Header.SetARCOUNT(len(msg.Additional))
	if err != nil {
		return err
	}
	err = msg.Header.SetNSCOUNT(len(msg.Authority))
	if err != nil {
		return err
	}
	return nil
}

// AddQuestion adds a question to the Message.Questions slice and increments the Message.Header.QDCOUNT
func (msg *Message) AddQuestion(q question.Question) error {
	msg.Questions = append(msg.Questions, q)
	return msg.Header.SetQDCOUNT(int(msg.Header.GetQDCOUNT()) + 1)
}

// createDNSQuery creates a new DNS query message
func createDNSQuery(name string, qtype DNS_Type.Type, qclass DNS_Class.Class, desireRecursion bool) (Message, error) {
	msg := Message{}
	err := msg.Header.SetRandomID()
	if err != nil {
		return Message{}, err
	}
	msg.Header.SetQRFlag(false)
	msg.Header.SetRD(desireRecursion)

	quest := question.Question{}
	quest.SetName(name)
	quest.SetType(qtype)
	quest.SetClass(qclass)
	err = msg.AddQuestion(quest)
	if err != nil {
		return Message{}, err
	}
	return msg, nil
}
