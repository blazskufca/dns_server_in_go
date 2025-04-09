package Message

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
	Questions  []question.Question
	Answers    []RR.RR
	Authority  []RR.RR
	Additional []RR.RR
	Header     header.Header
}

// UnmarshalBinary unmarshalls the Message from binary format which was sent across the wire.
// It fulfills the encoding.BinaryUnmarshaler interface.
func (msg *Message) UnmarshalBinary(buf []byte) error {
	if buf == nil {
		return errors.New("Message.UnmarshalBinary: nil buffer")
	}
	if len(buf) == 0 {
		return errors.New("Message.UnmarshalBinary: empty buffer")
	}
	if len(buf) < 12 {
		return errors.New("Message.UnmarshalBinary: buffer too short")
	}

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
			return err
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
			return err
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
			return err
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
			return err
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

func Copy(source *Message) (Message, error) {
	if source == nil {
		return Message{}, errors.New("copy got nil message")
	}

	msg := Message{}
	msg.Header = source.Header
	msg.Questions = source.Questions
	msg.Answers = make([]RR.RR, len(source.Answers), len(source.Answers))          // nolint:gosimple
	msg.Authority = make([]RR.RR, len(source.Authority), len(source.Authority))    // nolint:gosimple
	msg.Additional = make([]RR.RR, len(source.Additional), len(source.Additional)) // nolint:gosimple

	for i, a := range source.Answers {
		newA, err := RR.CopyRR(a)
		if err != nil {
			return Message{}, fmt.Errorf("failed to copy answer record: %w", err)
		}
		msg.Answers[i] = newA
	}

	for i, a := range source.Authority {
		newA, err := RR.CopyRR(a)
		if err != nil {
			return Message{}, fmt.Errorf("failed to copy authority record: %w", err)
		}
		msg.Authority[i] = newA
	}

	for i, a := range source.Additional {
		newA, err := RR.CopyRR(a)
		if err != nil {
			return Message{}, fmt.Errorf("failed to copy additional record: %w", err)
		}
		msg.Additional[i] = newA
	}

	// Update header counts
	if err := msg.Header.SetANCOUNT(len(msg.Answers)); err != nil {
		return Message{}, err
	}
	if err := msg.Header.SetARCOUNT(len(msg.Additional)); err != nil {
		return Message{}, err
	}
	if err := msg.Header.SetNSCOUNT(len(msg.Authority)); err != nil {
		return Message{}, err
	}

	return msg, nil
}

// AddQuestion adds a question to the Message.Questions slice and increments the Message.Header.QDCOUNT
func (msg *Message) AddQuestion(q question.Question) error {
	msg.Questions = append(msg.Questions, q)
	return msg.Header.SetQDCOUNT(int(msg.Header.GetQDCOUNT()) + 1)
}

// CreateDNSQuery creates a new DNS query message
func CreateDNSQuery(name string, qtype DNS_Type.Type, qclass DNS_Class.Class, desireRecursion bool) (Message, error) {
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

// New creates a new Message from data
func New(Data []byte) (Message, error) {
	msg := Message{}
	err := msg.UnmarshalBinary(Data)
	if err != nil {
		return Message{}, err
	}
	return msg, nil
}
