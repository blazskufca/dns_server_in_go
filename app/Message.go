package main

import (
	"encoding/binary"
	"errors"
	"fmt"
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
	// Inform this message is too long per RFC 1035 so a Truncation flag will be set
	// DNS RFCs tells us this will normally result in query being retried via TCP
	if binary.Size(*msg) > 512 {
		msg.Header.SetTC(true)
	}

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
