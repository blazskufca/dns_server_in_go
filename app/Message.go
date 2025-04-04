package main

import (
	"errors"
	"fmt"
	"github.com/codecrafters-io/dns-server-starter-go/internal/answer"
	"github.com/codecrafters-io/dns-server-starter-go/internal/header"
	"github.com/codecrafters-io/dns-server-starter-go/internal/question"
)

type Message struct {
	Header    header.Header
	Questions []question.Question
	Answers   []answer.Answer
	RawData   []byte
}

func (msg *Message) UnmarshalBinary(buf []byte) error {
	if len(buf) > 512 {
		return errors.New("message can not be larger than 512 bytes per RFC 1035")
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
		q, bytesRead, err := question.Unmarshal(buf[curOffset:])
		if err != nil {
			fmt.Println("Failed to unmarshal question:", err)
			continue
		}
		msg.Questions[i] = q
		curOffset += bytesRead
	}

	msg.Answers = make([]answer.Answer, 0, msg.Header.GetANCOUNT())
	for i := 0; i < int(msg.Header.GetANCOUNT()); i++ {
		if curOffset >= len(buf) {
			break
		}
		ans, bytesRead, err := answer.Unmarshal(buf[curOffset:])
		if err != nil {
			fmt.Println("Failed to unmarshal answer:", err)
			break
		}
		msg.Answers = append(msg.Answers, ans)
		curOffset += bytesRead
	}

	return nil
}

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

	return result, nil
}
