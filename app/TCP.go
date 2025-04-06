package main

import (
	"encoding/binary"
	"fmt"
	"github.com/blazskufca/dns_server_in_go/internal/header"
	"github.com/blazskufca/dns_server_in_go/internal/utils"
	"io"
	"log/slog"
	"math"
	"net"
	"time"
)

// startTCPServer starts a TCP server on which a client usually calls if DNS Message is truncated.
func (s *DNSServer) startTCPServer() {
	s.wg.Add(1)
	defer s.wg.Done()
	for {
		conn, err := s.tcpListener.Accept()
		if err != nil {
			s.logger.Error("failed to accept TCP connection", slog.Any("error", err))
			continue
		}

		s.wg.Add(1)
		go s.handleTCPConnection(conn)
	}
}

// handleTCPConnection handles incoming DNS queries on a TCP server.
// DNS Message's over TCP are prefixed with 2 byte (uint16) message length.
func (s *DNSServer) handleTCPConnection(conn net.Conn) {
	defer conn.Close()
	defer s.wg.Done()

	const lenPrefix = 2

	err := conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		s.logger.Error("failed to set connection deadline", slog.Any("error", err))
		return
	}

	lenBuf := make([]byte, lenPrefix)
	_, err = io.ReadFull(conn, lenBuf)
	if err != nil {
		s.logger.Error("failed to read message length", slog.Any("error", err))
		return
	}

	msgLen := binary.BigEndian.Uint16(lenBuf)
	if msgLen == 0 {
		s.logger.Error("received empty message or message length is missing", slog.Any("message_len", msgLen))
		return
	}

	msgBuf := make([]byte, msgLen)
	_, err = io.ReadFull(conn, msgBuf)
	if err != nil {
		s.logger.Error("failed to read message", slog.Any("error", err))
		return
	}

	response, err := s.processDNSRequestTCP(msgBuf)
	if err != nil {
		s.logger.Error("failed to process TCP DNS request", slog.Any("error", err))
		return
	}

	if utils.WouldOverflowUint16(len(response)) {
		s.logger.Error("response too large", slog.Any("response_size", len(response)),
			slog.Any("uint16_max", math.MaxUint16))
		return
	}
	lenBytes := make([]byte, lenPrefix)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(response)))

	_, err = conn.Write(append(lenBytes, response...))
	if err != nil {
		s.logger.Error("failed to write TCP response", slog.Any("error", err))
		return
	}
}

// processDNSRequestTCP takes care of incoming DNS request on TCP connection
func (s *DNSServer) processDNSRequestTCP(data []byte) ([]byte, error) {
	msg := Message{}
	err := msg.UnmarshalBinary(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal DNS request: %w", err)
	}

	s.logger.Debug("Received TCP DNS query",
		slog.String("question", msg.Questions[0].Name),
		slog.Any("type", msg.Questions[0].Type))

	if len(msg.Questions) == 0 {
		return nil, fmt.Errorf("DNS request contains no questions")
	}

	if len(msg.Questions) > 1 {
		s.logger.Warn("Multiple questions in TCP request, only processing the first one",
			slog.Int("question_count", len(msg.Questions)))

		msg.Questions = msg.Questions[:1]
		err = msg.Header.SetQDCOUNT(1)
		if err != nil {
			s.logger.Error("Failed to update question count", slog.Any("error", err))
		}
	}

	if msg.Header.IsRD() && s.recursive {
		response, err := s.resolveRecursively(&msg)
		if err != nil {
			return nil, fmt.Errorf("recursive resolution failed: %w", err)
		}
		return response.MarshalBinary()
	} else {
		msg.Header.SetQRFlag(false)
		queryData, err := msg.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("error marshalling query: %w", err)
		}

		msgData, err := s.forwardToResolverTCP(queryData)
		if err != nil {
			return nil, fmt.Errorf("error forwarding question via TCP: %w", err)
		}
		if msgData == nil {
			return nil, fmt.Errorf("error forwarding question via TCP: message is nil")
		}
		if msgData.Header.GetRCODE() != header.NoError {
			return nil, fmt.Errorf("error forwarding question via TCP: message has unexpected RCODE %v", msgData.Header.GetRCODE())
		}
		if msgData.Header.GetMessageID() != msg.Header.GetMessageID() {
			return nil, fmt.Errorf("error forwading question via TCP: mismatched message ID - Sent %v but got %v",
				msg.Header.GetMessageID(), msgData.Header.GetMessageID())
		}
		return msgData.MarshalBinary()
	}
}

// forwardToResolverTCP sends a DNS Message to upstream resolver via a TCP connection.
// As with reading from TCP socket, DNS messages are prefixed with uint16 message length
func (s *DNSServer) forwardToResolverTCP(query []byte) (*Message, error) {
	conn, err := net.DialTimeout("tcp4", s.resolverHost, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to resolver via TCP: %w", err)
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return nil, fmt.Errorf("failed to set connection deadline: %w", err)
	}

	lenBuf := make([]byte, 2)
	queryLen := len(query)

	if utils.WouldOverflowUint32(queryLen) {
		return nil, fmt.Errorf("query length overflow")
	}

	binary.BigEndian.PutUint16(lenBuf, uint16(queryLen))

	_, err = conn.Write(append(lenBuf, query...))
	if err != nil {
		return nil, fmt.Errorf("failed to send query to resolver via TCP: %w", err)
	}

	lenBuf = make([]byte, 2)
	_, err = io.ReadFull(conn, lenBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to read response length from resolver: %w", err)
	}
	responseLen := binary.BigEndian.Uint16(lenBuf)
	response := make([]byte, responseLen)
	_, err = io.ReadFull(conn, response)
	if err != nil {
		return nil, fmt.Errorf("failed to read response from resolver: %w", err)
	}
	responseMsg := Message{}
	err = responseMsg.UnmarshalBinary(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response from resolver: %w", err)
	}

	return &responseMsg, nil
}

// queryNameserverTCP sends a query to a specific nameserver using TCP and returns the response
func (s *DNSServer) queryNameserverTCP(serverIP net.IP, query *Message) (*Message, error) {
	if query == nil {
		return nil, fmt.Errorf("queryNameServerTCP got nil query")
	}
	queryData, err := query.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TCP query: %w", err)
	}

	serverAddr := net.TCPAddr{
		IP:   serverIP,
		Port: 53,
	}

	conn, err := net.DialTCP("tcp", nil, &serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to nameserver %s via TCP: %w", serverIP.String(), err)
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return nil, fmt.Errorf("failed to set TCP connection deadline: %w", err)
	}

	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(queryData)))

	_, err = conn.Write(append(lenBuf, queryData...))
	if err != nil {
		return nil, fmt.Errorf("failed to send TCP query to nameserver %s: %w", serverIP.String(), err)
	}

	respLenBuf := make([]byte, 2)
	_, err = io.ReadFull(conn, respLenBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCP response length from nameserver %s: %w", serverIP.String(), err)
	}

	respLen := binary.BigEndian.Uint16(respLenBuf)
	if respLen == 0 {
		return nil, fmt.Errorf("received empty TCP response from nameserver %s", serverIP.String())
	}

	responseData := make([]byte, respLen)
	_, err = io.ReadFull(conn, responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCP response from nameserver %s: %w", serverIP.String(), err)
	}

	response := &Message{}
	err = response.UnmarshalBinary(responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal TCP response from nameserver %s: %w", serverIP.String(), err)
	}
	if response.Header.GetRCODE() != header.NoError {
		return nil, fmt.Errorf("failed to query nameserver with unexpected RCODE %v", response.Header.GetRCODE())
	}
	if response.Header.GetMessageID() != query.Header.GetMessageID() {
		return nil, fmt.Errorf("failed to query nameserver with unexpected message ID: sent %v but got %v",
			query.Header.GetMessageID(), response.Header.GetMessageID())
	}
	return response, nil
}
