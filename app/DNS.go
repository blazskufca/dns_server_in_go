package main

import (
	"encoding/binary"
	"fmt"
	"github.com/blazskufca/dns_server_in_go/internal/RR"
	"github.com/blazskufca/dns_server_in_go/internal/header"
	"github.com/blazskufca/dns_server_in_go/internal/question"
	"github.com/blazskufca/dns_server_in_go/internal/utils"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"sync"
	"time"
)

type DNSServer struct {
	udpConn      *net.UDPConn
	tcpListener  net.Listener
	resolverAddr *net.UDPAddr
	resolverHost string
	wg           sync.WaitGroup
	logger       *slog.Logger
}

// New creates a new DNSServer with initialized UDP, TCP listener and a forwarder.
func New(address string, resolverAddr string, logger *slog.Logger) (*DNSServer, func(), error) {
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve UDP address: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen UDP address: %w", err)
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		udpConn.Close()
		return nil, nil, fmt.Errorf("failed to resolve TCP address: %w", err)
	}

	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		udpConn.Close()
		return nil, nil, fmt.Errorf("failed to listen on TCP address: %w", err)
	}

	resolver, err := net.ResolveUDPAddr("udp", resolverAddr)
	if err != nil {
		udpConn.Close()
		tcpListener.Close()
		return nil, nil, fmt.Errorf("failed to resolve resolver address: %w", err)
	}

	server := &DNSServer{
		udpConn:      udpConn,
		tcpListener:  tcpListener,
		resolverAddr: resolver,
		resolverHost: resolverAddr,
	}

	cleanup := func() {
		server.wg.Wait()
		udpConn.Close()
		tcpListener.Close()
	}

	if logger != nil {
		server.logger = logger
	} else {
		server.logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			AddSource:   true,
			Level:       slog.LevelDebug,
			ReplaceAttr: nil,
		}))
	}

	return server, cleanup, nil
}

// Start starts the TCP and the UDP servers and starts listening on them for incoming DNS queries.
func (s *DNSServer) Start() {
	s.logger.Info("Starting DNS forwarder with resolver", slog.Any("resolver", *s.resolverAddr), slog.Any("listener", s.udpConn.LocalAddr()))
	s.logger.Info("TCP listener started", slog.Any("listener", s.tcpListener.Addr()))

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.startTCPServer()
	}()

	for {
		buf := make([]byte, 512)
		n, addr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			s.logger.Error("failed to read from UDP connection", slog.Any("error", err))
			continue
		}

		s.wg.Add(1)

		go s.handleDNSRequest(buf[:n], addr)
	}
}

// startTCPServer starts a TCP server on which a client usually calls if DNS Message is truncated.
func (s *DNSServer) startTCPServer() {
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
		s.logger.Error("received empty message")
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

func (s *DNSServer) processDNSRequestTCP(data []byte) ([]byte, error) {
	msg := Message{}
	err := msg.UnmarshalBinary(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal DNS request: %w", err)
	}

	s.logger.Debug("Received TCP DNS query",
		slog.Any("num_questions_in_query", len(msg.Questions)))

	if len(msg.Questions) == 0 {
		return nil, fmt.Errorf("DNS request contains no questions")
	}

	if len(msg.Questions) > 1 {
		mergedResponse := Message{
			Header:    msg.Header,
			Questions: msg.Questions,
			Answers:   make([]RR.RR, 0),
		}

		mergedResponse.Header.SetQRFlag(true)
		mergedResponse.Header.SetRCODE(header.NoError)

		successfulQueries := 0
		for _, q := range msg.Questions {
			singleMsg := Message{
				Header:    msg.Header,
				Questions: []question.Question{q},
			}
			err = singleMsg.Header.SetQDCOUNT(1)
			if err != nil {
				return nil, fmt.Errorf("failed to set QDCOUNT: %w", err)
			}
			err = singleMsg.Header.SetANCOUNT(0)
			if err != nil {
				return nil, fmt.Errorf("failed to set ANCOUNT: %w", err)
			}
			err = singleMsg.Header.SetNSCOUNT(0)
			if err != nil {
				return nil, fmt.Errorf("failed to set NSCOUNT: %w", err)
			}
			err = singleMsg.Header.SetARCOUNT(0)
			if err != nil {
				return nil, fmt.Errorf("failed to set ARCOUNT: %w", err)
			}

			queryData, err := singleMsg.MarshalBinary()
			if err != nil {
				s.logger.Error("failed to marshal DNS query", slog.Any("error", err))
				continue
			}

			responseData, err := s.forwardToResolverTCP(queryData)
			if err != nil {
				s.logger.Error("error forwarding question via TCP", slog.Any("question_name", q.Name),
					slog.Any("error", err))
				continue
			}

			if responseData.Header.GetRCODE() != header.NoError {
				s.logger.Warn("Resolver returned error",
					slog.Any("question", q.Name),
					slog.Any("error_code", responseData.Header.GetRCODE()))
			}

			mergedResponse.Answers = append(mergedResponse.Answers, responseData.Answers...)
			successfulQueries++
		}

		if successfulQueries == 0 {
			return nil, fmt.Errorf("all queries failed")
		}

		err = mergedResponse.Header.SetANCOUNT(len(mergedResponse.Answers))
		if err != nil {
			return nil, fmt.Errorf("failed to set ANCOUNT: %w", err)
		}

		return mergedResponse.MarshalBinary()
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
		msgDataBytes, err := msgData.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("error marshalling message: %w", err)
		}
		return msgDataBytes, nil
	}
}

// handleDNSRequest processes a single DNS request and sends a response
func (s *DNSServer) handleDNSRequest(data []byte, addr *net.UDPAddr) {
	defer s.wg.Done()
	msg := Message{}
	err := msg.UnmarshalBinary(data)
	if err != nil {
		s.logger.Error("failed to unmarshal DNS request", slog.Any("error", err))
		s.sendErrorResponse(data, addr, header.FormatError)
		return
	}

	s.logger.Debug("Received DNS query from", slog.Any("from", addr.String()),
		slog.Any("num_questions_in_query", len(msg.Questions)))

	if len(msg.Questions) == 0 {
		s.logger.Error("DNS request contains no questions")
		s.sendErrorResponse(data, addr, header.FormatError)
		return
	}

	if len(msg.Questions) > 1 {
		mergedResponse := Message{
			Header:    msg.Header,
			Questions: msg.Questions,
			Answers:   make([]RR.RR, 0),
		}

		mergedResponse.Header.SetQRFlag(true)
		mergedResponse.Header.SetRCODE(header.NoError)

		successfulQueries := 0
		for _, q := range msg.Questions {
			singleMsg := Message{
				Header:    msg.Header,
				Questions: []question.Question{q},
			}
			err = singleMsg.Header.SetQDCOUNT(1)
			if err != nil {
				s.logger.Error("failed to set QDCOUNT", slog.Any("error", err))
				s.sendErrorResponse(data, addr, header.FormatError)
				return
			}
			err = singleMsg.Header.SetANCOUNT(0)
			if err != nil {
				s.logger.Error("failed to set single ANCOUNT", slog.Any("error", err))
				s.sendErrorResponse(data, addr, header.FormatError)
				return
			}
			err = singleMsg.Header.SetNSCOUNT(0)
			if err != nil {
				s.logger.Error("failed to set NSCOUNT", slog.Any("error", err))
				s.sendErrorResponse(data, addr, header.FormatError)
				return
			}
			err = singleMsg.Header.SetARCOUNT(0)
			if err != nil {
				s.logger.Error("failed to set ARCOUNT", slog.Any("error", err))
				s.sendErrorResponse(data, addr, header.FormatError)
				return
			}

			queryData, err := singleMsg.MarshalBinary()
			if err != nil {
				s.logger.Error("failed to marshal DNS query", slog.Any("error", err))
				continue
			}

			responseData, err := s.forwardToResolver(queryData)
			if err != nil {
				s.logger.Error("error forwarding question", slog.Any("question_name", q.Name),
					slog.Any("error", err))
				continue
			}

			if responseData.Header.IsTC() {
				s.logger.Info("Received truncated response from resolver. Preserving TC flag for client to retry via TCP.",
					slog.Any("question", q.Name))
			}

			if responseData.Header.GetRCODE() != header.NoError {
				s.logger.Warn("Resolver returned error",
					slog.Any("question", q.Name),
					slog.Any("error_code", responseData.Header.GetRCODE()))
			}

			mergedResponse.Answers = append(mergedResponse.Answers, responseData.Answers...)
			successfulQueries++
		}

		if successfulQueries == 0 {
			s.logger.Error("All queries failed", slog.Any("question_count", len(msg.Questions)))
			s.sendErrorResponse(data, addr, header.ServerFailure)
			return
		}

		err = mergedResponse.Header.SetANCOUNT(len(mergedResponse.Answers))
		if err != nil {
			s.logger.Error("failed to set ANCOUNT", slog.Any("error", err))
			s.sendErrorResponse(data, addr, header.ServerFailure)
			return
		}

		responseData, err := mergedResponse.MarshalBinary()
		if err != nil {
			s.logger.Error("Error marshalling merged response", slog.Any("error", err))
			s.sendErrorResponse(data, addr, header.ServerFailure)
			return
		}

		_, err = s.udpConn.WriteToUDP(responseData, addr)
		if err != nil {
			s.logger.Error("Error sending merged response", slog.Any("error", err), slog.Any("to_address", addr.String()))
		}
	} else {
		msg.Header.SetQRFlag(false)
		queryData, err := msg.MarshalBinary()
		if err != nil {
			s.logger.Error("Error marshalling query", slog.Any("error", err), slog.Any("to_address", addr.String()))
			s.sendErrorResponse(data, addr, header.ServerFailure)
			return
		}

		responseData, err := s.forwardToResolver(queryData)
		if err != nil {
			s.logger.Error("Error forwarding request", slog.Any("error", err))
			s.sendErrorResponse(data, addr, header.ServerFailure)
			return
		}

		if responseData.Header.IsTC() {
			s.logger.Info("Received truncated response from resolver. Preserving TC flag for client to retry via TCP.",
				slog.Any("question", responseData.Questions[0].Name))
		}

		marshalledData, err := responseData.MarshalBinary()
		if err != nil {
			s.logger.Error("Error marshalling response", slog.Any("error", err))
			s.sendErrorResponse(data, addr, header.ServerFailure)
			return
		}

		_, err = s.udpConn.WriteToUDP(marshalledData, addr)
		if err != nil {
			s.logger.Error("Error sending response", slog.Any("to_address", addr.String()), slog.Any("error", err))
		}
	}

	s.logger.Info("Processed request", slog.Any("from", addr.String()))
}

// sendErrorResponse sends a DNS error response with the specified error code
func (s *DNSServer) sendErrorResponse(data []byte, addr *net.UDPAddr, errorCode header.ResponseCode) {
	var h header.Header

	if len(data) >= 12 {
		originalHeader, err := header.Unmarshal(data[:12])
		if err == nil && originalHeader != nil {
			h = *originalHeader
		} else {
			h = header.Header{}
		}
	} else {
		h = header.Header{}
	}

	h.SetQRFlag(true)
	h.SetRCODE(errorCode)

	var questions []question.Question
	if len(data) >= 12 {
		msg := Message{}
		if err := msg.UnmarshalBinary(data); err == nil {
			questions = msg.Questions
		}
	}

	errorMsg := Message{
		Header:    h,
		Questions: questions,
		Answers:   []RR.RR{},
	}

	err := h.SetQDCOUNT(len(questions))
	if err != nil {
		s.logger.Error("failed to set QDCOUNT", slog.Any("error", err))
		return
	}
	err = h.SetANCOUNT(0)
	if err != nil {
		s.logger.Error("failed to set ANCOUNT", slog.Any("error", err))
		return
	}
	err = h.SetNSCOUNT(0)
	if err != nil {
		s.logger.Error("failed to set NSCOUNT", slog.Any("error", err))
		return
	}
	err = h.SetARCOUNT(0)
	if err != nil {
		s.logger.Error("failed to set ARCOUNT", slog.Any("error", err))
		return
	}

	responseData, err := errorMsg.MarshalBinary()
	if err != nil {
		s.logger.Error("Failed to marshal error response", slog.Any("error", err))
		return
	}

	_, err = s.udpConn.WriteToUDP(responseData, addr)
	if err != nil {
		s.logger.Error("Failed to send error response",
			slog.Any("error", err),
			slog.Any("to_address", addr.String()),
			slog.Any("error_code", errorCode))
		return
	} else {
		s.logger.Info("Sent error response",
			slog.Any("to_address", addr.String()),
			slog.Any("error_code", errorCode))
	}
}

func (s *DNSServer) forwardToResolver(query []byte) (*Message, error) {
	conn, err := net.DialTimeout("udp4", s.resolverAddr.String(), 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to resolver: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write(query)
	if err != nil {
		return nil, fmt.Errorf("failed to send query to resolver: %w", err)
	}

	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to receive response from resolver: %w", err)
	}

	msg := &Message{}
	err = msg.UnmarshalBinary(response[:n])
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response from resolver: %w", err)
	}

	return msg, nil
}

func (s *DNSServer) forwardToResolverTCP(query []byte) (*Message, error) {
	conn, err := net.DialTimeout("tcp", s.resolverHost, 5*time.Second)
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
