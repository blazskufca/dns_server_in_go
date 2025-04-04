package main

import (
	"fmt"
	"github.com/codecrafters-io/dns-server-starter-go/internal/answer"
	"github.com/codecrafters-io/dns-server-starter-go/internal/header"
	"github.com/codecrafters-io/dns-server-starter-go/internal/question"
	"log/slog"
	"net"
	"os"
	"sync"
)

type DNSServer struct {
	udpConn      *net.UDPConn
	resolverAddr *net.UDPAddr
	wg           sync.WaitGroup
	logger       *slog.Logger
}

func New(address string, resolverAddr string, logger *slog.Logger) (*DNSServer, func(), error) {
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen UDP address: %w", err)
	}

	resolver, err := net.ResolveUDPAddr("udp", resolverAddr)
	if err != nil {
		udpConn.Close()
		return nil, nil, fmt.Errorf("failed to resolve resolver address: %w", err)
	}

	server := &DNSServer{
		udpConn:      udpConn,
		resolverAddr: resolver,
	}

	cleanup := func() {
		server.wg.Wait()
		udpConn.Close()
	}

	if logger != nil {
		server.logger = logger
	} else {
		server.logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			AddSource:   true,
			Level:       slog.LevelInfo,
			ReplaceAttr: nil,
		}))
	}

	return server, cleanup, nil
}

func (s *DNSServer) Start() {
	s.logger.Info("Starting DNS forwarder with resolver", slog.Any("resolver", *s.resolverAddr), slog.Any("listener", s.udpConn.LocalAddr()))

	for {
		buf := make([]byte, 512)
		n, addr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			s.logger.Error("failed to read from UDP connection", slog.Any("error", err))
			continue
		}

		s.wg.Add(1)
		go func(data []byte, size int, clientAddr *net.UDPAddr) {
			defer s.wg.Done()
			s.handleDNSRequest(data[:size], clientAddr)
		}(buf, n, addr)
	}
}

// handleDNSRequest processes a single DNS request and sends a response
func (s *DNSServer) handleDNSRequest(data []byte, addr *net.UDPAddr) {
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
			Answers:   make([]answer.Answer, 0),
		}

		mergedResponse.Header.SetQRFlag(true)
		mergedResponse.Header.SetRCODE(header.NoError)

		successfulQueries := 0
		for _, q := range msg.Questions {
			singleMsg := Message{
				Header:    msg.Header,
				Questions: []question.Question{q},
			}
			singleMsg.Header.SetQDCOUNT(1)
			singleMsg.Header.SetANCOUNT(0)
			singleMsg.Header.SetNSCOUNT(0)
			singleMsg.Header.SetARCOUNT(0)

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

			responseMsg := Message{}
			err = responseMsg.UnmarshalBinary(responseData)
			if err != nil {
				s.logger.Error("Error unmarshalling resolver response", slog.Any("error", err))
				continue
			}

			if responseMsg.Header.GetRCODE() != header.NoError {
				s.logger.Warn("Resolver returned error",
					slog.Any("question", q.Name),
					slog.Any("error_code", responseMsg.Header.GetRCODE()))
			}

			mergedResponse.Answers = append(mergedResponse.Answers, responseMsg.Answers...)
			successfulQueries++
		}

		if successfulQueries == 0 {
			s.logger.Error("All queries failed", slog.Any("question_count", len(msg.Questions)))
			s.sendErrorResponse(data, addr, header.ServerFailure)
			return
		}

		mergedResponse.Header.SetANCOUNT(uint16(len(mergedResponse.Answers)))

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

		_, err = s.udpConn.WriteToUDP(responseData, addr)
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
		Answers:   []answer.Answer{},
	}

	h.SetQDCOUNT(uint16(len(questions)))
	h.SetANCOUNT(0)
	h.SetNSCOUNT(0)
	h.SetARCOUNT(0)

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
	} else {
		s.logger.Info("Sent error response",
			slog.Any("to_address", addr.String()),
			slog.Any("error_code", errorCode))
	}
}

func (s *DNSServer) forwardToResolver(query []byte) ([]byte, error) {
	conn, err := net.DialUDP("udp", nil, s.resolverAddr)
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

	return response[:n], nil
}
