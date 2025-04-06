package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/blazskufca/dns_server_in_go/internal/DNS_Class"
	"github.com/blazskufca/dns_server_in_go/internal/DNS_Type"
	"github.com/blazskufca/dns_server_in_go/internal/RR"
	"github.com/blazskufca/dns_server_in_go/internal/header"
	"github.com/blazskufca/dns_server_in_go/internal/question"
	"github.com/blazskufca/dns_server_in_go/internal/utils"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// RootServer represents a DNS root server
type RootServer struct {
	Name string
	IP   net.IP
}

type DNSServer struct {
	udpConn      *net.UDPConn
	tcpListener  net.Listener
	resolverAddr *net.UDPAddr
	resolverHost string
	wg           sync.WaitGroup
	logger       *slog.Logger
	cache        *DNSCache
	rootServers  []RootServer
	recursive    bool
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

	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			AddSource:   true,
			Level:       slog.LevelDebug,
			ReplaceAttr: nil,
		}))
	}

	server := &DNSServer{
		udpConn:      udpConn,
		tcpListener:  tcpListener,
		resolverAddr: resolver,
		resolverHost: resolverAddr,
		logger:       logger,
		cache:        newDNSCache(logger),
		recursive:    true,
	}

	cleanup := func() {
		server.wg.Wait()
		udpConn.Close()
		tcpListener.Close()
	}

	return server, cleanup, nil
}

// Start starts the TCP and the UDP servers and starts listening on them for incoming DNS queries.
func (s *DNSServer) Start() {
	s.logger.Info("Starting DNS server with resolver", slog.Any("resolver", *s.resolverAddr), slog.Any("listener", s.udpConn.LocalAddr()))

	err := s.bootstrapRootServers()
	if err != nil {
		s.logger.Error("Failed to bootstrap root servers, recursive resolution may not work properly",
			slog.Any("error", err))
	}

	s.logger.Info("TCP listener started", slog.Any("listener", s.tcpListener.Addr()))

	go s.startTCPServer()

	buf := make([]byte, 512)

	for {
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
		slog.String("question", msg.Questions[0].Name),
		slog.Any("type", msg.Questions[0].Type))

	if len(msg.Questions) == 0 || msg.Header.GetQDCOUNT() == 0 {
		s.logger.Error("DNS request contains no questions")
		s.sendErrorResponse(data, addr, header.FormatError)
		return
	}

	if len(msg.Questions) > 1 || msg.Header.GetQDCOUNT() > 1 {
		s.logger.Warn("Multiple questions in request, only processing the first one",
			slog.Int("question_count", len(msg.Questions)))

		msg.Questions = msg.Questions[:1]
		err = msg.Header.SetQDCOUNT(1)
		if err != nil {
			s.logger.Error("Failed to update question count", slog.Any("error", err))
		}
	}

	if msg.Header.IsRD() && s.recursive {
		resp, err := s.resolveRecursively(&msg)
		if err != nil {
			s.logger.Error("Recursive resolution failed",
				slog.String("question", msg.Questions[0].Name),
				slog.Any("error", err))
			s.sendErrorResponse(data, addr, header.ServerFailure)
			return
		}
		if resp == nil {
			s.logger.Error("got nil message after recursive resolution")
			s.sendErrorResponse(data, addr, header.ServerFailure)
			return
		}
		if resp.Header.GetRCODE() != header.NoError {
			s.logger.Error("got unexpected RCODE after recursive resolution", slog.Any("error", resp.Header.GetRCODE()))
			s.sendErrorResponse(data, addr, header.ServerFailure)
			return
		}

		resp.Header.ID = msg.Header.ID

		respData, err := resp.MarshalBinary()
		if err != nil {
			s.logger.Error("Failed to marshal recursive response", slog.Any("error", err))
			s.sendErrorResponse(data, addr, header.ServerFailure)
			return
		}

		_, err = s.udpConn.WriteToUDP(respData, addr)
		if err != nil {
			s.logger.Error("Failed to send recursive response",
				slog.Any("to_address", addr.String()),
				slog.Any("error", err))
		}

		s.logger.Info("Sent recursive response",
			slog.Any("to_address", addr.String()),
			slog.Int("answer_count", len(resp.Answers)))
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

		s.logger.Info("Sent forwarded response",
			slog.Any("to_address", addr.String()),
			slog.Int("answer_count", len(responseData.Answers)))
	}
}

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

// resolveRecursively performs recursive DNS resolution starting from root servers
func (s *DNSServer) resolveRecursively(query *Message) (*Message, error) {
	if query == nil {
		return nil, errors.New("recursive resolver got nil query")
	}
	if len(query.Questions) != 1 || query.Header.GetQDCOUNT() != 1 {
		return nil, fmt.Errorf("recursive resolution only supports single queryQuestion queries")
	}

	queryQuestion := query.Questions[0]
	questionType := queryQuestion.Type
	domain := queryQuestion.Name

	cacheKey := fmt.Sprintf("%s:%d", domain, questionType)
	if cr := s.cache.get(cacheKey); cr != nil {
		s.logger.Info("Cache hit", slog.String("domain", domain), slog.Any("type", questionType))

		cr.Header.ID = query.Header.ID
		return cr, nil
	}

	s.logger.Info("Starting recursive resolution",
		slog.String("domain", domain),
		slog.Any("type", questionType))

	response := &Message{
		Header:    query.Header,
		Questions: query.Questions,
		Answers:   []RR.RR{},
	}
	response.Header.SetQRFlag(true)
	response.Header.SetRA(true)

	var nameservers []RootServer
	var authority []string

	for _, root := range s.rootServers {
		nameservers = append(nameservers, root)
	}

	delegationCount := 0
	maxDelegations := 10 //TODO: Move this up to struct?
	cnameChain := make(map[string]bool)

	for len(nameservers) > 0 && delegationCount < maxDelegations {
		server := nameservers[0]
		nameservers = nameservers[1:]

		s.logger.Debug("Querying nameserver",
			slog.String("nameserver", server.Name),
			slog.String("ip", server.IP.String()),
			slog.String("domain", domain),
			slog.Any("type", questionType))

		nsQuery, err := createDNSQuery(domain, questionType, DNS_Class.IN, false)
		if err != nil {
			s.logger.Error("Failed to create nameserver query", slog.Any("error", err))
			continue
		}

		err = nsQuery.Header.SetRandomID()
		if err != nil {
			s.logger.Error("Failed to set random query ID", slog.Any("error", err))
			continue
		}

		nsResp, err := s.queryNameserver(server.IP, &nsQuery)
		if err != nil {
			s.logger.Debug("Failed to query nameserver",
				slog.String("nameserver", server.Name),
				slog.Any("error", err))
			continue
		}

		if nsResp.Header.GetRCODE() != header.NoError {
			s.logger.Error("Failed to query nameserver with unexpected RCODE", slog.Any("rcode", nsResp.Header.GetRCODE()))
			continue
		}

		if nsResp.Header.GetMessageID() != nsQuery.Header.GetMessageID() {
			s.logger.Error("Failed to query nameserver with unexpected message ID", slog.Any("sent_id",
				nsQuery.Header.GetMessageID()), slog.Any("got_id", nsResp.Header.GetMessageID()))
			continue
		}

		// Check for CNAMEs - if found for non-CNAME queries, follow them
		if questionType != DNS_Type.CNAME && nsResp.Header.GetANCOUNT() > 0 {
			if len(nsResp.Answers) != int(nsResp.Header.GetANCOUNT()) {
				s.logger.Error("Mismatch between ANCOUNT flag and actual answers",
					slog.Any("ANCOUNT_flag", nsResp.Header.GetANCOUNT()), slog.Any("actual answers",
						len(nsResp.Answers)))
				continue
			}
			for _, answer := range nsResp.Answers {
				if answer.Type == DNS_Type.CNAME && answer.GetName() == domain {
					cname, err := answer.GetRDATAAsCNAMERecord()
					if err != nil {
						s.logger.Warn("Failed to parse CNAME", slog.Any("error", err))
						continue
					}

					response.Answers = append(response.Answers, answer)

					if cnameChain[cname] {
						s.logger.Warn("Detected CNAME loop",
							slog.String("domain", domain),
							slog.String("cname", cname))
						break
					}

					cnameChain[cname] = true

					s.logger.Debug("Following CNAME",
						slog.String("from", domain),
						slog.String("to", cname))

					cnameQuery, err := createDNSQuery(cname, questionType, DNS_Class.IN, false)
					if err != nil {
						s.logger.Error("Failed to create CNAME query", slog.Any("error", err))
						break
					}

					cnameResp, err := s.resolveRecursively(&cnameQuery)
					if err != nil {
						s.logger.Error("Failed to resolve CNAME target",
							slog.String("cname", cname),
							slog.Any("error", err))
						break
					}

					if cnameResp.Header.GetRCODE() != header.NoError {
						s.logger.Error("Failed to query nameserver with unexpected RCODE", slog.Any("rcode", cnameResp.Header.GetRCODE()))
						break
					}

					if cnameQuery.Header.GetMessageID() != cnameResp.Header.GetMessageID() {
						s.logger.Error("Failed to query nameserver with unexpected message ID", slog.Any("sent_id",
							cnameResp.Header.GetMessageID()), slog.Any("got_id", cnameResp.Header.GetMessageID()))
						break
					}

					response.Answers = append(response.Answers, cnameResp.Answers...)

					err = response.Header.SetANCOUNT(len(response.Answers))
					if err != nil {
						s.logger.Error("Failed to set ANCOUNT", slog.Any("error", err))
					}

					s.cache.put(cacheKey, response)

					return response, nil
				}
			}
		}

		if nsResp.Header.IsAA() && len(nsResp.Answers) > 0 {
			response.Answers = nsResp.Answers
			response.Authority = nsResp.Authority
			response.Additional = nsResp.Additional

			err = response.Header.SetANCOUNT(len(response.Answers))
			if err != nil {
				s.logger.Error("Failed to set ANCOUNT", slog.Any("error", err))
			}
			err = response.Header.SetNSCOUNT(len(response.Authority))
			if err != nil {
				s.logger.Error("Failed to set NSCOUNT", slog.Any("error", err))
			}
			err = response.Header.SetARCOUNT(len(response.Additional))
			if err != nil {
				s.logger.Error("Failed to set ARCOUNT", slog.Any("error", err))
			}

			s.logger.Info("Found authoritative answer",
				slog.String("domain", domain),
				slog.Int("answer_count", len(response.Answers)))

			s.cache.put(cacheKey, response)

			return response, nil
		}

		newAuthority := []string{}
		for _, auth := range nsResp.Authority {
			if auth.Type == DNS_Type.NS {
				nsName, err := auth.GetRDATAAsNSRecord()
				if err != nil {
					s.logger.Warn("Failed to parse NS record", slog.Any("error", err))
					continue
				}
				newAuthority = append(newAuthority, nsName)
			}
		}

		if len(newAuthority) > 0 {
			delegationCount++
			authority = newAuthority

			// Clear nameservers list for new delegation
			nameservers = []RootServer{}

			// First try to get IPs from Additional section (glue records)
			foundGlue := false
			for _, add := range nsResp.Additional {
				if add.Type == DNS_Type.A {
					for _, auth := range authority {
						if add.GetName() == auth {
							ip, err := add.GetRDATAAsARecord()
							if err != nil {
								continue
							}

							nameservers = append(nameservers, RootServer{
								Name: auth,
								IP:   ip,
							})
							foundGlue = true
						}
					}
				}
			}

			// If no glue records, resolve nameservers manually
			if !foundGlue {
				for _, auth := range authority {
					// Avoid resolving the domain we're already trying to resolve (loop prevention)
					if strings.HasSuffix(domain, auth) {
						s.logger.Warn("Skipping nameserver resolution to avoid loop",
							slog.String("domain", domain),
							slog.String("nameserver", auth))
						continue
					}

					ips, err := s.resolveNameserverRecursively(auth)
					if err != nil {
						s.logger.Debug("Failed to resolve nameserver",
							slog.String("nameserver", auth),
							slog.Any("error", err))
						continue
					}

					for _, ip := range ips {
						nameservers = append(nameservers, RootServer{
							Name: auth,
							IP:   ip,
						})
					}
				}
			}

			// If we didn't find any nameserver IPs, try next server in current level
			if len(nameservers) == 0 {
				s.logger.Warn("Failed to find nameserver IPs for delegation",
					slog.Any("authority", authority))

				// If we've tried all current nameservers, give up
				if len(nameservers) == 0 {
					break
				}
			}
		}
	}

	// If we reached here without finding an answer, fall back to the upstream resolver
	s.logger.Info("Recursive resolution failed, falling back to upstream resolver",
		slog.String("domain", domain))

	// Reset query flags
	query.Header.SetQRFlag(false)
	queryData, err := query.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal fallback query: %w", err)
	}

	return s.forwardToResolver(queryData)
}

// resolveNameserverRecursively resolves a nameserver using recursive resolution
func (s *DNSServer) resolveNameserverRecursively(nameserver string) ([]net.IP, error) {
	// Create query for nameserver A record
	query, err := createDNSQuery(nameserver, DNS_Type.A, DNS_Class.IN, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create nameserver query: %w", err)
	}

	// Try to resolve recursively
	resp, err := s.resolveRecursively(&query)
	if err != nil {
		// Fall back to upstream resolver if recursive resolution fails
		return s.resolveNameserver(nameserver)
	}

	var ips []net.IP
	for _, answer := range resp.Answers {
		if answer.Type == DNS_Type.A {
			ip, err := answer.GetRDATAAsARecord()
			if err != nil {
				continue
			}
			ips = append(ips, ip)
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for nameserver %s", nameserver)
	}

	return ips, nil
}

// queryNameserver sends a query to a specific nameserver and returns the response
func (s *DNSServer) queryNameserver(serverIP net.IP, query *Message) (*Message, error) {
	// Marshal the query to binary
	queryData, err := query.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}

	// Create a UDP connection to the nameserver
	serverAddr := net.UDPAddr{
		IP:   serverIP,
		Port: 53, // Standard DNS port
	}

	conn, err := net.DialUDP("udp", nil, &serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to nameserver %s: %w", serverIP.String(), err)
	}
	defer conn.Close()

	// Set a timeout
	err = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err != nil {
		return nil, fmt.Errorf("failed to set connection deadline: %w", err)
	}

	// Send the query
	_, err = conn.Write(queryData)
	if err != nil {
		return nil, fmt.Errorf("failed to send query to nameserver %s: %w", serverIP.String(), err)
	}

	// Read the response
	responseData := make([]byte, 512)
	n, err := conn.Read(responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to receive response from nameserver %s: %w", serverIP.String(), err)
	}

	// Parse the response
	response := &Message{}
	err = response.UnmarshalBinary(responseData[:n])
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response from nameserver %s: %w", serverIP.String(), err)
	}

	// Check for truncation flag, retry with TCP if needed
	if response.Header.IsTC() {
		return s.queryNameserverTCP(serverIP, query)
	}

	return response, nil
}

// queryNameserverTCP sends a query to a specific nameserver using TCP and returns the response
func (s *DNSServer) queryNameserverTCP(serverIP net.IP, query *Message) (*Message, error) {
	// Marshal the query to binary
	queryData, err := query.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TCP query: %w", err)
	}

	// Create a TCP connection to the nameserver
	serverAddr := net.TCPAddr{
		IP:   serverIP,
		Port: 53, // Standard DNS port
	}

	conn, err := net.DialTCP("tcp", nil, &serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to nameserver %s via TCP: %w", serverIP.String(), err)
	}
	defer conn.Close()

	// Set a timeout
	err = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return nil, fmt.Errorf("failed to set TCP connection deadline: %w", err)
	}

	// Prepend message length for TCP
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(queryData)))

	// Send the length-prefixed query
	_, err = conn.Write(append(lenBuf, queryData...))
	if err != nil {
		return nil, fmt.Errorf("failed to send TCP query to nameserver %s: %w", serverIP.String(), err)
	}

	// Read the response length
	respLenBuf := make([]byte, 2)
	_, err = io.ReadFull(conn, respLenBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCP response length from nameserver %s: %w", serverIP.String(), err)
	}

	respLen := binary.BigEndian.Uint16(respLenBuf)
	if respLen == 0 {
		return nil, fmt.Errorf("received empty TCP response from nameserver %s", serverIP.String())
	}

	// Read the response
	responseData := make([]byte, respLen)
	_, err = io.ReadFull(conn, responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCP response from nameserver %s: %w", serverIP.String(), err)
	}

	// Parse the response
	response := &Message{}
	err = response.UnmarshalBinary(responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal TCP response from nameserver %s: %w", serverIP.String(), err)
	}

	return response, nil
}
