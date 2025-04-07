package main

import (
	"errors"
	"fmt"
	"github.com/blazskufca/dns_server_in_go/internal/DNS_Class"
	"github.com/blazskufca/dns_server_in_go/internal/DNS_Type"
	"github.com/blazskufca/dns_server_in_go/internal/RR"
	"github.com/blazskufca/dns_server_in_go/internal/header"
	"github.com/blazskufca/dns_server_in_go/internal/question"
	"log/slog"
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
func New(address string, resolverAddr string, recursive bool, logger *slog.Logger) (*DNSServer, func(), error) {
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
			AddSource:   false,
			Level:       slog.LevelInfo,
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
		recursive:    recursive,
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
	if s.recursive {
		err := s.bootstrapRootServers()
		if err != nil {
			s.logger.Error("Failed to bootstrap root servers, recursive resolution may not work properly",
				slog.Any("error", err))
		}
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

		if len(respData) > 512 {
			resp.Header.SetTC(true)
			respData, err = resp.MarshalBinary()
			if err != nil {
				s.logger.Error("Failed to marshal recursive response with TC flag", slog.Any("error", err))
				s.sendErrorResponse(data, addr, header.ServerFailure)
				return
			}
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

		if len(responseData.Answers) > 0 {
			marshalledData, err := responseData.MarshalBinary()
			if err != nil {
				s.logger.Error("Error marshalling response", slog.Any("error", err))
				s.sendErrorResponse(data, addr, header.ServerFailure)
				return
			}

			if len(marshalledData) > 512 {
				responseData.Header.SetTC(true)
				marshalledData, err = responseData.MarshalBinary()
				if err != nil {
					s.logger.Error("Error marshalling response with TC flag", slog.Any("error", err))
					s.sendErrorResponse(data, addr, header.ServerFailure)
					return
				}
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

// resolveRecursively performs recursive DNS resolution starting from root servers
func (s *DNSServer) resolveRecursively(query *Message) (*Message, error) {
	if query == nil {
		return nil, errors.New("recursive resolver got nil query")
	}
	if len(query.Questions) != 1 || query.Header.GetQDCOUNT() != 1 {
		return nil, fmt.Errorf("recursive resolution only supports single queryQuestion queries")
	}

	questionType := query.Questions[0].Type
	domain := query.Questions[0].Name
	cacheKey := fmt.Sprintf("%s:%d", domain, questionType)

	if che := s.cache.get(cacheKey); che != nil {
		s.logger.Info("Cache hit", slog.String("domain", domain), slog.Any("type", questionType))
		che.Header.ID = query.Header.ID
		return che, nil
	}

	s.logger.Info("Starting recursive resolution",
		slog.String("domain", domain),
		slog.Any("type", questionType))

	response := &Message{
		Header:    query.Header,
		Questions: query.Questions,
	}
	response.Header.SetQRFlag(true)
	response.Header.SetRA(true)

	var nameservers []RootServer
	for _, root := range s.rootServers {
		nameservers = append(nameservers, root)
	}

	result, err := s.resolveWithNameservers(domain, questionType, nameservers, 0, make(map[string]bool))
	if err != nil {
		s.logger.Error("Recursive resolution failed, falling back to upstream resolver",
			slog.String("domain", domain), slog.Any("error", err))

		query.Header.SetQRFlag(false)
		queryData, err := query.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal fallback query: %w", err)
		}

		return s.forwardToResolver(queryData)
	}

	response.Answers = result.Answers
	response.Authority = result.Authority
	response.Additional = result.Additional
	response.Header.SetAA(result.Header.IsAA())

	if err := response.Header.SetANCOUNT(len(response.Answers)); err != nil {
		s.logger.Error("Failed to set ANCOUNT", slog.Any("error", err))
	}
	if err := response.Header.SetNSCOUNT(len(response.Authority)); err != nil {
		s.logger.Error("Failed to set NSCOUNT", slog.Any("error", err))
	}
	if err := response.Header.SetARCOUNT(len(response.Additional)); err != nil {
		s.logger.Error("Failed to set ARCOUNT", slog.Any("error", err))
	}

	s.cache.put(cacheKey, response)
	return response, nil
}

// resolveWithNameservers recursively resolves a domain by querying nameservers
func (s *DNSServer) resolveWithNameservers(domain string, questionType DNS_Type.Type, nameservers []RootServer,
	delegationCount int, cnameChain map[string]bool) (*Message, error) {

	const maxDelegations = 10

	if delegationCount >= maxDelegations { // Base case: delegation limit reached
		return nil, fmt.Errorf("exceeded maximum delegation count (%d)", maxDelegations)
	}

	if len(nameservers) == 0 { // Base case: no nameservers left to try
		return nil, fmt.Errorf("no nameservers available to query")
	}

	server := nameservers[0]
	remainingServers := nameservers[1:]

	s.logger.Debug("Querying nameserver",
		slog.String("nameserver", server.Name),
		slog.String("ip", server.IP.String()),
		slog.String("domain", domain),
		slog.Any("type", questionType))

	nsQuery, err := createDNSQuery(domain, questionType, DNS_Class.IN, false)
	if err != nil {
		s.logger.Error("Failed to create nameserver query", slog.Any("error", err))
		return s.resolveWithNameservers(domain, questionType, remainingServers, delegationCount, cnameChain)
	}

	err = nsQuery.Header.SetRandomID()
	if err != nil {
		s.logger.Error("Failed to set random query ID", slog.Any("error", err))
		return s.resolveWithNameservers(domain, questionType, remainingServers, delegationCount, cnameChain)
	}

	nsResp, err := s.queryNameserver(server.IP, &nsQuery)
	if err != nil {
		s.logger.Debug("Failed to query nameserver",
			slog.String("nameserver", server.Name),
			slog.Any("error", err))
		return s.resolveWithNameservers(domain, questionType, remainingServers, delegationCount, cnameChain)
	}

	if nsResp.Header.GetRCODE() != header.NoError {
		s.logger.Error("Failed to query nameserver with unexpected RCODE", slog.Any("rcode", nsResp.Header.GetRCODE()))
		return s.resolveWithNameservers(domain, questionType, remainingServers, delegationCount, cnameChain)
	}

	if nsResp.Header.GetMessageID() != nsQuery.Header.GetMessageID() {
		s.logger.Error("Failed to query nameserver with unexpected message ID",
			slog.Any("sent_id", nsQuery.Header.GetMessageID()),
			slog.Any("got_id", nsResp.Header.GetMessageID()))
		return s.resolveWithNameservers(domain, questionType, remainingServers, delegationCount, cnameChain)
	}

	// Check for CNAME records when not specifically looking for CNAMEs
	if questionType != DNS_Type.CNAME && nsResp.Header.GetANCOUNT() > 0 {
		if len(nsResp.Answers) != int(nsResp.Header.GetANCOUNT()) {
			s.logger.Error("Mismatch between ANCOUNT flag and actual answers",
				slog.Any("ANCOUNT_flag", nsResp.Header.GetANCOUNT()),
				slog.Any("actual answers", len(nsResp.Answers)))
			return s.resolveWithNameservers(domain, questionType, remainingServers, delegationCount, cnameChain)
		}

		cnameResult := s.handleCNAMEs(domain, questionType, nsResp, cnameChain)
		if cnameResult != nil {
			return cnameResult, nil
		}
	}

	if nsResp.Header.IsAA() && len(nsResp.Answers) > 0 {
		s.logger.Info("Found authoritative answer",
			slog.String("domain", domain),
			slog.Int("answer_count", len(nsResp.Answers)))
		return nsResp, nil
	}

	hasSOA := false
	for _, auth := range nsResp.Authority {
		if auth.Type == DNS_Type.SOA {
			hasSOA = true
			break
		}
	}

	if hasSOA {
		s.logger.Info("Found authoritative negative response (SOA record)",
			slog.String("domain", domain))
		return nsResp, nil
	}

	nextNameservers, hasAuthority := s.extractAuthorityNameservers(domain, nsResp) // Recursive case: try new authority nameservers
	if hasAuthority {
		return s.resolveWithNameservers(domain, questionType, nextNameservers, delegationCount+1, cnameChain)
	}

	if len(remainingServers) > 0 { // If no authority records found, try next nameserver at current level
		return s.resolveWithNameservers(domain, questionType, remainingServers, delegationCount, cnameChain)
	}
	fmt.Println(nsResp)
	return nil, fmt.Errorf("all nameservers exhausted without finding an answer")
}

// handleCNAMEs processes any CNAME records in the response
func (s *DNSServer) handleCNAMEs(domain string, questionType DNS_Type.Type, nsResp *Message, cnameChain map[string]bool) *Message {
	if nsResp == nil {
		return nil
	}

	for _, answer := range nsResp.Answers {
		if answer.Type == DNS_Type.CNAME && answer.GetName() == domain {
			cname, err := answer.GetRDATAAsCNAMERecord()
			if err != nil {
				s.logger.Warn("Failed to parse CNAME", slog.Any("error", err))
				continue
			}

			if cnameChain[cname] {
				s.logger.Warn("Detected CNAME loop",
					slog.String("domain", domain),
					slog.String("cname", cname))
				return nil
			}

			cnameChain[cname] = true

			s.logger.Debug("Following CNAME",
				slog.String("from", domain),
				slog.String("to", cname))

			cnameQuery, err := createDNSQuery(cname, questionType, DNS_Class.IN, false)
			if err != nil {
				s.logger.Error("Failed to create CNAME query", slog.Any("error", err))
				return nil
			}

			cnameResp, err := s.resolveRecursively(&cnameQuery)
			if err != nil {
				s.logger.Error("Failed to resolve CNAME target",
					slog.String("cname", cname),
					slog.Any("error", err))
				return nil
			}

			if cnameResp.Header.GetRCODE() != header.NoError {
				s.logger.Error("Failed to query nameserver with unexpected RCODE",
					slog.Any("rcode", cnameResp.Header.GetRCODE()))
				return nil
			}

			if cnameQuery.Header.GetMessageID() != cnameResp.Header.GetMessageID() {
				s.logger.Error("Failed to query nameserver with unexpected message ID",
					slog.Any("sent_id", cnameResp.Header.GetMessageID()),
					slog.Any("got_id", cnameResp.Header.GetMessageID()))
				return nil
			}

			response := &Message{
				Header:    cnameResp.Header,
				Questions: cnameResp.Questions,
			}

			cleanCname := RR.RR{}
			cleanCname.SetName(answer.GetName())
			cleanCname.SetType(DNS_Type.CNAME)
			cleanCname.SetClass(answer.Class)
			err = cleanCname.SetTTL(int(answer.GetTTL()))
			if err != nil {
				s.logger.Error("Failed to set TTL", slog.Any("error", err))
				continue
			}
			err = cleanCname.SetRDATAToCNAMERecord(cname)
			if err != nil {
				s.logger.Error("Failed to create clean CNAME record", slog.Any("error", err))
				continue
			}

			response.Answers = append(response.Answers, cleanCname)

			for _, ans := range cnameResp.Answers {
				cleanAns := RR.RR{}
				cleanAns.SetName(ans.GetName())
				cleanAns.SetType(ans.Type)
				cleanAns.SetClass(ans.Class)
				cleanAns.SetTTL(int(ans.GetTTL()))

				if ans.Type == DNS_Type.CNAME {
					if target, err := ans.GetRDATAAsCNAMERecord(); err == nil {
						err = cleanAns.SetRDATAToCNAMERecord(target)
						if err != nil {
							s.logger.Error("Failed to set RDATA to CNAME record", slog.Any("error", err))
							continue
						}
					} else {
						cleanAns.SetRDATA(ans.GetRDATA())
					}
				} else {
					cleanAns.SetRDATA(ans.GetRDATA())
				}

				response.Answers = append(response.Answers, cleanAns)
			}

			for _, auth := range cnameResp.Authority {
				cleanAuth := RR.RR{}
				cleanAuth.SetName(auth.GetName())
				cleanAuth.SetType(auth.Type)
				cleanAuth.SetClass(auth.Class)
				cleanAuth.SetTTL(int(auth.GetTTL()))

				if auth.Type == DNS_Type.NS {
					if nsName, err := auth.GetRDATAAsNSRecord(); err == nil {
						cleanAuth.SetRDATAToNSRecord(nsName)
					} else {
						cleanAuth.SetRDATA(auth.GetRDATA())
					}
				} else {
					cleanAuth.SetRDATA(auth.GetRDATA())
				}

				response.Authority = append(response.Authority, cleanAuth)
			}

			for _, add := range cnameResp.Additional {
				cleanAdd := RR.RR{}
				cleanAdd.SetName(add.GetName())
				cleanAdd.SetType(add.Type)
				cleanAdd.SetClass(add.Class)
				cleanAdd.SetTTL(int(add.GetTTL()))

				if add.Type == DNS_Type.MX {
					if pref, exchange, err := add.GetRDATAAsMXRecord(); err == nil {
						cleanAdd.SetRDATAToMXRecord(pref, exchange)
					} else {
						cleanAdd.SetRDATA(add.GetRDATA())
					}
				} else if add.Type == DNS_Type.PTR {
					if ptr, err := add.GetRDATAAsPTRRecord(); err == nil {
						cleanAdd.SetRDATAToPTRRecord(ptr)
					} else {
						cleanAdd.SetRDATA(add.GetRDATA())
					}
				} else {
					cleanAdd.SetRDATA(add.GetRDATA())
				}

				response.Additional = append(response.Additional, cleanAdd)
			}

			if err := response.Header.SetANCOUNT(len(response.Answers)); err != nil {
				s.logger.Error("Failed to set ANCOUNT", slog.Any("error", err))
			}

			if err := response.Header.SetNSCOUNT(len(response.Authority)); err != nil {
				s.logger.Error("Failed to set NSCOUNT", slog.Any("error", err))
			}

			if err := response.Header.SetARCOUNT(len(response.Additional)); err != nil {
				s.logger.Error("Failed to set ARCOUNT", slog.Any("error", err))
			}

			return response
		}
	}
	return nil
}

// extractAuthorityNameservers extracts NS records from the Authority section and resolves their IP addresses
func (s *DNSServer) extractAuthorityNameservers(domain string, nsResp *Message) ([]RootServer, bool) {
	if nsResp == nil {
		return nil, false
	}

	var authority []string
	if nsResp.Header.GetNSCOUNT() != 0 {
		if int(nsResp.Header.GetNSCOUNT()) != len(nsResp.Authority) {
			s.logger.Error("Failed to extract authority nameservers", slog.String("domain", domain))
			return nil, false
		}
		for _, auth := range nsResp.Authority {
			if auth.Type == DNS_Type.NS {
				nsName, err := auth.GetRDATAAsNSRecord()
				if err != nil {
					s.logger.Warn("Failed to parse NS record", slog.Any("error", err))
					continue
				}
				authority = append(authority, nsName)
			}
		}
	}

	if len(authority) == 0 {
		return nil, false
	}

	var nameservers []RootServer

	foundGlue := false
	if nsResp.Header.GetARCOUNT() != 0 {

		if len(nsResp.Additional) != int(nsResp.Header.GetARCOUNT()) {
			s.logger.Error("Failed to extract glue records", slog.String("domain", domain))
			return nil, false
		}

		for _, add := range nsResp.Additional { // Glue records
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
	}

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

	return nameservers, len(nameservers) > 0
}

// resolveNameserverRecursively resolves a nameserver using recursive resolution
func (s *DNSServer) resolveNameserverRecursively(nameserver string) ([]net.IP, error) {
	query, err := createDNSQuery(nameserver, DNS_Type.A, DNS_Class.IN, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create nameserver query: %w", err)
	}

	resp, err := s.resolveRecursively(&query)
	if err != nil {
		s.logger.Warn("Failed to resolve nameserver recursively", slog.Any("error", err))
		return s.resolveNameserver(nameserver)
	}

	if resp.Header.GetRCODE() != header.NoError {
		return nil, fmt.Errorf("failed to query nameserver with unexpected RCODE %v", resp.Header.GetRCODE())
	}
	if resp.Header.GetMessageID() != query.Header.GetMessageID() {
		return nil, fmt.Errorf("failed to query nameserver with unexpected message ID: sent %v but got %v",
			query.Header.GetMessageID(), resp.Header.GetMessageID())
	}

	var ips []net.IP
	if resp.Header.GetANCOUNT() != 0 {
		if int(resp.Header.GetANCOUNT()) != len(resp.Answers) {
			return nil, fmt.Errorf("failed to query nameserver with unexpected ANCOUNT (%d) answers, expected %d",
				resp.Header.GetANCOUNT(), len(resp.Answers))
		}
		for _, answer := range resp.Answers {
			if answer.Type == DNS_Type.A {
				ip, err := answer.GetRDATAAsARecord()
				if err != nil {
					continue
				}
				ips = append(ips, ip)
			}
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for nameserver %s", nameserver)
	}

	return ips, nil
}

// queryNameserver sends a query to a specific nameserver and returns the response
func (s *DNSServer) queryNameserver(serverIP net.IP, query *Message) (*Message, error) {
	if query == nil {
		return nil, errors.New("query name server got nil query")
	}
	queryData, err := query.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}

	serverAddr := net.UDPAddr{
		IP:   serverIP,
		Port: 53,
	}

	conn, err := net.DialUDP("udp", nil, &serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to nameserver %s: %w", serverIP.String(), err)
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err != nil {
		return nil, fmt.Errorf("failed to set connection deadline: %w", err)
	}

	_, err = conn.Write(queryData)
	if err != nil {
		return nil, fmt.Errorf("failed to send query to nameserver %s: %w", serverIP.String(), err)
	}

	responseData := make([]byte, 512)
	n, err := conn.Read(responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to receive response from nameserver %s: %w", serverIP.String(), err)
	}

	response := &Message{}
	err = response.UnmarshalBinary(responseData[:n])
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response from nameserver %s: %w", serverIP.String(), err)
	}

	if response.Header.GetRCODE() != header.NoError {
		return nil, fmt.Errorf("failed to query nameserver with unexpected RCODE %v", response.Header.GetRCODE())
	}
	if response.Header.GetMessageID() != query.Header.GetMessageID() {
		return nil, fmt.Errorf("failed to query nameserver with unexpected message ID: sent %v but got %v",
			query.Header.GetMessageID(), response.Header.GetMessageID())
	}

	if response.Header.IsTC() {
		return s.queryNameserverTCP(serverIP, query)
	}

	return response, nil
}
