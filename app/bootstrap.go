package main

import (
	"errors"
	"fmt"
	"github.com/blazskufca/dns_server_in_go/internal/DNS_Class"
	"github.com/blazskufca/dns_server_in_go/internal/DNS_Type"
	"github.com/blazskufca/dns_server_in_go/internal/Message"
	"log/slog"
	"net"
)

// bootstrapRootServers queries the upstream resolver for root server information
func (s *DNSServer) bootstrapRootServers() error {
	s.logger.Info("Bootstrapping root servers from upstream resolver")

	query, err := Message.CreateDNSQuery(".", DNS_Type.NS, DNS_Class.IN, true)
	if err != nil {
		return fmt.Errorf("failed to create root servers query: %w", err)
	}

	queryData, err := query.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal root servers query: %w", err)
	}

	response, err := s.forwardToResolver(queryData)
	if err != nil {
		return fmt.Errorf("failed to get root servers from upstream: %w", err)
	}
	if response == nil {
		return fmt.Errorf("bootstrapRootServers get nil response *Message from forwardToResolver")
	}
	if !response.IsNoErrWithMatchingID(query.Header.GetMessageID()) {
		return errors.New("bootstrapRootServers got invalid response from forwardToResolver")
	}

	var rootServers []RootServer
	var nsNames []string

	if response.Header.GetANCOUNT() != 0 {
		for _, ns := range response.Answers {
			if ns.Type == DNS_Type.NS {
				nsName, err := ns.GetRDATAAsNSRecord()
				if err != nil {
					s.logger.Warn("Failed to parse NS record for root server", slog.Any("error", err))
					continue
				}
				nsNames = append(nsNames, nsName)
			}
		}
	}

	if response.Header.GetNSCOUNT() != 0 {
		for _, ns := range response.Authority {
			if ns.Type == DNS_Type.NS {
				nsName, err := ns.GetRDATAAsNSRecord()
				if err != nil {
					s.logger.Warn("Failed to parse NS record for root server", slog.Any("error", err))
					continue
				}
				nsNames = append(nsNames, nsName)
			}
		}
	}

	if response.Header.GetARCOUNT() != 0 {
		for _, add := range response.Additional {
			if add.Type == DNS_Type.A {
				for _, nsName := range nsNames {
					if add.GetName() == nsName {
						ip, err := add.GetRDATAAsARecord()
						if err != nil {
							s.logger.Warn("Failed to parse A record for root server",
								slog.String("name", nsName),
								slog.Any("error", err))
							continue
						}

						rootServers = append(rootServers, RootServer{
							Name: nsName,
							IP:   ip,
						})

						s.logger.Debug("Found root server",
							slog.String("name", nsName),
							slog.String("ip", ip.String()))
					}
				}
			}
		}
	}

	if len(rootServers) == 0 {
		for _, nsName := range nsNames {
			ips, err := s.resolveNameserver(nsName)
			if err != nil {
				s.logger.Warn("Failed to resolve root server IP",
					slog.String("name", nsName),
					slog.Any("error", err))
				continue
			}

			for _, ip := range ips {
				rootServers = append(rootServers, RootServer{
					Name: nsName,
					IP:   ip,
				})

				s.logger.Debug("Resolved root server",
					slog.String("name", nsName),
					slog.String("ip", ip.String()))
			}
		}
	}

	// If still nothing after Authority, Additional section or manually resolving then something must be going wrong
	if len(rootServers) == 0 {
		return fmt.Errorf("could not bootstartp any root server")
	}

	s.rootServers = rootServers
	s.logger.Info("Root servers bootstrapped successfully", slog.Int("count", len(rootServers)))
	return nil
}

// resolveNameserver resolves a nameserver hostname to IP addresses using the upstream resolver
func (s *DNSServer) resolveNameserver(name string) ([]net.IP, error) {
	query, err := Message.CreateDNSQuery(name, DNS_Type.A, DNS_Class.IN, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create nameserver query: %w", err)
	}

	queryData, err := query.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal nameserver query: %w", err)
	}

	response, err := s.forwardToResolver(queryData)
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, fmt.Errorf("resolveNameserver got nil response from forwardToResolver")
	}

	if !response.IsNoErrWithMatchingID(query.Header.GetMessageID()) {
		return nil, fmt.Errorf("resolveNameserver got invalid response from forwardToResolver")
	}

	var ips []net.IP
	if response.Header.GetANCOUNT() != 0 {

		if int(response.Header.GetANCOUNT()) != len(response.Answers) {
			return nil, fmt.Errorf("expected %v ANCOUNT response but got %v ANCOUNT responses",
				len(response.Answers), response.Header.GetANCOUNT())
		}

		for _, answer := range response.Answers {
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
		return nil, fmt.Errorf("no IP addresses found for nameserver %s", name)
	}

	return ips, nil
}
