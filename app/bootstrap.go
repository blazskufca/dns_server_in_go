package main

import (
	"fmt"
	"github.com/blazskufca/dns_server_in_go/internal/DNS_Class"
	"github.com/blazskufca/dns_server_in_go/internal/DNS_Type"
	"github.com/blazskufca/dns_server_in_go/internal/header"
	"log/slog"
)

// bootstrapRootServers queries the upstream resolver for root server information
func (s *DNSServer) bootstrapRootServers() error {
	s.logger.Info("Bootstrapping root servers from upstream resolver")

	query, err := createDNSQuery(".", DNS_Type.NS, DNS_Class.IN, true)
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
	if response.Header.GetRCODE() != header.NoError {
		return fmt.Errorf("unexpected response code from upstream: %v", response.Header.GetRCODE())
	}
	if !response.Header.IsResponse() {
		return fmt.Errorf("expected QR flag to best to response but it was not - %v", response.Header.IsResponse())
	}
	if response.Header.GetMessageID() != query.Header.GetMessageID() {
		return fmt.Errorf("expected message id %v but got %v", query.Header.GetMessageID(), response.Header.GetMessageID())
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
