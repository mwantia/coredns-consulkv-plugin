package consulkv

import (
	"context"

	"github.com/miekg/dns"
	"github.com/mwantia/coredns-consulkv-plugin/logging"
	"github.com/mwantia/coredns-consulkv-plugin/records"
)

func (plug *ConsulKVPlugin) HandleRecord(ctx context.Context, msg *dns.Msg, qname string, qtype uint16, record *records.Record) bool {
	ttl := GetDefaultTTL(record)
	foundRequestedType := false

	logging.Log.Debugf("Amount of available records: %v", len(record.Records))

	zname, _ := GetZoneAndRecord(plug.Config.Zones, qname)
	soa, err := plug.Consul.GetSOARecordFromConsul(zname, plug.Config.ConsulCache)

	if err != nil {
		logging.Log.Errorf("Error loading SOA record: %v", err)
		IncrementMetricsPluginErrorsTotal("SOA_GET")
	}

	for _, rec := range record.Records {
		logging.Log.Debugf("Searching record for type %s", rec.Type)

		switch rec.Type {
		case "CNAME":
			if qtype == dns.TypeCNAME || qtype == dns.TypeA || qtype == dns.TypeAAAA || qtype == dns.TypeTXT || (qtype == dns.TypeHTTPS && !foundRequestedType) {
				foundRequestedType = plug.AppendCNAMERecords(ctx, msg, qname, qtype, ttl, rec.Value)
			}

		case "NS":
			if qtype == dns.TypeNS {
				found, err := records.AppendNSRecords(msg, qname, ttl, rec.Value)
				if err != nil {
					logging.Log.Errorf("Error parsing JSON for NS record: %v", err)
					IncrementMetricsPluginErrorsTotal("JSON_UNMARSHAL")
				}

				foundRequestedType = found
			}

		case "SVCB":
			if qtype == dns.TypeSVCB {
				found, err := records.AppendSVCBRecords(msg, qname, ttl, rec.Value, dns.TypeSVCB)
				if err != nil {
					logging.Log.Errorf("Error parsing JSON for SVCB record: %v", err)
					IncrementMetricsPluginErrorsTotal("JSON_UNMARSHAL")
				}

				foundRequestedType = found
			}

		case "HTTPS":
			if qtype == dns.TypeHTTPS {
				found, err := records.AppendSVCBRecords(msg, qname, ttl, rec.Value, dns.TypeHTTPS)
				if err != nil {
					logging.Log.Errorf("Error parsing JSON for HTTPS record: %v", err)
					IncrementMetricsPluginErrorsTotal("JSON_UNMARSHAL")
				}

				foundRequestedType = found
			}

		case "SOA":
			if qtype == dns.TypeSOA || qtype == dns.TypeANY {
				foundRequestedType = records.AppendSOARecord(msg, qname, soa)
			}

		case "A":
			if qtype == dns.TypeA || (qtype == dns.TypeHTTPS && !foundRequestedType) {
				found, err := records.AppendARecords(msg, qname, ttl, rec.Value)
				if err != nil {
					logging.Log.Errorf("Error parsing JSON for A record: %v", err)
					IncrementMetricsPluginErrorsTotal("JSON_UNMARSHAL")
				}

				foundRequestedType = found
			}

		case "AAAA":
			if qtype == dns.TypeAAAA || (qtype == dns.TypeHTTPS && !foundRequestedType) {
				found, err := records.AppendAAAARecords(msg, qname, ttl, rec.Value)
				if err != nil {
					logging.Log.Errorf("Error parsing JSON for AAAA record: %v", err)
					IncrementMetricsPluginErrorsTotal("JSON_UNMARSHAL")
				}

				foundRequestedType = found
			}

		case "PTR":
			if qtype == dns.TypePTR {
				if records.IsDnsSdQuery(qname) {
					found, err := records.AppendDnsSdPTRRecords(msg, qname, ttl, rec.Value)
					if err != nil {
						logging.Log.Errorf("Error parsing JSON for DNS-SD record: %v", err)
						IncrementMetricsPluginErrorsTotal("JSON_UNMARSHAL")
					}

					foundRequestedType = found
				} else {
					found, err := records.AppendPTRRecords(msg, qname, ttl, rec.Value)
					if err != nil {
						logging.Log.Errorf("Error parsing JSON for PTR record: %v", err)
						IncrementMetricsPluginErrorsTotal("JSON_UNMARSHAL")
					}

					foundRequestedType = found
				}
			}

		case "SRV":
			if qtype == dns.TypeSRV {
				found, err := records.AppendSRVRecords(msg, qname, ttl, rec.Value)
				if err != nil {
					logging.Log.Errorf("Error parsing JSON for SRV record: %v", err)
					IncrementMetricsPluginErrorsTotal("JSON_UNMARSHAL")
				}

				foundRequestedType = found
			}

		case "TXT":
			txtAnswered, err := records.AppendTXTRecords(msg, qtype, qname, ttl, rec.Value)
			if err != nil {
				logging.Log.Errorf("Error parsing JSON for TXT record: %v", err)
				IncrementMetricsPluginErrorsTotal("JSON_UNMARSHAL")
			}

			if txtAnswered {
				foundRequestedType = txtAnswered
			}
		}
	}

	if (qtype == dns.TypeSVCB || qtype == dns.TypeHTTPS) && !foundRequestedType && len(msg.Answer) > 0 {
		foundRequestedType = true
	}

	if !foundRequestedType && soa != nil && qtype != dns.TypeSOA && qtype != dns.TypeANY {
		records.AppendSOAToAuthority(msg, qname, soa)
	}

	return foundRequestedType
}
