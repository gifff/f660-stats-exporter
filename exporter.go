package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/gifff/f660-stats-exporter/scraper"
	"github.com/prometheus/client_golang/prometheus"
)

const namespace = "zte_gpon_f660"

type Exporter struct {
	mu sync.Mutex

	s *scraper.Scraper

	// Exporter metrics.
	totalScrapes prometheus.Counter
	scrapeErrors prometheus.Counter

	// WLAN metrics.
	wlanStatus          *prometheus.Desc
	wlanReceivedBytes   *prometheus.Desc
	wlanSentBytes       *prometheus.Desc
	wlanReceivedPackets *prometheus.Desc
	wlanSentPackets     *prometheus.Desc

	// LAN metrics.
	lanStatus          *prometheus.Desc
	lanReceivedBytes   *prometheus.Desc
	lanSentBytes       *prometheus.Desc
	lanReceivedPackets *prometheus.Desc
	lanSentPackets     *prometheus.Desc

	// WAN metrics.
	wanInfo                   *prometheus.Desc
	wanIPv4Info               *prometheus.Desc
	wanIPv4ConnectionStatus   *prometheus.Desc
	wanIPv4DisconnectReason   *prometheus.Desc
	wanIPv4OnlineDuration     *prometheus.Desc
	wanIPv4RemainingLeaseTime *prometheus.Desc
}

func NewExporter(s *scraper.Scraper) *Exporter {
	return &Exporter{
		s: s,

		totalScrapes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "status_scrapes_total",
			Help:      "Total number of scrapes of the modem status page.",
		}),
		scrapeErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "status_scrape_errors_total",
			Help:      "Total number of failed scrapes of the modem status page.",
		}),

		// WLAN metrics
		wlanStatus: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "wlan", "ssid_status"),
			"Status of each WLAN SSID.",
			[]string{"name"}, nil,
		),
		wlanReceivedBytes: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "wlan", "received_bytes_total"),
			"Received bytes in each WLAN SSID.",
			[]string{"name"}, nil,
		),
		wlanSentBytes: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "wlan", "sent_bytes_total"),
			"Sent bytes in each WLAN SSID.",
			[]string{"name"}, nil,
		),
		wlanReceivedPackets: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "wlan", "received_packets_total"),
			"Received packets in each WLAN SSID.",
			[]string{"name"}, nil,
		),
		wlanSentPackets: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "wlan", "sent_packets_total"),
			"Sent packets in each WLAN SSID.",
			[]string{"name"}, nil,
		),

		// LAN metrics
		lanStatus: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "lan", "port_status"),
			"Status of each LAN port.",
			[]string{"name"}, nil,
		),
		lanReceivedBytes: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "lan", "received_bytes_total"),
			"Received bytes in each LAN port.",
			[]string{"name"}, nil,
		),
		lanSentBytes: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "lan", "sent_bytes_total"),
			"Sent bytes in each LAN port.",
			[]string{"name"}, nil,
		),
		lanReceivedPackets: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "lan", "received_packets_total"),
			"Received packets in each LAN port.",
			[]string{"name"}, nil,
		),
		lanSentPackets: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "lan", "sent_packets_total"),
			"Sent packets in each LAN port.",
			[]string{"name"}, nil,
		),

		// WAN metrics
		wanInfo: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "wan", "info"),
			"WAN Info.",
			[]string{
				"connection_name",
				"type",
				"ip_version",
				"nat_enabled",
				"mac_address",
			}, nil,
		),
		wanIPv4Info: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "wan", "ipv4_info"),
			"WAN IPv4 Info.",
			[]string{
				"connection_name",
				"address",
				"subnet_mask",
				"gateway",
				"dns",
			}, nil,
		),
		wanIPv4ConnectionStatus: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "wan", "ipv4_connection_status"),
			"WAN IPv4 connection Connection Status.",
			[]string{"connection_name", "connection_status"}, nil,
		),
		wanIPv4DisconnectReason: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "wan", "ipv4_disconnect_reason"),
			"WAN IPv4 connection Disconnect Reason.",
			[]string{"connection_name", "disconnect_reason"}, nil,
		),
		wanIPv4OnlineDuration: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "wan", "ipv4_online_duration_total"),
			"WAN IPv4 connection Online Duration.",
			[]string{"connection_name"}, nil,
		),
		wanIPv4RemainingLeaseTime: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "wan", "ipv4_remaining_lease_time"),
			"WAN IPv4 connection Remaining Lease Time.",
			[]string{"connection_name"}, nil,
		),
	}
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	// Exporter metrics.
	ch <- e.totalScrapes.Desc()
	ch <- e.scrapeErrors.Desc()
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.totalScrapes.Inc()

	ctx := context.Background()

	lanStats, wlanStats, wanStats, err := e.scrape(ctx)
	if err != nil {
		// TODO(gifff): Log!
		e.scrapeErrors.Inc()
	}

	for _, lanStat := range lanStats {
		lanStatus := 0.0
		if lanStat.LinkType == "Linkup" {
			lanStatus = 1
		}

		ch <- prometheus.MustNewConstMetric(e.lanStatus, prometheus.GaugeValue, lanStatus, lanStat.Name)
		ch <- prometheus.MustNewConstMetric(e.lanReceivedBytes, prometheus.CounterValue, float64(lanStat.BytesReceived), lanStat.Name)
		ch <- prometheus.MustNewConstMetric(e.lanSentBytes, prometheus.CounterValue, float64(lanStat.BytesSent), lanStat.Name)
		ch <- prometheus.MustNewConstMetric(e.lanReceivedPackets, prometheus.CounterValue, float64(lanStat.PacketsReceived), lanStat.Name)
		ch <- prometheus.MustNewConstMetric(e.lanSentPackets, prometheus.CounterValue, float64(lanStat.PacketsSent), lanStat.Name)
	}

	for _, wlanStat := range wlanStats {
		wlanStatus := 0.0
		if wlanStat.Enabled {
			wlanStatus = 1
		}

		ch <- prometheus.MustNewConstMetric(e.wlanStatus, prometheus.GaugeValue, wlanStatus, wlanStat.Name)
		ch <- prometheus.MustNewConstMetric(e.wlanReceivedBytes, prometheus.CounterValue, float64(wlanStat.BytesReceived), wlanStat.Name)
		ch <- prometheus.MustNewConstMetric(e.wlanSentBytes, prometheus.CounterValue, float64(wlanStat.BytesSent), wlanStat.Name)
		ch <- prometheus.MustNewConstMetric(e.wlanReceivedPackets, prometheus.CounterValue, float64(wlanStat.PacketsReceived), wlanStat.Name)
		ch <- prometheus.MustNewConstMetric(e.wlanSentPackets, prometheus.CounterValue, float64(wlanStat.PacketsSent), wlanStat.Name)
	}

	if wanStats != nil {
		ch <- prometheus.MustNewConstMetric(e.wanInfo, prometheus.GaugeValue, 1,
			wanStats.ConnectionName,
			wanStats.Type,
			wanStats.IPVersion,
			strconv.FormatBool(wanStats.NATEnabled),
			wanStats.MACAddress,
		)
		ch <- prometheus.MustNewConstMetric(e.wanIPv4Info, prometheus.GaugeValue, 1,
			wanStats.ConnectionName,
			wanStats.IPv4.Address,
			wanStats.IPv4.SubnetMask,
			wanStats.IPv4.Gateway,
			strings.Join(wanStats.DNSes, ","),
		)
		ch <- prometheus.MustNewConstMetric(e.wanIPv4ConnectionStatus, prometheus.GaugeValue, 1, wanStats.ConnectionName, wanStats.IPv4.ConnectionStatus)
		ch <- prometheus.MustNewConstMetric(e.wanIPv4DisconnectReason, prometheus.GaugeValue, 1, wanStats.ConnectionName, wanStats.IPv4.DisconnectReason)
		ch <- prometheus.MustNewConstMetric(e.wanIPv4OnlineDuration, prometheus.CounterValue, float64(wanStats.IPv4.OnlineDuration), wanStats.ConnectionName)
		ch <- prometheus.MustNewConstMetric(e.wanIPv4RemainingLeaseTime, prometheus.GaugeValue, float64(wanStats.IPv4.RemainingLeaseTime), wanStats.ConnectionName)
	}

	e.totalScrapes.Collect(ch)
	e.scrapeErrors.Collect(ch)
}

func (e *Exporter) scrape(ctx context.Context) ([]scraper.LANStat, []scraper.WLANStat, *scraper.WANStats, error) {
	err := e.s.EnsureLogin(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("scrape: %w", err)
	}

	lanStats, err := e.s.GetLANStats(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("scrape: %w", err)
	}

	wlanStats, err := e.s.GetWLANStats(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	wanStats, err := e.s.GetWANStats(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	return lanStats, wlanStats, wanStats, nil
}
