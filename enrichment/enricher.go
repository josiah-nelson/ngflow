// Package enrichment provides the main flow enrichment pipeline
// that combines multiple enrichment sources (SNMP, L7 classification, etc.)
package enrichment

import (
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	flowpb "github.com/netsampler/goflow2/v2/pb"
)

// EnrichedFlow contains a flow message with additional enrichment data
type EnrichedFlow struct {
	// Original flow data
	BaseFlow *flowpb.FlowMessage

	// SNMP enrichment
	InIfName        string
	InIfAlias       string
	InIfSpeed       uint64
	OutIfName       string
	OutIfAlias      string
	OutIfSpeed      uint64
	InLagIfIndex    uint32
	OutLagIfIndex   uint32
	DeviceSysName   string

	// L7/Application classification
	L7Protocol      L7Protocol
	L7Category      L7Category
	L7Confidence    uint8 // 0-100

	// Vendor-specific enrichment
	VendorType      string // e.g., "extreme"
	VendorFields    map[string]interface{}

	// Enrichment metadata
	EnrichmentTime  time.Duration
	SNMPEnriched    bool
	L7Enriched      bool
}

// L7Protocol represents detected application protocols
type L7Protocol uint16

const (
	L7Unknown L7Protocol = iota
	L7SIP
	L7RTP
	L7RTCP
	L7HTTP
	L7HTTPS
	L7DNS
	L7DHCP
	L7SSH
	L7Telnet
	L7SNMP
	L7NTP
	L7ICMP
	L7IGMP
)

func (p L7Protocol) String() string {
	switch p {
	case L7SIP:
		return "sip"
	case L7RTP:
		return "rtp"
	case L7RTCP:
		return "rtcp"
	case L7HTTP:
		return "http"
	case L7HTTPS:
		return "https"
	case L7DNS:
		return "dns"
	case L7DHCP:
		return "dhcp"
	case L7SSH:
		return "ssh"
	case L7Telnet:
		return "telnet"
	case L7SNMP:
		return "snmp"
	case L7NTP:
		return "ntp"
	case L7ICMP:
		return "icmp"
	case L7IGMP:
		return "igmp"
	default:
		return "unknown"
	}
}

// L7Category represents application categories
// Limited to 6-7 categories as specified
type L7Category uint8

const (
	L7CategoryUnknown L7Category = iota
	L7CategoryVoice              // SIP, RTP, RTCP
	L7CategoryVideo              // Video streaming (RTP video)
	L7CategoryAudio              // Audio streaming
	L7CategoryControl            // Management/control traffic (SSH, Telnet, SNMP)
	L7CategoryNetworkServices    // DNS, DHCP, NTP
	L7CategoryOther              // Anything else
)

func (c L7Category) String() string {
	switch c {
	case L7CategoryVoice:
		return "voice"
	case L7CategoryVideo:
		return "video"
	case L7CategoryAudio:
		return "audio"
	case L7CategoryControl:
		return "control"
	case L7CategoryNetworkServices:
		return "network_services"
	case L7CategoryOther:
		return "other"
	default:
		return "unknown"
	}
}

// EnricherConfig holds configuration for the flow enricher
type EnricherConfig struct {
	// SNMP enrichment
	SNMPConfig *SNMPEnricherConfig

	// L7 classification
	L7Enabled       bool
	L7Categories    []L7Category // Which categories to classify

	// General settings
	Enabled         bool
	MaxEnrichmentTime time.Duration

	// Metrics
	Metrics *EnricherMetrics
}

// EnricherMetrics holds prometheus metrics for enrichment
type EnricherMetrics struct {
	FlowsEnriched    *prometheus.CounterVec
	EnrichmentTime   prometheus.Histogram
	SNMPHits         prometheus.Counter
	SNMPMisses       prometheus.Counter
	L7Classifications *prometheus.CounterVec
}

// NewEnricherMetrics creates prometheus metrics for enrichment
func NewEnricherMetrics(namespace string) *EnricherMetrics {
	return &EnricherMetrics{
		FlowsEnriched: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "enrichment",
			Name:      "flows_enriched_total",
			Help:      "Total flows enriched",
		}, []string{"type"}),
		EnrichmentTime: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "enrichment",
			Name:      "duration_seconds",
			Help:      "Time spent enriching flows",
			Buckets:   prometheus.ExponentialBuckets(0.00001, 2, 15),
		}),
		SNMPHits: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "enrichment",
			Name:      "snmp_hits_total",
			Help:      "SNMP cache hits during enrichment",
		}),
		SNMPMisses: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "enrichment",
			Name:      "snmp_misses_total",
			Help:      "SNMP cache misses during enrichment",
		}),
		L7Classifications: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "enrichment",
			Name:      "l7_classifications_total",
			Help:      "L7 protocol classifications",
		}, []string{"protocol", "category"}),
	}
}

// FlowEnricher is the main enrichment pipeline
type FlowEnricher struct {
	config      *EnricherConfig
	snmpEnricher *SNMPEnricher
	l7Classifier *L7Classifier
	mu          sync.RWMutex
}

// NewFlowEnricher creates a new flow enricher
func NewFlowEnricher(cfg *EnricherConfig) *FlowEnricher {
	e := &FlowEnricher{
		config: cfg,
	}

	// Initialize SNMP enricher if configured
	if cfg.SNMPConfig != nil && cfg.SNMPConfig.Enabled {
		e.snmpEnricher = NewSNMPEnricher(cfg.SNMPConfig)
	}

	// Initialize L7 classifier if enabled
	if cfg.L7Enabled {
		e.l7Classifier = NewL7Classifier(&L7ClassifierConfig{
			EnabledCategories: cfg.L7Categories,
		})
	}

	return e
}

// Start starts all enrichment subsystems
func (e *FlowEnricher) Start() error {
	if e.snmpEnricher != nil {
		if err := e.snmpEnricher.Start(); err != nil {
			return err
		}
	}

	if e.l7Classifier != nil {
		if err := e.l7Classifier.Start(); err != nil {
			return err
		}
	}

	if log != nil {
		log.WithFields(map[string]interface{}{
			"snmp_enabled": e.snmpEnricher != nil,
			"l7_enabled":   e.l7Classifier != nil,
		}).Info("Flow enricher started")
	}

	return nil
}

// Stop stops all enrichment subsystems
func (e *FlowEnricher) Stop() {
	if e.snmpEnricher != nil {
		e.snmpEnricher.Stop()
	}
	if e.l7Classifier != nil {
		e.l7Classifier.Stop()
	}
	if log != nil {
		log.Info("Flow enricher stopped")
	}
}

// EnrichFlow enriches a flow with additional metadata
func (e *FlowEnricher) EnrichFlow(flow *flowpb.FlowMessage) *EnrichedFlow {
	if !e.config.Enabled {
		return &EnrichedFlow{BaseFlow: flow}
	}

	start := time.Now()
	enriched := &EnrichedFlow{
		BaseFlow:     flow,
		VendorFields: make(map[string]interface{}),
	}

	// Get exporter IP
	var exporterIP net.IP
	if len(flow.SamplerAddress) > 0 {
		exporterIP = net.IP(flow.SamplerAddress)
	}

	// SNMP enrichment
	if e.snmpEnricher != nil && exporterIP != nil {
		e.enrichFromSNMP(enriched, exporterIP, flow.InIf, flow.OutIf)
	}

	// L7 classification
	if e.l7Classifier != nil {
		e.classifyL7(enriched, flow)
	}

	enriched.EnrichmentTime = time.Since(start)

	// Record metrics
	if e.config.Metrics != nil {
		e.config.Metrics.EnrichmentTime.Observe(enriched.EnrichmentTime.Seconds())
		if enriched.SNMPEnriched {
			e.config.Metrics.FlowsEnriched.WithLabelValues("snmp").Inc()
		}
		if enriched.L7Enriched {
			e.config.Metrics.FlowsEnriched.WithLabelValues("l7").Inc()
		}
	}

	return enriched
}

func (e *FlowEnricher) enrichFromSNMP(enriched *EnrichedFlow, exporterIP net.IP, inIf, outIf uint32) {
	// Register exporter for SNMP polling
	e.snmpEnricher.RegisterExporter(exporterIP)

	// Get device info
	device := e.snmpEnricher.GetDeviceInfo(exporterIP)
	if device != nil {
		enriched.DeviceSysName = device.SysName
	}

	// Enrich input interface
	if inIf > 0 {
		if inInfo := e.snmpEnricher.GetInterfaceInfo(exporterIP, inIf); inInfo != nil {
			enriched.InIfName = inInfo.IfName
			enriched.InIfAlias = inInfo.IfAlias
			enriched.InIfSpeed = inInfo.IfSpeed
			enriched.InLagIfIndex = inInfo.LagIfIndex
			enriched.SNMPEnriched = true
			if e.config.Metrics != nil {
				e.config.Metrics.SNMPHits.Inc()
			}
		} else {
			if e.config.Metrics != nil {
				e.config.Metrics.SNMPMisses.Inc()
			}
		}
	}

	// Enrich output interface
	if outIf > 0 {
		if outInfo := e.snmpEnricher.GetInterfaceInfo(exporterIP, outIf); outInfo != nil {
			enriched.OutIfName = outInfo.IfName
			enriched.OutIfAlias = outInfo.IfAlias
			enriched.OutIfSpeed = outInfo.IfSpeed
			enriched.OutLagIfIndex = outInfo.LagIfIndex
			enriched.SNMPEnriched = true
			if e.config.Metrics != nil {
				e.config.Metrics.SNMPHits.Inc()
			}
		} else {
			if e.config.Metrics != nil {
				e.config.Metrics.SNMPMisses.Inc()
			}
		}
	}
}

func (e *FlowEnricher) classifyL7(enriched *EnrichedFlow, flow *flowpb.FlowMessage) {
	classification := e.l7Classifier.Classify(flow)

	enriched.L7Protocol = classification.Protocol
	enriched.L7Category = classification.Category
	enriched.L7Confidence = classification.Confidence

	if classification.Protocol != L7Unknown {
		enriched.L7Enriched = true

		if e.config.Metrics != nil {
			e.config.Metrics.L7Classifications.WithLabelValues(
				classification.Protocol.String(),
				classification.Category.String(),
			).Inc()
		}
	}
}

// RegisterExporter registers an exporter for SNMP polling
func (e *FlowEnricher) RegisterExporter(ip net.IP) {
	if e.snmpEnricher != nil {
		e.snmpEnricher.RegisterExporter(ip)
	}
}

// GetSNMPEnricher returns the SNMP enricher (for direct access if needed)
func (e *FlowEnricher) GetSNMPEnricher() *SNMPEnricher {
	return e.snmpEnricher
}

// GetL7Classifier returns the L7 classifier
func (e *FlowEnricher) GetL7Classifier() *L7Classifier {
	return e.l7Classifier
}

// IsEnabled returns whether enrichment is enabled
func (e *FlowEnricher) IsEnabled() bool {
	return e.config.Enabled
}
