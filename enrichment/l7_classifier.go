// Package enrichment - l7_classifier.go provides lightweight L7/application
// classification for flow data. This is inspired by nDPI but implements
// a simplified, focused classification for specific categories:
//   - Voice (SIP, RTP, RTCP)
//   - Video (RTP video streams)
//   - Audio (RTP audio streams)
//   - Control/Management (SSH, Telnet, SNMP)
//   - Network Services (DNS, DHCP, NTP)
//
// This implementation focuses on port-based and protocol-based heuristics
// suitable for air-gapped, stable traffic environments.

package enrichment

import (
	flowpb "github.com/netsampler/goflow2/v2/pb"
)

// L7Classification holds the result of L7 classification
type L7Classification struct {
	Protocol   L7Protocol
	Category   L7Category
	Confidence uint8  // 0-100 (0=unknown, 100=definite)
	Method     string // How classification was determined
}

// L7ClassifierConfig holds configuration for L7 classification
type L7ClassifierConfig struct {
	EnabledCategories []L7Category
}

// L7Classifier performs lightweight L7 classification
type L7Classifier struct {
	config *L7ClassifierConfig
	// Maps for fast lookup
	tcpPortMap map[uint16]portClassification
	udpPortMap map[uint16]portClassification
}

type portClassification struct {
	protocol   L7Protocol
	category   L7Category
	confidence uint8
}

// NewL7Classifier creates a new L7 classifier
func NewL7Classifier(cfg *L7ClassifierConfig) *L7Classifier {
	c := &L7Classifier{
		config:     cfg,
		tcpPortMap: make(map[uint16]portClassification),
		udpPortMap: make(map[uint16]portClassification),
	}

	c.initPortMaps()
	return c
}

func (c *L7Classifier) initPortMaps() {
	// Voice/VoIP ports
	c.udpPortMap[5060] = portClassification{L7SIP, L7CategoryVoice, 90}       // SIP
	c.udpPortMap[5061] = portClassification{L7SIP, L7CategoryVoice, 90}       // SIP TLS
	c.tcpPortMap[5060] = portClassification{L7SIP, L7CategoryVoice, 90}       // SIP TCP
	c.tcpPortMap[5061] = portClassification{L7SIP, L7CategoryVoice, 90}       // SIP TLS

	// RTP range - typically 16384-32767, we'll flag common ranges
	// Note: RTP detection from flow data alone is challenging
	// These are common RTP port ranges used by various systems
	for port := uint16(16384); port <= 16484; port++ {
		c.udpPortMap[port] = portClassification{L7RTP, L7CategoryVoice, 60}
	}
	for port := uint16(10000); port <= 10100; port++ {
		c.udpPortMap[port] = portClassification{L7RTP, L7CategoryVoice, 50}
	}

	// RTCP is typically RTP port + 1, handled in detection logic

	// Control/Management protocols
	c.tcpPortMap[22] = portClassification{L7SSH, L7CategoryControl, 95}      // SSH
	c.tcpPortMap[23] = portClassification{L7Telnet, L7CategoryControl, 95}   // Telnet
	c.udpPortMap[161] = portClassification{L7SNMP, L7CategoryControl, 95}    // SNMP
	c.udpPortMap[162] = portClassification{L7SNMP, L7CategoryControl, 95}    // SNMP Trap

	// Network services
	c.udpPortMap[53] = portClassification{L7DNS, L7CategoryNetworkServices, 95}    // DNS
	c.tcpPortMap[53] = portClassification{L7DNS, L7CategoryNetworkServices, 95}    // DNS over TCP
	c.udpPortMap[67] = portClassification{L7DHCP, L7CategoryNetworkServices, 95}   // DHCP Server
	c.udpPortMap[68] = portClassification{L7DHCP, L7CategoryNetworkServices, 95}   // DHCP Client
	c.udpPortMap[123] = portClassification{L7NTP, L7CategoryNetworkServices, 95}   // NTP

	// HTTP/HTTPS - categorized as "other" since we're not classifying web traffic
	// per requirements: "No general user/web traffic classification"
	// We include them for completeness but assign to "other" category
	c.tcpPortMap[80] = portClassification{L7HTTP, L7CategoryOther, 70}
	c.tcpPortMap[443] = portClassification{L7HTTPS, L7CategoryOther, 70}
	c.tcpPortMap[8080] = portClassification{L7HTTP, L7CategoryOther, 60}
	c.tcpPortMap[8443] = portClassification{L7HTTPS, L7CategoryOther, 60}
}

// Start initializes the classifier (placeholder for future nDPI integration)
func (c *L7Classifier) Start() error {
	if log != nil {
		log.Info("L7 classifier started (port-based heuristics)")
	}
	return nil
}

// Stop stops the classifier
func (c *L7Classifier) Stop() {
	if log != nil {
		log.Info("L7 classifier stopped")
	}
}

// Classify performs L7 classification on a flow
func (c *L7Classifier) Classify(flow *flowpb.FlowMessage) L7Classification {
	// Default result
	result := L7Classification{
		Protocol:   L7Unknown,
		Category:   L7CategoryUnknown,
		Confidence: 0,
		Method:     "none",
	}

	// Classify based on IP protocol first
	switch flow.Proto {
	case 1: // ICMP
		result.Protocol = L7ICMP
		result.Category = L7CategoryNetworkServices
		result.Confidence = 100
		result.Method = "protocol"
		return result

	case 2: // IGMP
		result.Protocol = L7IGMP
		result.Category = L7CategoryNetworkServices
		result.Confidence = 100
		result.Method = "protocol"
		return result

	case 6: // TCP
		if class, ok := c.tcpPortMap[uint16(flow.DstPort)]; ok {
			if c.isCategoryEnabled(class.category) {
				result.Protocol = class.protocol
				result.Category = class.category
				result.Confidence = class.confidence
				result.Method = "dst_port"
				return result
			}
		}
		if class, ok := c.tcpPortMap[uint16(flow.SrcPort)]; ok {
			if c.isCategoryEnabled(class.category) {
				result.Protocol = class.protocol
				result.Category = class.category
				// Lower confidence for source port match
				result.Confidence = class.confidence - 10
				result.Method = "src_port"
				return result
			}
		}

	case 17: // UDP
		if class, ok := c.udpPortMap[uint16(flow.DstPort)]; ok {
			if c.isCategoryEnabled(class.category) {
				result.Protocol = class.protocol
				result.Category = class.category
				result.Confidence = class.confidence
				result.Method = "dst_port"
				return result
			}
		}
		if class, ok := c.udpPortMap[uint16(flow.SrcPort)]; ok {
			if c.isCategoryEnabled(class.category) {
				result.Protocol = class.protocol
				result.Category = class.category
				result.Confidence = class.confidence - 10
				result.Method = "src_port"
				return result
			}
		}

		// RTP/RTCP heuristics for UDP traffic in typical ranges
		result = c.detectRTP(flow)
		if result.Protocol != L7Unknown {
			return result
		}
	}

	return result
}

// detectRTP uses heuristics to detect RTP/RTCP traffic
func (c *L7Classifier) detectRTP(flow *flowpb.FlowMessage) L7Classification {
	result := L7Classification{
		Protocol:   L7Unknown,
		Category:   L7CategoryUnknown,
		Confidence: 0,
		Method:     "none",
	}

	if flow.Proto != 17 { // UDP only
		return result
	}

	// RTP typically uses even ports, RTCP uses odd ports (RTP+1)
	srcPort := uint16(flow.SrcPort)
	dstPort := uint16(flow.DstPort)

	// Check if ports are in typical RTP ranges
	isRTPRange := func(port uint16) bool {
		// Common RTP port ranges
		return (port >= 16384 && port <= 32767) || // Standard range
			(port >= 10000 && port <= 20000) ||    // Common alternative
			(port >= 5004 && port <= 5005) ||      // Default RTP/RTCP
			(port >= 49152 && port <= 65535)       // Dynamic/ephemeral
	}

	if isRTPRange(dstPort) || isRTPRange(srcPort) {
		// Check for RTCP (odd port)
		port := dstPort
		if srcPort > dstPort {
			port = srcPort
		}

		if port%2 == 1 {
			// Odd port, likely RTCP
			result.Protocol = L7RTCP
			result.Category = L7CategoryVoice
			result.Confidence = 40 // Low confidence without DPI
			result.Method = "rtp_heuristic"
		} else {
			// Even port, likely RTP
			result.Protocol = L7RTP
			// Determine if voice or video based on packet size heuristics
			// Voice: typically 20-160 bytes payload
			// Video: typically larger, variable

			// We can only estimate from total bytes/packets
			if flow.Packets > 0 {
				avgPacketSize := flow.Bytes / flow.Packets
				if avgPacketSize < 200 {
					result.Category = L7CategoryVoice
				} else if avgPacketSize < 500 {
					result.Category = L7CategoryAudio
				} else {
					result.Category = L7CategoryVideo
				}
			} else {
				result.Category = L7CategoryVoice // Default
			}
			result.Confidence = 35
			result.Method = "rtp_heuristic"
		}
	}

	return result
}

func (c *L7Classifier) isCategoryEnabled(cat L7Category) bool {
	if len(c.config.EnabledCategories) == 0 {
		// All categories enabled by default
		return true
	}
	for _, enabled := range c.config.EnabledCategories {
		if enabled == cat {
			return true
		}
	}
	return false
}

// ClassifyByPorts is a simpler classification using only ports
func ClassifyByPorts(proto uint8, srcPort, dstPort uint16) (L7Protocol, L7Category) {
	// Quick port-based classification without full Classifier overhead
	switch proto {
	case 6: // TCP
		switch {
		case dstPort == 22 || srcPort == 22:
			return L7SSH, L7CategoryControl
		case dstPort == 23 || srcPort == 23:
			return L7Telnet, L7CategoryControl
		case dstPort == 53 || srcPort == 53:
			return L7DNS, L7CategoryNetworkServices
		case dstPort == 5060 || dstPort == 5061 || srcPort == 5060 || srcPort == 5061:
			return L7SIP, L7CategoryVoice
		}
	case 17: // UDP
		switch {
		case dstPort == 53 || srcPort == 53:
			return L7DNS, L7CategoryNetworkServices
		case dstPort == 67 || dstPort == 68 || srcPort == 67 || srcPort == 68:
			return L7DHCP, L7CategoryNetworkServices
		case dstPort == 123 || srcPort == 123:
			return L7NTP, L7CategoryNetworkServices
		case dstPort == 161 || dstPort == 162 || srcPort == 161 || srcPort == 162:
			return L7SNMP, L7CategoryControl
		case dstPort == 5060 || dstPort == 5061 || srcPort == 5060 || srcPort == 5061:
			return L7SIP, L7CategoryVoice
		}
	case 1: // ICMP
		return L7ICMP, L7CategoryNetworkServices
	case 2: // IGMP
		return L7IGMP, L7CategoryNetworkServices
	}

	return L7Unknown, L7CategoryUnknown
}
