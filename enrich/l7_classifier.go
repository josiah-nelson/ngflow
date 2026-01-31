package enrich

import (
	"strings"

	flowpb "github.com/netsampler/goflow2/v2/pb"
)

type L7Config struct {
	Enabled           bool
	AllowedCategories []string
}

type L7Classifier struct {
	enabled  bool
	allowed  map[string]bool
	tcpPortMap map[uint16]portClassification
	udpPortMap map[uint16]portClassification
}

type portClassification struct {
	protocol   string
	category   string
	confidence uint8
}

func NewL7Classifier(config L7Config) *L7Classifier {
	allowed := make(map[string]bool)
	for _, category := range config.AllowedCategories {
		category = strings.ToLower(strings.TrimSpace(category))
		if category == "" {
			continue
		}
		allowed[category] = true
	}
	if len(allowed) == 0 {
		allowed["voice"] = true
		allowed["video"] = true
		allowed["audio"] = true
		allowed["control"] = true
		allowed["services"] = true
		allowed["other"] = true
	}

	classifier := &L7Classifier{
		enabled:    config.Enabled,
		allowed:    allowed,
		tcpPortMap: make(map[uint16]portClassification),
		udpPortMap: make(map[uint16]portClassification),
	}
	classifier.initPortMaps()
	return classifier
}

func (c *L7Classifier) initPortMaps() {
	// Voice/VoIP
	c.udpPortMap[5060] = portClassification{protocol: "sip", category: "voice", confidence: 90}
	c.udpPortMap[5061] = portClassification{protocol: "sip", category: "voice", confidence: 90}
	c.tcpPortMap[5060] = portClassification{protocol: "sip", category: "voice", confidence: 90}
	c.tcpPortMap[5061] = portClassification{protocol: "sip", category: "voice", confidence: 90}

	// RTP common ranges (heuristic)
	for port := uint16(16384); port <= 16484; port++ {
		c.udpPortMap[port] = portClassification{protocol: "rtp", category: "voice", confidence: 60}
	}
	for port := uint16(10000); port <= 10100; port++ {
		c.udpPortMap[port] = portClassification{protocol: "rtp", category: "voice", confidence: 50}
	}

	// Control/Management
	c.tcpPortMap[22] = portClassification{protocol: "ssh", category: "control", confidence: 95}
	c.tcpPortMap[23] = portClassification{protocol: "telnet", category: "control", confidence: 95}
	c.udpPortMap[161] = portClassification{protocol: "snmp", category: "control", confidence: 95}
	c.udpPortMap[162] = portClassification{protocol: "snmp", category: "control", confidence: 95}

	// Network services
	c.udpPortMap[53] = portClassification{protocol: "dns", category: "services", confidence: 95}
	c.tcpPortMap[53] = portClassification{protocol: "dns", category: "services", confidence: 95}
	c.udpPortMap[67] = portClassification{protocol: "dhcp", category: "services", confidence: 95}
	c.udpPortMap[68] = portClassification{protocol: "dhcp", category: "services", confidence: 95}
	c.udpPortMap[123] = portClassification{protocol: "ntp", category: "services", confidence: 95}

	// HTTP/HTTPS tagged as other
	c.tcpPortMap[80] = portClassification{protocol: "http", category: "other", confidence: 70}
	c.tcpPortMap[443] = portClassification{protocol: "https", category: "other", confidence: 70}
	c.tcpPortMap[8080] = portClassification{protocol: "http", category: "other", confidence: 60}
	c.tcpPortMap[8443] = portClassification{protocol: "https", category: "other", confidence: 60}
}

func (c *L7Classifier) Classify(flow *flowpb.FlowMessage) (NDPIClassification, bool) {
	if c == nil || !c.enabled || flow == nil {
		return NDPIClassification{}, false
	}

	switch flow.Proto {
	case 1:
		return c.result("icmp", "services", 100, "protocol"), true
	case 2:
		return c.result("igmp", "services", 100, "protocol"), true
	case 6:
		if class, ok := c.tcpPortMap[uint16(flow.DstPort)]; ok {
			if c.allowedCategory(class.category) {
				return c.result(class.protocol, class.category, class.confidence, "dst_port"), true
			}
		}
		if class, ok := c.tcpPortMap[uint16(flow.SrcPort)]; ok {
			if c.allowedCategory(class.category) {
				return c.result(class.protocol, class.category, class.confidence-10, "src_port"), true
			}
		}
	case 17:
		if class, ok := c.udpPortMap[uint16(flow.DstPort)]; ok {
			if c.allowedCategory(class.category) {
				return c.result(class.protocol, class.category, class.confidence, "dst_port"), true
			}
		}
		if class, ok := c.udpPortMap[uint16(flow.SrcPort)]; ok {
			if c.allowedCategory(class.category) {
				return c.result(class.protocol, class.category, class.confidence-10, "src_port"), true
			}
		}
		if result, ok := c.detectRTP(flow); ok {
			return result, true
		}
	}

	return NDPIClassification{}, false
}

func (c *L7Classifier) detectRTP(flow *flowpb.FlowMessage) (NDPIClassification, bool) {
	if flow.Proto != 17 {
		return NDPIClassification{}, false
	}

	srcPort := uint16(flow.SrcPort)
	dstPort := uint16(flow.DstPort)

	isRTPRange := func(port uint16) bool {
		return (port >= 16384 && port <= 32767) ||
			(port >= 10000 && port <= 20000) ||
			(port >= 5004 && port <= 5005) ||
			(port >= 49152 && port <= 65535)
	}

	if !isRTPRange(srcPort) && !isRTPRange(dstPort) {
		return NDPIClassification{}, false
	}

	port := dstPort
	if srcPort > dstPort {
		port = srcPort
	}

	if port%2 == 1 {
		if c.allowedCategory("voice") {
			return c.result("rtcp", "voice", 40, "rtp_heuristic"), true
		}
		return NDPIClassification{}, false
	}

	category := "voice"
	if flow.Packets > 0 {
		avgPacketSize := flow.Bytes / flow.Packets
		switch {
		case avgPacketSize < 200:
			category = "voice"
		case avgPacketSize < 500:
			category = "audio"
		default:
			category = "video"
		}
	}

	if !c.allowedCategory(category) {
		return NDPIClassification{}, false
	}

	return c.result("rtp", category, 35, "rtp_heuristic"), true
}

func (c *L7Classifier) allowedCategory(category string) bool {
	return c.allowed[category]
}

func (c *L7Classifier) result(protocol, category string, confidence uint8, method string) NDPIClassification {
	return NDPIClassification{
		Protocol:   protocol,
		Category:   category,
		Confidence: confidence,
		Method:     method,
	}
}
