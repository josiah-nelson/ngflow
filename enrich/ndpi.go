package enrich

import "strings"

type NDPIConfig struct {
	Enabled           bool
	AllowedCategories []string
}

type NDPIClassification struct {
	Protocol   string
	Category   string
	Confidence uint8
	Method     string
}

type NDPIClassifier struct {
	enabled  bool
	allowed  map[string]bool
	rulebook []ndpiRule
}

type ndpiRule struct {
	Category string
	Matches  []string
}

func NewNDPIClassifier(config NDPIConfig) *NDPIClassifier {
	allowed := make(map[string]bool)
	for _, category := range config.AllowedCategories {
		category = strings.ToLower(strings.TrimSpace(category))
		if category != "" {
			allowed[category] = true
		}
	}
	if len(allowed) == 0 {
		allowed["sip"] = true
		allowed["video"] = true
		allowed["audio"] = true
		allowed["control"] = true
		allowed["services"] = true
	}
	return &NDPIClassifier{
		enabled: config.Enabled,
		allowed: allowed,
		rulebook: []ndpiRule{
			{Category: "sip", Matches: []string{"sip", "sips"}},
			{Category: "video", Matches: []string{"rtsp", "rtmp", "hls", "webrtc", "video", "mpeg", "h264", "h265"}},
			{Category: "audio", Matches: []string{"rtp", "srtp", "rtcp", "opus", "g711", "g729", "audio"}},
			{Category: "control", Matches: []string{"snmp", "ssh", "telnet", "netconf", "restconf", "bgp", "ospf", "isis", "lldp", "radius", "tacacs"}},
			{Category: "services", Matches: []string{"dns", "dhcp", "ntp", "icmp", "igmp"}},
		},
	}
}

func (c *NDPIClassifier) Classify(appName string) (NDPIClassification, bool) {
	if c == nil || !c.enabled {
		return NDPIClassification{}, false
	}
	appName = strings.TrimSpace(appName)
	if appName == "" {
		return NDPIClassification{}, false
	}
	lower := strings.ToLower(appName)
	for _, rule := range c.rulebook {
		if !c.allowed[rule.Category] {
			continue
		}
		for _, match := range rule.Matches {
			if strings.Contains(lower, match) {
				return NDPIClassification{
					Protocol:   appName,
					Category:   rule.Category,
					Confidence: 90,
					Method:     "application_name",
				}, true
			}
		}
	}
	return NDPIClassification{}, false
}
