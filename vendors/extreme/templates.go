// Package extreme provides Extreme Networks vendor support.
//
// IMPORTANT: Template definitions and field mappings in this file are derived
// from official Extreme Networks documentation. Do not add values that cannot
// be verified against vendor documentation.
//
// Documentation Sources:
//   - Fabric Engine User Guide: https://documentation.extremenetworks.com/FABRICENGINE/
//   - Switch Engine User Guide: https://documentation.extremenetworks.com/switchengine_32.4/
//   - ExtremeXOS User Guide: https://documentation.extremenetworks.com/exos_32.7.1/
//
// The actual IPFIX templates sent by devices are dynamically learned at runtime.
// These definitions serve as reference and for validation purposes only.

package extreme

import (
	"encoding/binary"
	"fmt"
)

// Standard IANA IPFIX Information Element IDs
// Reference: https://www.iana.org/assignments/ipfix/ipfix.xhtml
//
// These are standard IETF-defined field IDs that Fabric Engine exports.
// Per vendor documentation, Fabric Engine exports IPv4 flows with these elements.
const (
	IEOctetDeltaCount       = 1   // Total bytes in flow
	IEPacketDeltaCount      = 2   // Total packets in flow
	IEProtocolIdentifier    = 4   // IP protocol number
	IEIpClassOfService      = 5   // ToS/DSCP
	IETcpControlBits        = 6   // TCP flags
	IESourceTransportPort   = 7   // L4 source port
	IESourceIPv4Address     = 8   // IPv4 source
	IESourceIPv4PrefixLen   = 9   // Source prefix length
	IEIngressInterface      = 10  // Input ifIndex
	IEDestTransportPort     = 11  // L4 destination port
	IEDestIPv4Address       = 12  // IPv4 destination
	IEDestIPv4PrefixLen     = 13  // Destination prefix length
	IEEgressInterface       = 14  // Output ifIndex
	IEIpNextHopIPv4Address  = 15  // Next hop IPv4
	IEBgpSourceAsNumber     = 16  // Source AS
	IEBgpDestAsNumber       = 17  // Destination AS
	IESourceIPv6Address     = 27  // IPv6 source
	IEDestIPv6Address       = 28  // IPv6 destination
	IESourceIPv6PrefixLen   = 29  // IPv6 source prefix length
	IEDestIPv6PrefixLen     = 30  // IPv6 destination prefix length
	IEIpv6FlowLabel         = 31  // IPv6 flow label
	IESamplingInterval      = 34  // Sampling interval
	IESamplingAlgorithm     = 35  // Sampling algorithm
	IEFlowSamplerID         = 48  // Sampler ID
	IESourceMacAddress      = 56  // Source MAC
	IEVlanId                = 58  // VLAN ID
	IEIpVersion             = 60  // IP version (4 or 6)
	IEFlowDirection         = 61  // Flow direction
	IEDestMacAddress        = 80  // Destination MAC
	IEObservationPointId    = 138 // Observation point
	IEFlowId                = 148 // Flow identifier
	IEObservationDomainId   = 149 // Observation domain
	IEFlowStartMilliseconds = 152 // Flow start time (ms since epoch)
	IEFlowEndMilliseconds   = 153 // Flow end time (ms since epoch)
)

// FabricEngineIPFIXDefaults contains default values from Fabric Engine documentation.
//
// Source: Fabric Engine User Guide, IPFIX Configuration section
// Source: https://extreme-networks.my.site.com/ExtrArticleDetail?an=000067673
type FabricEngineIPFIXDefaults struct {
	// AgingInterval is the flow aging timeout in seconds.
	// Default: 30 seconds
	// Range: 0–2,147,400 seconds
	// CLI: ip ipfix slot <slot> aging-interval <seconds>
	AgingInterval uint32

	// ExportInterval is the export interval in seconds.
	// Range: 10–3,600 seconds
	// CLI: ip ipfix export-interval <seconds>
	ExportInterval uint32

	// TemplateRefreshInterval is the template refresh in seconds.
	// Default: 1,800 seconds (30 minutes)
	// Also refreshed every 10,000 packets
	TemplateRefreshInterval uint32

	// MaxCollectors is the maximum number of collectors supported.
	// Value: 2 (IPFIX data is not load balanced between collectors)
	MaxCollectors int
}

// DefaultFabricEngineIPFIX returns documented default values for Fabric Engine IPFIX.
func DefaultFabricEngineIPFIX() FabricEngineIPFIXDefaults {
	return FabricEngineIPFIXDefaults{
		AgingInterval:           30,
		ExportInterval:          60,   // Typical, not documented default
		TemplateRefreshInterval: 1800, // 30 minutes
		MaxCollectors:           2,
	}
}

// SwitchEngineSFlowDefaults contains default values from Switch Engine/EXOS documentation.
//
// Source: ExtremeXOS User Guide, sFlow Configuration section
// Source: https://documentation.extremenetworks.com/exos_32.7.1/GUID-C22DF001-16D7-4B6D-8044-DB4ECAAEDC85.shtml
type SwitchEngineSFlowDefaults struct {
	// PollInterval is the counter polling interval in seconds.
	// Default: 20 seconds
	// Range: 0–300 seconds (0 disables polling)
	// CLI: configure sflow poll-interval <seconds>
	PollInterval uint32

	// SamplingRate is the global sampling rate (1:N).
	// Default: 4096 (1 in 4096 packets)
	// CLI: configure sflow sample-rate <rate>
	SamplingRate uint32

	// DefaultUDPPort is the default sFlow collector port.
	// Default: 6343
	DefaultUDPPort uint16

	// SFlowVersion is the sFlow protocol version.
	// Value: 5 (per RFC 3176 improvements)
	SFlowVersion uint8
}

// DefaultSwitchEngineSFlow returns documented default values for Switch Engine sFlow.
func DefaultSwitchEngineSFlow() SwitchEngineSFlowDefaults {
	return SwitchEngineSFlowDefaults{
		PollInterval:   20,
		SamplingRate:   4096,
		DefaultUDPPort: 6343,
		SFlowVersion:   5,
	}
}

// IPFIXTemplateInfo describes an IPFIX template received from a device.
// Templates are learned dynamically; this struct captures what we receive.
type IPFIXTemplateInfo struct {
	TemplateID     uint16
	FieldCount     uint16
	ObservationDom uint32
	IsOptions      bool
	SourceIP       string
	ReceivedAt     int64
}

// SFlowEnterpriseRecord represents an enterprise-specific sFlow record.
// Per sFlow v5 specification, enterprise records have format: (enterprise << 12) | format
type SFlowEnterpriseRecord struct {
	Enterprise uint32
	Format     uint32
	Length     uint32
	RawData    []byte
}

// ParseEnterpriseRecord attempts to parse an enterprise-specific sFlow record.
// Returns the raw data if parsing is not possible (unknown format).
func ParseEnterpriseRecord(enterprise, format uint32, data []byte) (*SFlowEnterpriseRecord, error) {
	record := &SFlowEnterpriseRecord{
		Enterprise: enterprise,
		Format:     format,
		Length:     uint32(len(data)),
		RawData:    data,
	}

	// Only attempt to parse Extreme Networks enterprise records
	if enterprise != ExtremeEnterpriseID {
		return record, nil
	}

	// Parse known Extreme formats
	// Note: Exact formats are not fully documented; these are based on
	// observed behavior and should be validated against actual device output
	switch format {
	case 1: // Extended switch data (assumed)
		// Pass through - format not fully documented
	case 2: // CLEAR-FLOW data (assumed)
		if len(data) >= 12 {
			// Minimum: 4 bytes rule ID + 8 bytes counter
			// Additional fields may follow
		}
	default:
		// Unknown format - store raw data for inspection
	}

	return record, nil
}

// FabricEngineLimitations documents known limitations from vendor documentation.
//
// Source: Fabric Engine User Guide, IPFIX section
// These limitations affect how the collector should handle flows from these devices.
type FabricEngineLimitations struct {
	// IPv4Only: IPFIX on Fabric Engine only monitors IPv4 traffic flows.
	// IPv6 IPFIX is not supported as of Fabric Engine 9.3.
	IPv4Only bool

	// IngressOnly: Only ingress sampling is supported. Egress sampling is not available.
	IngressOnly bool

	// NoMacInMacTraversing: IPFIX does not process Mac-in-Mac flows that only
	// traverse the switch (Layer 2 switching). Only terminated flows are captured.
	NoMacInMacTraversing bool

	// NoL3VSNOnNNI: Layer 3 Virtual Services Network flow packets on NNI ports
	// are not learned by IPFIX.
	NoL3VSNOnNNI bool
}

// GetFabricEngineLimitations returns documented Fabric Engine IPFIX limitations.
func GetFabricEngineLimitations() FabricEngineLimitations {
	return FabricEngineLimitations{
		IPv4Only:             true,
		IngressOnly:          true,
		NoMacInMacTraversing: true,
		NoL3VSNOnNNI:         true,
	}
}

// ValidateIPFIXTemplate checks if a received template contains expected fields.
// Returns a list of issues found, if any.
func ValidateIPFIXTemplate(templateID uint16, fieldIDs []uint16) []string {
	var issues []string

	// Check for minimum required fields for flow identification
	hasSource := false
	hasDest := false
	hasProto := false
	hasBytes := false

	for _, id := range fieldIDs {
		switch id {
		case IESourceIPv4Address, IESourceIPv6Address:
			hasSource = true
		case IEDestIPv4Address, IEDestIPv6Address:
			hasDest = true
		case IEProtocolIdentifier:
			hasProto = true
		case IEOctetDeltaCount:
			hasBytes = true
		}
	}

	if !hasSource {
		issues = append(issues, "template missing source address field")
	}
	if !hasDest {
		issues = append(issues, "template missing destination address field")
	}
	if !hasProto {
		issues = append(issues, "template missing protocol field")
	}
	if !hasBytes {
		issues = append(issues, "template missing byte count field")
	}

	return issues
}

// ObservationDomainInfo provides context for an observation domain ID.
type ObservationDomainInfo struct {
	DomainID   uint32
	DeviceType DeviceType
	// Interpretation varies by device type:
	// - Fabric Engine: May indicate VRF (0 = GlobalRouter)
	// - Switch Engine: May indicate stack member (0 = primary/standalone)
	Interpretation string
}

// InterpretObservationDomain provides context for an observation domain value.
// Note: Actual meaning depends on device configuration and cannot be determined
// without SNMP or other out-of-band information.
func InterpretObservationDomain(deviceType DeviceType, domainID uint32) ObservationDomainInfo {
	info := ObservationDomainInfo{
		DomainID:   domainID,
		DeviceType: deviceType,
	}

	switch deviceType {
	case DeviceTypeFabricEngine, DeviceType5520:
		if domainID == 0 {
			info.Interpretation = "default (likely GlobalRouter VRF)"
		} else {
			info.Interpretation = fmt.Sprintf("configured domain %d (may indicate VRF)", domainID)
		}
	case DeviceTypeSwitchEngine, DeviceTypeEXOS, DeviceTypeX435, DeviceType5120:
		if domainID == 0 {
			info.Interpretation = "default (primary/standalone)"
		} else {
			info.Interpretation = fmt.Sprintf("sub-agent %d (may indicate stack member)", domainID)
		}
	default:
		info.Interpretation = "unknown device type"
	}

	return info
}

// Helper for parsing Extreme sFlow data with proper bounds checking
func safeGetUint32(data []byte, offset int) (uint32, bool) {
	if len(data) < offset+4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(data[offset : offset+4]), true
}

func safeGetUint64(data []byte, offset int) (uint64, bool) {
	if len(data) < offset+8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(data[offset : offset+8]), true
}
